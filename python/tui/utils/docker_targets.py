"""
Docker Target Manager

Utilities for discovering and managing Docker containers as attack targets.
Provides integration between Docker containers and security tools.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


@dataclass
class DockerTarget:
    """Represents a Docker container as an attackable target."""

    container_id: str
    container_name: str
    image: str
    status: str
    ip_addresses: Dict[str, str] = field(default_factory=dict)  # network -> IP
    ports: Dict[int, int] = field(default_factory=dict)  # container_port -> host_port
    services: List["TargetService"] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    networks: List[str] = field(default_factory=list)

    @property
    def is_running(self) -> bool:
        """Check if container is running."""
        return self.status.lower() in ("running", "up")

    @property
    def primary_ip(self) -> Optional[str]:
        """Get primary IP address (first available)."""
        if self.ip_addresses:
            return next(iter(self.ip_addresses.values()))
        return None

    @property
    def display_name(self) -> str:
        """Get a display-friendly name."""
        # Remove common prefixes like project name
        name = self.container_name
        if name.startswith("cptc11-"):
            name = name[7:]
        return name

    def get_target_string(self, service: Optional["TargetService"] = None) -> str:
        """Get target string for tools (IP:port or just IP)."""
        ip = self.primary_ip
        if not ip:
            return self.container_name

        if service and service.port:
            # Use host port if available, otherwise container port
            port = self.ports.get(service.port, service.port)
            return f"{ip}:{port}"
        return ip


@dataclass
class TargetService:
    """Represents an attackable service on a Docker target."""

    name: str
    port: int
    protocol: str = "tcp"
    description: str = ""
    attack_types: List[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        """Get display-friendly name."""
        return f"{self.name} ({self.port}/{self.protocol})"


# Service definitions based on docker-compose.yml
SERVICE_DEFINITIONS: Dict[str, List[TargetService]] = {
    "vulnerable-web": [
        TargetService(
            name="HTTP",
            port=80,
            protocol="tcp",
            description="Vulnerable web application",
            attack_types=["web-scan", "vuln-scan", "brute-force"]
        ),
        TargetService(
            name="HTTPS",
            port=443,
            protocol="tcp",
            description="Secure web application",
            attack_types=["web-scan", "ssl-scan", "vuln-scan"]
        ),
    ],
    "ftp-server": [
        TargetService(
            name="FTP",
            port=21,
            protocol="tcp",
            description="FTP service with anonymous access",
            attack_types=["brute-force", "enum", "anon-check"]
        ),
    ],
    "smtp-server": [
        TargetService(
            name="SMTP",
            port=25,
            protocol="tcp",
            description="SMTP mail server",
            attack_types=["enum", "relay-check", "vuln-scan"]
        ),
        TargetService(
            name="SMTP-Submission",
            port=587,
            protocol="tcp",
            description="SMTP submission port",
            attack_types=["brute-force", "relay-check"]
        ),
    ],
    "dns-server": [
        TargetService(
            name="DNS",
            port=53,
            protocol="udp",
            description="DNS server with zone transfer enabled",
            attack_types=["zone-transfer", "enum", "cache-snoop"]
        ),
    ],
    "smb-server": [
        TargetService(
            name="SMB",
            port=445,
            protocol="tcp",
            description="SMB file sharing",
            attack_types=["enum", "brute-force", "share-enum"]
        ),
        TargetService(
            name="NetBIOS",
            port=139,
            protocol="tcp",
            description="NetBIOS session service",
            attack_types=["enum", "null-session"]
        ),
    ],
    "mysql-server": [
        TargetService(
            name="MySQL",
            port=3306,
            protocol="tcp",
            description="MySQL database server",
            attack_types=["brute-force", "enum", "sql-audit"]
        ),
    ],
    "target-server-1": [
        TargetService(
            name="SSH",
            port=22,
            protocol="tcp",
            description="SSH remote access",
            attack_types=["brute-force", "enum", "key-scan"]
        ),
    ],
}

# Host port mappings from docker-compose.yml
HOST_PORT_MAPPINGS: Dict[str, Dict[int, int]] = {
    "vulnerable-web": {80: 8080, 443: 8443},
    "ftp-server": {21: 2121},
    "smtp-server": {25: 2525, 587: 587},
    "dns-server": {53: 5353},
    "smb-server": {445: 4445, 139: 1139},
    "mysql-server": {3306: 3307},
    "target-server-1": {22: 2222},
}


class DockerTargetManager:
    """
    Manages Docker containers as security testing targets.

    Provides methods to discover running containers, map their services,
    and generate target configurations for security tools.
    """

    DOCKER_COMPOSE_DIR = Path("/Users/ic/cptc11/docker")

    def __init__(self) -> None:
        self._targets: List[DockerTarget] = []
        self._last_refresh: Optional[float] = None

    async def _run_command(
        self,
        command: List[str],
        timeout: float = 30.0
    ) -> Tuple[int, str, str]:
        """Run a command asynchronously."""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.DOCKER_COMPOSE_DIR
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                return (
                    process.returncode or 0,
                    stdout.decode("utf-8", errors="replace"),
                    stderr.decode("utf-8", errors="replace")
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return (-1, "", "Command timed out")

        except FileNotFoundError:
            return (-1, "", f"Command not found: {command[0]}")
        except Exception as e:
            return (-1, "", str(e))

    async def get_running_targets(self, force_refresh: bool = False) -> List[DockerTarget]:
        """
        Get list of running Docker containers as targets.

        Args:
            force_refresh: If True, refresh even if cached data exists

        Returns:
            List of DockerTarget objects for running containers
        """
        await self._refresh_targets()
        return [t for t in self._targets if t.is_running]

    async def get_all_targets(self) -> List[DockerTarget]:
        """Get all Docker containers as targets (running or not)."""
        await self._refresh_targets()
        return self._targets

    async def _refresh_targets(self) -> None:
        """Refresh the target list from Docker."""
        targets: List[DockerTarget] = []

        # Get container information using docker inspect
        code, stdout, stderr = await self._run_command([
            "docker-compose", "ps", "-q"
        ])

        if code != 0:
            return

        container_ids = [cid.strip() for cid in stdout.strip().split("\n") if cid.strip()]

        for container_id in container_ids:
            target = await self._inspect_container(container_id)
            if target:
                targets.append(target)

        self._targets = targets

    async def _inspect_container(self, container_id: str) -> Optional[DockerTarget]:
        """Inspect a container and create a DockerTarget."""
        code, stdout, stderr = await self._run_command([
            "docker", "inspect", container_id
        ])

        if code != 0 or not stdout.strip():
            return None

        try:
            data = json.loads(stdout)
            if not data:
                return None

            info = data[0]

            # Extract container name (remove leading /)
            name = info.get("Name", "").lstrip("/")

            # Extract status
            state = info.get("State", {})
            status = state.get("Status", "unknown")

            # Extract image
            image = info.get("Config", {}).get("Image", "")

            # Extract labels
            labels = info.get("Config", {}).get("Labels", {})

            # Extract networks and IP addresses
            networks_data = info.get("NetworkSettings", {}).get("Networks", {})
            ip_addresses: Dict[str, str] = {}
            network_names: List[str] = []

            for network_name, network_info in networks_data.items():
                ip = network_info.get("IPAddress", "")
                if ip:
                    ip_addresses[network_name] = ip
                    network_names.append(network_name)

            # Extract port mappings
            ports: Dict[int, int] = {}
            port_bindings = info.get("NetworkSettings", {}).get("Ports", {})
            for container_port_str, bindings in port_bindings.items():
                if bindings:
                    # Parse container port (e.g., "80/tcp")
                    match = re.match(r"(\d+)", container_port_str)
                    if match:
                        container_port = int(match.group(1))
                        host_port = int(bindings[0].get("HostPort", container_port))
                        ports[container_port] = host_port

            # Get services for this container
            services = self._get_services_for_container(name)

            # Also apply host port mappings from our definitions
            service_name = self._get_service_name(name)
            if service_name in HOST_PORT_MAPPINGS:
                for container_port, host_port in HOST_PORT_MAPPINGS[service_name].items():
                    if container_port not in ports:
                        ports[container_port] = host_port

            return DockerTarget(
                container_id=container_id[:12],
                container_name=name,
                image=image,
                status=status,
                ip_addresses=ip_addresses,
                ports=ports,
                services=services,
                labels=labels,
                networks=network_names
            )

        except (json.JSONDecodeError, KeyError, IndexError):
            return None

    def _get_service_name(self, container_name: str) -> str:
        """Extract service name from container name."""
        # Handle names like "cptc11-vulnerable-web" -> "vulnerable-web"
        if container_name.startswith("cptc11-"):
            return container_name[7:]
        return container_name

    def _get_services_for_container(self, container_name: str) -> List[TargetService]:
        """Get known services for a container based on its name."""
        service_name = self._get_service_name(container_name)
        return SERVICE_DEFINITIONS.get(service_name, [])

    async def get_target_services(self) -> Dict[str, List[TargetService]]:
        """
        Get a mapping of running containers to their attackable services.

        Returns:
            Dictionary mapping container names to lists of services
        """
        await self._refresh_targets()

        result: Dict[str, List[TargetService]] = {}
        for target in self._targets:
            if target.is_running and target.services:
                result[target.container_name] = target.services

        return result

    async def get_target_by_name(self, name: str) -> Optional[DockerTarget]:
        """Get a specific target by container name."""
        await self._refresh_targets()
        for target in self._targets:
            if target.container_name == name or target.display_name == name:
                return target
        return None

    async def get_scan_all_preset(self) -> Dict[str, Any]:
        """
        Generate a preset configuration for scanning all Docker containers.

        Returns:
            Dictionary with scan configuration
        """
        targets = await self.get_running_targets()

        # Collect all IPs
        ips = []
        for target in targets:
            if target.primary_ip:
                ips.append(target.primary_ip)

        # Generate subnet from IPs (find common subnets)
        subnets = set()
        for ip in ips:
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                subnets.add(subnet)

        return {
            "name": "Scan Docker Environment",
            "description": "Scan all running Docker containers",
            "targets": ips,
            "subnets": list(subnets),
            "target_count": len(targets),
            "containers": [
                {
                    "name": t.display_name,
                    "ip": t.primary_ip,
                    "services": [s.name for s in t.services]
                }
                for t in targets if t.primary_ip
            ]
        }

    def get_quick_targets(self) -> List[Dict[str, str]]:
        """
        Get quick-select target options for tool configuration.

        Returns:
            List of target dictionaries with name, ip, port fields
        """
        quick_targets = []

        for target in self._targets:
            if not target.is_running:
                continue

            # Add target with primary IP
            if target.primary_ip:
                quick_targets.append({
                    "name": target.display_name,
                    "ip": target.primary_ip,
                    "port": "",
                    "description": f"Container: {target.container_name}"
                })

                # Add individual services
                for service in target.services:
                    host_port = target.ports.get(service.port, service.port)
                    quick_targets.append({
                        "name": f"{target.display_name} - {service.name}",
                        "ip": target.primary_ip,
                        "port": str(host_port),
                        "description": service.description
                    })

        return quick_targets


# Singleton instance for convenience
_manager_instance: Optional[DockerTargetManager] = None


def get_docker_target_manager() -> DockerTargetManager:
    """Get the singleton DockerTargetManager instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = DockerTargetManager()
    return _manager_instance
