"""
Network Targets Utility for CORE Network Integration

Provides functionality to extract network targets from CORE topology files
and running sessions for use with security scanning tools.
"""

from __future__ import annotations

import asyncio
import re
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class NetworkTarget:
    """Represents a network target extracted from CORE topology."""

    name: str
    node_id: str
    ip_addresses: List[str] = field(default_factory=list)
    node_type: str = "host"
    services: List[str] = field(default_factory=list)
    segment: str = ""

    @property
    def primary_ip(self) -> Optional[str]:
        """Get the primary (first) IP address."""
        return self.ip_addresses[0] if self.ip_addresses else None

    def __hash__(self) -> int:
        return hash(self.node_id)


@dataclass
class NetworkSegment:
    """Represents a network segment/subnet."""

    name: str
    cidr: str
    description: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        """Get the IPv4Network object."""
        return ipaddress.IPv4Network(self.cidr, strict=False)

    def contains(self, ip: str) -> bool:
        """Check if an IP address is in this segment."""
        try:
            return ipaddress.IPv4Address(ip) in self.network
        except ValueError:
            return False


class CoreTargetManager:
    """
    Manager for CORE network targets.

    Provides methods to extract targets from .imn topology files
    and running CORE sessions for use with security tools.
    """

    def __init__(self, networks_dir: Optional[Path] = None) -> None:
        """
        Initialize the CoreTargetManager.

        Args:
            networks_dir: Directory containing .imn topology files
        """
        self.networks_dir = networks_dir
        self._cached_targets: Dict[str, List[NetworkTarget]] = {}
        self._cached_segments: Dict[str, List[NetworkSegment]] = {}

    def parse_imn_targets(self, filepath: Path) -> List[NetworkTarget]:
        """
        Parse a .imn topology file and extract network targets.

        Args:
            filepath: Path to the .imn file

        Returns:
            List of NetworkTarget objects extracted from the file
        """
        targets: List[NetworkTarget] = []

        if not filepath.exists():
            return targets

        try:
            content = filepath.read_text()

            # Parse node definitions
            node_pattern = re.compile(
                r'node\s+(n\d+)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
                re.MULTILINE | re.DOTALL
            )

            for match in node_pattern.finditer(content):
                node_id = match.group(1)
                node_content = match.group(2)

                # Skip switches - they don't have IP addresses
                type_match = re.search(r'type\s+(\S+)', node_content)
                if type_match and type_match.group(1) == "lanswitch":
                    continue

                # Extract hostname
                hostname_match = re.search(r'hostname\s+(\S+)', node_content)
                hostname = hostname_match.group(1) if hostname_match else node_id

                # Extract model/type
                model_match = re.search(r'model\s+(\S+)', node_content)
                node_type = model_match.group(1) if model_match else "host"

                # Normalize node type
                node_type = self._normalize_node_type(node_type)

                # Extract IP addresses from interface configuration
                ip_addresses: List[str] = []
                ip_pattern = re.compile(r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)/?\d*')
                for ip_match in ip_pattern.finditer(node_content):
                    ip_addr = ip_match.group(1)
                    ip_addresses.append(ip_addr)

                # Extract services
                services: List[str] = []
                services_match = re.search(r'services\s*\{([^}]+)\}', node_content)
                if services_match:
                    services = services_match.group(1).strip().split()

                # Only add targets with IP addresses
                if ip_addresses:
                    target = NetworkTarget(
                        name=hostname,
                        node_id=node_id,
                        ip_addresses=ip_addresses,
                        node_type=node_type,
                        services=services
                    )
                    targets.append(target)

            # Assign segments to targets
            segments = self._parse_segments(content)
            for target in targets:
                for segment in segments:
                    if target.primary_ip and segment.contains(target.primary_ip):
                        target.segment = segment.name
                        break

            # Cache results
            self._cached_targets[str(filepath)] = targets
            self._cached_segments[str(filepath)] = segments

        except Exception as e:
            # Log error but return empty list
            pass

        return targets

    def _normalize_node_type(self, node_type: str) -> str:
        """Normalize node type string to standard categories."""
        type_lower = node_type.lower()
        if type_lower in ("router", "firewall"):
            return "router"
        elif type_lower in ("pc", "workstation"):
            return "pc"
        elif type_lower in ("host", "server"):
            return "host"
        elif type_lower in ("switch", "lanswitch", "hub"):
            return "switch"
        return node_type

    def _parse_segments(self, content: str) -> List[NetworkSegment]:
        """Parse network segments from annotation labels in .imn file."""
        segments: List[NetworkSegment] = []
        seen_cidrs: Set[str] = set()

        # Simple approach: find all "label {...}" patterns that contain CIDR
        label_pattern = re.compile(r'label\s*\{([^}]+)\}', re.MULTILINE)
        cidr_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+/\d+)')

        for label_match in label_pattern.finditer(content):
            label = label_match.group(1).strip()

            # Check if label contains a CIDR
            cidr_match = cidr_pattern.search(label)
            if cidr_match:
                cidr = cidr_match.group(1)

                # Skip if we've already seen this CIDR
                if cidr in seen_cidrs:
                    continue
                seen_cidrs.add(cidr)

                # Extract segment name by removing CIDR notation
                name = label.replace(cidr, "").strip(" ()[]")
                if name:
                    segments.append(NetworkSegment(
                        name=name,
                        cidr=cidr,
                        description=label
                    ))

        return segments

    async def get_active_session_targets(self) -> List[NetworkTarget]:
        """
        Get targets from a running CORE session.

        Returns:
            List of NetworkTarget objects from active session
        """
        targets: List[NetworkTarget] = []

        try:
            # Get list of active sessions
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "session", "list",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return targets

            # Parse session list to get first active session
            session_id = None
            for line in stdout.decode().strip().split("\n"):
                if line.strip() and not line.startswith("Session"):
                    parts = line.split()
                    if parts:
                        session_id = parts[0]
                        break

            if not session_id:
                return targets

            # Get nodes from the session
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "node", "list",
                "--id", session_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return targets

            # Parse node list
            for line in stdout.decode().strip().split("\n"):
                if line.strip() and not line.startswith("Node"):
                    parts = line.split()
                    if len(parts) >= 2:
                        node_id = parts[0]
                        name = parts[1] if len(parts) > 1 else f"node{node_id}"
                        node_type = parts[2] if len(parts) > 2 else "host"

                        # Get node details including IP
                        ip_addresses = await self._get_node_ips(session_id, node_id)

                        if ip_addresses:
                            target = NetworkTarget(
                                name=name,
                                node_id=node_id,
                                ip_addresses=ip_addresses,
                                node_type=node_type
                            )
                            targets.append(target)

        except FileNotFoundError:
            # CORE CLI not installed
            pass
        except Exception:
            pass

        return targets

    async def _get_node_ips(self, session_id: str, node_id: str) -> List[str]:
        """Get IP addresses for a specific node in a session."""
        ip_addresses: List[str] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "node", "info",
                "--id", session_id,
                "--node", node_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                # Parse IP addresses from output
                ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
                for match in ip_pattern.finditer(output):
                    ip = match.group(1)
                    # Skip localhost and 0.0.0.0
                    if ip not in ("127.0.0.1", "0.0.0.0"):
                        ip_addresses.append(ip)

        except Exception:
            pass

        return ip_addresses

    def get_network_ranges(self, filepath: Optional[Path] = None) -> List[NetworkSegment]:
        """
        Get network CIDR ranges for scanning.

        Args:
            filepath: Optional path to .imn file. If provided, extracts
                     ranges from that topology. Otherwise, returns
                     cached segments or scans networks_dir.

        Returns:
            List of NetworkSegment objects
        """
        if filepath:
            # Parse the specific file if not cached
            cache_key = str(filepath)
            if cache_key not in self._cached_segments:
                self.parse_imn_targets(filepath)
            return self._cached_segments.get(cache_key, [])

        # If no file specified, aggregate from all cached or scan directory
        if self._cached_segments:
            all_segments: List[NetworkSegment] = []
            seen_cidrs: Set[str] = set()
            for segments in self._cached_segments.values():
                for seg in segments:
                    if seg.cidr not in seen_cidrs:
                        all_segments.append(seg)
                        seen_cidrs.add(seg.cidr)
            return all_segments

        # Scan networks directory if available
        if self.networks_dir and self.networks_dir.exists():
            all_segments = []
            seen_cidrs: Set[str] = set()
            for imn_file in self.networks_dir.glob("*.imn"):
                self.parse_imn_targets(imn_file)
                for seg in self._cached_segments.get(str(imn_file), []):
                    if seg.cidr not in seen_cidrs:
                        all_segments.append(seg)
                        seen_cidrs.add(seg.cidr)
            return all_segments

        return []

    def get_targets_by_segment(
        self,
        filepath: Path,
        segment_name: Optional[str] = None
    ) -> Dict[str, List[NetworkTarget]]:
        """
        Get targets grouped by network segment.

        Args:
            filepath: Path to .imn file
            segment_name: Optional filter for specific segment

        Returns:
            Dictionary mapping segment names to target lists
        """
        targets = self.parse_imn_targets(filepath)
        grouped: Dict[str, List[NetworkTarget]] = {}

        for target in targets:
            seg = target.segment or "Unknown"
            if segment_name and seg != segment_name:
                continue
            if seg not in grouped:
                grouped[seg] = []
            grouped[seg].append(target)

        return grouped

    def get_targets_by_service(
        self,
        filepath: Path,
        service: str
    ) -> List[NetworkTarget]:
        """
        Get targets that have a specific service.

        Args:
            filepath: Path to .imn file
            service: Service name to filter by

        Returns:
            List of targets with the specified service
        """
        targets = self.parse_imn_targets(filepath)
        return [t for t in targets if service.upper() in [s.upper() for s in t.services]]

    def get_scannable_targets(
        self,
        filepath: Path,
        exclude_routers: bool = False
    ) -> List[NetworkTarget]:
        """
        Get targets suitable for scanning (hosts with IPs).

        Args:
            filepath: Path to .imn file
            exclude_routers: Whether to exclude router nodes

        Returns:
            List of scannable targets
        """
        targets = self.parse_imn_targets(filepath)

        if exclude_routers:
            return [t for t in targets if t.node_type not in ("router", "firewall")]

        return targets

    def create_scan_preset(
        self,
        name: str,
        targets: List[NetworkTarget],
        scan_type: str = "all"
    ) -> Dict[str, any]:
        """
        Create a scan preset configuration.

        Args:
            name: Name for the preset
            targets: List of targets to include
            scan_type: Type of scan (all, hosts_only, servers_only)

        Returns:
            Dictionary with scan configuration
        """
        filtered_targets = targets

        if scan_type == "hosts_only":
            filtered_targets = [t for t in targets if t.node_type in ("pc", "workstation")]
        elif scan_type == "servers_only":
            filtered_targets = [t for t in targets if t.node_type in ("host", "server")]

        return {
            "name": name,
            "targets": [t.primary_ip for t in filtered_targets if t.primary_ip],
            "target_count": len(filtered_targets),
            "scan_type": scan_type
        }

    def get_entire_network_preset(
        self,
        filepath: Path
    ) -> Dict[str, any]:
        """
        Create a preset for scanning the entire network using CIDR ranges.

        Args:
            filepath: Path to .imn file

        Returns:
            Dictionary with network scan configuration
        """
        segments = self.get_network_ranges(filepath)

        return {
            "name": "Scan Entire Network",
            "cidr_ranges": [seg.cidr for seg in segments],
            "segment_names": [seg.name for seg in segments],
            "segment_count": len(segments)
        }

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self._cached_targets.clear()
        self._cached_segments.clear()


# Convenience functions for module-level usage

def parse_imn_targets(filepath: Path) -> List[NetworkTarget]:
    """
    Parse a .imn topology file and extract network targets.

    Convenience function for quick parsing without manager instance.

    Args:
        filepath: Path to the .imn file

    Returns:
        List of NetworkTarget objects
    """
    manager = CoreTargetManager()
    return manager.parse_imn_targets(filepath)


async def get_active_session_targets() -> List[NetworkTarget]:
    """
    Get targets from a running CORE session.

    Convenience function for quick access without manager instance.

    Returns:
        List of NetworkTarget objects
    """
    manager = CoreTargetManager()
    return await manager.get_active_session_targets()


def get_network_ranges(filepath: Path) -> List[NetworkSegment]:
    """
    Get network CIDR ranges from a topology file.

    Convenience function for quick access without manager instance.

    Args:
        filepath: Path to the .imn file

    Returns:
        List of NetworkSegment objects
    """
    manager = CoreTargetManager()
    return manager.get_network_ranges(filepath)
