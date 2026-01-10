#!/usr/bin/env python3
"""
Network Monitor - Defensive Security Tool
Monitor network connections, detect anomalies, and identify suspicious activity.

Author: Defensive Security Toolsmith
Category: Defense - Network Security
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from abc import ABC, abstractmethod


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class NetworkConnection:
    """Represents a network connection."""
    protocol: str  # tcp, udp
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str  # ESTABLISHED, LISTEN, TIME_WAIT, etc.
    pid: Optional[int] = None
    process_name: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
            "process_name": self.process_name,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class NetworkAlert:
    """Represents a network security alert."""
    rule_name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    connections: List[NetworkConnection]
    timestamp: datetime
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "connections": [c.to_dict() for c in self.connections],
            "timestamp": self.timestamp.isoformat(),
            "recommendation": self.recommendation,
        }


@dataclass
class MonitorResult:
    """Complete monitoring result."""
    start_time: datetime
    end_time: datetime
    total_connections: int
    alerts: List[NetworkAlert]
    statistics: Dict[str, Any]
    connections: List[NetworkConnection]

    @property
    def duration(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration,
            "total_connections": self.total_connections,
            "alert_count": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
            "statistics": self.statistics,
        }


# ============================================================================
# Connection Collectors
# ============================================================================

class ConnectionCollector(ABC):
    """Abstract base class for connection collectors."""

    @abstractmethod
    def collect(self) -> List[NetworkConnection]:
        """Collect network connections."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return collector name."""
        pass


class NetstatCollector(ConnectionCollector):
    """Collect connections using netstat command."""

    def collect(self) -> List[NetworkConnection]:
        """Collect connections from netstat."""
        connections = []

        try:
            # Run netstat
            result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True,
                timeout=30
            )

            for line in result.stdout.split('\n'):
                conn = self._parse_line(line)
                if conn:
                    connections.append(conn)

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass
        except Exception:
            pass

        return connections

    def _parse_line(self, line: str) -> Optional[NetworkConnection]:
        """Parse a netstat output line."""
        parts = line.split()
        if len(parts) < 4:
            return None

        # Try to parse TCP/UDP lines
        proto = parts[0].lower()
        if proto not in ['tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6']:
            return None

        try:
            # Handle different netstat output formats
            if 'tcp' in proto or 'udp' in proto:
                local_addr = parts[3] if len(parts) > 3 else parts[1]
                remote_addr = parts[4] if len(parts) > 4 else parts[2]

                # Parse addresses
                local_ip, local_port = self._parse_address(local_addr)
                remote_ip, remote_port = self._parse_address(remote_addr)

                # Get state (may not exist for UDP)
                state = "UNKNOWN"
                for part in parts:
                    if part in ['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT',
                               'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2',
                               'CLOSING', 'LAST_ACK']:
                        state = part
                        break

                return NetworkConnection(
                    protocol=proto.replace('4', '').replace('6', ''),
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    state=state,
                )
        except (ValueError, IndexError):
            pass

        return None

    def _parse_address(self, addr: str) -> Tuple[str, int]:
        """Parse address:port string."""
        if addr == '*.*' or addr == '*:*':
            return ('*', 0)

        # Handle IPv6
        if addr.startswith('['):
            match = re.match(r'\[([^\]]+)\]:(\d+)', addr)
            if match:
                return (match.group(1), int(match.group(2)))

        # Handle IPv4 or hostname
        if '.' in addr:
            parts = addr.rsplit('.', 1)
            if len(parts) == 2 and parts[1].isdigit():
                return (parts[0], int(parts[1]))

        if ':' in addr:
            parts = addr.rsplit(':', 1)
            if len(parts) == 2:
                try:
                    return (parts[0], int(parts[1]))
                except ValueError:
                    return (parts[0], 0)

        return (addr, 0)

    def get_name(self) -> str:
        return "netstat"


class LsofCollector(ConnectionCollector):
    """Collect connections using lsof command (includes process info)."""

    def collect(self) -> List[NetworkConnection]:
        """Collect connections from lsof."""
        connections = []

        try:
            result = subprocess.run(
                ['lsof', '-i', '-n', '-P'],
                capture_output=True,
                text=True,
                timeout=30
            )

            for line in result.stdout.split('\n')[1:]:  # Skip header
                conn = self._parse_line(line)
                if conn:
                    connections.append(conn)

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass
        except Exception:
            pass

        return connections

    def _parse_line(self, line: str) -> Optional[NetworkConnection]:
        """Parse lsof output line."""
        parts = line.split()
        if len(parts) < 9:
            return None

        try:
            process_name = parts[0]
            pid = int(parts[1]) if parts[1].isdigit() else None

            # Find the network part (contains ->)
            for i, part in enumerate(parts):
                if '->' in part:
                    local, remote = part.split('->')
                    local_ip, local_port = self._parse_address(local)
                    remote_ip, remote_port = self._parse_address(remote)

                    # Get state
                    state = parts[i + 1] if i + 1 < len(parts) else "UNKNOWN"
                    state = state.strip('()')

                    # Get protocol
                    proto = 'tcp'
                    for p in parts:
                        if p.lower() in ['tcp', 'udp']:
                            proto = p.lower()
                            break

                    return NetworkConnection(
                        protocol=proto,
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        state=state,
                        pid=pid,
                        process_name=process_name,
                    )
        except (ValueError, IndexError):
            pass

        return None

    def _parse_address(self, addr: str) -> Tuple[str, int]:
        """Parse address:port string."""
        if ':' in addr:
            parts = addr.rsplit(':', 1)
            try:
                return (parts[0], int(parts[1]))
            except ValueError:
                return (parts[0], 0)
        return (addr, 0)

    def get_name(self) -> str:
        return "lsof"


# ============================================================================
# Detection Rules
# ============================================================================

class DetectionRule(ABC):
    """Abstract base class for detection rules."""

    @abstractmethod
    def analyze(self, connections: List[NetworkConnection]) -> List[NetworkAlert]:
        """Analyze connections and return alerts."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return rule name."""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Return rule description."""
        pass


class SuspiciousPortDetector(DetectionRule):
    """Detect connections to/from suspicious ports."""

    # Commonly abused ports
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default",
        5555: "Common RAT port",
        6666: "IRC/backdoor port",
        6667: "IRC/backdoor port",
        8080: "HTTP proxy (check context)",
        31337: "Elite/backdoor port",
        12345: "NetBus trojan",
        1234: "Common test/backdoor",
        9001: "Tor default",
        9050: "Tor SOCKS",
        9150: "Tor Browser",
    }

    def analyze(self, connections: List[NetworkConnection]) -> List[NetworkAlert]:
        alerts = []
        suspicious_conns = []

        for conn in connections:
            if conn.remote_port in self.SUSPICIOUS_PORTS:
                suspicious_conns.append(conn)

        if suspicious_conns:
            # Group by port
            by_port = defaultdict(list)
            for conn in suspicious_conns:
                by_port[conn.remote_port].append(conn)

            for port, conns in by_port.items():
                port_desc = self.SUSPICIOUS_PORTS.get(port, "Unknown")
                alerts.append(NetworkAlert(
                    rule_name=self.get_name(),
                    severity="HIGH",
                    description=f"Connections to suspicious port {port} ({port_desc}): {len(conns)} connection(s)",
                    connections=conns,
                    timestamp=datetime.now(),
                    recommendation="Investigate the process making these connections and verify legitimacy",
                ))

        return alerts

    def get_name(self) -> str:
        return "SUSPICIOUS_PORT"

    def get_description(self) -> str:
        return "Detects connections to commonly abused ports"


class HighPortCountDetector(DetectionRule):
    """Detect processes with unusually high connection counts."""

    def __init__(self, threshold: int = 50):
        self.threshold = threshold

    def analyze(self, connections: List[NetworkConnection]) -> List[NetworkAlert]:
        alerts = []

        # Group by process
        by_process: Dict[str, List[NetworkConnection]] = defaultdict(list)
        for conn in connections:
            key = conn.process_name or f"PID:{conn.pid}" or "unknown"
            by_process[key].append(conn)

        for process, conns in by_process.items():
            if len(conns) >= self.threshold:
                alerts.append(NetworkAlert(
                    rule_name=self.get_name(),
                    severity="MEDIUM",
                    description=f"Process '{process}' has {len(conns)} active connections",
                    connections=conns[:10],  # Only include first 10
                    timestamp=datetime.now(),
                    recommendation="Review process activity - may indicate scanning or C2 beaconing",
                ))

        return alerts

    def get_name(self) -> str:
        return "HIGH_CONNECTION_COUNT"

    def get_description(self) -> str:
        return f"Detects processes with more than {self.threshold} connections"


class ExternalConnectionDetector(DetectionRule):
    """Detect connections to external IPs from internal systems."""

    # Private IP ranges
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
    ]

    def _ip_to_int(self, ip: str) -> int:
        """Convert IP string to integer."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return 0
            return sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
        except (ValueError, AttributeError):
            return 0

    def _is_private(self, ip: str) -> bool:
        """Check if IP is in private range."""
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return True  # Invalid IPs treated as private

        for start, end in self.PRIVATE_RANGES:
            start_int = self._ip_to_int(start)
            end_int = self._ip_to_int(end)
            if start_int <= ip_int <= end_int:
                return True
        return False

    def analyze(self, connections: List[NetworkConnection]) -> List[NetworkAlert]:
        alerts = []
        external_conns = []

        for conn in connections:
            if conn.remote_ip and conn.remote_ip != '*':
                if not self._is_private(conn.remote_ip):
                    external_conns.append(conn)

        if len(external_conns) > 20:  # Only alert if many external connections
            alerts.append(NetworkAlert(
                rule_name=self.get_name(),
                severity="LOW",
                description=f"Found {len(external_conns)} connections to external IP addresses",
                connections=external_conns[:10],
                timestamp=datetime.now(),
                recommendation="Review external connections for unauthorized data exfiltration",
            ))

        return alerts

    def get_name(self) -> str:
        return "EXTERNAL_CONNECTIONS"

    def get_description(self) -> str:
        return "Monitors connections to external (non-private) IP addresses"


class UnusualListenerDetector(DetectionRule):
    """Detect unusual listening ports."""

    # Common legitimate listening ports
    KNOWN_PORTS = {22, 80, 443, 53, 3306, 5432, 6379, 27017, 8080, 8443}

    def analyze(self, connections: List[NetworkConnection]) -> List[NetworkAlert]:
        alerts = []
        unusual_listeners = []

        for conn in connections:
            if conn.state == 'LISTEN':
                if conn.local_port not in self.KNOWN_PORTS and conn.local_port > 1024:
                    unusual_listeners.append(conn)

        if unusual_listeners:
            alerts.append(NetworkAlert(
                rule_name=self.get_name(),
                severity="MEDIUM",
                description=f"Found {len(unusual_listeners)} unusual listening ports",
                connections=unusual_listeners,
                timestamp=datetime.now(),
                recommendation="Verify all listening services are authorized",
            ))

        return alerts

    def get_name(self) -> str:
        return "UNUSUAL_LISTENERS"

    def get_description(self) -> str:
        return "Detects processes listening on unusual ports"


class DNSTunnelingDetector(DetectionRule):
    """Detect potential DNS tunneling activity."""

    def analyze(self, connections: List[NetworkConnection]) -> List[NetworkAlert]:
        alerts = []

        # Count DNS connections per process
        dns_by_process: Dict[str, int] = defaultdict(int)
        dns_conns = []

        for conn in connections:
            if conn.remote_port == 53:
                key = conn.process_name or str(conn.pid) or "unknown"
                dns_by_process[key] += 1
                dns_conns.append(conn)

        # Alert on high DNS activity
        for process, count in dns_by_process.items():
            if count > 20:  # Threshold for suspicious DNS activity
                relevant_conns = [c for c in dns_conns
                                 if (c.process_name or str(c.pid)) == process]
                alerts.append(NetworkAlert(
                    rule_name=self.get_name(),
                    severity="HIGH",
                    description=f"High DNS query rate from '{process}': {count} connections",
                    connections=relevant_conns[:10],
                    timestamp=datetime.now(),
                    recommendation="Investigate for DNS tunneling or data exfiltration",
                ))

        return alerts

    def get_name(self) -> str:
        return "DNS_TUNNELING"

    def get_description(self) -> str:
        return "Detects potential DNS tunneling based on query patterns"


# ============================================================================
# Main Network Monitor
# ============================================================================

class NetworkMonitor:
    """Main network monitoring engine."""

    def __init__(self):
        self.collectors: List[ConnectionCollector] = [
            NetstatCollector(),
            LsofCollector(),
        ]
        self.rules: List[DetectionRule] = [
            SuspiciousPortDetector(),
            HighPortCountDetector(),
            ExternalConnectionDetector(),
            UnusualListenerDetector(),
            DNSTunnelingDetector(),
        ]

    def collect_connections(self) -> List[NetworkConnection]:
        """Collect connections using available collectors."""
        all_connections = []
        seen = set()

        for collector in self.collectors:
            connections = collector.collect()
            for conn in connections:
                # Deduplicate
                key = (conn.protocol, conn.local_ip, conn.local_port,
                       conn.remote_ip, conn.remote_port)
                if key not in seen:
                    seen.add(key)
                    all_connections.append(conn)

        return all_connections

    def analyze(self, connections: List[NetworkConnection]) -> List[NetworkAlert]:
        """Run all detection rules."""
        all_alerts = []
        for rule in self.rules:
            alerts = rule.analyze(connections)
            all_alerts.extend(alerts)
        return all_alerts

    def monitor(self) -> MonitorResult:
        """Perform a single monitoring cycle."""
        start_time = datetime.now()

        # Collect connections
        connections = self.collect_connections()

        # Analyze
        alerts = self.analyze(connections)

        # Calculate statistics
        statistics = self._calculate_statistics(connections)

        end_time = datetime.now()

        return MonitorResult(
            start_time=start_time,
            end_time=end_time,
            total_connections=len(connections),
            alerts=alerts,
            statistics=statistics,
            connections=connections,
        )

    def _calculate_statistics(self, connections: List[NetworkConnection]) -> Dict[str, Any]:
        """Calculate connection statistics."""
        stats = {
            'by_protocol': defaultdict(int),
            'by_state': defaultdict(int),
            'by_process': defaultdict(int),
            'listening_ports': [],
            'established_count': 0,
            'unique_remote_ips': set(),
        }

        for conn in connections:
            stats['by_protocol'][conn.protocol] += 1
            stats['by_state'][conn.state] += 1

            if conn.process_name:
                stats['by_process'][conn.process_name] += 1

            if conn.state == 'LISTEN':
                stats['listening_ports'].append(conn.local_port)
            elif conn.state == 'ESTABLISHED':
                stats['established_count'] += 1

            if conn.remote_ip and conn.remote_ip != '*':
                stats['unique_remote_ips'].add(conn.remote_ip)

        return {
            'by_protocol': dict(stats['by_protocol']),
            'by_state': dict(stats['by_state']),
            'by_process': dict(sorted(stats['by_process'].items(),
                                      key=lambda x: x[1], reverse=True)[:10]),
            'listening_ports': sorted(set(stats['listening_ports'])),
            'established_count': stats['established_count'],
            'unique_remote_ips': len(stats['unique_remote_ips']),
        }

    def get_plan(self, continuous: bool, interval: int, output_format: str) -> str:
        """Generate planning mode output."""
        plan = []
        plan.append("")
        plan.append("[PLAN MODE] Tool: network-monitor")
        plan.append("=" * 50)
        plan.append("")
        plan.append("Actions to be performed:")
        plan.append("")
        plan.append("  1. Collect network connections using:")
        for collector in self.collectors:
            plan.append(f"     - {collector.get_name()}")

        plan.append("")
        plan.append("  2. Apply detection rules:")
        for i, rule in enumerate(self.rules, 1):
            plan.append(f"     {i}. {rule.get_name()}")
            plan.append(f"        {rule.get_description()}")

        plan.append("")
        plan.append("  3. Generate statistics and alerts")
        plan.append(f"  4. Output format: {output_format}")

        if continuous:
            plan.append(f"  5. Continuous monitoring with {interval}s interval")
        else:
            plan.append("  5. Single snapshot mode")

        plan.append("")
        plan.append("Data collected:")
        plan.append("  - Local and remote IP addresses")
        plan.append("  - Port numbers and protocols")
        plan.append("  - Connection states")
        plan.append("  - Process information (if available)")

        plan.append("")
        plan.append("Risk Assessment: LOW (read-only monitoring)")
        plan.append("Detection Vectors: Process enumeration, network state queries")
        plan.append("")
        plan.append("No actions will be taken. Remove --plan to execute.")
        plan.append("=" * 50)

        return '\n'.join(plan)


# ============================================================================
# Documentation
# ============================================================================

def get_documentation() -> Dict[str, Any]:
    """Return structured documentation for this tool."""
    return {
        "name": "network-monitor",
        "category": "Defense - Network Security",
        "version": "1.0.0",
        "author": "Defensive Security Toolsmith",
        "description": "Monitor network connections and detect suspicious activity",
        "features": [
            "Real-time connection monitoring",
            "Suspicious port detection",
            "High connection count alerting",
            "External connection tracking",
            "Unusual listener detection",
            "DNS tunneling detection",
            "Process-level connection mapping",
            "Continuous monitoring mode",
        ],
        "detection_rules": [
            {"name": "SUSPICIOUS_PORT", "severity": "HIGH"},
            {"name": "HIGH_CONNECTION_COUNT", "severity": "MEDIUM"},
            {"name": "EXTERNAL_CONNECTIONS", "severity": "LOW"},
            {"name": "UNUSUAL_LISTENERS", "severity": "MEDIUM"},
            {"name": "DNS_TUNNELING", "severity": "HIGH"},
        ],
        "usage_examples": [
            "python tool.py --plan",
            "python tool.py --output json",
            "python tool.py --continuous --interval 60",
            "python tool.py --show-all",
        ],
        "arguments": {
            "--plan, -p": "Show execution plan without running monitor",
            "--continuous, -c": "Run in continuous monitoring mode",
            "--interval, -i": "Interval between checks in continuous mode (seconds)",
            "--output, -o": "Output format (text, json)",
            "--show-all": "Show all connections, not just alerts",
            "--quiet, -q": "Suppress informational output",
        },
        "legal_notice": "This tool is for authorized security monitoring only.",
    }


# ============================================================================
# Output Formatters
# ============================================================================

def format_output_text(result: MonitorResult, show_all: bool = False) -> str:
    """Format monitoring result as human-readable text."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  NETWORK MONITOR REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Timestamp: {result.start_time}")
    lines.append(f"Duration: {result.duration:.2f} seconds")
    lines.append(f"Total Connections: {result.total_connections}")
    lines.append(f"Alerts Generated: {len(result.alerts)}")
    lines.append("")

    # Alerts
    if result.alerts:
        lines.append("-" * 60)
        lines.append("  ALERTS")
        lines.append("-" * 60)

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_alerts = sorted(result.alerts,
                               key=lambda x: severity_order.get(x.severity, 4))

        for alert in sorted_alerts:
            lines.append("")
            lines.append(f"[{alert.severity}] {alert.rule_name}")
            lines.append(f"  {alert.description}")
            if alert.recommendation:
                lines.append(f"  Recommendation: {alert.recommendation}")
            lines.append("  Sample connections:")
            for conn in alert.connections[:3]:
                lines.append(f"    {conn.protocol} {conn.local_ip}:{conn.local_port} -> "
                           f"{conn.remote_ip}:{conn.remote_port} ({conn.state})")
                if conn.process_name:
                    lines.append(f"      Process: {conn.process_name}")
    else:
        lines.append("")
        lines.append("No security alerts detected.")

    # Statistics
    lines.append("")
    lines.append("-" * 60)
    lines.append("  STATISTICS")
    lines.append("-" * 60)
    lines.append("")

    stats = result.statistics
    lines.append("By Protocol:")
    for proto, count in stats.get('by_protocol', {}).items():
        lines.append(f"  {proto}: {count}")

    lines.append("")
    lines.append("By State:")
    for state, count in stats.get('by_state', {}).items():
        lines.append(f"  {state}: {count}")

    lines.append("")
    lines.append(f"Established Connections: {stats.get('established_count', 0)}")
    lines.append(f"Unique Remote IPs: {stats.get('unique_remote_ips', 0)}")
    lines.append(f"Listening Ports: {len(stats.get('listening_ports', []))}")

    if stats.get('by_process'):
        lines.append("")
        lines.append("Top Processes by Connection Count:")
        for proc, count in list(stats['by_process'].items())[:5]:
            lines.append(f"  {proc}: {count}")

    # Show all connections if requested
    if show_all and result.connections:
        lines.append("")
        lines.append("-" * 60)
        lines.append("  ALL CONNECTIONS")
        lines.append("-" * 60)

        for conn in result.connections[:50]:  # Limit to 50
            lines.append(f"  {conn.protocol} {conn.local_ip}:{conn.local_port} -> "
                        f"{conn.remote_ip}:{conn.remote_port} ({conn.state})")

        if len(result.connections) > 50:
            lines.append(f"  ... and {len(result.connections) - 50} more")

    lines.append("")
    lines.append("=" * 60)

    return '\n'.join(lines)


def format_output_json(result: MonitorResult) -> str:
    """Format monitoring result as JSON."""
    return json.dumps(result.to_dict(), indent=2)


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network Monitor - Monitor connections and detect suspicious activity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --plan
  %(prog)s --output json
  %(prog)s --continuous --interval 60
  %(prog)s --show-all

Detection Rules:
  - Suspicious port connections (4444, 31337, etc.)
  - High connection count per process
  - External IP connections
  - Unusual listening ports
  - DNS tunneling indicators
        """
    )

    parser.add_argument(
        '--plan', '-p',
        action='store_true',
        help='Show execution plan without running monitor'
    )

    parser.add_argument(
        '--continuous', '-c',
        action='store_true',
        help='Run in continuous monitoring mode'
    )

    parser.add_argument(
        '--interval', '-i',
        type=int,
        default=30,
        help='Interval between checks in continuous mode (default: 30s)'
    )

    parser.add_argument(
        '--output', '-o',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )

    parser.add_argument(
        '--show-all',
        action='store_true',
        help='Show all connections, not just alerts'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress informational output'
    )

    args = parser.parse_args()

    monitor = NetworkMonitor()

    # Planning mode
    if args.plan:
        print(monitor.get_plan(args.continuous, args.interval, args.output))
        return 0

    # Single run or continuous mode
    try:
        if args.continuous:
            import time
            if not args.quiet:
                print(f"Starting continuous monitoring (interval: {args.interval}s)...",
                      file=sys.stderr)
                print("Press Ctrl+C to stop", file=sys.stderr)

            while True:
                result = monitor.monitor()

                if args.output == 'json':
                    print(format_output_json(result))
                else:
                    print(format_output_text(result, args.show_all))

                time.sleep(args.interval)
        else:
            if not args.quiet:
                print("Collecting network connections...", file=sys.stderr)

            result = monitor.monitor()

            if args.output == 'json':
                print(format_output_json(result))
            else:
                print(format_output_text(result, args.show_all))

            # Return non-zero if high/critical alerts
            critical_high = len([a for a in result.alerts
                                if a.severity in ['CRITICAL', 'HIGH']])
            return 1 if critical_high > 0 else 0

    except KeyboardInterrupt:
        if not args.quiet:
            print("\nMonitoring stopped.", file=sys.stderr)
        return 0

    return 0


if __name__ == '__main__':
    sys.exit(main())
