#!/usr/bin/env python3
"""
IOC Scanner - Defensive Security Tool
Scan files, processes, and network connections for Indicators of Compromise (IOCs).

Author: Defensive Security Toolsmith
Category: Defense - Threat Detection
"""

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from abc import ABC, abstractmethod


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class IOC:
    """Represents an Indicator of Compromise."""
    ioc_type: str  # ip, domain, hash, url, filename, registry, mutex
    value: str
    description: str = ""
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    source: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.ioc_type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "tags": self.tags,
        }


@dataclass
class Match:
    """Represents a matched IOC."""
    ioc: IOC
    location: str  # file path, process name, etc.
    context: str  # surrounding text or additional info
    timestamp: datetime
    match_type: str  # file_content, filename, process, network

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc": self.ioc.to_dict(),
            "location": self.location,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "match_type": self.match_type,
        }


@dataclass
class ScanResult:
    """Complete scan result."""
    scan_type: str
    target: str
    start_time: datetime
    end_time: datetime
    matches: List[Match]
    statistics: Dict[str, Any]
    errors: List[str]

    @property
    def duration(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration,
            "total_matches": len(self.matches),
            "matches": [m.to_dict() for m in self.matches],
            "statistics": self.statistics,
            "errors": self.errors,
        }


# ============================================================================
# IOC Database
# ============================================================================

class IOCDatabase:
    """Manages IOC storage and lookup."""

    def __init__(self):
        self.iocs: Dict[str, List[IOC]] = {
            "ip": [],
            "domain": [],
            "hash_md5": [],
            "hash_sha1": [],
            "hash_sha256": [],
            "url": [],
            "filename": [],
            "registry": [],
            "mutex": [],
            "email": [],
            "yara": [],
        }
        self._compiled_patterns: Dict[str, List[Tuple[re.Pattern, IOC]]] = {}

    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC to the database."""
        if ioc.ioc_type in self.iocs:
            self.iocs[ioc.ioc_type].append(ioc)
            # Clear compiled patterns to force recompile
            self._compiled_patterns = {}

    def load_from_json(self, json_path: str) -> int:
        """Load IOCs from a JSON file."""
        count = 0
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)

            iocs_list = data if isinstance(data, list) else data.get("iocs", [])

            for item in iocs_list:
                ioc = IOC(
                    ioc_type=item.get("type", "unknown"),
                    value=item.get("value", ""),
                    description=item.get("description", ""),
                    severity=item.get("severity", "MEDIUM"),
                    source=item.get("source", json_path),
                    tags=item.get("tags", []),
                )
                self.add_ioc(ioc)
                count += 1
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise ValueError(f"Failed to load IOCs from {json_path}: {e}")

        return count

    def load_from_csv(self, csv_path: str, ioc_type: str = "hash_sha256") -> int:
        """Load IOCs from a CSV file (one value per line)."""
        count = 0
        try:
            with open(csv_path, 'r') as f:
                for line in f:
                    value = line.strip()
                    if value and not value.startswith('#'):
                        ioc = IOC(
                            ioc_type=ioc_type,
                            value=value.lower() if "hash" in ioc_type else value,
                            source=csv_path,
                        )
                        self.add_ioc(ioc)
                        count += 1
        except FileNotFoundError as e:
            raise ValueError(f"Failed to load IOCs from {csv_path}: {e}")

        return count

    def get_compiled_patterns(self, ioc_type: str) -> List[Tuple[re.Pattern, IOC]]:
        """Get compiled regex patterns for string-matching IOC types."""
        if ioc_type not in self._compiled_patterns:
            patterns = []
            for ioc in self.iocs.get(ioc_type, []):
                try:
                    # Escape special regex characters for exact matching
                    pattern = re.compile(re.escape(ioc.value), re.IGNORECASE)
                    patterns.append((pattern, ioc))
                except re.error:
                    continue
            self._compiled_patterns[ioc_type] = patterns
        return self._compiled_patterns[ioc_type]

    def get_hash_set(self, hash_type: str) -> Set[str]:
        """Get a set of hashes for fast lookup."""
        return {ioc.value.lower() for ioc in self.iocs.get(hash_type, [])}

    def get_statistics(self) -> Dict[str, int]:
        """Return IOC counts by type."""
        return {k: len(v) for k, v in self.iocs.items() if v}

    def total_iocs(self) -> int:
        """Return total number of IOCs."""
        return sum(len(v) for v in self.iocs.values())


# ============================================================================
# Scanners
# ============================================================================

class Scanner(ABC):
    """Abstract base class for scanners."""

    def __init__(self, db: IOCDatabase):
        self.db = db
        self.errors: List[str] = []

    @abstractmethod
    def scan(self, target: str) -> List[Match]:
        """Perform scan and return matches."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return scanner name."""
        pass


class FileScanner(Scanner):
    """Scan files for IOCs."""

    # Binary file extensions to skip for content scanning
    BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
        '.mp3', '.mp4', '.avi', '.mov', '.mkv',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    }

    def __init__(self, db: IOCDatabase, max_file_size: int = 50 * 1024 * 1024):
        super().__init__(db)
        self.max_file_size = max_file_size
        self.files_scanned = 0
        self.bytes_scanned = 0

    def scan(self, target: str) -> List[Match]:
        """Scan files at target path."""
        matches = []
        target_path = Path(target)

        if target_path.is_file():
            matches.extend(self._scan_file(target_path))
        elif target_path.is_dir():
            for file_path in target_path.rglob('*'):
                if file_path.is_file():
                    matches.extend(self._scan_file(file_path))

        return matches

    def _scan_file(self, file_path: Path) -> List[Match]:
        """Scan a single file."""
        matches = []

        try:
            stat = file_path.stat()

            # Skip files that are too large
            if stat.st_size > self.max_file_size:
                self.errors.append(f"Skipped large file: {file_path}")
                return matches

            # Check filename against IOCs
            matches.extend(self._check_filename(file_path))

            # Calculate and check file hashes
            matches.extend(self._check_hashes(file_path))

            # Scan file content for string IOCs (skip binary)
            if file_path.suffix.lower() not in self.BINARY_EXTENSIONS:
                matches.extend(self._check_content(file_path))

            self.files_scanned += 1
            self.bytes_scanned += stat.st_size

        except PermissionError:
            self.errors.append(f"Permission denied: {file_path}")
        except Exception as e:
            self.errors.append(f"Error scanning {file_path}: {str(e)}")

        return matches

    def _check_filename(self, file_path: Path) -> List[Match]:
        """Check if filename matches any IOCs."""
        matches = []
        filename = file_path.name

        for pattern, ioc in self.db.get_compiled_patterns("filename"):
            if pattern.search(filename):
                matches.append(Match(
                    ioc=ioc,
                    location=str(file_path),
                    context=f"Filename match: {filename}",
                    timestamp=datetime.now(),
                    match_type="filename",
                ))

        return matches

    def _check_hashes(self, file_path: Path) -> List[Match]:
        """Calculate file hashes and check against IOC database."""
        matches = []

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Calculate hashes
            md5_hash = hashlib.md5(content).hexdigest().lower()
            sha1_hash = hashlib.sha1(content).hexdigest().lower()
            sha256_hash = hashlib.sha256(content).hexdigest().lower()

            # Check against database
            hash_checks = [
                ("hash_md5", md5_hash),
                ("hash_sha1", sha1_hash),
                ("hash_sha256", sha256_hash),
            ]

            for hash_type, hash_value in hash_checks:
                hash_set = self.db.get_hash_set(hash_type)
                if hash_value in hash_set:
                    # Find the matching IOC for details
                    for ioc in self.db.iocs[hash_type]:
                        if ioc.value.lower() == hash_value:
                            matches.append(Match(
                                ioc=ioc,
                                location=str(file_path),
                                context=f"{hash_type.upper()}: {hash_value}",
                                timestamp=datetime.now(),
                                match_type="hash",
                            ))
                            break

        except Exception as e:
            self.errors.append(f"Hash error for {file_path}: {str(e)}")

        return matches

    def _check_content(self, file_path: Path) -> List[Match]:
        """Scan file content for string IOCs."""
        matches = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check IPs
            for pattern, ioc in self.db.get_compiled_patterns("ip"):
                for match in pattern.finditer(content):
                    context = self._get_context(content, match.start(), match.end())
                    matches.append(Match(
                        ioc=ioc,
                        location=str(file_path),
                        context=context,
                        timestamp=datetime.now(),
                        match_type="file_content",
                    ))

            # Check domains
            for pattern, ioc in self.db.get_compiled_patterns("domain"):
                for match in pattern.finditer(content):
                    context = self._get_context(content, match.start(), match.end())
                    matches.append(Match(
                        ioc=ioc,
                        location=str(file_path),
                        context=context,
                        timestamp=datetime.now(),
                        match_type="file_content",
                    ))

            # Check URLs
            for pattern, ioc in self.db.get_compiled_patterns("url"):
                for match in pattern.finditer(content):
                    context = self._get_context(content, match.start(), match.end())
                    matches.append(Match(
                        ioc=ioc,
                        location=str(file_path),
                        context=context,
                        timestamp=datetime.now(),
                        match_type="file_content",
                    ))

            # Check emails
            for pattern, ioc in self.db.get_compiled_patterns("email"):
                for match in pattern.finditer(content):
                    context = self._get_context(content, match.start(), match.end())
                    matches.append(Match(
                        ioc=ioc,
                        location=str(file_path),
                        context=context,
                        timestamp=datetime.now(),
                        match_type="file_content",
                    ))

        except Exception as e:
            self.errors.append(f"Content scan error for {file_path}: {str(e)}")

        return matches

    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """Extract context around a match."""
        ctx_start = max(0, start - context_size)
        ctx_end = min(len(content), end + context_size)
        context = content[ctx_start:ctx_end]
        # Clean up whitespace
        context = ' '.join(context.split())
        return f"...{context}..."

    def get_name(self) -> str:
        return "file_scanner"

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "errors": len(self.errors),
        }


class NetworkScanner(Scanner):
    """Scan network connections for IOCs (mock implementation)."""

    def __init__(self, db: IOCDatabase):
        super().__init__(db)
        self.connections_scanned = 0

    def scan(self, target: str = "") -> List[Match]:
        """Scan active network connections."""
        matches = []

        # Try to get network connections using platform-specific methods
        connections = self._get_connections()

        ip_set = {ioc.value for ioc in self.db.iocs.get("ip", [])}
        domain_patterns = self.db.get_compiled_patterns("domain")

        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            remote_host = conn.get("remote_host", "")

            # Check IP
            if remote_ip in ip_set:
                for ioc in self.db.iocs.get("ip", []):
                    if ioc.value == remote_ip:
                        matches.append(Match(
                            ioc=ioc,
                            location=f"Network connection to {remote_ip}:{conn.get('remote_port', '?')}",
                            context=f"Process: {conn.get('process', 'unknown')}",
                            timestamp=datetime.now(),
                            match_type="network",
                        ))

            # Check domain
            for pattern, ioc in domain_patterns:
                if pattern.search(remote_host):
                    matches.append(Match(
                        ioc=ioc,
                        location=f"Network connection to {remote_host}",
                        context=f"Process: {conn.get('process', 'unknown')}",
                        timestamp=datetime.now(),
                        match_type="network",
                    ))

            self.connections_scanned += 1

        return matches

    def _get_connections(self) -> List[Dict[str, str]]:
        """Get active network connections (platform-specific)."""
        # This is a simplified implementation
        # In a real tool, this would use psutil or platform-specific APIs
        connections = []

        try:
            # Try to parse netstat output
            import subprocess
            result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 4 and 'ESTABLISHED' in line:
                    try:
                        remote = parts[4] if len(parts) > 4 else parts[3]
                        if ':' in remote:
                            ip, port = remote.rsplit(':', 1)
                            connections.append({
                                "remote_ip": ip,
                                "remote_port": port,
                                "remote_host": "",
                                "process": "unknown",
                            })
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            self.errors.append(f"Network scan error: {str(e)}")

        return connections

    def get_name(self) -> str:
        return "network_scanner"

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "connections_scanned": self.connections_scanned,
            "errors": len(self.errors),
        }


class ProcessScanner(Scanner):
    """Scan running processes for IOCs (mock implementation)."""

    def __init__(self, db: IOCDatabase):
        super().__init__(db)
        self.processes_scanned = 0

    def scan(self, target: str = "") -> List[Match]:
        """Scan running processes."""
        matches = []

        processes = self._get_processes()
        filename_patterns = self.db.get_compiled_patterns("filename")
        mutex_patterns = self.db.get_compiled_patterns("mutex")

        for proc in processes:
            proc_name = proc.get("name", "")
            proc_path = proc.get("path", "")

            # Check process name/path against filename IOCs
            for pattern, ioc in filename_patterns:
                if pattern.search(proc_name) or pattern.search(proc_path):
                    matches.append(Match(
                        ioc=ioc,
                        location=f"Process: {proc_name} (PID: {proc.get('pid', '?')})",
                        context=f"Path: {proc_path}",
                        timestamp=datetime.now(),
                        match_type="process",
                    ))

            self.processes_scanned += 1

        return matches

    def _get_processes(self) -> List[Dict[str, Any]]:
        """Get list of running processes."""
        processes = []

        try:
            import subprocess

            # Use ps command (works on macOS and Linux)
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.split('\n')[1:]:  # Skip header
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({
                        "name": parts[10].split()[0] if parts[10] else "",
                        "path": parts[10],
                        "pid": parts[1],
                        "user": parts[0],
                    })
        except Exception as e:
            self.errors.append(f"Process scan error: {str(e)}")

        return processes

    def get_name(self) -> str:
        return "process_scanner"

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "processes_scanned": self.processes_scanned,
            "errors": len(self.errors),
        }


# ============================================================================
# Main IOC Scanner
# ============================================================================

class IOCScanner:
    """Main IOC scanning engine."""

    def __init__(self):
        self.db = IOCDatabase()
        self.scanners: Dict[str, Scanner] = {}

    def load_iocs(self, source: str, ioc_type: Optional[str] = None) -> int:
        """Load IOCs from a file."""
        if source.endswith('.json'):
            return self.db.load_from_json(source)
        elif source.endswith('.csv') or source.endswith('.txt'):
            return self.db.load_from_csv(source, ioc_type or "hash_sha256")
        else:
            raise ValueError(f"Unsupported IOC file format: {source}")

    def add_builtin_iocs(self) -> int:
        """Add some built-in example IOCs for testing."""
        # These are example/test IOCs - not real threat indicators
        example_iocs = [
            IOC("ip", "10.0.0.1", "Test malicious IP", "LOW", "builtin", ["test"]),
            IOC("domain", "malware-test.example.com", "Test malicious domain", "MEDIUM", "builtin", ["test"]),
            IOC("hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty file hash (test)", "LOW", "builtin", ["test"]),
            IOC("filename", "mimikatz.exe", "Known credential dumping tool", "CRITICAL", "builtin", ["credential_theft"]),
            IOC("filename", "nc.exe", "Netcat - potential lateral movement", "HIGH", "builtin", ["lateral_movement"]),
        ]

        for ioc in example_iocs:
            self.db.add_ioc(ioc)

        return len(example_iocs)

    def scan_files(self, target: str) -> ScanResult:
        """Scan files for IOCs."""
        scanner = FileScanner(self.db)
        self.scanners["file"] = scanner

        start_time = datetime.now()
        matches = scanner.scan(target)
        end_time = datetime.now()

        return ScanResult(
            scan_type="file",
            target=target,
            start_time=start_time,
            end_time=end_time,
            matches=matches,
            statistics=scanner.get_statistics(),
            errors=scanner.errors,
        )

    def scan_network(self) -> ScanResult:
        """Scan network connections for IOCs."""
        scanner = NetworkScanner(self.db)
        self.scanners["network"] = scanner

        start_time = datetime.now()
        matches = scanner.scan()
        end_time = datetime.now()

        return ScanResult(
            scan_type="network",
            target="active_connections",
            start_time=start_time,
            end_time=end_time,
            matches=matches,
            statistics=scanner.get_statistics(),
            errors=scanner.errors,
        )

    def scan_processes(self) -> ScanResult:
        """Scan running processes for IOCs."""
        scanner = ProcessScanner(self.db)
        self.scanners["process"] = scanner

        start_time = datetime.now()
        matches = scanner.scan()
        end_time = datetime.now()

        return ScanResult(
            scan_type="process",
            target="running_processes",
            start_time=start_time,
            end_time=end_time,
            matches=matches,
            statistics=scanner.get_statistics(),
            errors=scanner.errors,
        )

    def get_plan(self, scan_types: List[str], target: str, ioc_files: List[str]) -> str:
        """Generate planning mode output."""
        plan = []
        plan.append("")
        plan.append("[PLAN MODE] Tool: ioc-scanner")
        plan.append("=" * 50)
        plan.append("")
        plan.append("Actions to be performed:")
        plan.append("")

        step = 1

        # IOC loading
        if ioc_files:
            for ioc_file in ioc_files:
                plan.append(f"  {step}. Load IOCs from: {ioc_file}")
                step += 1
        else:
            plan.append(f"  {step}. Load built-in IOCs (test/example indicators)")
            step += 1

        # Scans to perform
        if "file" in scan_types or "all" in scan_types:
            plan.append(f"  {step}. File scan target: {target}")
            plan.append(f"       - Calculate MD5, SHA1, SHA256 hashes")
            plan.append(f"       - Check filenames against IOC database")
            plan.append(f"       - Scan text file content for indicators")
            step += 1

        if "network" in scan_types or "all" in scan_types:
            plan.append(f"  {step}. Network scan")
            plan.append(f"       - Enumerate active connections")
            plan.append(f"       - Check remote IPs/domains against IOC database")
            step += 1

        if "process" in scan_types or "all" in scan_types:
            plan.append(f"  {step}. Process scan")
            plan.append(f"       - Enumerate running processes")
            plan.append(f"       - Check process names/paths against IOC database")
            step += 1

        plan.append("")
        plan.append("IOC Database Statistics:")
        stats = self.db.get_statistics()
        if stats:
            for ioc_type, count in stats.items():
                plan.append(f"  - {ioc_type}: {count} indicators")
        else:
            plan.append("  - No IOCs loaded (will use built-in test IOCs)")

        plan.append("")
        plan.append("Risk Assessment: LOW (read-only scanning)")
        plan.append("Detection Vectors: File access, process enumeration, network enumeration")
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
        "name": "ioc-scanner",
        "category": "Defense - Threat Detection",
        "version": "1.0.0",
        "author": "Defensive Security Toolsmith",
        "description": "Scan files, processes, and network connections for Indicators of Compromise",
        "features": [
            "File hash scanning (MD5, SHA1, SHA256)",
            "Filename pattern matching",
            "File content scanning for IPs, domains, URLs",
            "Network connection monitoring",
            "Process enumeration and matching",
            "JSON and CSV IOC feed support",
            "Customizable IOC database",
            "Multiple output formats",
        ],
        "supported_ioc_types": [
            "ip", "domain", "hash_md5", "hash_sha1", "hash_sha256",
            "url", "filename", "email", "registry", "mutex",
        ],
        "usage_examples": [
            "python tool.py --plan --scan-type file --target /home/user",
            "python tool.py --scan-type file --target /var/log --ioc-file threats.json",
            "python tool.py --scan-type network --ioc-file known_bad_ips.csv",
            "python tool.py --scan-type all --target /opt/apps --output json",
        ],
        "arguments": {
            "--plan, -p": "Show execution plan without running scan",
            "--scan-type": "Type of scan (file, network, process, all)",
            "--target, -t": "Target path for file scanning",
            "--ioc-file": "Path to IOC file (JSON or CSV)",
            "--output, -o": "Output format (text, json)",
            "--quiet, -q": "Suppress informational output",
        },
        "ioc_file_formats": {
            "json": {
                "description": "JSON array of IOC objects",
                "example": '[{"type": "ip", "value": "1.2.3.4", "severity": "HIGH"}]',
            },
            "csv": {
                "description": "One IOC value per line",
                "example": "hash1\\nhash2\\nhash3",
            },
        },
        "legal_notice": "This tool is for authorized security scanning only.",
    }


# ============================================================================
# Output Formatters
# ============================================================================

def format_output_text(result: ScanResult) -> str:
    """Format scan result as human-readable text."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  IOC SCAN REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Scan Type: {result.scan_type}")
    lines.append(f"Target: {result.target}")
    lines.append(f"Duration: {result.duration:.2f} seconds")
    lines.append(f"Matches Found: {len(result.matches)}")
    lines.append("")

    if result.matches:
        lines.append("-" * 60)
        lines.append("  MATCHES")
        lines.append("-" * 60)

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_matches = sorted(
            result.matches,
            key=lambda x: severity_order.get(x.ioc.severity, 4)
        )

        for match in sorted_matches:
            lines.append("")
            lines.append(f"[{match.ioc.severity}] {match.ioc.ioc_type.upper()}: {match.ioc.value}")
            lines.append(f"  Location: {match.location}")
            lines.append(f"  Context: {match.context[:100]}...")
            if match.ioc.description:
                lines.append(f"  Description: {match.ioc.description}")
            lines.append(f"  Time: {match.timestamp}")
    else:
        lines.append("")
        lines.append("No IOC matches found.")

    lines.append("")
    lines.append("-" * 60)
    lines.append("  STATISTICS")
    lines.append("-" * 60)
    for key, value in result.statistics.items():
        lines.append(f"  {key}: {value}")

    if result.errors:
        lines.append("")
        lines.append("-" * 60)
        lines.append("  ERRORS")
        lines.append("-" * 60)
        for error in result.errors[:10]:
            lines.append(f"  - {error}")
        if len(result.errors) > 10:
            lines.append(f"  ... and {len(result.errors) - 10} more errors")

    lines.append("")
    lines.append("=" * 60)

    return '\n'.join(lines)


def format_output_json(result: ScanResult) -> str:
    """Format scan result as JSON."""
    return json.dumps(result.to_dict(), indent=2)


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="IOC Scanner - Scan for Indicators of Compromise",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --plan --scan-type file --target /home/user
  %(prog)s --scan-type file --target /var/log --ioc-file threats.json
  %(prog)s --scan-type network
  %(prog)s --scan-type all --target /opt --output json

Supported IOC types: ip, domain, hash_md5, hash_sha1, hash_sha256, url, filename
        """
    )

    parser.add_argument(
        '--plan', '-p',
        action='store_true',
        help='Show execution plan without running scan'
    )

    parser.add_argument(
        '--scan-type',
        choices=['file', 'network', 'process', 'all'],
        default='file',
        help='Type of scan to perform (default: file)'
    )

    parser.add_argument(
        '--target', '-t',
        default='.',
        help='Target path for file scanning (default: current directory)'
    )

    parser.add_argument(
        '--ioc-file',
        action='append',
        dest='ioc_files',
        help='Path to IOC file (can specify multiple)'
    )

    parser.add_argument(
        '--ioc-type',
        default='hash_sha256',
        help='IOC type for CSV files (default: hash_sha256)'
    )

    parser.add_argument(
        '--output', '-o',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress informational output'
    )

    parser.add_argument(
        '--builtin',
        action='store_true',
        help='Include built-in test IOCs'
    )

    args = parser.parse_args()

    scanner = IOCScanner()

    # Load IOCs
    ioc_count = 0
    if args.ioc_files:
        for ioc_file in args.ioc_files:
            try:
                count = scanner.load_iocs(ioc_file, args.ioc_type)
                ioc_count += count
                if not args.quiet:
                    print(f"Loaded {count} IOCs from {ioc_file}", file=sys.stderr)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1

    if args.builtin or not args.ioc_files:
        count = scanner.add_builtin_iocs()
        ioc_count += count
        if not args.quiet:
            print(f"Loaded {count} built-in IOCs", file=sys.stderr)

    # Planning mode
    if args.plan:
        scan_types = ['all'] if args.scan_type == 'all' else [args.scan_type]
        print(scanner.get_plan(scan_types, args.target, args.ioc_files or []))
        return 0

    # Execution mode
    results = []

    if args.scan_type in ['file', 'all']:
        if not args.quiet:
            print(f"Scanning files at {args.target}...", file=sys.stderr)
        results.append(scanner.scan_files(args.target))

    if args.scan_type in ['network', 'all']:
        if not args.quiet:
            print("Scanning network connections...", file=sys.stderr)
        results.append(scanner.scan_network())

    if args.scan_type in ['process', 'all']:
        if not args.quiet:
            print("Scanning processes...", file=sys.stderr)
        results.append(scanner.scan_processes())

    # Output results
    for result in results:
        if args.output == 'json':
            print(format_output_json(result))
        else:
            print(format_output_text(result))

    # Return non-zero if matches found
    total_matches = sum(len(r.matches) for r in results)
    critical_high = sum(
        1 for r in results for m in r.matches
        if m.ioc.severity in ['CRITICAL', 'HIGH']
    )

    return 1 if critical_high > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
