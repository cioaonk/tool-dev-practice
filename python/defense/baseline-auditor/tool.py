#!/usr/bin/env python3
"""
Baseline Auditor - Defensive Security Tool
Compare system state to baseline for file integrity, process, and network monitoring.

Author: Defensive Security Toolsmith
Category: Defense - Integrity Monitoring
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class FileEntry:
    """Represents a file in the baseline."""
    path: str
    hash_sha256: str
    size: int
    mode: int
    mtime: float
    owner: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "hash_sha256": self.hash_sha256,
            "size": self.size,
            "mode": self.mode,
            "mtime": self.mtime,
            "owner": self.owner,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'FileEntry':
        return FileEntry(
            path=data["path"],
            hash_sha256=data["hash_sha256"],
            size=data["size"],
            mode=data["mode"],
            mtime=data["mtime"],
            owner=data.get("owner", ""),
        )


@dataclass
class ProcessEntry:
    """Represents a process in the baseline."""
    name: str
    path: str
    user: str
    expected: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "user": self.user,
            "expected": self.expected,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'ProcessEntry':
        return ProcessEntry(
            name=data["name"],
            path=data["path"],
            user=data["user"],
            expected=data.get("expected", True),
        )


@dataclass
class NetworkEntry:
    """Represents a network connection in the baseline."""
    local_port: int
    protocol: str
    process: str = ""
    expected: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "local_port": self.local_port,
            "protocol": self.protocol,
            "process": self.process,
            "expected": self.expected,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'NetworkEntry':
        return NetworkEntry(
            local_port=data["local_port"],
            protocol=data["protocol"],
            process=data.get("process", ""),
            expected=data.get("expected", True),
        )


@dataclass
class Baseline:
    """Complete system baseline."""
    created: datetime
    hostname: str
    files: Dict[str, FileEntry]
    processes: Dict[str, ProcessEntry]
    listening_ports: Dict[int, NetworkEntry]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "created": self.created.isoformat(),
            "hostname": self.hostname,
            "files": {k: v.to_dict() for k, v in self.files.items()},
            "processes": {k: v.to_dict() for k, v in self.processes.items()},
            "listening_ports": {str(k): v.to_dict() for k, v in self.listening_ports.items()},
            "metadata": self.metadata,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Baseline':
        return Baseline(
            created=datetime.fromisoformat(data["created"]),
            hostname=data["hostname"],
            files={k: FileEntry.from_dict(v) for k, v in data.get("files", {}).items()},
            processes={k: ProcessEntry.from_dict(v) for k, v in data.get("processes", {}).items()},
            listening_ports={int(k): NetworkEntry.from_dict(v) for k, v in data.get("listening_ports", {}).items()},
            metadata=data.get("metadata", {}),
        )


@dataclass
class Violation:
    """Represents a baseline violation."""
    category: str
    violation_type: str
    severity: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "violation_type": self.violation_type,
            "severity": self.severity,
            "description": self.description,
            "details": self.details,
        }


@dataclass
class AuditResult:
    """Complete audit result."""
    timestamp: datetime
    baseline_date: datetime
    hostname: str
    files_checked: int
    processes_checked: int
    ports_checked: int
    violations: List[Violation]
    summary: str

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "HIGH")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "baseline_date": self.baseline_date.isoformat(),
            "hostname": self.hostname,
            "files_checked": self.files_checked,
            "processes_checked": self.processes_checked,
            "ports_checked": self.ports_checked,
            "violation_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "summary": self.summary,
        }


# ============================================================================
# Collectors
# ============================================================================

class FileCollector:
    """Collect file information for baseline."""

    def __init__(self, paths: List[str], exclude_patterns: Optional[List[str]] = None):
        """Initialize the file collector.

        Args:
            paths: List of file or directory paths to collect.
            exclude_patterns: Optional list of glob patterns to exclude.
        """
        self.paths = paths
        self.exclude_patterns = exclude_patterns or []

    def collect(self) -> Dict[str, FileEntry]:
        """Collect file entries from configured paths."""
        entries = {}

        for base_path in self.paths:
            if os.path.isfile(base_path):
                entry = self._get_file_entry(base_path)
                if entry:
                    entries[base_path] = entry
            elif os.path.isdir(base_path):
                for root, dirs, files in os.walk(base_path):
                    dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        if not self._is_excluded(fpath):
                            entry = self._get_file_entry(fpath)
                            if entry:
                                entries[fpath] = entry

        return entries

    def _is_excluded(self, path: str) -> bool:
        """Check if path should be excluded."""
        import fnmatch
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def _get_file_entry(self, path: str) -> Optional[FileEntry]:
        """Get file entry for a single file."""
        try:
            stat = os.stat(path)
            file_hash = self._calculate_hash(path)

            try:
                import pwd
                owner = pwd.getpwuid(stat.st_uid).pw_name
            except (ImportError, KeyError):
                owner = str(stat.st_uid)

            return FileEntry(
                path=path,
                hash_sha256=file_hash,
                size=stat.st_size,
                mode=stat.st_mode,
                mtime=stat.st_mtime,
                owner=owner,
            )
        except (OSError, IOError):
            return None

    def _calculate_hash(self, path: str, max_size: int = 100 * 1024 * 1024) -> str:
        """Calculate SHA256 hash of file."""
        try:
            if os.path.getsize(path) > max_size:
                return "SKIPPED_LARGE_FILE"

            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (OSError, IOError):
            return "ERROR"


class ProcessCollector:
    """Collect process information for baseline."""

    def collect(self) -> Dict[str, ProcessEntry]:
        """Collect running processes."""
        entries = {}

        try:
            if sys.platform != 'win32':
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                for line in result.stdout.split('\n')[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        user = parts[0]
                        cmd = parts[10]
                        name = cmd.split()[0] if cmd else ""
                        name = os.path.basename(name)

                        if name and name not in entries:
                            entries[name] = ProcessEntry(
                                name=name,
                                path=cmd.split()[0] if cmd else "",
                                user=user,
                                expected=True,
                            )
        except Exception:
            pass

        return entries


class NetworkCollector:
    """Collect network information for baseline."""

    def collect(self) -> Dict[int, NetworkEntry]:
        """Collect listening ports."""
        entries = {}

        try:
            result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True,
                timeout=30
            )

            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        proto = parts[0].lower().replace('4', '').replace('6', '')
                        local_addr = parts[3] if len(parts) > 3 else parts[1]

                        try:
                            if '.' in local_addr:
                                port = int(local_addr.rsplit('.', 1)[1])
                            elif ':' in local_addr:
                                port = int(local_addr.rsplit(':', 1)[1])
                            else:
                                continue

                            if port not in entries:
                                entries[port] = NetworkEntry(
                                    local_port=port,
                                    protocol=proto,
                                    expected=True,
                                )
                        except (ValueError, IndexError):
                            pass
        except Exception:
            pass

        return entries


# ============================================================================
# Auditor
# ============================================================================

class BaselineAuditor:
    """Main baseline auditing engine."""

    CRITICAL_PATHS = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers',
        '/etc/ssh/sshd_config', '/root/.ssh/authorized_keys',
    ]

    HIGH_SEVERITY_PATTERNS = [
        '/etc/*', '/bin/*', '/sbin/*', '/usr/bin/*', '/usr/sbin/*',
    ]

    def __init__(self, baseline: Baseline):
        self.baseline = baseline

    def audit_files(self, current_files: Dict[str, FileEntry]) -> List[Violation]:
        """Audit files against baseline."""
        violations = []

        baseline_paths = set(self.baseline.files.keys())
        current_paths = set(current_files.keys())

        for path in current_paths - baseline_paths:
            violations.append(Violation(
                category="file",
                violation_type="added",
                severity=self._get_file_severity(path),
                description=f"New file detected: {path}",
                details={"path": path}
            ))

        for path in baseline_paths - current_paths:
            violations.append(Violation(
                category="file",
                violation_type="removed",
                severity=self._get_file_severity(path),
                description=f"File removed: {path}",
                details={"path": path}
            ))

        for path in baseline_paths & current_paths:
            baseline_entry = self.baseline.files[path]
            current_entry = current_files[path]

            if baseline_entry.hash_sha256 != current_entry.hash_sha256:
                violations.append(Violation(
                    category="file",
                    violation_type="modified",
                    severity=self._get_file_severity(path),
                    description=f"File content changed: {path}",
                    details={
                        "path": path,
                        "baseline_hash": baseline_entry.hash_sha256,
                        "current_hash": current_entry.hash_sha256,
                    }
                ))

        return violations

    def audit_processes(self, current_processes: Dict[str, ProcessEntry]) -> List[Violation]:
        """Audit processes against baseline."""
        violations = []

        baseline_names = set(self.baseline.processes.keys())
        current_names = set(current_processes.keys())

        for name in current_names - baseline_names:
            violations.append(Violation(
                category="process",
                violation_type="unexpected",
                severity="MEDIUM",
                description=f"Unexpected process: {name}",
                details=current_processes[name].to_dict()
            ))

        return violations

    def audit_network(self, current_ports: Dict[int, NetworkEntry]) -> List[Violation]:
        """Audit network ports against baseline."""
        violations = []

        baseline_ports = set(self.baseline.listening_ports.keys())
        current_ports_set = set(current_ports.keys())

        for port in current_ports_set - baseline_ports:
            severity = "HIGH" if port < 1024 else "MEDIUM"
            violations.append(Violation(
                category="network",
                violation_type="new_listener",
                severity=severity,
                description=f"New listening port: {port}",
                details=current_ports[port].to_dict()
            ))

        return violations

    def _get_file_severity(self, path: str) -> str:
        """Determine severity based on file path."""
        import fnmatch

        if path in self.CRITICAL_PATHS:
            return "CRITICAL"

        for pattern in self.HIGH_SEVERITY_PATTERNS:
            if fnmatch.fnmatch(path, pattern):
                return "HIGH"

        return "MEDIUM"

    def audit(self, check_files: bool = True, check_processes: bool = True,
              check_network: bool = True, file_paths: List[str] = None) -> AuditResult:
        """Run full audit against baseline."""
        import socket

        violations = []
        files_checked = 0
        processes_checked = 0
        ports_checked = 0

        if check_files:
            paths = file_paths or list(set(os.path.dirname(p) for p in self.baseline.files.keys()))
            collector = FileCollector(paths)
            current_files = collector.collect()
            violations.extend(self.audit_files(current_files))
            files_checked = len(current_files)

        if check_processes:
            collector = ProcessCollector()
            current_processes = collector.collect()
            violations.extend(self.audit_processes(current_processes))
            processes_checked = len(current_processes)

        if check_network:
            collector = NetworkCollector()
            current_ports = collector.collect()
            violations.extend(self.audit_network(current_ports))
            ports_checked = len(current_ports)

        critical = sum(1 for v in violations if v.severity == "CRITICAL")
        high = sum(1 for v in violations if v.severity == "HIGH")
        summary = f"Found {len(violations)} violations: {critical} critical, {high} high."

        return AuditResult(
            timestamp=datetime.now(),
            baseline_date=self.baseline.created,
            hostname=socket.gethostname(),
            files_checked=files_checked,
            processes_checked=processes_checked,
            ports_checked=ports_checked,
            violations=violations,
            summary=summary,
        )


# ============================================================================
# Baseline Manager
# ============================================================================

class BaselineManager:
    """Manage baseline creation and storage."""

    def create_baseline(self, file_paths: List[str], exclude_patterns: List[str] = None) -> Baseline:
        """Create a new baseline from current system state."""
        import socket

        file_collector = FileCollector(file_paths, exclude_patterns)
        process_collector = ProcessCollector()
        network_collector = NetworkCollector()

        return Baseline(
            created=datetime.now(),
            hostname=socket.gethostname(),
            files=file_collector.collect(),
            processes=process_collector.collect(),
            listening_ports=network_collector.collect(),
            metadata={"file_paths": file_paths, "exclude_patterns": exclude_patterns or []},
        )

    def save_baseline(self, baseline: Baseline, path: str) -> None:
        """Save baseline to file."""
        with open(path, 'w') as f:
            json.dump(baseline.to_dict(), f, indent=2)

    def load_baseline(self, path: str) -> Baseline:
        """Load baseline from file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return Baseline.from_dict(data)

    def get_plan(self, mode: str, paths: List[str], baseline_file: str) -> str:
        """Generate planning mode output."""
        plan = []
        plan.append("")
        plan.append("[PLAN MODE] Tool: baseline-auditor")
        plan.append("=" * 50)
        plan.append(f"Mode: {mode}")
        plan.append("")
        if mode == "create":
            plan.append("Actions:")
            plan.append(f"  1. Scan paths: {paths}")
            plan.append("  2. Calculate SHA256 hashes")
            plan.append("  3. Collect metadata")
            plan.append("  4. Enumerate processes")
            plan.append("  5. Identify listening ports")
            plan.append(f"  6. Save to: {baseline_file}")
        else:
            plan.append("Actions:")
            plan.append(f"  1. Load baseline: {baseline_file}")
            plan.append("  2. Compare current state")
            plan.append("  3. Generate violations")
        plan.append("")
        plan.append("Risk Assessment: LOW (read-only)")
        plan.append("No actions taken. Remove --plan to execute.")
        plan.append("=" * 50)
        return '\n'.join(plan)


# ============================================================================
# Documentation
# ============================================================================

def get_documentation() -> Dict[str, Any]:
    """Return structured documentation for this tool."""
    return {
        "name": "baseline-auditor",
        "category": "Defense - Integrity Monitoring",
        "version": "1.0.0",
        "author": "Defensive Security Toolsmith",
        "description": "Compare system state to baseline for integrity monitoring",
        "features": [
            "File integrity monitoring (SHA256)",
            "File permission tracking",
            "Process baseline comparison",
            "Network port monitoring",
            "Severity-based alerting",
        ],
        "usage_examples": [
            "python tool.py --plan --mode create --paths /etc",
            "python tool.py --mode create --paths /etc --baseline baseline.json",
            "python tool.py --mode audit --baseline baseline.json",
        ],
        "arguments": {
            "--plan, -p": "Show execution plan",
            "--mode": "Operation mode (create, audit)",
            "--paths": "Comma-separated paths to monitor",
            "--baseline": "Baseline file path",
            "--output, -o": "Output format (text, json)",
        },
        "legal_notice": "For authorized security monitoring only.",
    }


# ============================================================================
# Output Formatters
# ============================================================================

def format_output_text(result: AuditResult) -> str:
    """Format audit result as human-readable text."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  BASELINE AUDIT REPORT")
    lines.append("=" * 60)
    lines.append(f"Audit Time: {result.timestamp}")
    lines.append(f"Baseline Date: {result.baseline_date}")
    lines.append(f"Summary: {result.summary}")
    lines.append("")

    if result.violations:
        lines.append("-" * 60)
        lines.append("  VIOLATIONS")
        lines.append("-" * 60)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_violations = sorted(result.violations, key=lambda x: severity_order.get(x.severity, 4))

        for v in sorted_violations:
            lines.append(f"[{v.severity}] {v.category}: {v.description}")
    else:
        lines.append("No violations detected.")

    lines.append("=" * 60)
    return '\n'.join(lines)


def format_output_json(result: AuditResult) -> str:
    """Format audit result as JSON."""
    return json.dumps(result.to_dict(), indent=2)


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Baseline Auditor - System integrity monitoring")
    parser.add_argument('--plan', '-p', action='store_true', help='Show plan')
    parser.add_argument('--mode', choices=['create', 'audit'], help='Operation mode')
    parser.add_argument('--paths', help='Comma-separated paths')
    parser.add_argument('--baseline', default='baseline.json', help='Baseline file')
    parser.add_argument('--exclude', help='Patterns to exclude')
    parser.add_argument('--output', '-o', choices=['text', 'json'], default='text')
    parser.add_argument('--quiet', '-q', action='store_true')

    args = parser.parse_args()
    manager = BaselineManager()

    paths = args.paths.split(',') if args.paths else ['/etc']
    exclude = args.exclude.split(',') if args.exclude else []

    if args.plan:
        mode = args.mode or 'audit'
        print(manager.get_plan(mode, paths, args.baseline))
        return 0

    if not args.mode:
        parser.print_help()
        print("\nError: --mode required")
        return 1

    if args.mode == 'create':
        if not args.quiet:
            print(f"Creating baseline...", file=sys.stderr)
        baseline = manager.create_baseline(paths, exclude)
        manager.save_baseline(baseline, args.baseline)
        print(f"Baseline saved: {args.baseline} ({len(baseline.files)} files)")
        return 0

    elif args.mode == 'audit':
        if not os.path.exists(args.baseline):
            print(f"Error: Baseline not found: {args.baseline}", file=sys.stderr)
            return 1

        baseline = manager.load_baseline(args.baseline)
        auditor = BaselineAuditor(baseline)
        result = auditor.audit(file_paths=paths)

        if args.output == 'json':
            print(format_output_json(result))
        else:
            print(format_output_text(result))

        return 1 if result.critical_count > 0 or result.high_count > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
