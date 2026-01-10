#!/usr/bin/env python3
"""
YARA Scanner - Python wrapper for YARA rule scanning
Author: Detection Engineering Team
Date: 2026-01-10

Educational/CTF Training Resource

Features:
- Scan files with all YARA rules
- Scan memory/processes (requires elevated privileges)
- JSON output format
- Planning mode (--plan flag)
"""

import argparse
import json
import os
import sys
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

# Try to import yara, provide helpful error if not installed
try:
    import yara
except ImportError:
    print("ERROR: yara-python is not installed.")
    print("Install with: pip install yara-python")
    sys.exit(1)


class OutputFormat(Enum):
    """Output format options"""
    JSON = "json"
    TEXT = "text"
    CSV = "csv"


@dataclass
class MatchResult:
    """Represents a single YARA rule match"""
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Dict[str, Any]]
    file_path: str
    file_hash: str
    file_size: int
    timestamp: str


@dataclass
class ScanResult:
    """Represents the complete scan result"""
    scan_time: str
    total_files: int
    files_with_matches: int
    total_matches: int
    matches: List[MatchResult]
    errors: List[Dict[str, str]]
    rules_loaded: int
    scan_mode: str


class YaraScanner:
    """YARA rule scanner with multiple scan modes and output formats"""

    def __init__(self, rules_dir: str = None, rules_file: str = None):
        """
        Initialize the scanner with YARA rules.

        Args:
            rules_dir: Directory containing .yar files
            rules_file: Single .yar file to load
        """
        self.rules = None
        self.rules_count = 0
        self.rules_dir = rules_dir
        self.errors: List[Dict[str, str]] = []

        if rules_dir:
            self._load_rules_from_directory(rules_dir)
        elif rules_file:
            self._load_rules_from_file(rules_file)

    def _load_rules_from_directory(self, rules_dir: str) -> None:
        """Load all YARA rules from a directory"""
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

        # Collect all .yar files
        yar_files = {}
        for yar_file in rules_path.glob("**/*.yar"):
            namespace = yar_file.stem
            yar_files[namespace] = str(yar_file)

        if not yar_files:
            raise ValueError(f"No .yar files found in {rules_dir}")

        # Compile rules
        try:
            self.rules = yara.compile(filepaths=yar_files)
            self.rules_count = len(yar_files)
        except yara.Error as e:
            self.errors.append({
                "type": "compilation_error",
                "message": str(e)
            })
            raise

    def _load_rules_from_file(self, rules_file: str) -> None:
        """Load YARA rules from a single file"""
        if not os.path.exists(rules_file):
            raise FileNotFoundError(f"Rules file not found: {rules_file}")

        try:
            self.rules = yara.compile(filepath=rules_file)
            self.rules_count = 1
        except yara.Error as e:
            self.errors.append({
                "type": "compilation_error",
                "message": str(e)
            })
            raise

    def _get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "error_calculating_hash"

    def _format_strings(self, strings: List) -> List[Dict[str, Any]]:
        """Format matched strings for output"""
        formatted = []
        for offset, identifier, data in strings:
            formatted.append({
                "offset": offset,
                "identifier": identifier,
                "data": data.hex() if isinstance(data, bytes) else str(data),
                "data_preview": data[:50].decode('utf-8', errors='replace') if isinstance(data, bytes) else str(data)[:50]
            })
        return formatted

    def scan_file(self, file_path: str) -> List[MatchResult]:
        """
        Scan a single file with loaded YARA rules.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of MatchResult objects
        """
        if not self.rules:
            raise RuntimeError("No rules loaded")

        matches = []
        try:
            file_hash = self._get_file_hash(file_path)
            file_size = os.path.getsize(file_path)

            yara_matches = self.rules.match(file_path)

            for match in yara_matches:
                result = MatchResult(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings=self._format_strings(match.strings),
                    file_path=str(file_path),
                    file_hash=file_hash,
                    file_size=file_size,
                    timestamp=datetime.datetime.now().isoformat()
                )
                matches.append(result)

        except yara.Error as e:
            self.errors.append({
                "type": "scan_error",
                "file": str(file_path),
                "message": str(e)
            })
        except Exception as e:
            self.errors.append({
                "type": "general_error",
                "file": str(file_path),
                "message": str(e)
            })

        return matches

    def scan_directory(self, directory: str, recursive: bool = True) -> ScanResult:
        """
        Scan all files in a directory.

        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            ScanResult object with all matches
        """
        all_matches = []
        files_scanned = 0
        files_with_matches = set()

        dir_path = Path(directory)
        pattern = "**/*" if recursive else "*"

        for file_path in dir_path.glob(pattern):
            if file_path.is_file():
                files_scanned += 1
                matches = self.scan_file(str(file_path))
                if matches:
                    files_with_matches.add(str(file_path))
                    all_matches.extend(matches)

        return ScanResult(
            scan_time=datetime.datetime.now().isoformat(),
            total_files=files_scanned,
            files_with_matches=len(files_with_matches),
            total_matches=len(all_matches),
            matches=all_matches,
            errors=self.errors,
            rules_loaded=self.rules_count,
            scan_mode="directory"
        )

    def scan_data(self, data: bytes, identifier: str = "memory") -> List[MatchResult]:
        """
        Scan raw bytes/memory data.

        Args:
            data: Bytes to scan
            identifier: Identifier for the data source

        Returns:
            List of MatchResult objects
        """
        if not self.rules:
            raise RuntimeError("No rules loaded")

        matches = []
        try:
            yara_matches = self.rules.match(data=data)

            sha256_hash = hashlib.sha256(data).hexdigest()

            for match in yara_matches:
                result = MatchResult(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings=self._format_strings(match.strings),
                    file_path=identifier,
                    file_hash=sha256_hash,
                    file_size=len(data),
                    timestamp=datetime.datetime.now().isoformat()
                )
                matches.append(result)

        except yara.Error as e:
            self.errors.append({
                "type": "scan_error",
                "file": identifier,
                "message": str(e)
            })

        return matches

    def scan_process(self, pid: int) -> List[MatchResult]:
        """
        Scan a running process memory.

        Args:
            pid: Process ID to scan

        Returns:
            List of MatchResult objects

        Note: Requires elevated privileges on most systems
        """
        if not self.rules:
            raise RuntimeError("No rules loaded")

        matches = []
        try:
            yara_matches = self.rules.match(pid=pid)

            for match in yara_matches:
                result = MatchResult(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings=self._format_strings(match.strings),
                    file_path=f"pid:{pid}",
                    file_hash="N/A",
                    file_size=0,
                    timestamp=datetime.datetime.now().isoformat()
                )
                matches.append(result)

        except yara.Error as e:
            self.errors.append({
                "type": "process_scan_error",
                "pid": pid,
                "message": str(e)
            })

        return matches


def format_output(result: ScanResult, format_type: OutputFormat) -> str:
    """Format scan results for output"""

    if format_type == OutputFormat.JSON:
        # Convert dataclasses to dicts for JSON serialization
        result_dict = asdict(result)
        return json.dumps(result_dict, indent=2)

    elif format_type == OutputFormat.CSV:
        lines = ["rule,namespace,file_path,file_hash,severity,confidence,timestamp"]
        for match in result.matches:
            severity = match.meta.get('severity', 'unknown')
            confidence = match.meta.get('confidence', 'unknown')
            lines.append(f"{match.rule},{match.namespace},{match.file_path},{match.file_hash},{severity},{confidence},{match.timestamp}")
        return "\n".join(lines)

    else:  # TEXT format
        lines = []
        lines.append("=" * 60)
        lines.append("YARA SCAN REPORT")
        lines.append("=" * 60)
        lines.append(f"Scan Time: {result.scan_time}")
        lines.append(f"Rules Loaded: {result.rules_loaded}")
        lines.append(f"Scan Mode: {result.scan_mode}")
        lines.append(f"Total Files Scanned: {result.total_files}")
        lines.append(f"Files with Matches: {result.files_with_matches}")
        lines.append(f"Total Matches: {result.total_matches}")
        lines.append("")

        if result.matches:
            lines.append("-" * 60)
            lines.append("MATCHES")
            lines.append("-" * 60)

            for match in result.matches:
                lines.append(f"\n[MATCH] {match.rule}")
                lines.append(f"  Namespace: {match.namespace}")
                lines.append(f"  File: {match.file_path}")
                lines.append(f"  Hash: {match.file_hash}")
                lines.append(f"  Size: {match.file_size} bytes")

                if match.meta:
                    lines.append("  Metadata:")
                    for key, value in match.meta.items():
                        lines.append(f"    {key}: {value}")

                if match.tags:
                    lines.append(f"  Tags: {', '.join(match.tags)}")

                if match.strings:
                    lines.append("  Matched Strings:")
                    for s in match.strings[:5]:  # Limit to first 5
                        lines.append(f"    0x{s['offset']:08x}: {s['identifier']} = {s['data_preview']}")
                    if len(match.strings) > 5:
                        lines.append(f"    ... and {len(match.strings) - 5} more")

        if result.errors:
            lines.append("\n" + "-" * 60)
            lines.append("ERRORS")
            lines.append("-" * 60)
            for error in result.errors:
                lines.append(f"  [{error['type']}] {error.get('file', 'N/A')}: {error['message']}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)


def generate_plan() -> Dict[str, Any]:
    """Generate a scan plan showing what would be done"""
    script_dir = Path(__file__).parent
    rules_dir = script_dir / "rules"

    plan = {
        "action": "YARA Scan Plan",
        "timestamp": datetime.datetime.now().isoformat(),
        "rules_directory": str(rules_dir),
        "rules_files": [],
        "total_rules_estimated": 0,
        "capabilities": [
            "File scanning with pattern matching",
            "Directory recursive scanning",
            "Process memory scanning (requires elevated privileges)",
            "Raw data/bytes scanning",
            "Multiple output formats (JSON, CSV, TEXT)"
        ],
        "rule_categories": [],
        "usage_examples": [
            "yara_scanner.py --file /path/to/suspicious.exe",
            "yara_scanner.py --directory /path/to/scan --recursive",
            "yara_scanner.py --process 1234",
            "yara_scanner.py --file sample.exe --format json --output results.json"
        ]
    }

    if rules_dir.exists():
        for yar_file in rules_dir.glob("**/*.yar"):
            plan["rules_files"].append(str(yar_file))
            plan["rule_categories"].append(yar_file.stem)
            # Estimate rule count by counting 'rule ' occurrences
            try:
                content = yar_file.read_text()
                plan["total_rules_estimated"] += content.count("\nrule ")
            except Exception:
                pass

    return plan


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="YARA Scanner - Educational CTF/Training Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file sample.exe
  %(prog)s --directory ./samples --recursive
  %(prog)s --process 1234
  %(prog)s --file sample.exe --format json --output results.json
  %(prog)s --plan
        """
    )

    # Scan targets (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-f", "--file",
        help="File to scan"
    )
    target_group.add_argument(
        "-d", "--directory",
        help="Directory to scan"
    )
    target_group.add_argument(
        "-p", "--process",
        type=int,
        help="Process ID to scan (requires elevated privileges)"
    )
    target_group.add_argument(
        "--plan",
        action="store_true",
        help="Show scan plan without executing"
    )

    # Rules options
    parser.add_argument(
        "-r", "--rules",
        help="Rules directory or file (default: ./rules)"
    )

    # Scan options
    parser.add_argument(
        "--recursive",
        action="store_true",
        default=True,
        help="Recursively scan directories (default: True)"
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Don't recursively scan directories"
    )

    # Output options
    parser.add_argument(
        "--format",
        choices=["json", "text", "csv"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and informational messages"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output including all matched strings"
    )

    args = parser.parse_args()

    # Handle plan mode
    if args.plan:
        plan = generate_plan()
        print(json.dumps(plan, indent=2))
        return 0

    # Require a scan target
    if not any([args.file, args.directory, args.process]):
        parser.print_help()
        print("\nError: No scan target specified. Use --file, --directory, --process, or --plan")
        return 1

    # Print banner unless quiet
    if not args.quiet:
        print("""
╔═══════════════════════════════════════════════════════════╗
║  YARA Scanner - Detection Engineering Toolkit             ║
║  Educational/CTF Training Resource                        ║
╚═══════════════════════════════════════════════════════════╝
""")

    # Determine rules path
    script_dir = Path(__file__).parent
    if args.rules:
        rules_path = args.rules
    else:
        rules_path = script_dir / "rules"

    # Initialize scanner
    try:
        if Path(rules_path).is_dir():
            scanner = YaraScanner(rules_dir=str(rules_path))
        else:
            scanner = YaraScanner(rules_file=str(rules_path))

        if not args.quiet:
            print(f"[*] Loaded {scanner.rules_count} rule file(s)")
    except Exception as e:
        print(f"[!] Error loading rules: {e}", file=sys.stderr)
        return 1

    # Perform scan based on target type
    try:
        if args.file:
            if not args.quiet:
                print(f"[*] Scanning file: {args.file}")
            matches = scanner.scan_file(args.file)
            result = ScanResult(
                scan_time=datetime.datetime.now().isoformat(),
                total_files=1,
                files_with_matches=1 if matches else 0,
                total_matches=len(matches),
                matches=matches,
                errors=scanner.errors,
                rules_loaded=scanner.rules_count,
                scan_mode="file"
            )

        elif args.directory:
            if not args.quiet:
                print(f"[*] Scanning directory: {args.directory}")
            recursive = not args.no_recursive
            result = scanner.scan_directory(args.directory, recursive=recursive)

        elif args.process:
            if not args.quiet:
                print(f"[*] Scanning process: {args.process}")
            matches = scanner.scan_process(args.process)
            result = ScanResult(
                scan_time=datetime.datetime.now().isoformat(),
                total_files=1,
                files_with_matches=1 if matches else 0,
                total_matches=len(matches),
                matches=matches,
                errors=scanner.errors,
                rules_loaded=scanner.rules_count,
                scan_mode="process"
            )

        else:
            print("[!] No valid scan target", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"[!] Scan error: {e}", file=sys.stderr)
        return 1

    # Format and output results
    output_format = OutputFormat(args.format)
    formatted = format_output(result, output_format)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(formatted)
        if not args.quiet:
            print(f"[*] Results written to: {args.output}")
    else:
        print(formatted)

    # Return exit code based on matches
    return 0 if result.total_matches == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
