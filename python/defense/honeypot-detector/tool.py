#!/usr/bin/env python3
"""
Honeypot Detector - Defensive Security Tool
Detect honeypots and deception technologies in network environments.

Author: Defensive Security Toolsmith
Category: Defense - Deception Detection
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from abc import ABC, abstractmethod


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class HoneypotIndicator:
    """Represents a honeypot indicator."""
    indicator_type: str  # banner, timing, service, behavior, network
    name: str
    description: str
    confidence: str  # LOW, MEDIUM, HIGH
    evidence: str
    target: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_type": self.indicator_type,
            "name": self.name,
            "description": self.description,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "target": self.target,
        }


@dataclass
class TargetAnalysis:
    """Analysis results for a single target."""
    target: str
    port: int
    service: str
    indicators: List[HoneypotIndicator]
    honeypot_probability: float  # 0.0 to 1.0
    analysis_time: datetime

    @property
    def is_likely_honeypot(self) -> bool:
        return self.honeypot_probability >= 0.6

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "indicators": [i.to_dict() for i in self.indicators],
            "honeypot_probability": self.honeypot_probability,
            "is_likely_honeypot": self.is_likely_honeypot,
            "analysis_time": self.analysis_time.isoformat(),
        }


@dataclass
class DetectionResult:
    """Complete detection result."""
    targets_analyzed: int
    honeypots_detected: int
    analyses: List[TargetAnalysis]
    start_time: datetime
    end_time: datetime
    summary: str

    @property
    def duration(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets_analyzed": self.targets_analyzed,
            "honeypots_detected": self.honeypots_detected,
            "analyses": [a.to_dict() for a in self.analyses],
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration,
            "summary": self.summary,
        }


# ============================================================================
# Detection Techniques
# ============================================================================

class DetectionTechnique(ABC):
    """Abstract base class for detection techniques."""

    @abstractmethod
    def analyze(self, target: str, port: int, service_info: Dict[str, Any]) -> List[HoneypotIndicator]:
        """Analyze target for honeypot indicators."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return technique name."""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Return technique description."""
        pass


class BannerAnalyzer(DetectionTechnique):
    """Analyze service banners for honeypot signatures."""

    # Known honeypot banner patterns
    HONEYPOT_PATTERNS = {
        # Cowrie SSH honeypot
        r'SSH-2\.0-OpenSSH_\d+\.\d+p\d+ Debian': ('cowrie_possible', 'MEDIUM'),
        r'SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u\d+': ('cowrie', 'HIGH'),

        # Kippo SSH honeypot
        r'SSH-2\.0-OpenSSH_5\.1p1 Debian-5': ('kippo', 'HIGH'),
        r'SSH-1\.99-OpenSSH_5\.1p1 Debian-5': ('kippo', 'HIGH'),

        # Dionaea
        r'Microsoft FTP Service': ('dionaea_ftp', 'MEDIUM'),

        # HoneyD
        r'honeyd': ('honeyd', 'HIGH'),

        # Generic suspicious patterns
        r'Welcome to.*honey': ('generic_honey', 'HIGH'),
        r'Ubuntu 12\.04': ('old_os', 'MEDIUM'),
        r'Debian 7': ('old_os', 'MEDIUM'),

        # Too perfect version strings
        r'^220 ProFTPD 1\.3\.5 Server': ('perfect_version', 'LOW'),
    }

    def analyze(self, target: str, port: int, service_info: Dict[str, Any]) -> List[HoneypotIndicator]:
        indicators = []
        banner = service_info.get('banner', '')

        if not banner:
            return indicators

        for pattern, (name, confidence) in self.HONEYPOT_PATTERNS.items():
            if re.search(pattern, banner, re.IGNORECASE):
                indicators.append(HoneypotIndicator(
                    indicator_type="banner",
                    name=name,
                    description=f"Banner matches known honeypot pattern: {pattern}",
                    confidence=confidence,
                    evidence=banner[:200],
                    target=f"{target}:{port}",
                ))

        # Check for anomalous banner characteristics
        if self._check_banner_anomalies(banner):
            indicators.append(HoneypotIndicator(
                indicator_type="banner",
                name="anomalous_banner",
                description="Banner has unusual characteristics",
                confidence="LOW",
                evidence=banner[:200],
                target=f"{target}:{port}",
            ))

        return indicators

    def _check_banner_anomalies(self, banner: str) -> bool:
        """Check for banner anomalies."""
        # Very old versions still in use
        old_versions = ['5.1p1', '5.5p1', '5.9p1', '6.0p1']
        for ver in old_versions:
            if ver in banner:
                return True

        # Inconsistent OS information
        if 'Debian' in banner and 'Ubuntu' in banner:
            return True

        return False

    def get_name(self) -> str:
        return "banner_analysis"

    def get_description(self) -> str:
        return "Analyze service banners for honeypot signatures"


class TimingAnalyzer(DetectionTechnique):
    """Analyze response timing for honeypot indicators."""

    def analyze(self, target: str, port: int, service_info: Dict[str, Any]) -> List[HoneypotIndicator]:
        indicators = []

        response_time = service_info.get('response_time_ms', 0)
        connection_time = service_info.get('connection_time_ms', 0)

        # Extremely fast responses can indicate honeypots
        if response_time > 0 and response_time < 5:
            indicators.append(HoneypotIndicator(
                indicator_type="timing",
                name="instant_response",
                description=f"Suspiciously fast response time: {response_time}ms",
                confidence="LOW",
                evidence=f"Response time: {response_time}ms",
                target=f"{target}:{port}",
            ))

        # Very consistent timing can indicate simulation
        timing_variance = service_info.get('timing_variance', -1)
        if timing_variance >= 0 and timing_variance < 0.5:
            indicators.append(HoneypotIndicator(
                indicator_type="timing",
                name="consistent_timing",
                description="Responses have unusually consistent timing",
                confidence="MEDIUM",
                evidence=f"Timing variance: {timing_variance}",
                target=f"{target}:{port}",
            ))

        return indicators

    def get_name(self) -> str:
        return "timing_analysis"

    def get_description(self) -> str:
        return "Analyze response timing patterns"


class ServiceBehaviorAnalyzer(DetectionTechnique):
    """Analyze service behavior for honeypot indicators."""

    def analyze(self, target: str, port: int, service_info: Dict[str, Any]) -> List[HoneypotIndicator]:
        indicators = []

        # Check for services on unusual ports
        unusual_mappings = {
            22: ['http', 'ftp'],
            80: ['ssh', 'telnet'],
            443: ['ssh', 'telnet'],
            21: ['ssh', 'http'],
        }

        detected_service = service_info.get('service', '').lower()
        if port in unusual_mappings and detected_service in unusual_mappings[port]:
            indicators.append(HoneypotIndicator(
                indicator_type="behavior",
                name="unusual_port_service",
                description=f"Service '{detected_service}' on unusual port {port}",
                confidence="MEDIUM",
                evidence=f"Expected typical service, found {detected_service}",
                target=f"{target}:{port}",
            ))

        # Check for too many open ports
        open_ports = service_info.get('other_open_ports', [])
        if len(open_ports) > 50:
            indicators.append(HoneypotIndicator(
                indicator_type="behavior",
                name="many_open_ports",
                description=f"Target has {len(open_ports)} open ports",
                confidence="HIGH",
                evidence=f"Open ports: {len(open_ports)}",
                target=target,
            ))

        # Check for services that accept any input
        accepts_anything = service_info.get('accepts_any_credentials', False)
        if accepts_anything:
            indicators.append(HoneypotIndicator(
                indicator_type="behavior",
                name="accepts_any_input",
                description="Service accepts invalid/any credentials",
                confidence="HIGH",
                evidence="Service accepted test credentials",
                target=f"{target}:{port}",
            ))

        return indicators

    def get_name(self) -> str:
        return "service_behavior"

    def get_description(self) -> str:
        return "Analyze service behavior patterns"


class NetworkAnalyzer(DetectionTechnique):
    """Analyze network characteristics for honeypot indicators."""

    # Known honeypot hosting ranges (example - not real data)
    KNOWN_HONEYPOT_ASNS = {
        'AS-HONEYPOT-RESEARCH',
    }

    def analyze(self, target: str, port: int, service_info: Dict[str, Any]) -> List[HoneypotIndicator]:
        indicators = []

        # Check TTL anomalies
        ttl = service_info.get('ttl', 0)
        if ttl > 0:
            # Common OS TTL values: 64 (Linux), 128 (Windows), 255 (Cisco)
            if ttl not in [64, 128, 255] and ttl not in range(55, 70) and ttl not in range(120, 135):
                indicators.append(HoneypotIndicator(
                    indicator_type="network",
                    name="unusual_ttl",
                    description=f"Unusual TTL value: {ttl}",
                    confidence="LOW",
                    evidence=f"TTL: {ttl}",
                    target=target,
                ))

        # Check for multiple services with identical fingerprints
        service_fingerprints = service_info.get('service_fingerprints', [])
        if len(service_fingerprints) > 1:
            unique_fps = set(service_fingerprints)
            if len(unique_fps) == 1 and len(service_fingerprints) > 3:
                indicators.append(HoneypotIndicator(
                    indicator_type="network",
                    name="identical_fingerprints",
                    description="Multiple services have identical fingerprints",
                    confidence="HIGH",
                    evidence=f"All {len(service_fingerprints)} services have same fingerprint",
                    target=target,
                ))

        return indicators

    def get_name(self) -> str:
        return "network_analysis"

    def get_description(self) -> str:
        return "Analyze network-level characteristics"


class KnownHoneypotDetector(DetectionTechnique):
    """Detect known honeypot software signatures."""

    # Signatures for known honeypot software
    HONEYPOT_SIGNATURES = {
        'cowrie': {
            'patterns': [
                r'cowrie',
                r'kippo-data',
            ],
            'ports': [2222, 2223],
            'confidence': 'HIGH',
        },
        'kippo': {
            'patterns': [
                r'kippo',
                r'twisted\.conch',
            ],
            'ports': [2222],
            'confidence': 'HIGH',
        },
        'dionaea': {
            'patterns': [
                r'dionaea',
            ],
            'ports': [21, 42, 135, 445, 1433, 3306],
            'confidence': 'HIGH',
        },
        'glastopf': {
            'patterns': [
                r'glastopf',
            ],
            'ports': [80, 8080],
            'confidence': 'HIGH',
        },
        'conpot': {
            'patterns': [
                r'conpot',
            ],
            'ports': [102, 161, 502],
            'confidence': 'HIGH',
        },
        'honeyd': {
            'patterns': [
                r'honeyd',
            ],
            'ports': [],  # Can be any port
            'confidence': 'HIGH',
        },
    }

    def analyze(self, target: str, port: int, service_info: Dict[str, Any]) -> List[HoneypotIndicator]:
        indicators = []
        banner = service_info.get('banner', '').lower()
        response = service_info.get('response', '').lower()

        for honeypot_name, signature in self.HONEYPOT_SIGNATURES.items():
            # Check patterns
            for pattern in signature['patterns']:
                if re.search(pattern, banner, re.IGNORECASE) or \
                   re.search(pattern, response, re.IGNORECASE):
                    indicators.append(HoneypotIndicator(
                        indicator_type="signature",
                        name=f"known_{honeypot_name}",
                        description=f"Detected {honeypot_name} honeypot signature",
                        confidence=signature['confidence'],
                        evidence=f"Pattern match: {pattern}",
                        target=f"{target}:{port}",
                    ))

            # Check characteristic ports
            if signature['ports'] and port in signature['ports']:
                # Lower confidence just for port match
                indicators.append(HoneypotIndicator(
                    indicator_type="signature",
                    name=f"possible_{honeypot_name}",
                    description=f"Port {port} is commonly used by {honeypot_name}",
                    confidence="LOW",
                    evidence=f"Port {port} matches {honeypot_name} default",
                    target=f"{target}:{port}",
                ))

        return indicators

    def get_name(self) -> str:
        return "known_honeypot"

    def get_description(self) -> str:
        return "Detect known honeypot software signatures"


# ============================================================================
# Service Probing
# ============================================================================

class ServiceProber:
    """Probe services to gather information for analysis."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def probe(self, target: str, port: int) -> Dict[str, Any]:
        """Probe a service and gather information."""
        info = {
            'target': target,
            'port': port,
            'banner': '',
            'response': '',
            'service': '',
            'connection_time_ms': 0,
            'response_time_ms': 0,
            'error': None,
        }

        try:
            start_time = datetime.now()

            # Attempt connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            connect_start = datetime.now()
            sock.connect((target, port))
            connect_end = datetime.now()

            info['connection_time_ms'] = (connect_end - connect_start).total_seconds() * 1000

            # Try to receive banner
            sock.settimeout(2.0)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                info['banner'] = banner.strip()
                info['response_time_ms'] = (datetime.now() - connect_end).total_seconds() * 1000
            except socket.timeout:
                pass

            # Detect service type
            info['service'] = self._identify_service(port, info['banner'])

            sock.close()

        except socket.timeout:
            info['error'] = 'Connection timeout'
        except ConnectionRefusedError:
            info['error'] = 'Connection refused'
        except Exception as e:
            info['error'] = str(e)

        return info

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service type from port and banner."""
        # Common port mappings
        port_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            80: 'http',
            443: 'https',
            3306: 'mysql',
            5432: 'postgresql',
            6379: 'redis',
            27017: 'mongodb',
        }

        if port in port_services:
            return port_services[port]

        # Check banner for service hints
        banner_lower = banner.lower()
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower:
            return 'smtp'
        elif 'http' in banner_lower:
            return 'http'
        elif 'mysql' in banner_lower:
            return 'mysql'

        return 'unknown'

    def quick_port_scan(self, target: str, ports: List[int]) -> List[int]:
        """Quick scan to find open ports."""
        open_ports = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass

        return open_ports


# ============================================================================
# Main Honeypot Detector
# ============================================================================

class HoneypotDetector:
    """Main honeypot detection engine."""

    def __init__(self, timeout: float = 5.0):
        self.prober = ServiceProber(timeout)
        self.techniques: List[DetectionTechnique] = [
            BannerAnalyzer(),
            TimingAnalyzer(),
            ServiceBehaviorAnalyzer(),
            NetworkAnalyzer(),
            KnownHoneypotDetector(),
        ]

    def analyze_target(self, target: str, port: int) -> TargetAnalysis:
        """Analyze a single target for honeypot indicators."""
        # Probe the service
        service_info = self.prober.probe(target, port)

        # Run all detection techniques
        all_indicators = []
        for technique in self.techniques:
            indicators = technique.analyze(target, port, service_info)
            all_indicators.extend(indicators)

        # Calculate honeypot probability
        probability = self._calculate_probability(all_indicators)

        return TargetAnalysis(
            target=target,
            port=port,
            service=service_info.get('service', 'unknown'),
            indicators=all_indicators,
            honeypot_probability=probability,
            analysis_time=datetime.now(),
        )

    def _calculate_probability(self, indicators: List[HoneypotIndicator]) -> float:
        """Calculate honeypot probability from indicators."""
        if not indicators:
            return 0.0

        # Weight by confidence
        confidence_weights = {
            'LOW': 0.1,
            'MEDIUM': 0.3,
            'HIGH': 0.5,
        }

        total_weight = 0.0
        for indicator in indicators:
            total_weight += confidence_weights.get(indicator.confidence, 0.1)

        # Cap at 0.95
        probability = min(total_weight, 0.95)

        return probability

    def detect(self, targets: List[Tuple[str, int]]) -> DetectionResult:
        """Run detection on multiple targets."""
        start_time = datetime.now()
        analyses = []
        honeypots_detected = 0

        for target, port in targets:
            analysis = self.analyze_target(target, port)
            analyses.append(analysis)

            if analysis.is_likely_honeypot:
                honeypots_detected += 1

        end_time = datetime.now()

        # Generate summary
        summary = self._generate_summary(analyses, honeypots_detected)

        return DetectionResult(
            targets_analyzed=len(targets),
            honeypots_detected=honeypots_detected,
            analyses=analyses,
            start_time=start_time,
            end_time=end_time,
            summary=summary,
        )

    def _generate_summary(self, analyses: List[TargetAnalysis], honeypots: int) -> str:
        """Generate detection summary."""
        total = len(analyses)
        return (
            f"Analyzed {total} target(s). "
            f"Detected {honeypots} likely honeypot(s). "
            f"Found {sum(len(a.indicators) for a in analyses)} total indicators."
        )

    def get_plan(self, targets: List[Tuple[str, int]], output_format: str) -> str:
        """Generate planning mode output."""
        plan = []
        plan.append("")
        plan.append("[PLAN MODE] Tool: honeypot-detector")
        plan.append("=" * 50)
        plan.append("")
        plan.append("Actions to be performed:")
        plan.append("")
        plan.append(f"  1. Analyze {len(targets)} target(s):")
        for target, port in targets[:5]:
            plan.append(f"     - {target}:{port}")
        if len(targets) > 5:
            plan.append(f"     - ... and {len(targets) - 5} more")

        plan.append("")
        plan.append("  2. Apply detection techniques:")
        for i, technique in enumerate(self.techniques, 1):
            plan.append(f"     {i}. {technique.get_name()}")
            plan.append(f"        {technique.get_description()}")

        plan.append("")
        plan.append("  3. Calculate honeypot probability")
        plan.append(f"  4. Generate report in {output_format} format")

        plan.append("")
        plan.append("Detection methods:")
        plan.append("  - Banner signature analysis")
        plan.append("  - Response timing analysis")
        plan.append("  - Service behavior analysis")
        plan.append("  - Network characteristic analysis")
        plan.append("  - Known honeypot fingerprinting")

        plan.append("")
        plan.append("Risk Assessment: LOW (passive analysis)")
        plan.append("Detection Vectors: Network connections, banner grabbing")
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
        "name": "honeypot-detector",
        "category": "Defense - Deception Detection",
        "version": "1.0.0",
        "author": "Defensive Security Toolsmith",
        "description": "Detect honeypots and deception technologies in network environments",
        "features": [
            "Banner signature analysis",
            "Response timing analysis",
            "Service behavior analysis",
            "Network characteristic analysis",
            "Known honeypot fingerprinting",
            "Probability-based detection",
            "Multiple output formats",
        ],
        "detection_techniques": [
            {"name": "banner_analysis", "description": "Analyze service banners for honeypot signatures"},
            {"name": "timing_analysis", "description": "Analyze response timing patterns"},
            {"name": "service_behavior", "description": "Analyze service behavior patterns"},
            {"name": "network_analysis", "description": "Analyze network-level characteristics"},
            {"name": "known_honeypot", "description": "Detect known honeypot software signatures"},
        ],
        "known_honeypots": ["cowrie", "kippo", "dionaea", "glastopf", "conpot", "honeyd"],
        "usage_examples": [
            "python tool.py --plan --target 192.168.1.100 --port 22",
            "python tool.py --target 192.168.1.100 --port 22",
            "python tool.py --targets targets.txt --output json",
            "python tool.py --target 10.0.0.1 --ports 22,80,443",
        ],
        "arguments": {
            "--plan, -p": "Show execution plan without running detection",
            "--target, -t": "Single target IP/hostname",
            "--port": "Single port to analyze",
            "--ports": "Comma-separated list of ports",
            "--targets": "File with target:port pairs",
            "--output, -o": "Output format (text, json)",
            "--timeout": "Connection timeout in seconds",
        },
        "legal_notice": "This tool is for authorized security testing only.",
    }


# ============================================================================
# Output Formatters
# ============================================================================

def format_output_text(result: DetectionResult) -> str:
    """Format detection result as human-readable text."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  HONEYPOT DETECTION REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Summary: {result.summary}")
    lines.append(f"Duration: {result.duration:.2f} seconds")
    lines.append("")

    for analysis in result.analyses:
        lines.append("-" * 60)
        lines.append(f"Target: {analysis.target}:{analysis.port}")
        lines.append(f"Service: {analysis.service}")
        lines.append(f"Honeypot Probability: {analysis.honeypot_probability:.1%}")

        if analysis.is_likely_honeypot:
            lines.append("Status: LIKELY HONEYPOT")
        else:
            lines.append("Status: Probably legitimate")

        if analysis.indicators:
            lines.append("")
            lines.append("Indicators found:")
            for indicator in analysis.indicators:
                lines.append(f"  [{indicator.confidence}] {indicator.name}")
                lines.append(f"    Type: {indicator.indicator_type}")
                lines.append(f"    Description: {indicator.description}")
                if indicator.evidence:
                    evidence_preview = indicator.evidence[:100]
                    lines.append(f"    Evidence: {evidence_preview}...")
        else:
            lines.append("")
            lines.append("No honeypot indicators found.")

        lines.append("")

    lines.append("=" * 60)
    lines.append("")
    lines.append("Detection Summary:")
    lines.append(f"  Targets analyzed: {result.targets_analyzed}")
    lines.append(f"  Likely honeypots: {result.honeypots_detected}")
    lines.append(f"  Clean targets: {result.targets_analyzed - result.honeypots_detected}")

    lines.append("")
    lines.append("=" * 60)

    return '\n'.join(lines)


def format_output_json(result: DetectionResult) -> str:
    """Format detection result as JSON."""
    return json.dumps(result.to_dict(), indent=2)


# ============================================================================
# CLI Interface
# ============================================================================

def parse_targets(args) -> List[Tuple[str, int]]:
    """Parse targets from command line arguments."""
    targets = []

    if args.targets_file:
        # Read from file
        try:
            with open(args.targets_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            host, port = line.rsplit(':', 1)
                            targets.append((host, int(port)))
                        else:
                            # Default to port 22
                            targets.append((line, 22))
        except FileNotFoundError:
            print(f"Error: File not found: {args.targets_file}", file=sys.stderr)
            sys.exit(1)
    elif args.target:
        # Single target
        if args.ports:
            # Multiple ports
            for port in args.ports.split(','):
                targets.append((args.target, int(port.strip())))
        else:
            # Single port
            targets.append((args.target, args.port))

    return targets


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Honeypot Detector - Detect honeypots and deception technologies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --plan --target 192.168.1.100 --port 22
  %(prog)s --target 192.168.1.100 --port 22
  %(prog)s --target 10.0.0.1 --ports 22,80,443
  %(prog)s --targets targets.txt --output json

Target file format (one per line):
  192.168.1.100:22
  192.168.1.101:80
  # Comment lines start with #
        """
    )

    parser.add_argument(
        '--plan', '-p',
        action='store_true',
        help='Show execution plan without running detection'
    )

    parser.add_argument(
        '--target', '-t',
        help='Single target IP or hostname'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=22,
        help='Single port to analyze (default: 22)'
    )

    parser.add_argument(
        '--ports',
        help='Comma-separated list of ports to analyze'
    )

    parser.add_argument(
        '--targets',
        dest='targets_file',
        help='File containing target:port pairs'
    )

    parser.add_argument(
        '--output', '-o',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )

    parser.add_argument(
        '--timeout',
        type=float,
        default=5.0,
        help='Connection timeout in seconds (default: 5.0)'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress informational output'
    )

    args = parser.parse_args()

    # Parse targets
    targets = parse_targets(args)

    if not targets and not args.plan:
        parser.print_help()
        print("\nError: At least one target is required", file=sys.stderr)
        return 1

    detector = HoneypotDetector(timeout=args.timeout)

    # Planning mode
    if args.plan:
        if not targets:
            targets = [('example.com', 22)]  # Placeholder for plan
        print(detector.get_plan(targets, args.output))
        return 0

    # Execute detection
    if not args.quiet:
        print(f"Analyzing {len(targets)} target(s)...", file=sys.stderr)

    result = detector.detect(targets)

    # Output results
    if args.output == 'json':
        print(format_output_json(result))
    else:
        print(format_output_text(result))

    # Return non-zero if honeypots detected
    return 1 if result.honeypots_detected > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
