#!/usr/bin/env python3
"""
Log Analyzer - Defensive Security Tool
Parse and analyze security logs for suspicious patterns and anomalies.

Author: Defensive Security Toolsmith
Category: Defense - Log Analysis
"""

import argparse
import re
import sys
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
from abc import ABC, abstractmethod
import ipaddress


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class LogEntry:
    """Represents a parsed log entry."""
    timestamp: Optional[datetime]
    source_ip: Optional[str]
    user: Optional[str]
    action: str
    message: str
    severity: str = "INFO"
    raw_line: str = ""
    line_number: int = 0
    log_format: str = "unknown"


@dataclass
class Alert:
    """Represents a security alert."""
    rule_name: str
    severity: str
    description: str
    evidence: List[str]
    timestamp: datetime
    source_ips: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class AnalysisResult:
    """Complete analysis result."""
    total_entries: int
    parsed_entries: int
    alerts: List[Alert]
    statistics: Dict[str, Any]
    timespan: Tuple[Optional[datetime], Optional[datetime]]
    summary: str


# ============================================================================
# Log Parsers
# ============================================================================

class LogParser(ABC):
    """Abstract base class for log parsers."""

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> Optional[LogEntry]:
        """Parse a single log line."""
        pass

    @abstractmethod
    def get_format_name(self) -> str:
        """Return the format name."""
        pass


class SyslogParser(LogParser):
    """Parser for syslog format logs."""

    # Standard syslog pattern: Mon DD HH:MM:SS hostname process[pid]: message
    PATTERN = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )

    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    def parse_line(self, line: str, line_number: int) -> Optional[LogEntry]:
        match = self.PATTERN.match(line.strip())
        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp (assume current year)
        try:
            month = self.MONTHS.get(groups['month'], 1)
            day = int(groups['day'])
            time_parts = groups['time'].split(':')
            timestamp = datetime(
                datetime.now().year, month, day,
                int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
            )
        except (ValueError, IndexError):
            timestamp = None

        # Extract IP addresses from message
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = ip_pattern.findall(groups['message'])
        source_ip = ips[0] if ips else None

        # Extract user from message
        user_patterns = [
            r'user[=:\s]+(\S+)',
            r'for\s+(\S+)\s+from',
            r'session\s+\w+\s+for\s+user\s+(\S+)',
        ]
        user = None
        for pattern in user_patterns:
            user_match = re.search(pattern, groups['message'], re.IGNORECASE)
            if user_match:
                user = user_match.group(1)
                break

        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            user=user,
            action=groups['process'],
            message=groups['message'],
            raw_line=line,
            line_number=line_number,
            log_format="syslog"
        )

    def get_format_name(self) -> str:
        return "syslog"


class AuthLogParser(LogParser):
    """Parser for authentication logs (auth.log, secure)."""

    # Extends syslog with auth-specific patterns
    SYSLOG_PATTERN = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )

    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    # Authentication event patterns
    AUTH_PATTERNS = {
        'failed_login': re.compile(r'Failed\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)', re.IGNORECASE),
        'successful_login': re.compile(r'Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)', re.IGNORECASE),
        'invalid_user': re.compile(r'Invalid\s+user\s+(\S+)\s+from\s+(\S+)', re.IGNORECASE),
        'session_opened': re.compile(r'session\s+opened\s+for\s+user\s+(\S+)', re.IGNORECASE),
        'session_closed': re.compile(r'session\s+closed\s+for\s+user\s+(\S+)', re.IGNORECASE),
        'sudo_command': re.compile(r'(\S+)\s*:\s*.*COMMAND=(.+)$', re.IGNORECASE),
    }

    def parse_line(self, line: str, line_number: int) -> Optional[LogEntry]:
        match = self.SYSLOG_PATTERN.match(line.strip())
        if not match:
            return None

        groups = match.groupdict()
        message = groups['message']

        # Parse timestamp
        try:
            month = self.MONTHS.get(groups['month'], 1)
            day = int(groups['day'])
            time_parts = groups['time'].split(':')
            timestamp = datetime(
                datetime.now().year, month, day,
                int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
            )
        except (ValueError, IndexError):
            timestamp = None

        # Determine action and extract details
        action = groups['process']
        source_ip = None
        user = None
        severity = "INFO"

        for event_type, pattern in self.AUTH_PATTERNS.items():
            event_match = pattern.search(message)
            if event_match:
                action = event_type
                if event_type in ['failed_login', 'successful_login', 'invalid_user']:
                    user = event_match.group(1)
                    source_ip = event_match.group(2)
                    if event_type == 'failed_login':
                        severity = "WARNING"
                    elif event_type == 'invalid_user':
                        severity = "WARNING"
                elif event_type in ['session_opened', 'session_closed']:
                    user = event_match.group(1)
                elif event_type == 'sudo_command':
                    user = event_match.group(1)
                break

        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            user=user,
            action=action,
            message=message,
            severity=severity,
            raw_line=line,
            line_number=line_number,
            log_format="auth"
        )

    def get_format_name(self) -> str:
        return "auth"


class ApacheLogParser(LogParser):
    """Parser for Apache access logs (Combined Log Format)."""

    # Combined Log Format: IP - user [timestamp] "request" status size "referer" "user-agent"
    PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
    )

    def parse_line(self, line: str, line_number: int) -> Optional[LogEntry]:
        match = self.PATTERN.match(line.strip())
        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp: DD/Mon/YYYY:HH:MM:SS +ZZZZ
        try:
            ts_str = groups['timestamp'].split()[0]  # Remove timezone
            timestamp = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S')
        except (ValueError, IndexError):
            timestamp = None

        # Determine severity based on status code
        status = int(groups['status'])
        if status >= 500:
            severity = "ERROR"
        elif status >= 400:
            severity = "WARNING"
        else:
            severity = "INFO"

        user = groups['user'] if groups['user'] != '-' else None

        return LogEntry(
            timestamp=timestamp,
            source_ip=groups['ip'],
            user=user,
            action=f"HTTP_{status}",
            message=groups['request'],
            severity=severity,
            raw_line=line,
            line_number=line_number,
            log_format="apache"
        )

    def get_format_name(self) -> str:
        return "apache"


class NginxLogParser(LogParser):
    """Parser for Nginx access logs."""

    # Similar to Apache combined format
    PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'-\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
    )

    def parse_line(self, line: str, line_number: int) -> Optional[LogEntry]:
        match = self.PATTERN.match(line.strip())
        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp
        try:
            ts_str = groups['timestamp'].split()[0]
            timestamp = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S')
        except (ValueError, IndexError):
            timestamp = None

        status = int(groups['status'])
        if status >= 500:
            severity = "ERROR"
        elif status >= 400:
            severity = "WARNING"
        else:
            severity = "INFO"

        user = groups['user'] if groups['user'] != '-' else None

        return LogEntry(
            timestamp=timestamp,
            source_ip=groups['ip'],
            user=user,
            action=f"HTTP_{status}",
            message=groups['request'],
            severity=severity,
            raw_line=line,
            line_number=line_number,
            log_format="nginx"
        )

    def get_format_name(self) -> str:
        return "nginx"


# ============================================================================
# Detection Rules
# ============================================================================

class DetectionRule(ABC):
    """Abstract base class for detection rules."""

    @abstractmethod
    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        """Analyze log entries and return alerts."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return the rule name."""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Return the rule description."""
        pass


class BruteForceDetector(DetectionRule):
    """Detect brute force login attempts."""

    def __init__(self, threshold: int = 5, window_minutes: int = 5):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        alerts = []

        # Group failed logins by source IP
        failed_by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.action == 'failed_login' and entry.source_ip:
                failed_by_ip[entry.source_ip].append(entry)

        for ip, failures in failed_by_ip.items():
            # Sort by timestamp
            failures.sort(key=lambda x: x.timestamp or datetime.min)

            # Sliding window detection
            window_failures = []
            for failure in failures:
                if failure.timestamp:
                    # Remove entries outside window
                    window_failures = [
                        f for f in window_failures
                        if f.timestamp and (failure.timestamp - f.timestamp) <= self.window
                    ]
                    window_failures.append(failure)

                    if len(window_failures) >= self.threshold:
                        affected_users = list(set(
                            f.user for f in window_failures if f.user
                        ))
                        alerts.append(Alert(
                            rule_name=self.get_name(),
                            severity="HIGH",
                            description=f"Brute force attack detected from {ip}: "
                                       f"{len(window_failures)} failed attempts in {self.window.seconds // 60} minutes",
                            evidence=[f.raw_line for f in window_failures[:5]],
                            timestamp=failure.timestamp,
                            source_ips=[ip],
                            affected_users=affected_users,
                            recommendation="Block the source IP and investigate affected accounts"
                        ))
                        window_failures = []  # Reset window after alert

        return alerts

    def get_name(self) -> str:
        return "BRUTE_FORCE_DETECTION"

    def get_description(self) -> str:
        return f"Detects {self.threshold}+ failed login attempts from same IP within {self.window.seconds // 60} minutes"


class PasswordSprayDetector(DetectionRule):
    """Detect password spray attacks (same password against multiple users)."""

    def __init__(self, threshold: int = 10, window_minutes: int = 10):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        alerts = []

        # Group failed logins by source IP
        failed_by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.action == 'failed_login' and entry.source_ip:
                failed_by_ip[entry.source_ip].append(entry)

        for ip, failures in failed_by_ip.items():
            # Check for many unique users targeted from same IP
            failures.sort(key=lambda x: x.timestamp or datetime.min)

            window_failures = []
            for failure in failures:
                if failure.timestamp:
                    window_failures = [
                        f for f in window_failures
                        if f.timestamp and (failure.timestamp - f.timestamp) <= self.window
                    ]
                    window_failures.append(failure)

                    unique_users = set(f.user for f in window_failures if f.user)
                    if len(unique_users) >= self.threshold:
                        alerts.append(Alert(
                            rule_name=self.get_name(),
                            severity="CRITICAL",
                            description=f"Password spray attack detected from {ip}: "
                                       f"{len(unique_users)} unique users targeted",
                            evidence=[f.raw_line for f in window_failures[:5]],
                            timestamp=failure.timestamp,
                            source_ips=[ip],
                            affected_users=list(unique_users),
                            recommendation="Block source IP, reset passwords for targeted accounts, enable MFA"
                        ))
                        window_failures = []

        return alerts

    def get_name(self) -> str:
        return "PASSWORD_SPRAY_DETECTION"

    def get_description(self) -> str:
        return f"Detects attempts against {self.threshold}+ unique users from same IP within {self.window.seconds // 60} minutes"


class SuspiciousUserAgentDetector(DetectionRule):
    """Detect suspicious user agents in web logs."""

    SUSPICIOUS_PATTERNS = [
        r'sqlmap',
        r'nikto',
        r'nmap',
        r'masscan',
        r'dirbuster',
        r'gobuster',
        r'wfuzz',
        r'hydra',
        r'metasploit',
        r'curl.*libcurl',
        r'python-requests',
        r'wget',
        r'scanner',
        r'bot(?!.*google|.*bing|.*yahoo)',
    ]

    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_PATTERNS]

    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        alerts = []
        suspicious_by_ip: Dict[str, List[Tuple[LogEntry, str]]] = defaultdict(list)

        for entry in entries:
            if entry.log_format in ['apache', 'nginx']:
                # Extract user agent from raw line
                ua_match = re.search(r'"([^"]*)"$', entry.raw_line)
                if ua_match:
                    user_agent = ua_match.group(1)
                    for pattern in self.patterns:
                        if pattern.search(user_agent):
                            suspicious_by_ip[entry.source_ip].append((entry, user_agent))
                            break

        for ip, matches in suspicious_by_ip.items():
            if len(matches) >= 3:  # Multiple suspicious requests
                alerts.append(Alert(
                    rule_name=self.get_name(),
                    severity="MEDIUM",
                    description=f"Suspicious user agent detected from {ip}: {len(matches)} requests",
                    evidence=[m[0].raw_line for m in matches[:5]],
                    timestamp=matches[0][0].timestamp or datetime.now(),
                    source_ips=[ip],
                    recommendation="Investigate source IP for scanning/attack activity"
                ))

        return alerts

    def get_name(self) -> str:
        return "SUSPICIOUS_USER_AGENT"

    def get_description(self) -> str:
        return "Detects known malicious tools and suspicious user agents"


class SQLInjectionDetector(DetectionRule):
    """Detect SQL injection attempts in web logs."""

    SQLI_PATTERNS = [
        r"(?:'|\"|;|--|\#|/\*)",
        r"(?:union\s+select|select\s+.*\s+from)",
        r"(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
        r"(?:drop\s+table|truncate\s+table)",
        r"(?:insert\s+into|update\s+.*\s+set)",
        r"(?:exec\s*\(|execute\s*\()",
        r"(?:benchmark\s*\(|sleep\s*\()",
        r"(?:load_file\s*\(|into\s+outfile)",
    ]

    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.SQLI_PATTERNS]

    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        alerts = []
        sqli_by_ip: Dict[str, List[LogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.log_format in ['apache', 'nginx']:
                for pattern in self.patterns:
                    if pattern.search(entry.message):
                        sqli_by_ip[entry.source_ip].append(entry)
                        break

        for ip, matches in sqli_by_ip.items():
            alerts.append(Alert(
                rule_name=self.get_name(),
                severity="HIGH",
                description=f"SQL injection attempts detected from {ip}: {len(matches)} attempts",
                evidence=[m.raw_line for m in matches[:5]],
                timestamp=matches[0].timestamp or datetime.now(),
                source_ips=[ip],
                recommendation="Block source IP, review application WAF rules, check for successful exploitation"
            ))

        return alerts

    def get_name(self) -> str:
        return "SQL_INJECTION_ATTEMPT"

    def get_description(self) -> str:
        return "Detects SQL injection patterns in HTTP requests"


class PathTraversalDetector(DetectionRule):
    """Detect path traversal attempts."""

    TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e/',
        r'\.%2e/',
        r'%252e%252e%252f',
        r'/etc/passwd',
        r'/etc/shadow',
        r'c:\\windows',
        r'c:/windows',
    ]

    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.TRAVERSAL_PATTERNS]

    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        alerts = []
        traversal_by_ip: Dict[str, List[LogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.log_format in ['apache', 'nginx']:
                for pattern in self.patterns:
                    if pattern.search(entry.message):
                        traversal_by_ip[entry.source_ip].append(entry)
                        break

        for ip, matches in traversal_by_ip.items():
            alerts.append(Alert(
                rule_name=self.get_name(),
                severity="HIGH",
                description=f"Path traversal attempts detected from {ip}: {len(matches)} attempts",
                evidence=[m.raw_line for m in matches[:5]],
                timestamp=matches[0].timestamp or datetime.now(),
                source_ips=[ip],
                recommendation="Block source IP, verify no sensitive files were accessed"
            ))

        return alerts

    def get_name(self) -> str:
        return "PATH_TRAVERSAL_ATTEMPT"

    def get_description(self) -> str:
        return "Detects directory traversal attack patterns"


class PrivilegeEscalationDetector(DetectionRule):
    """Detect potential privilege escalation attempts."""

    SUSPICIOUS_COMMANDS = [
        r'sudo\s+su',
        r'sudo\s+-i',
        r'sudo\s+bash',
        r'sudo\s+sh',
        r'pkexec',
        r'/usr/bin/passwd',
        r'usermod.*-aG.*sudo',
        r'usermod.*-aG.*wheel',
        r'visudo',
        r'chmod\s+[0-7]*s',
        r'chown.*root',
    ]

    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_COMMANDS]

    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        alerts = []
        escalation_attempts: List[LogEntry] = []

        for entry in entries:
            if entry.log_format == 'auth':
                for pattern in self.patterns:
                    if pattern.search(entry.message):
                        escalation_attempts.append(entry)
                        break

        if escalation_attempts:
            users = list(set(e.user for e in escalation_attempts if e.user))
            alerts.append(Alert(
                rule_name=self.get_name(),
                severity="MEDIUM",
                description=f"Privilege escalation activity detected: {len(escalation_attempts)} events",
                evidence=[e.raw_line for e in escalation_attempts[:5]],
                timestamp=escalation_attempts[0].timestamp or datetime.now(),
                affected_users=users,
                recommendation="Review user activity and verify authorized privilege changes"
            ))

        return alerts

    def get_name(self) -> str:
        return "PRIVILEGE_ESCALATION"

    def get_description(self) -> str:
        return "Detects suspicious commands related to privilege escalation"


# ============================================================================
# Main Analyzer
# ============================================================================

class LogAnalyzer:
    """Main log analysis engine."""

    def __init__(self):
        self.parsers: Dict[str, LogParser] = {
            'syslog': SyslogParser(),
            'auth': AuthLogParser(),
            'apache': ApacheLogParser(),
            'nginx': NginxLogParser(),
        }

        self.rules: List[DetectionRule] = [
            BruteForceDetector(),
            PasswordSprayDetector(),
            SuspiciousUserAgentDetector(),
            SQLInjectionDetector(),
            PathTraversalDetector(),
            PrivilegeEscalationDetector(),
        ]

    def detect_format(self, sample_lines: List[str]) -> str:
        """Auto-detect log format from sample lines."""
        for line in sample_lines[:10]:
            for format_name, parser in self.parsers.items():
                if parser.parse_line(line, 0):
                    return format_name
        return 'syslog'  # Default fallback

    def parse_logs(self, log_content: str, log_format: Optional[str] = None) -> List[LogEntry]:
        """Parse log content into structured entries."""
        lines = log_content.strip().split('\n')

        if not log_format:
            log_format = self.detect_format(lines)

        parser = self.parsers.get(log_format, self.parsers['syslog'])
        entries = []

        for i, line in enumerate(lines, 1):
            if line.strip():
                entry = parser.parse_line(line, i)
                if entry:
                    entries.append(entry)

        return entries

    def analyze(self, entries: List[LogEntry]) -> AnalysisResult:
        """Run all detection rules against parsed entries."""
        all_alerts = []

        for rule in self.rules:
            alerts = rule.analyze(entries)
            all_alerts.extend(alerts)

        # Calculate statistics
        stats = self._calculate_statistics(entries)

        # Determine timespan
        timestamps = [e.timestamp for e in entries if e.timestamp]
        timespan = (min(timestamps), max(timestamps)) if timestamps else (None, None)

        # Generate summary
        summary = self._generate_summary(entries, all_alerts)

        return AnalysisResult(
            total_entries=len(entries),
            parsed_entries=len([e for e in entries if e.timestamp]),
            alerts=all_alerts,
            statistics=stats,
            timespan=timespan,
            summary=summary
        )

    def _calculate_statistics(self, entries: List[LogEntry]) -> Dict[str, Any]:
        """Calculate statistical metrics from log entries."""
        stats = {
            'by_severity': defaultdict(int),
            'by_action': defaultdict(int),
            'by_source_ip': defaultdict(int),
            'by_user': defaultdict(int),
            'by_format': defaultdict(int),
        }

        for entry in entries:
            stats['by_severity'][entry.severity] += 1
            stats['by_action'][entry.action] += 1
            stats['by_format'][entry.log_format] += 1
            if entry.source_ip:
                stats['by_source_ip'][entry.source_ip] += 1
            if entry.user:
                stats['by_user'][entry.user] += 1

        # Convert to regular dicts and sort
        return {
            'by_severity': dict(stats['by_severity']),
            'by_action': dict(sorted(stats['by_action'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'by_source_ip': dict(sorted(stats['by_source_ip'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'by_user': dict(sorted(stats['by_user'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'by_format': dict(stats['by_format']),
        }

    def _generate_summary(self, entries: List[LogEntry], alerts: List[Alert]) -> str:
        """Generate a human-readable summary."""
        critical = len([a for a in alerts if a.severity == 'CRITICAL'])
        high = len([a for a in alerts if a.severity == 'HIGH'])
        medium = len([a for a in alerts if a.severity == 'MEDIUM'])

        return (
            f"Analyzed {len(entries)} log entries. "
            f"Found {len(alerts)} alerts: {critical} critical, {high} high, {medium} medium severity."
        )

    def get_plan(self, log_files: List[str], log_format: Optional[str],
                 output_format: str, rules_enabled: List[str]) -> str:
        """Generate planning mode output."""
        plan = []
        plan.append("")
        plan.append("[PLAN MODE] Tool: log-analyzer")
        plan.append("=" * 50)
        plan.append("")
        plan.append("Actions to be performed:")
        plan.append(f"  1. Parse log files: {', '.join(log_files)}")
        plan.append(f"  2. Log format: {log_format or 'auto-detect'}")
        plan.append(f"  3. Output format: {output_format}")
        plan.append("")
        plan.append("Detection rules to apply:")

        for i, rule in enumerate(self.rules, 1):
            status = "ENABLED" if not rules_enabled or rule.get_name() in rules_enabled else "DISABLED"
            plan.append(f"  {i}. [{status}] {rule.get_name()}")
            plan.append(f"      {rule.get_description()}")

        plan.append("")
        plan.append("Analysis phases:")
        plan.append("  Phase 1: Log parsing and normalization")
        plan.append("  Phase 2: Pattern detection and correlation")
        plan.append("  Phase 3: Alert generation and prioritization")
        plan.append("  Phase 4: Statistical analysis and reporting")
        plan.append("")
        plan.append("Risk Assessment: LOW (read-only analysis)")
        plan.append("Detection Vectors: None (defensive tool)")
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
        "name": "log-analyzer",
        "category": "Defense - Log Analysis",
        "version": "1.0.0",
        "author": "Defensive Security Toolsmith",
        "description": "Parse and analyze security logs for suspicious patterns and anomalies",
        "features": [
            "Multi-format log parsing (syslog, auth.log, Apache, Nginx)",
            "Brute force attack detection",
            "Password spray attack detection",
            "SQL injection attempt detection",
            "Path traversal attempt detection",
            "Suspicious user agent detection",
            "Privilege escalation monitoring",
            "Statistical analysis and reporting",
        ],
        "supported_formats": ["syslog", "auth", "apache", "nginx"],
        "detection_rules": [
            {"name": "BRUTE_FORCE_DETECTION", "severity": "HIGH"},
            {"name": "PASSWORD_SPRAY_DETECTION", "severity": "CRITICAL"},
            {"name": "SUSPICIOUS_USER_AGENT", "severity": "MEDIUM"},
            {"name": "SQL_INJECTION_ATTEMPT", "severity": "HIGH"},
            {"name": "PATH_TRAVERSAL_ATTEMPT", "severity": "HIGH"},
            {"name": "PRIVILEGE_ESCALATION", "severity": "MEDIUM"},
        ],
        "usage_examples": [
            "python tool.py --plan -f auth.log",
            "python tool.py -f /var/log/auth.log --format auth",
            "python tool.py -f access.log --format apache --output json",
            "python tool.py -f /var/log/syslog -f /var/log/auth.log",
        ],
        "arguments": {
            "--plan, -p": "Show execution plan without running analysis",
            "--file, -f": "Log file(s) to analyze (can specify multiple)",
            "--format": "Log format (syslog, auth, apache, nginx) or auto-detect",
            "--output, -o": "Output format (text, json)",
            "--quiet, -q": "Suppress informational output",
        },
        "legal_notice": "This tool is for authorized security monitoring only.",
    }


# ============================================================================
# Output Formatters
# ============================================================================

def format_output_text(result: AnalysisResult) -> str:
    """Format analysis result as human-readable text."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  LOG ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Summary: {result.summary}")
    lines.append("")

    if result.timespan[0] and result.timespan[1]:
        lines.append(f"Time Range: {result.timespan[0]} to {result.timespan[1]}")
        lines.append("")

    if result.alerts:
        lines.append("-" * 60)
        lines.append("  ALERTS")
        lines.append("-" * 60)

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_alerts = sorted(result.alerts, key=lambda x: severity_order.get(x.severity, 4))

        for alert in sorted_alerts:
            lines.append("")
            lines.append(f"[{alert.severity}] {alert.rule_name}")
            lines.append(f"  Description: {alert.description}")
            lines.append(f"  Time: {alert.timestamp}")
            if alert.source_ips:
                lines.append(f"  Source IPs: {', '.join(alert.source_ips)}")
            if alert.affected_users:
                lines.append(f"  Affected Users: {', '.join(alert.affected_users)}")
            if alert.recommendation:
                lines.append(f"  Recommendation: {alert.recommendation}")
            if alert.evidence:
                lines.append("  Evidence (first 3 entries):")
                for ev in alert.evidence[:3]:
                    lines.append(f"    > {ev[:100]}...")
    else:
        lines.append("")
        lines.append("No security alerts detected.")

    lines.append("")
    lines.append("-" * 60)
    lines.append("  STATISTICS")
    lines.append("-" * 60)
    lines.append("")

    lines.append("By Severity:")
    for sev, count in result.statistics.get('by_severity', {}).items():
        lines.append(f"  {sev}: {count}")

    lines.append("")
    lines.append("Top Actions:")
    for action, count in list(result.statistics.get('by_action', {}).items())[:5]:
        lines.append(f"  {action}: {count}")

    lines.append("")
    lines.append("Top Source IPs:")
    for ip, count in list(result.statistics.get('by_source_ip', {}).items())[:5]:
        lines.append(f"  {ip}: {count}")

    lines.append("")
    lines.append("=" * 60)

    return '\n'.join(lines)


def format_output_json(result: AnalysisResult) -> str:
    """Format analysis result as JSON."""
    output = {
        "summary": result.summary,
        "total_entries": result.total_entries,
        "parsed_entries": result.parsed_entries,
        "timespan": {
            "start": result.timespan[0].isoformat() if result.timespan[0] else None,
            "end": result.timespan[1].isoformat() if result.timespan[1] else None,
        },
        "alerts": [
            {
                "rule_name": a.rule_name,
                "severity": a.severity,
                "description": a.description,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "source_ips": a.source_ips,
                "affected_users": a.affected_users,
                "recommendation": a.recommendation,
                "evidence_count": len(a.evidence),
            }
            for a in result.alerts
        ],
        "statistics": result.statistics,
    }
    return json.dumps(output, indent=2)


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Log Analyzer - Parse and analyze security logs for suspicious patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --plan -f auth.log
  %(prog)s -f /var/log/auth.log --format auth
  %(prog)s -f access.log --format apache --output json
  %(prog)s -f /var/log/syslog -f /var/log/auth.log

Supported formats: syslog, auth, apache, nginx
        """
    )

    parser.add_argument(
        '--plan', '-p',
        action='store_true',
        help='Show execution plan without running analysis'
    )

    parser.add_argument(
        '--file', '-f',
        action='append',
        dest='files',
        required=False,
        help='Log file(s) to analyze (can specify multiple)'
    )

    parser.add_argument(
        '--format',
        choices=['syslog', 'auth', 'apache', 'nginx', 'auto'],
        default='auto',
        help='Log format (default: auto-detect)'
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
        '--rules',
        nargs='*',
        help='Specific rules to enable (default: all)'
    )

    args = parser.parse_args()

    analyzer = LogAnalyzer()

    # Planning mode
    if args.plan:
        files = args.files or ['<stdin>']
        log_format = args.format if args.format != 'auto' else None
        print(analyzer.get_plan(files, log_format, args.output, args.rules or []))
        return 0

    # Execution mode requires files
    if not args.files:
        parser.print_help()
        print("\nError: At least one log file is required (use -f/--file)")
        return 1

    # Read and combine log content
    all_content = []
    for log_file in args.files:
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                all_content.append(f.read())
        except FileNotFoundError:
            print(f"Error: File not found: {log_file}", file=sys.stderr)
            return 1
        except PermissionError:
            print(f"Error: Permission denied: {log_file}", file=sys.stderr)
            return 1

    combined_content = '\n'.join(all_content)

    # Determine format
    log_format = args.format if args.format != 'auto' else None

    # Parse and analyze
    if not args.quiet:
        print("Parsing log entries...", file=sys.stderr)

    entries = analyzer.parse_logs(combined_content, log_format)

    if not args.quiet:
        print(f"Parsed {len(entries)} entries. Running analysis...", file=sys.stderr)

    result = analyzer.analyze(entries)

    # Output results
    if args.output == 'json':
        print(format_output_json(result))
    else:
        print(format_output_text(result))

    # Return non-zero if critical/high alerts found
    critical_high = len([a for a in result.alerts if a.severity in ['CRITICAL', 'HIGH']])
    return 1 if critical_high > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
