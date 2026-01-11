# Blue Team Defensive Tools Training Guide

**CPTC11 Training Module**
**Category:** Defensive Security Operations
**Difficulty:** Intermediate to Advanced
**Estimated Time:** 4-6 hours

---

## Table of Contents

1. [Blue Team Tooling Introduction](#blue-team-tooling-introduction)
2. [Log Analyzer Tool](#log-analyzer-tool)
3. [IOC Scanner Tool](#ioc-scanner-tool)
4. [Network Monitor Tool](#network-monitor-tool)
5. [Honeypot Detector Tool](#honeypot-detector-tool)
6. [Baseline Auditor Tool](#baseline-auditor-tool)
7. [Blue Team Workflows](#blue-team-workflows)
8. [Hands-On Labs](#hands-on-labs)

---

## Blue Team Tooling Introduction

### The Critical Role of Defensive Capabilities

In modern cybersecurity operations, defensive capabilities form the backbone of organizational resilience against sophisticated threat actors. While offensive security skills enable penetration testers to identify vulnerabilities and simulate attacks, blue team competencies ensure that organizations can detect, respond to, and recover from security incidents effectively. The CPTC11 defensive toolkit represents a comprehensive suite of tools designed to empower security professionals with the detection and monitoring capabilities essential for protecting critical infrastructure.

The importance of defensive tooling cannot be overstated. According to industry research, the average time to detect a breach exceeds 200 days in many organizations, with attackers often maintaining persistence for months before discovery. This detection gap represents a critical failure in security operations that well-implemented defensive tools can address. The tools in this module provide capabilities spanning log analysis, indicator of compromise scanning, network monitoring, honeypot detection, and baseline integrity verification - covering the essential detection vectors that security teams require.

### Purple Team Methodology

The purple team approach represents a paradigm shift in how organizations think about security operations. Rather than maintaining strict separation between red team (offensive) and blue team (defensive) activities, purple teaming emphasizes collaboration and continuous improvement through shared knowledge and integrated exercises.

In a purple team context, offensive operators understand the detection mechanisms they may trigger, while defenders gain insight into attacker techniques, tactics, and procedures (TTPs). This mutual understanding creates a feedback loop that strengthens both capabilities. The CPTC11 defensive tools are designed with this philosophy in mind - they can be used by defenders to monitor environments, but equally valuable when offensive operators understand their detection capabilities to develop more sophisticated evasion techniques or to validate that defenses are functioning correctly.

Key purple team principles embodied in this toolkit include:

**Detection Validation**: Offensive operators can use these tools to verify that their activities would be detected, ensuring realistic assessments that account for defensive capabilities.

**Capability Gap Analysis**: By running both offensive and defensive tools against target environments, teams can identify gaps where attacks succeed without generating alerts.

**Continuous Improvement**: Each engagement generates data that informs both offensive tradecraft and defensive rule tuning.

### Detection and Response Fundamentals

Effective detection and response relies on multiple data sources and analysis techniques working in concert. The defensive tools in this module address the core pillars of detection:

**Log-Based Detection**: Security logs from systems, applications, and network devices provide a historical record of activity. The Log Analyzer tool processes these logs to identify patterns indicative of malicious activity, from brute force attacks to SQL injection attempts.

**Indicator Matching**: Known bad indicators - IP addresses, file hashes, domains, and other artifacts associated with threats - enable rapid identification of known threats. The IOC Scanner provides this capability across files, processes, and network connections.

**Behavioral Analysis**: Beyond known indicators, anomalous behavior often signals compromise. The Network Monitor detects suspicious connection patterns, unusual port usage, and potential data exfiltration through behavioral rules.

**Integrity Verification**: Attackers frequently modify system files, install backdoors, or open new network listeners. The Baseline Auditor detects these changes by comparing current system state against known-good baselines.

**Deception Detection**: Understanding defensive deception technologies helps operators avoid honeypots that could expose their activities. The Honeypot Detector identifies common honeypot signatures and behavioral indicators.

Together, these tools provide layered detection capabilities that address threats across the attack lifecycle, from initial reconnaissance through persistence and lateral movement.

---

## Log Analyzer Tool

**Location:** `/Users/ic/cptc11/python/defense/log-analyzer/tool.py`
**Category:** Defense - Log Analysis
**Purpose:** Parse and analyze security logs for suspicious patterns and anomalies

### Supported Log Formats

The Log Analyzer supports four primary log formats with automatic detection:

| Format | Description | Common Sources |
|--------|-------------|----------------|
| `syslog` | Standard syslog format | /var/log/syslog, /var/log/messages |
| `auth` | Authentication logs | /var/log/auth.log, /var/log/secure |
| `apache` | Apache Combined Log Format | /var/log/apache2/access.log |
| `nginx` | Nginx access logs | /var/log/nginx/access.log |

**Format Auto-Detection**: When no format is specified, the tool samples the first 10 lines and attempts to match against known patterns. This enables seamless analysis of log files without requiring manual format specification.

### Detection Rules

The Log Analyzer includes six built-in detection rules:

#### 1. Brute Force Detection (BRUTE_FORCE_DETECTION)
- **Severity:** HIGH
- **Threshold:** 5+ failed logins from same IP within 5 minutes
- **Evidence:** Failed password attempts, invalid user attempts
- **Recommendation:** Block source IP, investigate affected accounts

#### 2. Password Spray Detection (PASSWORD_SPRAY_DETECTION)
- **Severity:** CRITICAL
- **Threshold:** 10+ unique users targeted from same IP within 10 minutes
- **Evidence:** Pattern of single attempts against multiple accounts
- **Recommendation:** Block source IP, reset passwords, enable MFA

#### 3. Suspicious User Agent Detection (SUSPICIOUS_USER_AGENT)
- **Severity:** MEDIUM
- **Patterns Detected:** sqlmap, nikto, nmap, masscan, dirbuster, gobuster, wfuzz, hydra, metasploit, scanner bots
- **Recommendation:** Investigate source IP for scanning activity

#### 4. SQL Injection Detection (SQL_INJECTION_ATTEMPT)
- **Severity:** HIGH
- **Patterns:** UNION SELECT, OR 1=1, DROP TABLE, SLEEP(), BENCHMARK(), etc.
- **Recommendation:** Block source IP, review WAF rules, check for exploitation

#### 5. Path Traversal Detection (PATH_TRAVERSAL_ATTEMPT)
- **Severity:** HIGH
- **Patterns:** ../, ..\, %2e%2e%2f, /etc/passwd, /etc/shadow
- **Recommendation:** Block source IP, verify no sensitive file access

#### 6. Privilege Escalation Detection (PRIVILEGE_ESCALATION)
- **Severity:** MEDIUM
- **Patterns:** sudo su, sudo -i, pkexec, usermod adding sudo/wheel groups
- **Recommendation:** Review user activity, verify authorized changes

### Alert Generation

Alerts are generated with the following structure:

```
[SEVERITY] RULE_NAME
  Description: Detailed description of the detected activity
  Time: Timestamp of detection
  Source IPs: List of involved IP addresses
  Affected Users: List of targeted user accounts
  Recommendation: Suggested response actions
  Evidence: Sample log entries triggering the alert
```

### Usage and Configuration

**Basic Usage:**

```bash
# Show execution plan without analysis
python tool.py --plan -f /var/log/auth.log

# Analyze authentication logs
python tool.py -f /var/log/auth.log --format auth

# Analyze web server logs with JSON output
python tool.py -f /var/log/apache2/access.log --format apache --output json

# Analyze multiple log files
python tool.py -f /var/log/syslog -f /var/log/auth.log

# Quiet mode (suppress informational output)
python tool.py -f auth.log --quiet
```

**Command Line Arguments:**

| Argument | Description |
|----------|-------------|
| `--plan, -p` | Show execution plan without running analysis |
| `--file, -f` | Log file(s) to analyze (can specify multiple) |
| `--format` | Log format: syslog, auth, apache, nginx, auto |
| `--output, -o` | Output format: text, json |
| `--quiet, -q` | Suppress informational output |
| `--rules` | Specific rules to enable (default: all) |

**Exit Codes:**
- `0`: No critical/high severity alerts
- `1`: Critical or high severity alerts detected

---

## IOC Scanner Tool

**Location:** `/Users/ic/cptc11/python/defense/ioc-scanner/tool.py`
**Category:** Defense - Threat Detection
**Purpose:** Scan files, processes, and network connections for Indicators of Compromise

### IOC Database Management

The IOC Scanner maintains a database supporting multiple indicator types:

| IOC Type | Description | Example |
|----------|-------------|---------|
| `ip` | Malicious IP addresses | 185.234.72.10 |
| `domain` | Malicious domains | evil-c2.example.com |
| `hash_md5` | MD5 file hashes | d41d8cd98f00b204e9800998ecf8427e |
| `hash_sha1` | SHA1 file hashes | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| `hash_sha256` | SHA256 file hashes | e3b0c44298fc1c149afbf4c8996fb924... |
| `url` | Malicious URLs | http://evil.com/payload.exe |
| `filename` | Suspicious filenames | mimikatz.exe, nc.exe |
| `email` | Malicious email addresses | attacker@phishing.com |
| `registry` | Malicious registry keys | HKLM\Software\Malware |
| `mutex` | Malware mutex names | Global\EvilMutex |

**Loading IOCs from JSON:**

```json
[
  {
    "type": "ip",
    "value": "192.168.1.100",
    "description": "Known C2 server",
    "severity": "HIGH",
    "source": "threat_intel_feed",
    "tags": ["apt", "c2"]
  },
  {
    "type": "hash_sha256",
    "value": "abc123...",
    "description": "Ransomware payload",
    "severity": "CRITICAL"
  }
]
```

**Loading IOCs from CSV/TXT:**

```
# One IOC value per line
d41d8cd98f00b204e9800998ecf8427e
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### File, Network, and Process Scanning

**File Scanning Capabilities:**

- **Hash Matching**: Calculates MD5, SHA1, and SHA256 for each file
- **Filename Matching**: Checks filenames against IOC patterns
- **Content Scanning**: Searches text files for IP addresses, domains, URLs, and emails
- **Size Limits**: Skips files larger than 50MB by default
- **Binary Exclusion**: Skips binary file content scanning (.exe, .dll, .png, etc.)

**Network Scanning:**

- Enumerates active network connections via netstat
- Checks remote IP addresses against IOC database
- Matches remote hostnames against domain IOCs
- Associates connections with process information

**Process Scanning:**

- Enumerates running processes via ps command
- Matches process names against filename IOCs
- Checks process paths for suspicious indicators
- Reports process ownership and PID

### Threat Intelligence Integration

**Loading External Threat Feeds:**

```bash
# Load from JSON threat feed
python tool.py --ioc-file threat_intel.json --scan-type all --target /home

# Load from hash list (specify IOC type for CSV)
python tool.py --ioc-file malware_hashes.csv --ioc-type hash_sha256 --scan-type file --target /opt

# Combine multiple sources
python tool.py --ioc-file feed1.json --ioc-file feed2.json --builtin --scan-type all
```

**Built-in Test IOCs:**

The scanner includes built-in test IOCs for validation:
- `mimikatz.exe` (CRITICAL) - Credential dumping tool
- `nc.exe` (HIGH) - Netcat lateral movement
- Test IP addresses and domains

### Usage Examples

```bash
# Planning mode - show what will be scanned
python tool.py --plan --scan-type all --target /var/www

# Scan directory for IOCs
python tool.py --scan-type file --target /home/user --ioc-file threats.json

# Scan network connections
python tool.py --scan-type network --ioc-file known_bad_ips.json

# Scan running processes
python tool.py --scan-type process

# Full system scan with JSON output
python tool.py --scan-type all --target / --output json --ioc-file iocs.json
```

**Command Line Arguments:**

| Argument | Description |
|----------|-------------|
| `--plan, -p` | Show execution plan |
| `--scan-type` | Scan type: file, network, process, all |
| `--target, -t` | Target path for file scanning |
| `--ioc-file` | Path to IOC file (can specify multiple) |
| `--ioc-type` | IOC type for CSV files (default: hash_sha256) |
| `--output, -o` | Output format: text, json |
| `--builtin` | Include built-in test IOCs |

---

## Network Monitor Tool

**Location:** `/Users/ic/cptc11/python/defense/network-monitor/tool.py`
**Category:** Defense - Network Security
**Purpose:** Monitor network connections, detect anomalies, and identify suspicious activity

### Connection Monitoring

The Network Monitor uses multiple data collection methods:

**Netstat Collector:**
- Parses `netstat -an` output
- Captures protocol, local/remote addresses, ports, and connection state
- Cross-platform support (Linux, macOS)

**Lsof Collector:**
- Parses `lsof -i -n -P` output
- Provides process-level attribution for connections
- Includes PID and process name

**Collected Data Points:**
- Protocol (TCP/UDP)
- Local IP and port
- Remote IP and port
- Connection state (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
- Process ID and name (when available)
- Timestamp

### Threat Detection Rules

#### 1. Suspicious Port Detection (SUSPICIOUS_PORT)
- **Severity:** HIGH
- **Monitored Ports:**
  - 4444: Metasploit default
  - 5555: Common RAT port
  - 6666/6667: IRC/backdoor
  - 31337: Elite/backdoor
  - 12345: NetBus trojan
  - 9001/9050/9150: Tor ports

#### 2. High Connection Count (HIGH_CONNECTION_COUNT)
- **Severity:** MEDIUM
- **Threshold:** 50+ connections per process
- **Indication:** Scanning activity, C2 beaconing

#### 3. External Connections (EXTERNAL_CONNECTIONS)
- **Severity:** LOW
- **Threshold:** 20+ external connections
- **Purpose:** Monitor potential data exfiltration

#### 4. Unusual Listeners (UNUSUAL_LISTENERS)
- **Severity:** MEDIUM
- **Detection:** Listening ports not in known-good list
- **Known Ports:** 22, 80, 443, 53, 3306, 5432, 6379, 27017, 8080, 8443

#### 5. DNS Tunneling (DNS_TUNNELING)
- **Severity:** HIGH
- **Threshold:** 20+ DNS connections from single process
- **Indication:** Data exfiltration via DNS

### Alert Thresholds

| Rule | Threshold | Severity |
|------|-----------|----------|
| Suspicious Ports | Any connection | HIGH |
| High Connection Count | 50+ per process | MEDIUM |
| External Connections | 20+ total | LOW |
| Unusual Listeners | Non-standard high ports | MEDIUM |
| DNS Tunneling | 20+ DNS queries/process | HIGH |

### Baseline Comparison

The Network Monitor tracks statistics for baseline comparison:

- Connections by protocol
- Connections by state
- Connections by process
- Listening ports list
- Established connection count
- Unique remote IP count

### Usage and Configuration

```bash
# Planning mode
python tool.py --plan

# Single snapshot with all connections
python tool.py --show-all

# Continuous monitoring (30-second interval)
python tool.py --continuous --interval 30

# JSON output for SIEM integration
python tool.py --output json

# Quiet mode continuous monitoring
python tool.py --continuous --interval 60 --quiet
```

**Command Line Arguments:**

| Argument | Description |
|----------|-------------|
| `--plan, -p` | Show execution plan |
| `--continuous, -c` | Run in continuous monitoring mode |
| `--interval, -i` | Interval between checks (seconds, default: 30) |
| `--output, -o` | Output format: text, json |
| `--show-all` | Show all connections, not just alerts |
| `--quiet, -q` | Suppress informational output |

---

## Honeypot Detector Tool

**Location:** `/Users/ic/cptc11/python/defense/honeypot-detector/tool.py`
**Category:** Defense - Deception Detection
**Purpose:** Detect honeypots and deception technologies in network environments

### Detection Techniques

The Honeypot Detector employs five analysis techniques:

#### 1. Banner Analysis
Analyzes service banners for known honeypot signatures:

| Pattern | Honeypot | Confidence |
|---------|----------|------------|
| SSH-2.0-OpenSSH_6.0p1 Debian-4 | Cowrie | HIGH |
| SSH-2.0-OpenSSH_5.1p1 Debian-5 | Kippo | HIGH |
| Microsoft FTP Service (anomalous) | Dionaea | MEDIUM |
| "honeyd" in banner | HoneyD | HIGH |
| Very old OS versions | Various | MEDIUM |

#### 2. Timing Analysis
Detects simulation artifacts through response timing:
- Suspiciously fast responses (<5ms)
- Unusually consistent timing variance (<0.5)
- Response patterns inconsistent with real services

#### 3. Service Behavior Analysis
Identifies behavioral anomalies:
- Services on unusual ports (SSH on port 80, etc.)
- Excessive open ports (>50)
- Services accepting any credentials

#### 4. Network Analysis
Examines network-level characteristics:
- Unusual TTL values
- Identical fingerprints across multiple services
- Known honeypot hosting ranges

#### 5. Known Honeypot Fingerprinting
Signature matching for common honeypot software:
- **Cowrie**: SSH/Telnet honeypot (ports 2222, 2223)
- **Kippo**: SSH honeypot (port 2222)
- **Dionaea**: Multi-protocol honeypot (21, 42, 135, 445, 1433, 3306)
- **Glastopf**: Web application honeypot (80, 8080)
- **Conpot**: ICS/SCADA honeypot (102, 161, 502)
- **HoneyD**: Virtual honeypot framework

### Reconnaissance Safety

**Why Honeypot Detection Matters:**

During penetration testing engagements, interacting with honeypots can:
- Alert defenders to your presence
- Log detailed information about your techniques
- Waste time on non-productive targets
- Provide misleading information about the environment

**Safe Reconnaissance Practices:**

1. **Pre-Scan Analysis**: Run honeypot detection before deep enumeration
2. **Passive First**: Use banner grabbing before authentication attempts
3. **Probability Assessment**: Targets with >60% honeypot probability warrant caution
4. **Indicator Correlation**: Multiple indicators increase confidence

### Identifying Security Traps

**Common Honeypot Indicators:**

```
[HIGH] known_cowrie
  Type: signature
  Description: Detected cowrie honeypot signature
  Evidence: Pattern match: SSH-2.0-OpenSSH_6.0p1 Debian-4

[MEDIUM] many_open_ports
  Type: behavior
  Description: Target has 127 open ports
  Evidence: Excessive services for typical server

[LOW] instant_response
  Type: timing
  Description: Suspiciously fast response time: 2ms
  Evidence: Real services typically show more latency
```

### Usage Examples

```bash
# Planning mode
python tool.py --plan --target 192.168.1.100 --port 22

# Single target analysis
python tool.py --target 192.168.1.100 --port 22

# Multiple ports on single target
python tool.py --target 10.0.0.1 --ports 22,80,443,2222

# Batch analysis from file
python tool.py --targets targets.txt --output json

# Custom timeout for slow networks
python tool.py --target 192.168.1.100 --port 22 --timeout 10
```

**Target File Format:**

```
# targets.txt - one target:port per line
192.168.1.100:22
192.168.1.101:80
10.0.0.50:2222
# Comments start with #
```

---

## Baseline Auditor Tool

**Location:** `/Users/ic/cptc11/python/defense/baseline-auditor/tool.py`
**Category:** Defense - Integrity Monitoring
**Purpose:** Compare system state to baseline for file integrity, process, and network monitoring

### File Integrity Monitoring

The Baseline Auditor tracks file attributes:

| Attribute | Description | Change Impact |
|-----------|-------------|---------------|
| `hash_sha256` | File content hash | Detects modifications |
| `size` | File size in bytes | Indicates content change |
| `mode` | File permissions | Security configuration |
| `mtime` | Modification time | Activity tracking |
| `owner` | File ownership | Privilege changes |

**Critical Path Monitoring:**

Files automatically flagged as CRITICAL severity:
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sudoers`
- `/etc/ssh/sshd_config`
- `/root/.ssh/authorized_keys`

**High Severity Patterns:**

Paths matching these patterns receive HIGH severity:
- `/etc/*`
- `/bin/*`
- `/sbin/*`
- `/usr/bin/*`
- `/usr/sbin/*`

### Baseline Creation

**Creating a New Baseline:**

```bash
# Create baseline for /etc directory
python tool.py --mode create --paths /etc --baseline etc_baseline.json

# Create baseline for multiple paths
python tool.py --mode create --paths /etc,/usr/bin,/usr/sbin --baseline system_baseline.json

# Exclude patterns during creation
python tool.py --mode create --paths /var --exclude "*.log,*.tmp" --baseline var_baseline.json
```

**Baseline JSON Structure:**

```json
{
  "created": "2024-01-10T12:00:00",
  "hostname": "webserver01",
  "files": {
    "/etc/passwd": {
      "path": "/etc/passwd",
      "hash_sha256": "abc123...",
      "size": 2048,
      "mode": 33188,
      "mtime": 1704844800.0,
      "owner": "root"
    }
  },
  "processes": {
    "sshd": {
      "name": "sshd",
      "path": "/usr/sbin/sshd",
      "user": "root",
      "expected": true
    }
  },
  "listening_ports": {
    "22": {
      "local_port": 22,
      "protocol": "tcp",
      "process": "sshd",
      "expected": true
    }
  },
  "metadata": {
    "file_paths": ["/etc"],
    "exclude_patterns": []
  }
}
```

### Change Detection

**Violation Types:**

| Type | Category | Description |
|------|----------|-------------|
| `added` | file | New file not in baseline |
| `removed` | file | Baseline file no longer exists |
| `modified` | file | File content hash changed |
| `unexpected` | process | Process not in baseline |
| `new_listener` | network | New listening port detected |

### Compliance Verification

**Running an Audit:**

```bash
# Audit against saved baseline
python tool.py --mode audit --baseline system_baseline.json

# Audit with JSON output for compliance reporting
python tool.py --mode audit --baseline baseline.json --output json

# Audit specific paths only
python tool.py --mode audit --baseline baseline.json --paths /etc/ssh
```

**Sample Audit Report:**

```
============================================================
  BASELINE AUDIT REPORT
============================================================
Audit Time: 2024-01-10 14:30:00
Baseline Date: 2024-01-09 10:00:00
Summary: Found 3 violations: 1 critical, 1 high.

------------------------------------------------------------
  VIOLATIONS
------------------------------------------------------------
[CRITICAL] file: File content changed: /etc/passwd
[HIGH] file: New file detected: /etc/cron.d/backdoor
[MEDIUM] network: New listening port: 4444
============================================================
```

### Usage Examples

```bash
# Planning mode for create
python tool.py --plan --mode create --paths /etc,/usr/bin

# Planning mode for audit
python tool.py --plan --mode audit --baseline baseline.json

# Create baseline with exclusions
python tool.py --mode create --paths /var/www --exclude "*.log,*.cache,tmp/*" --baseline www_baseline.json

# Quiet audit for automation
python tool.py --mode audit --baseline baseline.json --quiet --output json > audit_results.json
```

---

## Blue Team Workflows

### Incident Detection Pipeline

A comprehensive incident detection pipeline integrates all defensive tools:

```
                    +------------------+
                    |   Data Sources   |
                    +--------+---------+
                             |
            +----------------+----------------+
            |                |                |
            v                v                v
    +-------+------+  +------+-------+  +-----+------+
    | Log Files    |  | Network      |  | File       |
    | (syslog,     |  | Connections  |  | System     |
    | auth, web)   |  | (netstat)    |  | (hashes)   |
    +-------+------+  +------+-------+  +-----+------+
            |                |                |
            v                v                v
    +-------+------+  +------+-------+  +-----+------+
    | Log Analyzer |  | Network      |  | IOC        |
    |              |  | Monitor      |  | Scanner    |
    +-------+------+  +------+-------+  +-----+------+
            |                |                |
            +----------------+----------------+
                             |
                             v
                    +--------+---------+
                    |  Alert Triage    |
                    |  & Correlation   |
                    +--------+---------+
                             |
                             v
                    +--------+---------+
                    | Incident Response|
                    +------------------+
```

**Pipeline Implementation:**

```bash
#!/bin/bash
# incident_detection.sh - Automated detection pipeline

# Run all detection tools and collect results
LOG_RESULTS=$(python /path/to/log-analyzer/tool.py -f /var/log/auth.log -f /var/log/syslog --output json)
NET_RESULTS=$(python /path/to/network-monitor/tool.py --output json)
IOC_RESULTS=$(python /path/to/ioc-scanner/tool.py --scan-type all --target / --ioc-file /path/to/iocs.json --output json)
BASELINE_RESULTS=$(python /path/to/baseline-auditor/tool.py --mode audit --baseline /path/to/baseline.json --output json)

# Aggregate and analyze results
echo "$LOG_RESULTS" | jq '.alerts[] | select(.severity == "HIGH" or .severity == "CRITICAL")'
echo "$NET_RESULTS" | jq '.alerts[] | select(.severity == "HIGH" or .severity == "CRITICAL")'
echo "$IOC_RESULTS" | jq '.matches[] | select(.ioc.severity == "HIGH" or .ioc.severity == "CRITICAL")'
echo "$BASELINE_RESULTS" | jq '.violations[] | select(.severity == "CRITICAL" or .severity == "HIGH")'
```

### Threat Hunting Scenarios

#### Scenario 1: Hunting for Lateral Movement

```bash
# 1. Check for brute force activity in auth logs
python log-analyzer/tool.py -f /var/log/auth.log --format auth

# 2. Look for unusual network connections
python network-monitor/tool.py --show-all | grep -E "4444|5555|31337"

# 3. Scan for lateral movement tools
python ioc-scanner/tool.py --scan-type file --target /tmp --builtin

# 4. Check for new listening services
python baseline-auditor/tool.py --mode audit --baseline baseline.json
```

#### Scenario 2: Hunting for Data Exfiltration

```bash
# 1. Monitor for DNS tunneling indicators
python network-monitor/tool.py --output json | jq '.alerts[] | select(.rule_name == "DNS_TUNNELING")'

# 2. Check for connections to external IPs
python network-monitor/tool.py --show-all | grep -v "192.168\|10\.\|172\.16"

# 3. Analyze web logs for data exfiltration patterns
python log-analyzer/tool.py -f /var/log/nginx/access.log --format nginx
```

#### Scenario 3: Hunting for Persistence Mechanisms

```bash
# 1. Audit critical system files
python baseline-auditor/tool.py --mode audit --baseline baseline.json --paths /etc/cron.d,/etc/systemd

# 2. Check for new unauthorized processes
python baseline-auditor/tool.py --mode audit --baseline baseline.json

# 3. Scan for known malicious files
python ioc-scanner/tool.py --scan-type file --target /etc --ioc-file persistence_iocs.json
```

### Integration with Offensive Tools

The defensive tools complement offensive operations in several ways:

**Pre-Engagement Reconnaissance:**
```bash
# Before scanning a network, check for honeypots
python honeypot-detector/tool.py --target 192.168.1.100 --ports 22,80,443,8080

# Interpret results
# Probability > 60%: Likely honeypot, proceed with caution
# Probability < 30%: Probably legitimate, safe to engage
```

**Post-Exploitation Validation:**
```bash
# After gaining access, verify your activities would be detected
# This helps improve evasion techniques

# Would your network activity trigger alerts?
python network-monitor/tool.py --show-all

# Would your tools be detected by IOC scanning?
python ioc-scanner/tool.py --scan-type file --target /tmp/tools --builtin
```

**Detection Gap Analysis:**
```bash
# Run offensive tool, then check if defensive tools detect it
./offensive_tool --target victim

# Immediately run defensive analysis
python log-analyzer/tool.py -f /var/log/auth.log
python network-monitor/tool.py
python baseline-auditor/tool.py --mode audit --baseline pre_attack_baseline.json

# If no alerts: Detection gap identified
# If alerts: Defensive coverage confirmed
```

---

## Hands-On Labs

### Lab 1: Log Analysis for Intrusion Detection

**Objective:** Analyze authentication logs to identify brute force attacks and unauthorized access attempts.

**Environment Setup:**
```bash
# Create sample malicious auth log
cat > /tmp/lab1_auth.log << 'EOF'
Jan 10 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2
Jan 10 10:00:02 server sshd[1235]: Failed password for invalid user root from 192.168.1.50 port 54322 ssh2
Jan 10 10:00:03 server sshd[1236]: Failed password for invalid user test from 192.168.1.50 port 54323 ssh2
Jan 10 10:00:04 server sshd[1237]: Failed password for invalid user user from 192.168.1.50 port 54324 ssh2
Jan 10 10:00:05 server sshd[1238]: Failed password for invalid user guest from 192.168.1.50 port 54325 ssh2
Jan 10 10:00:06 server sshd[1239]: Failed password for admin from 192.168.1.50 port 54326 ssh2
Jan 10 10:00:07 server sshd[1240]: Accepted password for admin from 192.168.1.50 port 54327 ssh2
Jan 10 10:05:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
EOF
```

**Task Instructions:**

1. Run the Log Analyzer in planning mode to understand what analysis will be performed:
```bash
python tool.py --plan -f /tmp/lab1_auth.log
```

2. Analyze the log file and identify security events:
```bash
python tool.py -f /tmp/lab1_auth.log --format auth
```

3. Generate JSON output for further analysis:
```bash
python tool.py -f /tmp/lab1_auth.log --format auth --output json > /tmp/lab1_results.json
```

**Validation Criteria:**
- [ ] Identified brute force attack from 192.168.1.50
- [ ] Detected multiple failed login attempts
- [ ] Noted successful login following failed attempts
- [ ] Identified privilege escalation via sudo

**Extension Challenge:** Modify the threshold parameters in the BruteForceDetector class to detect attacks with fewer attempts.

---

### Lab 2: IOC Scanning Workflow

**Objective:** Create an IOC database and scan a target directory for indicators of compromise.

**Environment Setup:**
```bash
# Create test directory structure
mkdir -p /tmp/lab2_target/uploads
mkdir -p /tmp/lab2_target/logs

# Create IOC database
cat > /tmp/lab2_iocs.json << 'EOF'
[
  {
    "type": "filename",
    "value": "malware.exe",
    "description": "Known malware executable",
    "severity": "CRITICAL"
  },
  {
    "type": "ip",
    "value": "10.10.10.10",
    "description": "Command and control server",
    "severity": "HIGH"
  },
  {
    "type": "domain",
    "value": "evil-domain.com",
    "description": "Malicious domain",
    "severity": "HIGH"
  },
  {
    "type": "hash_sha256",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "description": "Empty file (test indicator)",
    "severity": "LOW"
  }
]
EOF

# Create test files
echo "Connection to 10.10.10.10 established" > /tmp/lab2_target/logs/access.log
echo "Downloading from evil-domain.com" > /tmp/lab2_target/uploads/config.txt
touch /tmp/lab2_target/uploads/empty_file.txt
```

**Task Instructions:**

1. Review the IOC database and plan the scan:
```bash
python tool.py --plan --scan-type file --target /tmp/lab2_target --ioc-file /tmp/lab2_iocs.json
```

2. Execute the file scan:
```bash
python tool.py --scan-type file --target /tmp/lab2_target --ioc-file /tmp/lab2_iocs.json
```

3. Run a comprehensive scan including processes and network:
```bash
python tool.py --scan-type all --target /tmp/lab2_target --ioc-file /tmp/lab2_iocs.json --builtin
```

**Validation Criteria:**
- [ ] Loaded custom IOCs from JSON file
- [ ] Detected IP address 10.10.10.10 in log file
- [ ] Detected domain evil-domain.com in config file
- [ ] Detected empty file by hash match
- [ ] Generated report with severity classifications

**Extension Challenge:** Create a CSV file with additional hash IOCs and scan for files matching those hashes.

---

### Lab 3: Network Baseline Monitoring

**Objective:** Establish a network baseline and detect deviations indicating potential compromise.

**Environment Setup:**
```bash
# This lab requires actual network connections
# The baseline will capture current listening ports
```

**Task Instructions:**

1. Create a network baseline:
```bash
python baseline-auditor/tool.py --mode create --paths /etc --baseline /tmp/lab3_baseline.json
```

2. View the baseline contents:
```bash
cat /tmp/lab3_baseline.json | python -m json.tool | grep -A5 "listening_ports"
```

3. Start a new listener to simulate unauthorized service (in another terminal):
```bash
# Using netcat to create a listener
nc -l 4444 &
```

4. Run the baseline audit to detect the new listener:
```bash
python baseline-auditor/tool.py --mode audit --baseline /tmp/lab3_baseline.json
```

5. Run the Network Monitor for real-time detection:
```bash
python network-monitor/tool.py --show-all
```

**Validation Criteria:**
- [ ] Created baseline capturing initial listening ports
- [ ] Detected new listener on port 4444
- [ ] Network Monitor flagged suspicious port
- [ ] Generated violation report with severity

**Cleanup:**
```bash
# Kill the netcat listener
pkill nc
```

**Extension Challenge:** Configure continuous monitoring and generate alerts when new connections are established to external IPs.

---

### Lab 4: Purple Team Exercise

**Objective:** Conduct a purple team exercise combining offensive actions with defensive detection.

**Scenario:** An attacker has gained initial access and is attempting to establish persistence and exfiltrate data. Defenders must detect each phase of the attack.

**Phase 1: Initial Compromise Simulation**

```bash
# Attacker: Create evidence of brute force in logs
cat > /tmp/lab4_auth.log << 'EOF'
Jan 10 14:00:01 server sshd[5001]: Failed password for invalid user admin from 10.20.30.40 port 44001 ssh2
Jan 10 14:00:02 server sshd[5002]: Failed password for invalid user root from 10.20.30.40 port 44002 ssh2
Jan 10 14:00:03 server sshd[5003]: Failed password for invalid user administrator from 10.20.30.40 port 44003 ssh2
Jan 10 14:00:04 server sshd[5004]: Failed password for invalid user backup from 10.20.30.40 port 44004 ssh2
Jan 10 14:00:05 server sshd[5005]: Failed password for invalid user oracle from 10.20.30.40 port 44005 ssh2
Jan 10 14:00:06 server sshd[5006]: Accepted password for webadmin from 10.20.30.40 port 44006 ssh2
EOF

# Defender: Detect the brute force and successful compromise
python log-analyzer/tool.py -f /tmp/lab4_auth.log --format auth
```

**Phase 2: Persistence Mechanism**

```bash
# Attacker: Drop a "malicious" file
mkdir -p /tmp/lab4_target/cron.d
echo "* * * * * root /tmp/backdoor.sh" > /tmp/lab4_target/cron.d/persistence

# Create baseline before (for demonstration, create after)
python baseline-auditor/tool.py --mode create --paths /tmp/lab4_target --baseline /tmp/lab4_before.json

# Create the persistence file
echo "#!/bin/bash" > /tmp/lab4_target/cron.d/malicious_cron

# Defender: Detect the new file
python baseline-auditor/tool.py --mode audit --baseline /tmp/lab4_before.json --paths /tmp/lab4_target
```

**Phase 3: Command and Control**

```bash
# Attacker: Simulate C2 connection (use listener)
nc -l 31337 &

# Defender: Detect suspicious network activity
python network-monitor/tool.py --show-all

# Note the suspicious port detection
```

**Phase 4: IOC Sweep**

```bash
# Create IOC list based on observed attack
cat > /tmp/lab4_iocs.json << 'EOF'
[
  {"type": "ip", "value": "10.20.30.40", "severity": "HIGH", "description": "Attack source IP"},
  {"type": "filename", "value": "malicious_cron", "severity": "CRITICAL", "description": "Persistence file"}
]
EOF

# Defender: Comprehensive IOC sweep
python ioc-scanner/tool.py --scan-type file --target /tmp/lab4_target --ioc-file /tmp/lab4_iocs.json
```

**Validation Criteria:**
- [ ] Detected brute force attack in Phase 1
- [ ] Identified successful login following failed attempts
- [ ] Detected new persistence file in Phase 2
- [ ] Flagged suspicious port 31337 in Phase 3
- [ ] IOC scan identified attack artifacts in Phase 4
- [ ] Correlated findings across multiple tools

**Cleanup:**
```bash
pkill nc
rm -rf /tmp/lab4_*
```

**Extension Challenge:**
1. Document the complete attack timeline based on defensive tool outputs
2. Identify detection gaps - what attacker activities were NOT detected?
3. Propose additional detection rules to close those gaps

---

## Summary

This training guide has covered the five core defensive tools in the CPTC11 toolkit:

1. **Log Analyzer**: Multi-format log parsing with pattern-based threat detection
2. **IOC Scanner**: File, process, and network scanning against indicator databases
3. **Network Monitor**: Real-time connection monitoring with behavioral detection
4. **Honeypot Detector**: Deception technology identification for safe reconnaissance
5. **Baseline Auditor**: System integrity monitoring through baseline comparison

These tools provide comprehensive coverage across the detection landscape, enabling security professionals to identify threats ranging from brute force attacks to sophisticated persistence mechanisms. When integrated into a purple team methodology, they create a feedback loop that strengthens both offensive and defensive capabilities.

**Key Takeaways:**

- Layered detection provides defense in depth
- Baseline comparison catches changes that pattern matching might miss
- Purple team integration improves both attack simulation and defense validation
- Automated pipelines enable continuous security monitoring
- Understanding detection capabilities informs evasion research

---

**Document Information**
Version: 1.0
Last Updated: January 2026
Author: Defensive Security Training Team
Classification: Training Use Only
