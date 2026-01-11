# Network Scanner - Complete Training Guide

**Tool Version:** 1.0.0
**Category:** Reconnaissance
**Author:** Offensive Security Toolsmith
**Classification:** For Authorized Security Testing Only

---

## Table of Contents

1. [Tool Overview](#1-tool-overview)
2. [Technical Architecture](#2-technical-architecture)
3. [Complete CLI Reference](#3-complete-cli-reference)
4. [Usage Scenarios](#4-usage-scenarios)
5. [Output Interpretation](#5-output-interpretation)
6. [Hands-On Lab Exercises](#6-hands-on-lab-exercises)
7. [Troubleshooting Guide](#7-troubleshooting-guide)

---

## 1. Tool Overview

### Purpose and Capabilities

The Network Scanner is a purpose-built reconnaissance tool designed for authorized penetration testing engagements. Unlike general-purpose network scanners, this tool was developed with operational security (OPSEC) as a primary design consideration. It enables security professionals to perform host discovery while maintaining control over their detection footprint.

The tool provides three distinct scanning methodologies that can be used individually or in combination: TCP Connect scanning for reliable host detection through standard port connections, ARP scanning for efficient local network discovery, and DNS reverse lookup scanning for passive host identification through PTR record queries. This multi-method approach allows operators to select the appropriate technique based on their operational requirements, network position, and stealth considerations.

A distinguishing feature of the Network Scanner is its in-memory operation model. All scan results are stored in memory during execution, with optional file output controlled by the operator. This design minimizes forensic artifacts on the scanning system, which is particularly important during red team engagements where the assessment machine may be subject to blue team analysis.

The tool supports flexible target specification including individual IP addresses, CIDR notation for network ranges, and hyphenated IP ranges. Combined with configurable threading and timing controls, operators can scale scans from single-host verification to enterprise-wide network enumeration while maintaining appropriate operational tempo.

### When to Use This Tool

The Network Scanner excels in several operational contexts:

- **Initial Reconnaissance Phase**: When beginning a penetration test and needing to identify live hosts within scope before detailed service enumeration
- **Red Team Operations**: When stealth is paramount and you need fine-grained control over scan timing and detection footprint
- **Verification Scans**: When confirming host availability before launching targeted attacks
- **Segmentation Testing**: When validating network segmentation by testing reachability from different network positions
- **Pre-Attack Planning**: When the plan mode is valuable for briefing team members or documenting intended actions

### Comparison with Alternatives

| Feature | Network Scanner | Nmap | Masscan |
|---------|-----------------|------|---------|
| Stealth Controls | Built-in jitter/delays | Timing templates | Rate limiting |
| In-Memory Results | Default behavior | Requires flags | Not supported |
| Plan Mode | Native support | Not available | Not available |
| Learning Curve | Low | High | Medium |
| Raw Packet Scans | Limited | Full support | Full support |
| OS Detection | No | Yes | No |
| Service Versioning | No | Yes | Limited |
| Threading Control | Configurable | Automatic | Rate-based |

**When to choose Network Scanner over Nmap:**
- When you need explicit planning/preview capability before execution
- When minimal disk artifacts are required
- When built-in stealth features with simpler syntax are preferred
- When training junior operators on scanning concepts

**When to choose Nmap instead:**
- When OS detection or service version identification is required
- When NSE scripting capabilities are needed
- When advanced scan types (SYN, FIN, XMAS) are required

---

## 2. Technical Architecture

### Code Structure Walkthrough

The Network Scanner follows a modular, object-oriented design pattern that separates concerns and enables extensibility. The architecture consists of five primary components:

```
+------------------------------------------------------------------+
|                        tool.py Structure                          |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------+     +------------------+                    |
|  |   Data Classes   |     |   Configuration  |                    |
|  +------------------+     +------------------+                    |
|  | - ScanResult     |     | - ScanConfig     |                    |
|  | - to_dict()      |     | - defaults       |                    |
|  +--------+---------+     +--------+---------+                    |
|           |                        |                              |
|           v                        v                              |
|  +------------------------------------------------+              |
|  |            ScanTechnique (Abstract Base)        |              |
|  +------------------------------------------------+              |
|  | + scan(ip, config) -> ScanResult                |              |
|  | + name -> str                                   |              |
|  | + description -> str                            |              |
|  +----------------------+-------------------------+               |
|                         |                                         |
|     +-------------------+-------------------+                     |
|     |                   |                   |                     |
|     v                   v                   v                     |
| +----------+      +----------+      +---------------+             |
| | TCPConnect|     | ARPScan  |      | DNSResolution |             |
| | Scan     |      |          |      | Scan          |             |
| +----------+      +----------+      +---------------+             |
|                                                                   |
|  +------------------------------------------------+              |
|  |              NetworkScanner (Core Engine)       |              |
|  +------------------------------------------------+              |
|  | - config: ScanConfig                            |              |
|  | - results: List[ScanResult]                     |              |
|  | - _expand_targets() -> Generator                |              |
|  | - _apply_jitter() -> None                       |              |
|  | - _scan_host(ip) -> ScanResult                  |              |
|  | - scan() -> List[ScanResult]                    |              |
|  | - get_live_hosts() -> List[ScanResult]          |              |
|  +------------------------------------------------+              |
|                                                                   |
+------------------------------------------------------------------+
```

### Key Classes and Data Structures

#### ScanResult Dataclass

The `ScanResult` dataclass encapsulates all information about a single host scan:

```python
@dataclass
class ScanResult:
    ip: str                              # Target IP address
    is_alive: bool                       # Whether host responded
    response_time: Optional[float]       # Time to receive response
    method: str                          # Scan technique that succeeded
    hostname: Optional[str]              # Resolved hostname if available
    timestamp: datetime                  # When scan was performed
```

The `to_dict()` method enables JSON serialization for output file generation.

#### ScanConfig Dataclass

Configuration parameters are centralized in `ScanConfig`:

```python
@dataclass
class ScanConfig:
    targets: List[str]           # Target specifications
    timeout: float = 2.0         # Socket timeout
    threads: int = 10            # Concurrent workers
    delay_min: float = 0.0       # Minimum inter-scan delay
    delay_max: float = 0.1       # Maximum inter-scan delay
    resolve_hostnames: bool      # Enable reverse DNS
    scan_methods: List[str]      # Techniques to use
    tcp_ports: List[int]         # Ports for TCP scanning
    verbose: bool                # Output verbosity
    plan_mode: bool              # Preview without execution
```

### Scanning Methods

#### TCP Connect Scan

The `TCPConnectScan` class implements full TCP handshake connections to determine host availability:

```
Operator                    Target Host
   |                             |
   |------ SYN (port 80) ------->|
   |<----- SYN-ACK -------------|  (Host alive)
   |------ ACK ---------------->|
   |------ RST ---------------->|  (Connection closed)
   |                             |
```

This technique:
- Iterates through configured TCP ports (default: 80, 443, 22)
- Returns success on first successful connection
- Records which port responded in the method field
- Optionally resolves hostname via reverse DNS

#### ARP Scan

The `ARPScan` class is designed for local network discovery:

```
Operator                    Local Network
   |                             |
   |-- ARP Who-has 192.168.1.5? -->|
   |<-- ARP Reply: MAC address ---|  (Host alive)
   |                             |
```

**Note:** The current implementation falls back to TCP scanning due to raw socket privilege requirements. Full ARP implementation requires root/administrator privileges.

#### DNS Resolution Scan

The `DNSResolutionScan` class uses reverse DNS lookups:

```
Operator                    DNS Server
   |                             |
   |-- PTR query for 1.1.168.192.in-addr.arpa -->|
   |<-- PTR response: hostname.domain.com -------|  (Host has PTR)
   |                             |
```

This passive technique:
- Queries for PTR records without touching the target
- Identifies hosts with configured reverse DNS
- Useful for initial enumeration without direct target contact

### Threading Implementation

The scanner uses Python's `concurrent.futures.ThreadPoolExecutor` for parallel scanning:

```
+-------------------+
|   Main Thread     |
+-------------------+
         |
         v
+-------------------+
|  ThreadPoolExecutor|
|  (max_workers=N)  |
+-------------------+
    |    |    |
    v    v    v
+-----+ +-----+ +-----+
|  T1 | |  T2 | | T3  |  Worker Threads
+-----+ +-----+ +-----+
    |    |    |
    v    v    v
  scan  scan  scan     _scan_host() calls
    |    |    |
    v    v    v
+-------------------+
|  Results List     |  Thread-safe collection
|  (with Lock)      |  using threading.Lock()
+-------------------+
```

Key threading features:
- Configurable worker count via `--threads`
- Thread-safe result collection using `threading.Lock()`
- Graceful shutdown via `threading.Event()` stop signal
- `as_completed()` for processing results as they arrive

---

## 3. Complete CLI Reference

### Synopsis

```
python tool.py [OPTIONS] TARGET [TARGET ...]
```

### Arguments Reference

| Argument | Short | Type | Default | Description |
|----------|-------|------|---------|-------------|
| `targets` | - | positional | (required) | Target IPs, CIDR ranges, or IP ranges |
| `--timeout` | `-t` | float | 2.0 | Connection timeout in seconds |
| `--threads` | `-T` | int | 10 | Number of concurrent scanning threads |
| `--methods` | `-m` | list | tcp | Scanning methods: tcp, arp, dns |
| `--ports` | `-P` | list | 80,443,22 | TCP ports for connect scanning |
| `--delay-min` | - | float | 0.0 | Minimum delay between scans (seconds) |
| `--delay-max` | - | float | 0.1 | Maximum delay between scans (seconds) |
| `--resolve` | `-r` | flag | False | Resolve hostnames for discovered hosts |
| `--plan` | `-p` | flag | False | Show execution plan without scanning |
| `--verbose` | `-v` | flag | False | Enable verbose output |
| `--output` | `-o` | string | None | Output file path for JSON results |

### Target Specification Formats

```bash
# Single IP address
python tool.py 192.168.1.100

# Multiple IP addresses
python tool.py 192.168.1.1 192.168.1.2 192.168.1.3

# CIDR notation
python tool.py 192.168.1.0/24

# IP range (last octet)
python tool.py 192.168.1.1-50

# Mixed specifications
python tool.py 192.168.1.0/24 10.0.0.1-10 172.16.0.5
```

### Output Formats

#### Standard Output (Default)

```
[*] Network Scanner starting...
[*] Targets: 192.168.1.0/24

============================================================
SCAN RESULTS
============================================================
Total hosts scanned: 254
Live hosts found:    12

LIVE HOSTS:
------------------------------------------------------------
  192.168.1.1 (router.local) [0.023s] - tcp_connect:80
  192.168.1.10 [0.045s] - tcp_connect:22
  192.168.1.25 (workstation1.local) [0.031s] - tcp_connect:443
```

#### JSON Output (--output flag)

```json
{
  "scan_time": "2024-01-15T14:32:00.123456",
  "config": {
    "targets": ["192.168.1.0/24"],
    "methods": ["tcp"],
    "ports": [80, 443, 22]
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "is_alive": true,
      "response_time": 0.023,
      "method": "tcp_connect:80",
      "hostname": "router.local",
      "timestamp": "2024-01-15T14:32:00.123456"
    }
  ]
}
```

### Plan Mode Explanation

Plan mode (`--plan` or `-p`) displays a comprehensive preview of planned actions without executing any network operations. This feature supports:

- **Pre-engagement documentation**: Capture planned scanning activities for approval
- **Team coordination**: Share exact parameters with team members
- **Risk assessment**: Review automated risk analysis before execution
- **Training**: Demonstrate tool capabilities without network impact

Example plan mode output:

```
[PLAN MODE] Tool: network-scanner
================================================================================

OPERATION SUMMARY
----------------------------------------
  Target Specification: 192.168.1.0/24
  Total IPs to scan:    254
  Scan Methods:         tcp
  TCP Ports:            [80, 443, 22]
  Threads:              10
  Timeout:              2.0s
  Delay Range:          0.0s - 0.1s
  Resolve Hostnames:    False

RISK ASSESSMENT
----------------------------------------
  Risk Level: MEDIUM
  Risk Factors:
    - Large scan scope

================================================================================
No actions will be taken. Remove --plan flag to execute.
================================================================================
```

---

## 4. Usage Scenarios

### Scenario 1: Basic Network Discovery

**Objective:** Identify all live hosts on a target network segment during initial reconnaissance.

```bash
# Preview the scan first
python tool.py 192.168.1.0/24 --plan

# Execute basic discovery
python tool.py 192.168.1.0/24 -v

# With hostname resolution for context
python tool.py 192.168.1.0/24 -v --resolve

# Output results for documentation
python tool.py 192.168.1.0/24 --resolve -o discovery_results.json
```

**Expected Output:**
```
[*] Network Scanner starting...
[*] Targets: 192.168.1.0/24
[*] Scanning 254 hosts with 10 threads
[+] 192.168.1.1 is alive (tcp_connect:80)
[+] 192.168.1.10 is alive (tcp_connect:22)
[+] 192.168.1.50 is alive (tcp_connect:443)

============================================================
SCAN RESULTS
============================================================
Total hosts scanned: 254
Live hosts found:    3
```

### Scenario 2: Stealth Scanning Configuration

**Objective:** Perform host discovery with minimal detection footprint during red team operations.

```bash
# Slow scan with significant jitter
python tool.py 10.0.0.0/24 \
    --delay-min 2.0 \
    --delay-max 5.0 \
    --threads 2 \
    --timeout 3.0 \
    -v

# DNS-only passive reconnaissance
python tool.py 10.0.0.0/24 \
    --methods dns \
    --threads 1 \
    --delay-min 1.0 \
    --delay-max 3.0

# Multi-method with controlled pacing
python tool.py 192.168.50.1-100 \
    --methods dns tcp \
    --ports 443 \
    --delay-min 0.5 \
    --delay-max 2.0 \
    --threads 3
```

**Stealth Configuration Guidelines:**

| Parameter | Aggressive | Normal | Stealthy | Ultra-Stealthy |
|-----------|------------|--------|----------|----------------|
| threads | 50+ | 10 | 2-5 | 1 |
| delay-min | 0 | 0 | 0.5 | 2.0 |
| delay-max | 0 | 0.1 | 2.0 | 10.0 |
| timeout | 1.0 | 2.0 | 3.0 | 5.0 |

### Scenario 3: Large Network Enumeration

**Objective:** Scan a large enterprise network efficiently while managing resource usage.

```bash
# Enterprise /16 network - plan first
python tool.py 10.0.0.0/16 --plan

# Segmented approach - scan by subnet
for subnet in $(seq 0 255); do
    python tool.py 10.0.${subnet}.0/24 \
        --threads 20 \
        --timeout 1.0 \
        -o results_10.0.${subnet}.json
done

# High-performance discovery
python tool.py 10.0.0.0/16 \
    --threads 50 \
    --timeout 1.0 \
    --ports 80 443 \
    --delay-max 0 \
    -o enterprise_discovery.json
```

**Performance Estimates:**

| Network Size | Threads | Est. Duration | Notes |
|--------------|---------|---------------|-------|
| /24 (254 hosts) | 10 | ~1 minute | Default settings |
| /24 (254 hosts) | 50 | ~15 seconds | Aggressive |
| /16 (65,534 hosts) | 10 | ~2 hours | Not recommended |
| /16 (65,534 hosts) | 100 | ~15 minutes | High resource use |

### Scenario 4: Integration with Other Tools

**Objective:** Chain Network Scanner output with other assessment tools.

```bash
# Export live hosts for Nmap service scan
python tool.py 192.168.1.0/24 -o discovery.json
cat discovery.json | jq -r '.results[] | select(.is_alive==true) | .ip' > live_hosts.txt
nmap -sV -iL live_hosts.txt -oA service_scan

# Feed into custom exploitation framework
python tool.py 10.0.0.0/24 -o scan.json
python exploit_framework.py --targets-from scan.json

# Integration with reporting
python tool.py $TARGET_NETWORK -o scan_$(date +%Y%m%d).json --resolve
```

**JSON Processing Examples:**

```bash
# Extract only live hosts
jq '.results[] | select(.is_alive==true)' results.json

# Count live hosts per method
jq '[.results[] | select(.is_alive==true)] | group_by(.method) | map({method: .[0].method, count: length})' results.json

# Get list of IPs with hostnames
jq -r '.results[] | select(.hostname != null) | "\(.ip) \(.hostname)"' results.json
```

---

## 5. Output Interpretation

### Understanding Results

#### Standard Output Fields

```
192.168.1.10 (webserver.corp.local) [0.045s] - tcp_connect:443
    |              |                    |           |
    |              |                    |           +-- Detection method:port
    |              |                    +-------------- Response time
    |              +----------------------------------- Resolved hostname
    +------------------------------------------------- Target IP address
```

#### Result Status Indicators

| Indicator | Meaning | Action |
|-----------|---------|--------|
| `is_alive: true` | Host responded to probe | Include in further testing |
| `is_alive: false` | No response received | May be filtered or offline |
| `tcp_connect:PORT` | TCP handshake completed | Port is open, host is live |
| `dns_ptr` | PTR record exists | Host has reverse DNS configured |
| `arp_fallback_tcp` | ARP unavailable, used TCP | Privilege limitation |

### JSON Output Parsing

**Complete JSON Structure:**

```json
{
  "scan_time": "2024-01-15T14:32:00.123456",
  "config": {
    "targets": ["192.168.1.0/24"],
    "methods": ["tcp", "dns"],
    "ports": [80, 443, 22]
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "is_alive": true,
      "response_time": 0.023,
      "method": "tcp_connect:80",
      "hostname": "gateway.local",
      "timestamp": "2024-01-15T14:32:01.234567"
    },
    {
      "ip": "192.168.1.2",
      "is_alive": false,
      "response_time": null,
      "method": "all_methods",
      "hostname": null,
      "timestamp": "2024-01-15T14:32:02.345678"
    }
  ]
}
```

**Common jq Queries:**

```bash
# Live host count
jq '[.results[] | select(.is_alive==true)] | length' results.json

# Live IPs only (one per line)
jq -r '.results[] | select(.is_alive==true) | .ip' results.json

# Hosts responding on specific port
jq -r '.results[] | select(.method | contains(":443")) | .ip' results.json

# Average response time of live hosts
jq '[.results[] | select(.is_alive==true) | .response_time] | add/length' results.json

# Export to CSV format
jq -r '.results[] | [.ip, .is_alive, .method, .hostname // "N/A"] | @csv' results.json
```

### Identifying Live Hosts

**Decision Matrix for Host Status:**

```
+--------------------+-------------------+---------------------------+
| Scan Result        | Interpretation    | Next Steps                |
+--------------------+-------------------+---------------------------+
| TCP connect: open  | Host confirmed    | Service enumeration       |
|                    | alive             |                           |
+--------------------+-------------------+---------------------------+
| DNS PTR: resolved  | Host exists in    | Verify with TCP scan      |
|                    | DNS               |                           |
+--------------------+-------------------+---------------------------+
| All methods:       | Possibly offline, | Try different ports,      |
| no response        | filtered, or slow | increase timeout          |
+--------------------+-------------------+---------------------------+
| Partial response   | Host alive but    | Note filtering, adjust    |
| (some ports)       | filtered          | approach                  |
+--------------------+-------------------+---------------------------+
```

---

## 6. Hands-On Lab Exercises

### Exercise 1: Basic Network Discovery

**Objective:** Perform initial network reconnaissance to identify all live hosts on a target subnet.

**Scenario:** You have been authorized to perform a penetration test on the 192.168.100.0/24 network. Your first task is to identify all responsive hosts before detailed enumeration.

**Environment Setup:**
- Target network: 192.168.100.0/24 (lab environment)
- Scanning system: Your assessment workstation
- Required privileges: Standard user (no root required)

**Tasks:**

1. **Plan the scan** (5 minutes)
   - Use plan mode to preview the operation
   - Document the number of hosts to be scanned
   - Note the default scan parameters

2. **Execute basic discovery** (10 minutes)
   - Run a standard TCP discovery scan
   - Enable verbose mode to observe progress
   - Record the number of live hosts found

3. **Enhance with hostname resolution** (5 minutes)
   - Re-run the scan with hostname resolution enabled
   - Export results to JSON format
   - Use jq to extract a clean list of live hosts

**Deliverables:**
- Screenshot of plan mode output
- Count of live hosts discovered
- JSON output file
- Text file listing live IP addresses

**Validation Criteria:**
- [ ] Successfully executed plan mode
- [ ] Identified all live hosts (verify against lab answer key)
- [ ] JSON output contains required fields
- [ ] Live host list is properly formatted

<details>
<summary>Hints (click to expand)</summary>

**Hint 1:** Start with `python tool.py 192.168.100.0/24 --plan`

**Hint 2:** Use `-v` flag to see real-time progress

**Hint 3:** Combine `-r` and `-o` flags for full output

</details>

<details>
<summary>Solution Guide</summary>

```bash
# Step 1: Plan the scan
python tool.py 192.168.100.0/24 --plan

# Step 2: Execute basic discovery
python tool.py 192.168.100.0/24 -v

# Step 3: Enhanced scan with output
python tool.py 192.168.100.0/24 -v --resolve -o lab1_results.json

# Extract live hosts
jq -r '.results[] | select(.is_alive==true) | .ip' lab1_results.json > live_hosts.txt
```

</details>

---

### Exercise 2: Stealth Scanning Configuration

**Objective:** Configure and execute a low-profile network scan that minimizes detection by network security controls.

**Scenario:** You are conducting a red team assessment where stealth is critical. The target network has IDS/IPS monitoring, and you need to discover live hosts without triggering alerts.

**Environment Setup:**
- Target network: 10.50.0.0/24
- Security controls: Network IDS monitoring all traffic
- Detection threshold: More than 10 connections per second triggers alert

**Tasks:**

1. **Calculate safe timing parameters** (5 minutes)
   - Determine appropriate delay values to stay under detection threshold
   - Select optimal thread count for stealth operation
   - Document your reasoning

2. **Configure stealth scan** (10 minutes)
   - Set delay parameters to maintain low connection rate
   - Limit concurrent threads appropriately
   - Select the least intrusive scanning method

3. **Execute and validate** (10 minutes)
   - Run the stealth scan
   - Calculate actual scan duration
   - Verify results match aggressive scan (optional comparison)

**Deliverables:**
- Written justification for timing parameters
- Complete command used for stealth scan
- Comparison of stealth vs. normal scan (optional)

**Validation Criteria:**
- [ ] Delay parameters prevent >10 connections/second
- [ ] Thread count is appropriately limited
- [ ] Scan completes successfully
- [ ] Results are accurate (if compared)

<details>
<summary>Hints (click to expand)</summary>

**Hint 1:** To stay under 10 connections/second with 2 threads, minimum delay should be ~0.2 seconds

**Hint 2:** DNS-only scans generate no direct target connections

**Hint 3:** Consider `--methods dns tcp` order - DNS first is less intrusive

</details>

<details>
<summary>Solution Guide</summary>

```bash
# Calculation:
# - 10 connections/second limit
# - With 2 threads: each thread can do 5 connections/second
# - Minimum delay: 1/5 = 0.2 seconds
# - Add margin: 0.3-0.5 second delay

# Stealth scan configuration
python tool.py 10.50.0.0/24 \
    --methods dns tcp \
    --threads 2 \
    --delay-min 0.3 \
    --delay-max 0.8 \
    --timeout 3.0 \
    --ports 443 \
    -v -o stealth_results.json

# For comparison (aggressive - DO NOT run during stealth exercise):
# python tool.py 10.50.0.0/24 --threads 20 --delay-max 0 -v
```

</details>

---

### Exercise 3: Tool Chaining and Automation

**Objective:** Integrate Network Scanner with other tools to create an automated reconnaissance pipeline.

**Scenario:** You need to establish a repeatable process that discovers hosts, then automatically feeds results into Nmap for service enumeration, and generates a consolidated report.

**Environment Setup:**
- Target networks: 192.168.1.0/24 and 192.168.2.0/24
- Required tools: Network Scanner, Nmap, jq
- Output location: ~/assessment/recon/

**Tasks:**

1. **Create discovery script** (15 minutes)
   - Write a bash script that scans multiple networks
   - Export results to timestamped JSON files
   - Extract live hosts into a consolidated target list

2. **Integrate with Nmap** (10 minutes)
   - Use Network Scanner output to create Nmap target list
   - Run Nmap service scan against discovered hosts
   - Save Nmap results in multiple formats

3. **Generate summary report** (10 minutes)
   - Parse JSON results to create summary statistics
   - Combine with Nmap output for comprehensive view
   - Create final deliverable document

**Deliverables:**
- `recon.sh` - Automated discovery script
- `live_targets.txt` - Consolidated host list
- `service_scan.*` - Nmap results (XML, nmap, gnmap)
- `summary.txt` - Statistics and findings summary

**Validation Criteria:**
- [ ] Script handles multiple network targets
- [ ] JSON files are properly timestamped
- [ ] Live host extraction works correctly
- [ ] Nmap scan completes against discovered hosts
- [ ] Summary includes host counts and key findings

<details>
<summary>Hints (click to expand)</summary>

**Hint 1:** Use `date +%Y%m%d_%H%M%S` for timestamps

**Hint 2:** `jq -s` can merge multiple JSON files

**Hint 3:** Nmap's `-iL` flag accepts a file of targets

</details>

<details>
<summary>Solution Guide</summary>

```bash
#!/bin/bash
# recon.sh - Automated reconnaissance pipeline

OUTDIR=~/assessment/recon
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGETS=("192.168.1.0/24" "192.168.2.0/24")

mkdir -p "$OUTDIR"

# Phase 1: Network Discovery
echo "[*] Starting network discovery..."
for target in "${TARGETS[@]}"; do
    safe_name=$(echo "$target" | tr '/' '_')
    python tool.py "$target" \
        --resolve \
        -o "${OUTDIR}/discovery_${safe_name}_${TIMESTAMP}.json"
done

# Phase 2: Extract live hosts
echo "[*] Extracting live hosts..."
cat ${OUTDIR}/discovery_*_${TIMESTAMP}.json | \
    jq -rs '[.[].results[] | select(.is_alive==true) | .ip] | unique | .[]' \
    > "${OUTDIR}/live_targets.txt"

LIVE_COUNT=$(wc -l < "${OUTDIR}/live_targets.txt")
echo "[*] Found $LIVE_COUNT live hosts"

# Phase 3: Service enumeration with Nmap
if [ "$LIVE_COUNT" -gt 0 ]; then
    echo "[*] Running service enumeration..."
    nmap -sV -sC -iL "${OUTDIR}/live_targets.txt" \
        -oA "${OUTDIR}/service_scan_${TIMESTAMP}"
fi

# Phase 4: Generate summary
echo "[*] Generating summary..."
cat > "${OUTDIR}/summary_${TIMESTAMP}.txt" << EOF
RECONNAISSANCE SUMMARY
Generated: $(date)
=====================================

NETWORK DISCOVERY
-----------------
Networks scanned: ${#TARGETS[@]}
Total live hosts: $LIVE_COUNT

LIVE HOSTS:
$(cat "${OUTDIR}/live_targets.txt")

SERVICE SCAN:
See service_scan_${TIMESTAMP}.nmap for details
=====================================
EOF

echo "[*] Complete. Results in $OUTDIR"
```

</details>

---

## 7. Troubleshooting Guide

### Common Errors and Solutions

#### Error: "Permission denied" or Socket Errors

**Symptom:**
```
[!] Error scanning 192.168.1.1: [Errno 13] Permission denied
```

**Cause:** ARP scanning requires raw socket privileges.

**Solution:**
```bash
# Option 1: Use TCP method instead (recommended)
python tool.py 192.168.1.0/24 --methods tcp

# Option 2: Run with elevated privileges (if ARP required)
sudo python tool.py 192.168.1.0/24 --methods arp
```

---

#### Error: "Invalid target specification"

**Symptom:**
```
[!] Invalid target specification: 192.168.1.256 - '256' does not appear to be an IPv4 or IPv6 address
```

**Cause:** IP address or range syntax error.

**Solution:**
```bash
# Verify IP addresses are valid (0-255 per octet)
# Correct formats:
python tool.py 192.168.1.1-254     # Range in last octet
python tool.py 192.168.1.0/24      # CIDR notation
python tool.py 192.168.1.1         # Single IP
```

---

#### Error: Scan takes extremely long

**Symptom:** Scan appears hung or takes hours for a /24.

**Cause:** High timeout with many unresponsive hosts, or excessive delays.

**Solution:**
```bash
# Reduce timeout for faster failure detection
python tool.py 192.168.1.0/24 --timeout 1.0

# Increase parallelism
python tool.py 192.168.1.0/24 --threads 50 --timeout 1.0

# Reduce inter-scan delays
python tool.py 192.168.1.0/24 --delay-max 0

# Scan fewer ports
python tool.py 192.168.1.0/24 --ports 80
```

---

#### Error: No hosts found (false negatives)

**Symptom:** Scan reports 0 live hosts when hosts are known to exist.

**Cause:** Firewall blocking scanned ports, timeout too low, or wrong scan method.

**Solution:**
```bash
# Try additional ports
python tool.py 192.168.1.0/24 --ports 22 80 443 8080 3389

# Increase timeout for slow networks
python tool.py 192.168.1.0/24 --timeout 5.0

# Use multiple methods
python tool.py 192.168.1.0/24 --methods tcp dns

# Enable verbose to see what's happening
python tool.py 192.168.1.0/24 -v --timeout 3.0
```

---

#### Error: JSON output file is empty or malformed

**Symptom:** Output file exists but contains incomplete JSON.

**Cause:** Scan interrupted before completion.

**Solution:**
```bash
# Allow scan to complete fully
# If interrupted, results up to that point are lost

# For large scans, consider segmenting:
python tool.py 192.168.1.0/25 -o results_part1.json
python tool.py 192.168.1.128/25 -o results_part2.json

# Then merge:
jq -s '.[0].results += .[1].results | .[0]' results_part1.json results_part2.json > combined.json
```

---

### Performance Optimization

#### Optimizing for Speed

```bash
# Maximum speed configuration
python tool.py TARGET \
    --threads 100 \
    --timeout 0.5 \
    --delay-max 0 \
    --ports 80 443

# Considerations:
# - May overwhelm target network
# - Higher false negative rate
# - Easily detected by security tools
```

#### Optimizing for Accuracy

```bash
# Maximum accuracy configuration
python tool.py TARGET \
    --threads 5 \
    --timeout 5.0 \
    --methods tcp dns \
    --ports 22 80 443 8080 8443 3389 \
    --resolve

# Considerations:
# - Significantly slower
# - Lower false negative rate
# - More comprehensive results
```

#### Optimizing for Stealth

```bash
# Maximum stealth configuration
python tool.py TARGET \
    --threads 1 \
    --timeout 10.0 \
    --delay-min 5.0 \
    --delay-max 30.0 \
    --methods dns \
    --ports 443

# Considerations:
# - Very slow (hours for /24)
# - Minimal detection footprint
# - DNS method requires no target contact
```

#### Resource Usage Guidelines

| Threads | Memory Impact | CPU Impact | Network Impact |
|---------|---------------|------------|----------------|
| 1-10 | Minimal | Low | Low |
| 10-50 | Low | Medium | Medium |
| 50-100 | Medium | High | High |
| 100+ | High | Very High | Very High |

---

## Appendix A: Quick Reference Card

```
NETWORK SCANNER QUICK REFERENCE
================================

BASIC USAGE:
  python tool.py TARGET [OPTIONS]

TARGET FORMATS:
  192.168.1.1          Single IP
  192.168.1.0/24       CIDR notation
  192.168.1.1-254      IP range

COMMON OPTIONS:
  -v, --verbose        Show progress
  -p, --plan           Preview only
  -r, --resolve        Resolve hostnames
  -o FILE              Save JSON output

TUNING OPTIONS:
  -t, --timeout SEC    Connection timeout (def: 2.0)
  -T, --threads N      Parallel threads (def: 10)
  -m, --methods LIST   tcp, arp, dns (def: tcp)
  -P, --ports LIST     TCP ports (def: 80 443 22)
  --delay-min SEC      Min delay (def: 0.0)
  --delay-max SEC      Max delay (def: 0.1)

PRESET CONFIGURATIONS:
  Fast:    -T 50 -t 0.5 --delay-max 0
  Normal:  (defaults)
  Stealth: -T 2 --delay-min 1 --delay-max 3

JSON PARSING:
  Live IPs: jq -r '.results[] | select(.is_alive) | .ip'
  Count:    jq '[.results[] | select(.is_alive)] | length'
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| ARP | Address Resolution Protocol - Layer 2 protocol for IP to MAC resolution |
| CIDR | Classless Inter-Domain Routing - Network notation (e.g., /24) |
| Jitter | Random timing variation to avoid pattern-based detection |
| OPSEC | Operational Security - Practices to minimize detection |
| PTR | Pointer Record - DNS record for reverse lookups |
| TCP Connect | Full TCP handshake scan technique |
| Thread Pool | Collection of worker threads for parallel execution |

---

**Document Version:** 1.0
**Last Updated:** 2024-01-15
**Classification:** Training Material - For Authorized Use Only
