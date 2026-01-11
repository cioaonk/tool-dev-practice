# Port Scanner Complete Training Guide

**Tool Version:** 1.0.0
**Category:** Reconnaissance
**Skill Level:** Beginner to Intermediate
**Estimated Training Time:** 3-4 hours

---

## Table of Contents

1. [Tool Overview](#1-tool-overview)
2. [Technical Architecture](#2-technical-architecture)
3. [Complete CLI Reference](#3-complete-cli-reference)
4. [Usage Scenarios](#4-usage-scenarios)
5. [Banner Grabbing Deep Dive](#5-banner-grabbing-deep-dive)
6. [Hands-On Labs](#6-hands-on-labs)
7. [Tool Comparison](#7-tool-comparison)
8. [Performance Tuning](#8-performance-tuning)
9. [Quick Reference Card](#9-quick-reference-card)

---

## 1. Tool Overview

### Purpose

The Port Scanner is an advanced TCP/UDP port scanning utility designed for authorized security assessments. It enables security professionals to discover open ports and running services on target systems, which is a critical first step in network reconnaissance and vulnerability assessment.

### Core Capabilities

- **Multiple Scan Types:** TCP Connect, TCP SYN (half-open), and UDP scanning
- **Flexible Port Targeting:** Single ports, ranges, lists, and predefined port sets
- **Stealth Features:** Port randomization, configurable delays, and jitter
- **Service Detection:** Automatic service identification based on port numbers
- **Banner Grabbing:** Active service fingerprinting through banner collection
- **Planning Mode:** Preview scan parameters before execution
- **Threaded Architecture:** High-performance concurrent scanning

### Scan Types Explained

```
+------------------+-------------+------------+----------------+
|    Scan Type     |  Stealth    | Privileges | Reliability    |
+------------------+-------------+------------+----------------+
| TCP Connect      |    Low      |   None     |     High       |
| TCP SYN          |   Medium    |   Root     |     High       |
| UDP              |    High     |   None     |     Low        |
+------------------+-------------+------------+----------------+
```

#### TCP Connect Scan

The TCP Connect scan performs a full three-way handshake with each target port:

```
    Scanner                    Target
       |                         |
       |  -----> SYN ------>     |
       |  <--- SYN/ACK <---      |  Port OPEN
       |  -----> ACK ------>     |
       |  -----> RST ------>     |  (Connection closed)
       |                         |
       |  -----> SYN ------>     |
       |  <----- RST <------     |  Port CLOSED
       |                         |
```

**Advantages:**
- No elevated privileges required
- Most reliable results
- Works through proxies

**Disadvantages:**
- Easily detected and logged
- Creates full connections in target logs
- Slower due to complete handshake

#### TCP SYN Scan (Half-Open)

The SYN scan sends only the initial SYN packet and analyzes the response:

```
    Scanner                    Target
       |                         |
       |  -----> SYN ------>     |
       |  <--- SYN/ACK <---      |  Port OPEN (RST sent to close)
       |  -----> RST ------>     |
       |                         |
       |  -----> SYN ------>     |
       |  <----- RST <------     |  Port CLOSED
       |                         |
```

**Advantages:**
- Stealthier than Connect scan
- Faster execution
- May avoid some logging mechanisms

**Disadvantages:**
- Requires root/administrator privileges
- May trigger IDS/IPS alerts
- Falls back to Connect scan without privileges

#### UDP Scan

UDP scanning sends packets to target ports and analyzes responses:

```
    Scanner                    Target
       |                         |
       |  --> UDP Packet -->     |
       |  <-- UDP Response <--   |  Port OPEN (service responded)
       |                         |
       |  --> UDP Packet -->     |
       |  <-- ICMP Unreachable   |  Port CLOSED
       |                         |
       |  --> UDP Packet -->     |
       |       (silence)         |  Port OPEN|FILTERED
       |                         |
```

**Advantages:**
- Discovers UDP services (DNS, SNMP, etc.)
- No privileges required

**Disadvantages:**
- Slow and unreliable
- Many firewalls block ICMP responses
- Cannot distinguish open from filtered ports

---

## 2. Technical Architecture

### Code Structure Overview

```
port-scanner/
    tool.py
       |
       +-- Configuration & Constants
       |      - DEFAULT_TIMEOUT (1.0s)
       |      - DEFAULT_THREADS (50)
       |      - TOP_20_PORTS / TOP_100_PORTS
       |      - SERVICE_PORTS mapping
       |
       +-- Enums & Data Classes
       |      - PortState (OPEN, CLOSED, FILTERED, etc.)
       |      - ScanType (TCP_CONNECT, TCP_SYN, UDP)
       |      - PortResult (scan result container)
       |      - ScanConfig (configuration object)
       |      - ScanReport (aggregated results)
       |
       +-- Scan Techniques (Abstract Pattern)
       |      - ScanTechnique (base class)
       |      - TCPConnectScan
       |      - TCPSYNScan
       |      - UDPScan
       |
       +-- Core Scanner Engine
       |      - PortScanner class
       |
       +-- CLI Interface
              - parse_arguments()
              - main()
```

### Key Classes and Their Roles

#### PortState Enum

Represents possible states for scanned ports:

```python
class PortState(Enum):
    OPEN = "open"           # Port accepting connections
    CLOSED = "closed"       # Port reachable but no service
    FILTERED = "filtered"   # Firewall blocking access
    OPEN_FILTERED = "open|filtered"  # UDP uncertainty
    UNKNOWN = "unknown"     # Unable to determine
```

#### ScanConfig Dataclass

Configuration container passed throughout the scanner:

```python
@dataclass
class ScanConfig:
    target: str = ""                    # Target host
    ports: List[int] = field(...)       # Ports to scan
    scan_type: ScanType = TCP_CONNECT   # Scan method
    timeout: float = 1.0                # Socket timeout
    threads: int = 50                   # Concurrency level
    delay_min: float = 0.0              # Min jitter delay
    delay_max: float = 0.05             # Max jitter delay
    banner_grab: bool = False           # Enable banner grabbing
    randomize_ports: bool = True        # Shuffle port order
    verbose: bool = False               # Verbose output
    plan_mode: bool = False             # Preview only
```

#### PortScanner Class

The main scanning engine orchestrating all operations:

```
                    +-------------------+
                    |   PortScanner     |
                    +-------------------+
                    | - config          |
                    | - report          |
                    | - _stop_event     |
                    | - _lock           |
                    | - _technique      |
                    +-------------------+
                    | + scan()          |
                    | + stop()          |
                    | - _resolve_target |
                    | - _apply_jitter   |
                    | - _scan_single    |
                    +-------------------+
                            |
             +--------------+--------------+
             |              |              |
      TCPConnectScan   TCPSYNScan      UDPScan
```

### Threading Model

The scanner uses Python's `ThreadPoolExecutor` for concurrent port scanning:

```
                        +------------------+
                        |  Main Thread     |
                        +------------------+
                               |
                    Creates ThreadPoolExecutor
                               |
          +--------------------+--------------------+
          |          |         |         |         |
       Thread-1   Thread-2  Thread-3  Thread-N   ...
          |          |         |         |
      Port 443    Port 22   Port 80   Port 3389
          |          |         |         |
          +--------------------+--------------------+
                               |
                    Results aggregated via Lock
                               |
                        +------------------+
                        |   ScanReport     |
                        +------------------+
```

**Key Threading Features:**

1. **Work Distribution:** Ports submitted as futures to the executor
2. **Thread Safety:** `threading.Lock` protects result aggregation
3. **Graceful Shutdown:** `threading.Event` signals workers to stop
4. **Result Collection:** `as_completed()` provides results as they finish

### Scan Flow Diagram

```
    +-------------+     +---------------+     +----------------+
    | CLI Input   | --> | Parse Args    | --> | Build Config   |
    +-------------+     +---------------+     +----------------+
                                                      |
                               +----------------------+
                               v
                        +-------------+
                        | Plan Mode?  |----Yes----> Print Plan & Exit
                        +-------------+
                               | No
                               v
                        +-------------+
                        | Resolve DNS |
                        +-------------+
                               |
                               v
                    +-------------------+
                    | Randomize Ports?  |
                    +-------------------+
                               |
                               v
                    +-------------------+
                    | ThreadPoolExecutor|
                    +-------------------+
                               |
            +------------------+------------------+
            |                  |                  |
            v                  v                  v
    +---------------+  +---------------+  +---------------+
    | Scan Port N   |  | Scan Port N+1 |  | Scan Port N+2 |
    | Apply Jitter  |  | Apply Jitter  |  | Apply Jitter  |
    | Get Result    |  | Get Result    |  | Get Result    |
    +---------------+  +---------------+  +---------------+
            |                  |                  |
            +------------------+------------------+
                               |
                               v
                    +-------------------+
                    | Aggregate Results |
                    +-------------------+
                               |
                               v
                    +-------------------+
                    | Generate Report   |
                    +-------------------+
```

---

## 3. Complete CLI Reference

### Basic Syntax

```bash
python tool.py <target> [options]
```

### Positional Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `target` | Target IP address or hostname | Yes |

### Port Specification Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--ports` | `-P` | `top20` | Port specification |

**Port Specification Formats:**

```bash
# Single port
--ports 80

# Port range
--ports 1-1024

# Port list
--ports 22,80,443,8080

# Combined format
--ports 22,80,443,8000-8100

# Keywords
--ports top20      # Most common 20 ports
--ports top100     # Most common 100 ports
--ports all        # All 65535 ports (use with caution)
```

**Top 20 Ports Include:**
```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS),
80 (HTTP), 110 (POP3), 111 (RPC), 135 (MSRPC), 139 (NetBIOS),
143 (IMAP), 443 (HTTPS), 445 (SMB), 993 (IMAPS), 995 (POP3S),
1723 (PPTP), 3306 (MySQL), 3389 (RDP), 5900 (VNC), 8080 (HTTP-Proxy)
```

### Scan Type Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--scan-type` | `-s` | `connect` | Scan technique |

**Available Types:**
- `connect` - Full TCP handshake (no privileges needed)
- `syn` - Half-open SYN scan (requires root)
- `udp` - UDP port scan

### Timing and Performance Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--timeout` | `-t` | `1.0` | Socket timeout in seconds |
| `--threads` | `-T` | `50` | Concurrent threads |
| `--delay-min` | - | `0.0` | Minimum delay between scans |
| `--delay-max` | - | `0.05` | Maximum delay between scans |

### Feature Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--banner` | `-b` | `false` | Enable banner grabbing |
| `--no-randomize` | - | `false` | Disable port randomization |
| `--verbose` | `-v` | `false` | Verbose output |
| `--plan` | `-p` | `false` | Show plan without scanning |
| `--output` | `-o` | - | Save results to JSON file |

### Complete Examples

```bash
# Preview scan plan (no actual scanning)
python tool.py 192.168.1.1 --plan

# Quick scan of default top 20 ports
python tool.py 192.168.1.1

# Scan specific ports with verbose output
python tool.py 192.168.1.1 -P 22,80,443,8080 -v

# Comprehensive scan with banner grabbing
python tool.py 10.0.0.1 --ports 1-1024 --banner --verbose

# Stealth scan with increased delays
python tool.py target.com -P top100 --delay-min 0.5 --delay-max 2.0

# High-speed scan (use responsibly)
python tool.py 192.168.1.0/24 -P top20 -T 200 --timeout 0.5

# UDP service discovery
python tool.py 192.168.1.1 -s udp -P 53,67,68,123,161,162,500

# Save results to file
python tool.py 192.168.1.1 -P top100 -b -o scan_results.json
```

---

## 4. Usage Scenarios

### Scenario 1: Quick Service Discovery

**Objective:** Rapidly identify common services on a target.

```bash
python tool.py 192.168.1.100 -P top20 -v
```

**Expected Output:**
```
[*] Port Scanner starting...
[*] Target: 192.168.1.100
[*] Ports: 20
[*] Scanning 20 ports on 192.168.1.100 (192.168.1.100)
[*] Scan type: TCP Connect
[+] 22/tcp open - ssh
[+] 80/tcp open - http
[+] 443/tcp open - https

============================================================
SCAN RESULTS
============================================================
Target:       192.168.1.100
Resolved IP:  192.168.1.100
Scan Type:    connect
Duration:     2.34s

Open ports:     3
Filtered ports: 0

OPEN PORTS:
------------------------------------------------------------
  22/tcp open  ssh
  80/tcp open  http
  443/tcp open  https
```

### Scenario 2: Comprehensive Network Audit

**Objective:** Thorough port scan with service identification.

```bash
python tool.py 10.0.0.50 --ports 1-10000 --banner --threads 100 --verbose --output audit.json
```

**Use Case:** Initial reconnaissance during authorized penetration test.

### Scenario 3: Stealth Configuration

**Objective:** Minimize detection while scanning.

```bash
python tool.py target.com \
    --ports top100 \
    --delay-min 1.0 \
    --delay-max 5.0 \
    --threads 5 \
    --timeout 2.0
```

**Stealth Techniques Applied:**
- Reduced thread count (5 vs default 50)
- Significant random delays (1-5 seconds)
- Port randomization (enabled by default)
- Longer timeout to avoid retransmissions

### Scenario 4: Pre-Engagement Planning

**Objective:** Review scan parameters before execution.

```bash
python tool.py 192.168.1.1 --ports 1-1024 --banner --threads 100 --plan
```

**Output Includes:**
- Target resolution verification
- Full configuration summary
- Actions to be performed
- Time estimates
- Risk assessment
- Detection vectors

### Scenario 5: UDP Service Discovery

**Objective:** Identify UDP services (DNS, SNMP, etc.).

```bash
python tool.py 192.168.1.1 \
    --scan-type udp \
    --ports 53,67,68,69,123,161,162,500,514,520 \
    --timeout 3.0 \
    --verbose
```

**Note:** UDP scanning is inherently slower and less reliable. Increase timeout and expect many "open|filtered" results.

---

## 5. Banner Grabbing Deep Dive

### How Banner Grabbing Works

Banner grabbing is an active reconnaissance technique that collects service identification strings from open ports. The scanner implements protocol-aware probing:

```
    Scanner                         Target Service
       |                                  |
       |   TCP Connection Established     |
       |=================================>|
       |                                  |
       |   Protocol-Specific Probe        |
       |--------------------------------->|
       |   (HTTP: "HEAD / HTTP/1.0")     |
       |   (SSH: wait for banner)         |
       |                                  |
       |   Service Banner Response        |
       |<---------------------------------|
       |   "SSH-2.0-OpenSSH_8.2p1"       |
       |                                  |
```

### Protocol-Specific Probes

The tool sends different probes based on the target port:

| Port | Service | Probe Strategy |
|------|---------|----------------|
| 21 | FTP | Wait for server banner |
| 22 | SSH | Wait for server banner |
| 25 | SMTP | Wait for server banner |
| 80 | HTTP | Send `HEAD / HTTP/1.0\r\n\r\n` |
| Other | Generic | Wait for data or send null |

### Implementation Details

```python
def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
    """Attempt to grab service banner."""
    try:
        # Protocol-specific probes
        probes = {
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"",   # HTTPS needs TLS
            22: b"",    # SSH sends banner first
            21: b"",    # FTP sends banner first
            25: b"",    # SMTP sends banner first
        }

        probe = probes.get(port, b"")
        if probe:
            sock.send(probe)

        sock.settimeout(2.0)
        banner = sock.recv(1024)
        return banner.decode('utf-8', errors='ignore').strip()[:200]
    except Exception:
        return None
```

### Banner Examples

**SSH Banner:**
```
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```

**HTTP Banner:**
```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
```

**FTP Banner:**
```
220 (vsFTPd 3.0.3)
```

**SMTP Banner:**
```
220 mail.example.com ESMTP Postfix
```

### Security Implications

Banner information reveals:
- Service name and version
- Operating system details
- Configuration information
- Potential vulnerability targets

**OPSEC Consideration:** Banner grabbing creates additional traffic and log entries. Use judiciously during stealth operations.

---

## 6. Hands-On Labs

### Lab 1: Basic Port Discovery (Beginner)

**Objective:** Perform basic port scanning against a Docker target.

**Environment Setup:**
```bash
# Start vulnerable web application container
docker run -d --name lab1-target -p 8080:80 -p 8443:443 nginx:latest

# Verify container is running
docker ps
```

**Exercise Tasks:**

1. **Task 1.1:** Run a plan-mode scan to preview parameters
   ```bash
   python tool.py localhost --ports 8080,8443 --plan
   ```

2. **Task 1.2:** Execute the scan with verbose output
   ```bash
   python tool.py localhost --ports 8080,8443 --verbose
   ```

3. **Task 1.3:** Add banner grabbing to identify the service
   ```bash
   python tool.py localhost --ports 8080,8443 --banner --verbose
   ```

**Expected Results:**
- Port 8080: OPEN (http)
- Port 8443: OPEN (https-alt) or CLOSED if SSL not configured
- Banner should show "nginx" server identification

**Validation:**
```bash
# Verify with netcat
nc -zv localhost 8080
```

**Cleanup:**
```bash
docker stop lab1-target && docker rm lab1-target
```

---

### Lab 2: Multi-Service Environment (Intermediate)

**Objective:** Scan a complex environment with multiple services.

**Environment Setup:**
```bash
# Create Docker network
docker network create lab2-net

# Deploy multiple services
docker run -d --name lab2-web --network lab2-net -p 80:80 nginx:latest
docker run -d --name lab2-db --network lab2-net -p 3306:3306 \
    -e MYSQL_ROOT_PASSWORD=labpassword mysql:8.0
docker run -d --name lab2-ssh --network lab2-net -p 2222:22 \
    rastasheep/ubuntu-sshd:18.04
```

**Exercise Tasks:**

1. **Task 2.1:** Quick scan to identify open ports
   ```bash
   python tool.py localhost --ports 22,80,443,2222,3306,5432,8080 --verbose
   ```

2. **Task 2.2:** Full scan with service detection
   ```bash
   python tool.py localhost \
       --ports 1-10000 \
       --threads 100 \
       --banner \
       --verbose \
       --output lab2_results.json
   ```

3. **Task 2.3:** Analyze results and identify services
   ```bash
   cat lab2_results.json | python -m json.tool
   ```

**Challenge Questions:**
- Which ports are open?
- What services are running based on banners?
- Are there any unexpected open ports?

**Validation Criteria:**
- Correctly identified HTTP on port 80
- Correctly identified MySQL on port 3306
- Correctly identified SSH on port 2222
- Results saved to JSON file

**Cleanup:**
```bash
docker stop lab2-web lab2-db lab2-ssh
docker rm lab2-web lab2-db lab2-ssh
docker network rm lab2-net
```

---

### Lab 3: CORE Network Reconnaissance (Advanced)

**Objective:** Conduct reconnaissance against a simulated network environment using CORE (Common Open Research Emulator).

**Environment Setup:**

Using CORE network emulator, create a topology with:
- Router (10.0.0.1)
- Web Server (10.0.1.10)
- Database Server (10.0.1.20)
- Workstation (10.0.2.100)

**Exercise Tasks:**

1. **Task 3.1:** Network sweep for live hosts
   ```bash
   # Scan each subnet's common gateway
   for subnet in 10.0.0.1 10.0.1.1 10.0.2.1; do
       python tool.py $subnet --ports 22,80,443 --timeout 0.5 --verbose
   done
   ```

2. **Task 3.2:** Targeted scan of discovered hosts
   ```bash
   python tool.py 10.0.1.10 --ports top100 --banner --verbose
   python tool.py 10.0.1.20 --ports top100 --banner --verbose
   ```

3. **Task 3.3:** Stealth scan of sensitive target
   ```bash
   python tool.py 10.0.2.100 \
       --ports top100 \
       --delay-min 2.0 \
       --delay-max 10.0 \
       --threads 3 \
       --timeout 3.0 \
       --verbose
   ```

4. **Task 3.4:** Document findings
   Create a reconnaissance report including:
   - Network topology discovered
   - Open ports per host
   - Services identified
   - Potential attack vectors

**Advanced Challenge:**
- Compare scan times between aggressive and stealth configurations
- Analyze any IDS alerts generated (if monitoring is configured)
- Identify service versions from banners

**Hints (Progressive):**

*Hint 1:* Use `--plan` mode first to estimate scan duration.

*Hint 2:* Start with quick scans (top20) before comprehensive scans.

*Hint 3:* For the stealth scan, consider the trade-off between speed and detection.

**Solution Guide (Instructor Reference):**

Expected findings for typical CORE lab setup:
- 10.0.0.1 (Router): Ports 22 (SSH management)
- 10.0.1.10 (Web): Ports 22, 80, 443
- 10.0.1.20 (Database): Ports 22, 3306 or 5432
- 10.0.2.100 (Workstation): Ports 22, possibly 139/445

---

## 7. Tool Comparison

### Port Scanner vs. Nmap

```
+-------------------+------------------+------------------+
|     Feature       |   Port Scanner   |      Nmap        |
+-------------------+------------------+------------------+
| Scan Types        | Connect,SYN,UDP  | 12+ scan types   |
| OS Detection      |        No        |       Yes        |
| Version Detection | Basic (banner)   | Advanced probes  |
| Scripting Engine  |        No        |  NSE (600+ )     |
| Output Formats    |    JSON only     | XML,JSON,etc.    |
| Learning Curve    |       Low        |      Medium      |
| Dependencies      |   Python only    | Requires install |
| Customization     |   Source code    |   NSE scripts    |
| Stealth Features  |  Good (jitter)   |    Excellent     |
+-------------------+------------------+------------------+
```

**When to Use Port Scanner:**
- Quick reconnaissance with minimal footprint
- Environments where nmap is unavailable
- Custom integration with Python workflows
- Learning port scanning fundamentals

**When to Use Nmap:**
- Comprehensive security assessments
- OS and service version detection
- Vulnerability scanning with NSE
- Complex scan configurations

### Port Scanner vs. Masscan

```
+-------------------+------------------+------------------+
|     Feature       |   Port Scanner   |     Masscan      |
+-------------------+------------------+------------------+
| Speed             |     Medium       |  Extremely Fast  |
| Accuracy          |       High       |      Medium      |
| Stealth           |      Good        |       Poor       |
| Banner Grabbing   |       Yes        |   Limited        |
| Ease of Use       |       High       |      Medium      |
| Network Impact    |       Low        |       High       |
+-------------------+------------------+------------------+
```

**When to Use Port Scanner:**
- Targeted host scanning
- Banner collection needed
- Stealth is important
- Moderate port ranges

**When to Use Masscan:**
- Internet-wide scanning
- Large network ranges
- Speed over stealth
- Initial discovery phase

### Advantages of This Tool

1. **Simplicity:** Single Python file, no complex dependencies
2. **Transparency:** Full source code access for learning/modification
3. **Integration:** Easy to import as a Python module
4. **Planning Mode:** Preview scans before execution
5. **Operational Focus:** Built-in OPSEC considerations

### Disadvantages

1. **Limited Scan Types:** Only Connect, SYN, and UDP
2. **No OS Detection:** Cannot fingerprint operating systems
3. **Basic Service Detection:** Relies on port numbers and banners
4. **No Scripting:** Cannot extend with custom probes
5. **Single Host Focus:** Not optimized for large-scale scanning

---

## 8. Performance Tuning

### Thread Optimization

The thread count significantly impacts scan performance:

```
Threads vs. Scan Time (1024 ports, 1s timeout)
================================================

Threads  |  Estimated Time  |  Notes
---------|------------------|----------------------------------
    10   |    ~102 seconds  |  Very slow, minimal detection
    25   |     ~41 seconds  |  Slow, low network impact
    50   |     ~21 seconds  |  Default, balanced performance
   100   |     ~11 seconds  |  Fast, moderate network load
   200   |      ~6 seconds  |  Very fast, high network load
   500   |      ~3 seconds  |  Aggressive, may cause issues
```

**Recommendations:**

| Environment | Recommended Threads |
|-------------|---------------------|
| Stealth operation | 5-10 |
| Standard assessment | 50-100 |
| Internal network | 100-200 |
| Lab environment | 200-500 |

### Timeout Settings

```
Timeout Impact Analysis
========================

Timeout  |  Filtered Detection  |  Speed Impact
---------|----------------------|---------------
  0.25s  |  May miss slow hosts |  Very fast
  0.50s  |  Good for local nets |  Fast
  1.00s  |  Default, reliable   |  Moderate
  2.00s  |  High reliability    |  Slow
  5.00s  |  Maximum reliability |  Very slow
```

**Guidelines:**
- Local networks: 0.5-1.0 seconds
- Remote targets: 1.0-2.0 seconds
- High-latency networks: 2.0-5.0 seconds
- UDP scanning: 2.0-3.0 seconds (minimum)

### Delay Configuration

Delays introduce jitter between scans for stealth:

```python
# Aggressive (fast, easily detected)
--delay-min 0.0 --delay-max 0.01

# Default (balanced)
--delay-min 0.0 --delay-max 0.05

# Moderate stealth
--delay-min 0.1 --delay-max 0.5

# High stealth
--delay-min 1.0 --delay-max 5.0

# Maximum stealth
--delay-min 5.0 --delay-max 30.0
```

### Optimal Configurations

**Speed Priority (Lab/Internal):**
```bash
python tool.py target --threads 200 --timeout 0.5 --delay-max 0.01
```

**Balanced (Standard Assessment):**
```bash
python tool.py target --threads 50 --timeout 1.0 --delay-max 0.1
```

**Stealth Priority (External/Sensitive):**
```bash
python tool.py target --threads 5 --timeout 2.0 --delay-min 1.0 --delay-max 5.0
```

### Memory and Resource Considerations

- Each thread maintains its own socket connection
- Banner grabbing increases memory usage slightly
- Large port ranges (--ports all) consume more memory
- Results stored in memory until scan completion

**Resource Estimation:**
```
Memory ~ (threads * 2KB) + (open_ports * 1KB) + base_overhead
```

For most scans, memory usage remains under 50MB.

---

## 9. Quick Reference Card

### Essential Commands

```bash
# Basic scan (top 20 ports)
python tool.py <target>

# Scan specific ports
python tool.py <target> -P 22,80,443

# Scan port range
python tool.py <target> -P 1-1024

# Common ports with banner grabbing
python tool.py <target> -P top100 -b -v

# Stealth scan
python tool.py <target> -P top100 --delay-min 1 --delay-max 5 -T 10

# UDP scan
python tool.py <target> -s udp -P 53,161,500

# Preview scan (no execution)
python tool.py <target> -P 1-1024 --plan

# Save results
python tool.py <target> -P top100 -o results.json
```

### Port Specification Cheatsheet

| Format | Example | Description |
|--------|---------|-------------|
| Single | `80` | Port 80 only |
| Range | `1-1024` | Ports 1 through 1024 |
| List | `22,80,443` | Specific ports |
| Mixed | `22,80,8000-8100` | Combined format |
| Keyword | `top20` | Common 20 ports |
| Keyword | `top100` | Common 100 ports |
| Keyword | `all` | All 65535 ports |

### Scan Type Quick Reference

| Type | Flag | Privileges | Speed | Stealth |
|------|------|------------|-------|---------|
| TCP Connect | `-s connect` | None | Medium | Low |
| TCP SYN | `-s syn` | Root | Fast | Medium |
| UDP | `-s udp` | None | Slow | High |

### Output States

| State | Meaning |
|-------|---------|
| `open` | Port accepting connections |
| `closed` | Port reachable, no service |
| `filtered` | Firewall blocking access |
| `open\|filtered` | UDP uncertainty |

---

## Assessment Questions

1. What is the primary difference between TCP Connect and TCP SYN scans?
2. Why does UDP scanning often report ports as "open|filtered"?
3. What configuration would you use to minimize detection during a scan?
4. How does port randomization improve operational security?
5. What information can be extracted from service banners?
6. When would you use planning mode before executing a scan?
7. What are the trade-offs between thread count and scan time?
8. How does this tool compare to nmap for comprehensive assessments?

---

## Additional Resources

- Tool Source Code: `/Users/ic/cptc11/python/tools/port-scanner/tool.py`
- RFC 793: Transmission Control Protocol
- RFC 768: User Datagram Protocol
- NIST SP 800-115: Technical Guide to Information Security Testing

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Author:** Offensive Security Training Team

**DISCLAIMER:** This tool and training material are intended for authorized security testing only. Unauthorized port scanning may violate computer crime laws. Always obtain proper authorization before conducting any security assessments.
