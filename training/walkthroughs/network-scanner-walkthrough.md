# Network Scanner Walkthrough

**Skill Level**: Beginner to Intermediate [B/I]

A comprehensive guide to network reconnaissance using the CPTC toolkit scanning utilities.

> **New to security?** Review the [Glossary](../GLOSSARY.md) for definitions of technical terms used in this walkthrough.

---

## Prerequisites

Before starting this walkthrough, ensure you:

- [ ] Have Python 3.8+ installed (`python3 --version`)
- [ ] Can access the tools directory
- [ ] Understand what an IP address is (e.g., 192.168.1.1)
- [ ] Know how to use a command-line terminal
- [ ] Have read permission for the lab network (authorized testing only)

**Recommended Reading**: [Glossary](../GLOSSARY.md) entries for: Port, Protocol, TCP, CIDR, Reconnaissance

---

## Module Overview

### Purpose
Master network reconnaissance techniques essential for identifying live hosts, open ports, and running services in target environments. These skills form the foundation of any penetration test or CTF competition.

> **What is reconnaissance?** The process of gathering information about a target network before attempting to gain access. Good reconnaissance is like scouting a location before a trip - it helps you know what to expect.

### Learning Objectives
By completing this walkthrough, you will be able to:
- Discover live hosts on network segments using multiple techniques
- Perform comprehensive port scanning with appropriate stealth levels
- Fingerprint services to identify versions and potential vulnerabilities
- Enumerate DNS records and discover subdomains
- Chain tools together for efficient reconnaissance workflows

### Time Estimate
- Reading: 45 minutes
- Hands-on Practice: 2-3 hours

---

## Part 1: Conceptual Foundation

### The Reconnaissance Phase

Reconnaissance is the first phase of any security assessment. Quality reconnaissance directly impacts your success rate - thorough enumeration reveals attack vectors that rushed scanning misses.

#### Why Reconnaissance Matters

```
Poor Recon        -> Miss 60% of attack surface -> Limited exploitation options
Thorough Recon    -> Complete visibility        -> Maximum exploitation options
```

#### The Recon Hierarchy

1. **Host Discovery** - Which machines are alive?
2. **Port Scanning** - Which ports are open?
3. **Service Fingerprinting** - What services/versions are running?
4. **Vulnerability Mapping** - What can be exploited?

### Network Scanning Fundamentals

#### How TCP Connect Scanning Works

> **Key Terms**:
> - **SYN** (Synchronize): "Hello, I want to connect"
> - **ACK** (Acknowledge): "I received your message"
> - **RST** (Reset): "Connection refused/closed"

**When the port is OPEN** (service is listening):
```
Your Machine                    Target (port open)
    |                                |
    | -------- SYN ---------------> |  Step 1: You say "Hello"
    |                                |
    | <------- SYN/ACK ------------ |  Step 2: Server says "Hello back, ready"
    |                                |
    | -------- ACK ---------------> |  Step 3: You say "Great, connected"
    |                                |
    [Connection Established - Port Open]
```

**When the port is CLOSED** (no service listening):
```
Your Machine                    Target (port closed)
    |                                |
    | -------- SYN ---------------> |  Step 1: You say "Hello"
    |                                |
    | <------- RST ---------------- |  Step 2: Server says "Go away"
    |                                |
    [Connection Refused - Port Closed]
```

#### Scanning Method Comparison

| Method | Speed | Stealth | Accuracy | Privileges | Best For |
|--------|-------|---------|----------|------------|----------|
| TCP Connect | Medium | Low | High | None | General use, beginners |
| TCP SYN | Fast | Medium | High | Root | Fast scans when you have admin access |
| UDP | Slow | Medium | Low | Root | Finding services like DNS, SNMP |
| ARP | Fast | High (LAN) | High | Root | Local network discovery only |
| DNS | Fast | High | Medium | None | Finding hostnames without direct probing |

> **Note on Privileges**: "Root" means administrator access on Linux/Mac or elevated cmd/PowerShell on Windows. Without root privileges, tools will use TCP Connect which works but creates more log entries on the target.

### Operational Security (OPSEC) Considerations

> **What is OPSEC?** Operational Security means being aware of what traces you leave behind. In security testing, this affects whether defenders detect your activities.

Every network scan leaves traces. Understanding what traces you leave helps you make informed decisions about scan aggressiveness.

#### What Gets Logged

| Action | Logged By | Log Location | Detection Risk |
|--------|-----------|--------------|----------------|
| TCP Connect | Target OS | System/Security logs | HIGH - Full connection recorded |
| DNS Query | DNS Server | Query logs | LOW - Common traffic |
| ARP Request | Network devices | ARP tables (temporary) | LOW - Normal network traffic |
| Failed Auth | Applications | Application logs | HIGH - May trigger alerts |

> **Competition Note**: In CPTC, aggressive scanning may trigger defensive alerts and cost points. Always consider stealth requirements in competition rules.

#### Stealth Continuum

```
More Stealthy                                    Less Stealthy
<---------------------------------------------------------->
DNS Lookup | ARP (LAN) | Slow TCP | Fast TCP | All Ports
   |            |           |          |           |
 Least      Only works   Adds      High        Maximum
 intrusive   locally    delays    traffic      noise
```

**When to use each approach:**
- **Competition with stealth scoring**: Use slow TCP with delays
- **CTF with time pressure**: Fast TCP on common ports
- **Real engagement**: Start stealthy, escalate if needed

---

## Part 2: Network Scanner Deep-Dive

### Tool Location

```
/path/to/tools/network-scanner/tool.py
```

### Core Capabilities

The Network Scanner performs host discovery using:
- **TCP Connect Probes** - Tests connectivity on specified ports
- **ARP Discovery** - Fast local network host detection
- **DNS Reverse Lookup** - Identifies hosts with PTR records

### Basic Usage Patterns

#### Pattern 1: Single Target Assessment

```bash
# First, always preview your scan
python3 tool.py 192.168.1.100 --plan
```

**Expected Output:**
```
[PLAN MODE] Network Scanner
============================================================
Configuration:
  Targets: 192.168.1.100
  Methods: tcp
  Ports: 80, 443, 22
  Timeout: 2.0s
  Threads: 10

Actions:
  1. Resolve target to IP address
  2. Probe 3 TCP ports per host
  3. Report live hosts to stdout

Estimated time: <1 second
Total probes: 3
```

```bash
# Execute the scan
python3 tool.py 192.168.1.100
```

#### Pattern 2: Network Range Scanning

```bash
# Scan a /24 network (254 hosts)
python3 tool.py 192.168.1.0/24 --plan
```

**Understanding the output:**
```
[PLAN MODE] Network Scanner
============================================================
Configuration:
  Targets: 192.168.1.0/24 (254 hosts)
  Methods: tcp
  Ports: 80, 443, 22
  Threads: 10

Actions:
  1. Expand CIDR to 254 target IPs
  2. Probe 3 TCP ports per host (762 total probes)
  3. Report live hosts to stdout

Estimated time: ~25 seconds (parallel execution)
Total probes: 762
```

```bash
# Execute with progress
python3 tool.py 192.168.1.0/24 --verbose
```

#### Pattern 3: Stealthy Scanning

For environments with monitoring (when detection avoidance matters):

```bash
# Slow scan with randomized delays
python3 tool.py 192.168.1.0/24 \
    --methods tcp \
    --delay-min 2 \
    --delay-max 10 \
    --threads 2 \
    --verbose
```

**Why these options:**
- `--delay-min 2 --delay-max 10`: Random 2-10 **second** delays evade rate-based detection
- `--threads 2`: Low parallelism reduces traffic spikes
- Sequential probes blend with normal network traffic

> **OPSEC Note**: IDS/IPS systems often trigger alerts based on:
> - Many connections in a short time period
> - Sequential port scanning (port 1, 2, 3, 4...)
> - Connections to many hosts rapidly
>
> The stealth options help avoid these detection patterns, but increase scan time significantly.

### Advanced Usage

#### Multi-Method Discovery

```bash
# Combine methods for thorough discovery
python3 tool.py 192.168.1.0/24 \
    --methods tcp dns \
    --ports 22 80 443 445 3389 8080 \
    --resolve \
    --verbose
```

**Method Selection Guide:**
- Use `tcp` for reliable detection on common ports
- Use `dns` to find hosts with reverse DNS entries
- Use `arp` on local networks for fastest discovery (requires privileges)

#### Saving Results

```bash
# Save for later analysis
python3 tool.py 192.168.1.0/24 --output scan-results.json
```

**JSON Output Structure:**
```json
{
  "scan_time": "2026-01-10T14:30:00.000000",
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
      "hostname": "gateway.local",
      "timestamp": "2026-01-10T14:30:05.123456"
    }
  ]
}
```

### Programmatic Integration

```python
from tool import NetworkScanner, ScanConfig

# Create configuration
config = ScanConfig(
    targets=["192.168.1.0/24"],
    timeout=2.0,
    threads=10,
    scan_methods=["tcp", "dns"],
    tcp_ports=[22, 80, 443, 445, 3389],
    resolve_hostnames=True
)

# Initialize scanner
scanner = NetworkScanner(config)

# Execute scan
results = scanner.scan()

# Process results
live_hosts = scanner.get_live_hosts()
for host in live_hosts:
    print(f"[+] {host.ip} ({host.hostname}) - {host.method}")
```

---

## Part 3: Port Scanner Deep-Dive

### Tool Location

```
/path/to/tools/port-scanner/tool.py
```

### Core Capabilities

The Port Scanner identifies open ports and services:
- **TCP Connect** - Full connection (reliable, logged)
- **TCP SYN** - Half-open scan (stealthier, requires root)
- **UDP** - UDP port detection (slow, less reliable)

### Basic Usage Patterns

#### Pattern 1: Quick Port Survey

```bash
# Scan top 20 most common ports
python3 tool.py 192.168.1.100 --plan
```

```bash
# Execute scan
python3 tool.py 192.168.1.100
```

**Expected Output:**
```
[*] Port Scanner starting...
[*] Target: 192.168.1.100
[*] Ports: 20
[*] Scanning 20 ports on 192.168.1.100
[+] 22/tcp open - ssh
[+] 80/tcp open - http
[+] 443/tcp open - https

============================================================
SCAN RESULTS
============================================================
Target:       192.168.1.100
Scan Type:    connect
Duration:     1.23s

Open ports:     3
Filtered ports: 0

OPEN PORTS:
------------------------------------------------------------
  22/tcp open  ssh
  80/tcp open  http
  443/tcp open https
```

#### Pattern 2: Comprehensive Port Scan

```bash
# Scan first 1024 privileged ports
python3 tool.py 192.168.1.100 --ports 1-1024 --threads 100
```

```bash
# Scan all ports (time-intensive)
python3 tool.py 192.168.1.100 --ports all --threads 200
```

#### Pattern 3: Banner Grabbing

```bash
# Grab service banners for version info
python3 tool.py 192.168.1.100 --ports 22,80,443,21,25 --banner --verbose
```

**Sample Output with Banners:**
```
OPEN PORTS:
------------------------------------------------------------
  22/tcp open  ssh    SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
  80/tcp open  http   Apache/2.4.41 (Ubuntu)
  21/tcp open  ftp    vsftpd 3.0.3
```

### Port Specification Reference

| Specification | Example | Ports Scanned | Use Case |
|--------------|---------|---------------|----------|
| Single | `80` | 80 | Testing specific service |
| Range | `1-100` | 1 through 100 | Scanning segment |
| List | `22,80,443` | 22, 80, 443 | Known services |
| Combined | `22,80,8000-8100` | 22, 80, 8000-8100 | Mixed approach |
| Preset | `top20` | 20 most common | Quick survey |
| Preset | `top100` | 100 most common | Standard scan |
| All | `all` | 1-65535 | Comprehensive (slow) |

> **What is "top20" or "top100"?** These are the most commonly open ports across the internet based on research. They include services like HTTP (80), HTTPS (443), SSH (22), and SMB (445). Using presets saves time by checking likely targets first.

### Stealth Scanning Techniques

```bash
# Maximum stealth (slow but quiet)
python3 tool.py 192.168.1.100 \
    --ports top100 \
    --scan-type connect \
    --delay-min 5 \
    --delay-max 15 \
    --threads 1 \
    --no-randomize
```

**Note on Port Randomization:**
By default, ports are scanned in random order to avoid sequential patterns that trigger IDS rules. Use `--no-randomize` only when you specifically need sequential scanning.

---

## Part 4: Service Fingerprinter Deep-Dive

### Tool Location

```
/path/to/tools/service-fingerprinter/tool.py
```

### Core Capabilities

The Service Fingerprinter performs deep service analysis:
- Protocol-specific probes (HTTP, SSH, FTP, SMTP, MySQL, RDP)
- Version extraction from banners
- SSL/TLS detection and certificate analysis
- Confidence scoring for identifications

### Basic Usage

```bash
# Fingerprint discovered ports
python3 tool.py 192.168.1.100 --ports 22,80,443,3306 --plan
```

```bash
# Execute fingerprinting
python3 tool.py 192.168.1.100 --ports 22,80,443,3306 --verbose
```

**Expected Output:**
```
[*] Service Fingerprinter starting...
[*] Target: 192.168.1.100
[*] Ports: [22, 80, 443, 3306]
[+] 22/tcp - ssh OpenSSH 8.2p1 (95%)
[+] 80/tcp - http Apache 2.4.41 (95%)
[+] 443/tcp - https nginx 1.18.0 (95%)
[+] 3306/tcp - mysql MySQL 8.0.23 (90%)

======================================================================
FINGERPRINT RESULTS
======================================================================
PORT     SERVICE         PRODUCT              VERSION         SSL
----------------------------------------------------------------------
22       ssh             OpenSSH              8.2p1           No
80       http            Apache               2.4.41          No
443      https           nginx                1.18.0          Yes
3306     mysql           MySQL                8.0.23          No
```

### Aggressive Mode

When default probes fail to identify services:

```bash
# Try all probes on all ports
python3 tool.py 192.168.1.100 --ports 8080,8443,9000 --aggressive --verbose
```

### Understanding Confidence Scores

| Score | Meaning | Action |
|-------|---------|--------|
| 90-100% | High confidence identification | Trust the result |
| 70-89% | Likely identification | Verify manually if critical |
| 50-69% | Possible identification | Investigate further |
| <50% | Low confidence | May be misidentified |

---

## Part 5: DNS Enumerator Deep-Dive

### Tool Location

```
/path/to/tools/dns-enumerator/tool.py
```

### Core Capabilities

- Subdomain bruteforcing with built-in and custom wordlists
- Zone transfer (AXFR) attempts
- Multiple record type enumeration (A, AAAA, NS, MX, TXT, SOA, CNAME)
- Custom nameserver specification

### Basic Usage

```bash
# Enumerate domain with default wordlist
python3 tool.py example.com --plan
```

```bash
# Execute enumeration
python3 tool.py example.com --verbose
```

### Zone Transfer Attempts

Zone transfers, when successful, reveal all DNS records for a domain:

```bash
# Attempt zone transfer
python3 tool.py example.com --zone-transfer --verbose
```

**If successful (misconfigured DNS):**
```
[*] Attempting zone transfer against ns1.example.com...
[+] Zone transfer successful!
[+] Retrieved 156 records
```

**If blocked (proper configuration):**
```
[*] Attempting zone transfer against ns1.example.com...
[-] Zone transfer refused (expected for properly configured servers)
```

### Custom Wordlist Scanning

```bash
# Use custom subdomain wordlist
python3 tool.py example.com \
    -w /path/to/subdomains-top1million.txt \
    --threads 20 \
    --delay-min 0.1 \
    --delay-max 0.5
```

### Record Type Enumeration

```bash
# Query specific record types
python3 tool.py example.com -r A,MX,TXT,NS,SOA
```

**Useful Record Types:**
- **A/AAAA**: IP addresses (IPv4/IPv6)
- **MX**: Mail servers
- **TXT**: SPF, DKIM, verification records
- **NS**: Nameservers
- **CNAME**: Aliases pointing to other domains

---

## Part 6: Reconnaissance Workflow

### Recommended Workflow

```
                    +------------------+
                    | 1. Host Discovery|
                    |  (Network Scan)  |
                    +--------+---------+
                             |
              Live hosts identified
                             |
                    +--------v---------+
                    | 2. Port Scanning |
                    | (Per live host)  |
                    +--------+---------+
                             |
              Open ports identified
                             |
                    +--------v---------+
                    | 3. Service FP    |
                    | (Per open port)  |
                    +--------+---------+
                             |
              Services identified
                             |
                    +--------v---------+
                    | 4. DNS Enum      |
                    | (Domain recon)   |
                    +--------+---------+
                             |
            Attack surface mapped
```

### Practical Example: Full Network Reconnaissance

**Scenario**: You need to map a target network 10.10.10.0/24

#### Step 1: Host Discovery

```bash
# Quick discovery of live hosts
python3 /path/to/network-scanner/tool.py 10.10.10.0/24 \
    --methods tcp \
    --ports 22 80 443 445 3389 \
    --output hosts.json \
    --verbose
```

**Document results:**
```
Live hosts found: 10.10.10.1, 10.10.10.5, 10.10.10.10, 10.10.10.50
```

#### Step 2: Port Scanning

```bash
# Scan each live host thoroughly
for host in 10.10.10.1 10.10.10.5 10.10.10.10 10.10.10.50; do
    python3 /path/to/port-scanner/tool.py $host \
        --ports top100 \
        --banner \
        --output "ports_${host}.json"
done
```

#### Step 3: Service Fingerprinting

```bash
# Deep fingerprint interesting ports
python3 /path/to/service-fingerprinter/tool.py 10.10.10.10 \
    --ports 22,80,443,8080,3306 \
    --aggressive \
    --output fp_10.10.10.10.json
```

#### Step 4: DNS Enumeration (if applicable)

```bash
# If a domain is discovered
python3 /path/to/dns-enumerator/tool.py target.local \
    --zone-transfer \
    -w /usr/share/wordlists/subdomains.txt \
    --output dns_enum.json
```

---

## Part 7: Troubleshooting

### Common Issues and Solutions

#### Issue: "Connection refused" on all ports

**Possible Causes:**
1. Host is down
2. Firewall blocking all traffic
3. Wrong IP address

**Solution:**
```bash
# Verify host is reachable
ping -c 3 <target_ip>

# Try ARP discovery on local network
python3 tool.py <target_ip> --methods arp
```

#### Issue: Slow scans

**Possible Causes:**
1. Too many threads overwhelming network
2. High timeout values
3. IDS/IPS rate limiting

**Solution:**
```bash
# Reduce threads and timeout
python3 tool.py <target> --threads 20 --timeout 1
```

#### Issue: Inconsistent results between scans

**Possible Causes:**
1. Load balancers rotating backends
2. Temporary network issues
3. Dynamic port assignments

**Solution:**
```bash
# Run multiple scans and compare
python3 tool.py <target> --ports top100 --output scan1.json
# Wait, then rescan
python3 tool.py <target> --ports top100 --output scan2.json
# Compare results
```

#### Issue: "Permission denied" for SYN scanning

**Cause:** SYN scanning requires raw socket access

**Solution:**
```bash
# Run with elevated privileges (if authorized)
sudo python3 tool.py <target> --scan-type syn

# Or fall back to connect scanning (no privileges needed)
python3 tool.py <target> --scan-type connect
```

---

## Part 8: Competition Tips

### Time-Optimized Scanning

In CTF/CPTC with time pressure:

```bash
# Fast initial discovery
python3 network-scanner/tool.py <range> --threads 50 --timeout 1

# Quick port scan
python3 port-scanner/tool.py <target> --ports top100 --threads 100

# Rapid fingerprinting
python3 service-fingerprinter/tool.py <target> --ports <discovered> --threads 20
```

### Documentation Template

```
## Host: 10.10.10.x

### Discovery
- Method: TCP Connect
- Time: HH:MM
- Response: <details>

### Open Ports
| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22   | SSH     | OpenSSH 8.2 | |
| 80   | HTTP    | Apache 2.4.41 | |

### Attack Vectors
1. SSH - password auth enabled
2. HTTP - potential webapp vulns
```

### Red Flags to Investigate

| Finding | Priority | Why |
|---------|----------|-----|
| SSH on non-22 port | Medium | May indicate honeypot or restricted access |
| HTTP 8080/8443 | High | Development servers often have vulns |
| MySQL 3306 exposed | High | Database access |
| RDP 3389 open | High | Windows target, possible brute force |
| SMB 445 open | High | Share enumeration, potential EternalBlue |

---

## Summary Checklist

Before moving to exploitation, verify you have:

- [ ] Identified all live hosts in scope
- [ ] Discovered all open ports on each host
- [ ] Fingerprinted services with version information
- [ ] Enumerated DNS records (if applicable)
- [ ] Documented all findings with timestamps
- [ ] Identified potential attack vectors
- [ ] Saved raw output for reporting

---

## Next Steps

After completing this walkthrough:
1. Complete **Lab 01: Network Reconnaissance** for hands-on practice
2. Keep the **Network Scanning Cheatsheet** accessible for quick reference
3. Progress to **Lab 02: Service Exploitation** to act on your reconnaissance
