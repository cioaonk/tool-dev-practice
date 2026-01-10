# Lab 01: Network Reconnaissance

A hands-on exercise in network discovery, port scanning, and service enumeration.

## Lab Information

| Attribute | Value |
|-----------|-------|
| Difficulty | Beginner to Intermediate |
| Time Estimate | 60-90 minutes |
| Prerequisites | Network Scanner Walkthrough |
| Tools Required | network-scanner, port-scanner, service-fingerprinter, dns-enumerator |

---

## Objective

Perform comprehensive reconnaissance on a target network segment to identify all live hosts, open ports, and running services. Document findings in a format suitable for penetration test reporting.

---

## Environment Setup

### Lab Network Configuration

For this lab, you will work with a simulated corporate network:

```
Network: 10.10.10.0/24
Gateway: 10.10.10.1
DNS Server: 10.10.10.2
Target Systems: Unknown (your job to discover)
Domain: corp.local
```

### Your Attack Machine

Ensure you have:
- Python 3.6+ installed
- Network connectivity to the target range
- All toolkit tools accessible

### Verification

```bash
# Verify Python
python3 --version

# Verify network connectivity (adjust IP as needed)
ping -c 3 10.10.10.1

# Verify tool access
python3 /path/to/network-scanner/tool.py --help
```

---

## Scenario

You have been engaged to perform a penetration test for CorpTech Industries. The client has provided you with the network range 10.10.10.0/24 as in-scope. Your first task is to map the network and identify all potential targets.

**Rules of Engagement:**
- Network range 10.10.10.0/24 is in scope
- Avoid denial of service conditions
- Document all findings
- The domain corp.local is associated with the network

---

## Tasks

### Task 1: Host Discovery (Level 1 - Foundation)

**Objective**: Identify all live hosts on the target network.

**Instructions**:

1. Before scanning, always use planning mode to understand what will happen:
```bash
python3 /path/to/network-scanner/tool.py 10.10.10.0/24 --plan
```

2. Perform initial host discovery using TCP probes on common ports:
```bash
python3 /path/to/network-scanner/tool.py 10.10.10.0/24 \
    --methods tcp \
    --ports 22 80 443 445 3389 \
    --verbose \
    --output task1_hosts.json
```

3. Record all discovered live hosts.

**Deliverable**: List of live IP addresses

**Validation**: You should discover at least 5 live hosts on the network.

---

### Task 2: Comprehensive Port Scanning (Level 1 - Foundation)

**Objective**: Identify all open ports on discovered hosts.

**Instructions**:

1. For each live host discovered in Task 1, perform a comprehensive port scan:
```bash
python3 /path/to/port-scanner/tool.py <target_ip> \
    --ports top100 \
    --verbose \
    --output task2_ports_<ip>.json
```

2. For hosts with interesting services, scan all ports:
```bash
python3 /path/to/port-scanner/tool.py <target_ip> \
    --ports 1-65535 \
    --threads 200 \
    --output task2_fullscan_<ip>.json
```

**Deliverable**: Port scan results for each host

**Validation**: Identify at least 3 different services across your targets.

---

### Task 3: Service Fingerprinting (Level 2 - Application)

**Objective**: Identify service versions and gather detailed information.

**Instructions**:

1. Use the service fingerprinter on discovered open ports:
```bash
python3 /path/to/service-fingerprinter/tool.py <target_ip> \
    --ports <discovered_ports> \
    --verbose \
    --output task3_services_<ip>.json
```

2. For services that don't fingerprint well, try aggressive mode:
```bash
python3 /path/to/service-fingerprinter/tool.py <target_ip> \
    --ports <ports> \
    --aggressive \
    --verbose
```

3. Document version information for vulnerability research.

**Deliverable**: Service and version information for all open ports

**Validation**: Extract version numbers for at least 5 services.

---

### Task 4: DNS Enumeration (Level 2 - Application)

**Objective**: Enumerate DNS records and discover subdomains.

**Instructions**:

1. Attempt zone transfer against the DNS server:
```bash
python3 /path/to/dns-enumerator/tool.py corp.local \
    --nameserver 10.10.10.2 \
    --zone-transfer \
    --verbose \
    --output task4_dns.json
```

2. Perform subdomain enumeration:
```bash
python3 /path/to/dns-enumerator/tool.py corp.local \
    --nameserver 10.10.10.2 \
    -r A,MX,NS,TXT \
    --verbose
```

3. Document any discovered subdomains and their IP mappings.

**Deliverable**: DNS enumeration results including any subdomains

**Validation**: Identify the mail server and at least 2 subdomains.

---

### Task 5: Stealth Scanning (Level 3 - Integration)

**Objective**: Perform reconnaissance while minimizing detection.

**Instructions**:

You are now operating in a more sensitive environment. Perform scanning with reduced footprint.

1. Design a scan strategy that:
   - Uses delays between probes
   - Minimizes thread count
   - Targets only essential ports first

2. Execute your stealth scan:
```bash
# Example approach - adjust based on your strategy
python3 /path/to/network-scanner/tool.py 10.10.10.0/24 \
    --methods tcp dns \
    --ports 22 80 443 \
    --delay-min 2 \
    --delay-max 5 \
    --threads 2 \
    --verbose
```

3. Document your approach and reasoning.

**Deliverable**: Stealth scan results and strategy documentation

**Validation**: Successfully scan without triggering more than 3 IDS alerts (simulated - document your approach).

---

### Task 6: Attack Surface Documentation (Level 3 - Integration)

**Objective**: Compile all findings into an attack surface map.

**Instructions**:

Using all gathered data, create a comprehensive attack surface document:

1. Create a host inventory table
2. Map services to potential vulnerabilities
3. Identify high-value targets
4. Prioritize attack vectors

**Template**:

```
# Attack Surface Report - CorpTech Industries

## Executive Summary
[Brief overview of findings]

## Host Inventory

| IP Address | Hostname | OS (if known) | Role |
|------------|----------|---------------|------|
| 10.10.10.x | xxx.corp.local | Windows/Linux | Server/Workstation |

## Service Inventory

| Host | Port | Service | Version | Notes |
|------|------|---------|---------|-------|
| 10.10.10.x | 22 | SSH | OpenSSH 8.2 | |

## DNS Findings
[Zone transfer results, subdomains, etc.]

## High-Value Targets
1. [Target 1 - Reasoning]
2. [Target 2 - Reasoning]

## Recommended Attack Vectors
1. [Vector 1]
2. [Vector 2]
```

**Deliverable**: Complete attack surface report

---

## Challenge Tasks (Level 4 - Mastery)

### Challenge 1: Identify the Domain Controller

Using only reconnaissance data, identify which host is likely the domain controller. Document your reasoning based on:
- Open ports
- Service fingerprints
- DNS records

### Challenge 2: Find the Hidden Service

One host is running a service on a non-standard high port (above 10000). Find it using efficient scanning techniques.

### Challenge 3: Time-Optimized Full Scan

Complete a full network reconnaissance (all hosts, top 100 ports, service fingerprinting) in under 10 minutes. Document your approach.

---

## Hints

<details>
<summary>Hint 1: Host Discovery Not Finding Hosts</summary>

Try multiple methods. Some hosts may not respond to TCP probes on common ports:
```bash
python3 tool.py 10.10.10.0/24 --methods tcp dns --ports 22 80 443 445 139 3389 8080
```
</details>

<details>
<summary>Hint 2: Slow Port Scanning</summary>

Increase thread count for faster scanning, but be aware this increases detection risk:
```bash
python3 tool.py <target> --ports top100 --threads 100 --timeout 1
```
</details>

<details>
<summary>Hint 3: Service Not Fingerprinting</summary>

Try aggressive mode with increased timeout:
```bash
python3 tool.py <target> --ports <port> --aggressive --timeout 10
```
</details>

<details>
<summary>Hint 4: Zone Transfer Failing</summary>

Zone transfers are usually blocked. Focus on subdomain enumeration and record queries instead.
</details>

<details>
<summary>Hint 5: Finding Domain Controller</summary>

Look for these indicators:
- Ports 88 (Kerberos), 389 (LDAP), 636 (LDAPS)
- Port 53 (DNS) combined with 445 (SMB)
- Hostname patterns (dc, domaincontroller, ad)
</details>

---

## Solution Guide

<details>
<summary>Click to reveal solution (Instructor Use)</summary>

### Task 1 Solution

```bash
# Full command
python3 /path/to/network-scanner/tool.py 10.10.10.0/24 \
    --methods tcp \
    --ports 22 80 443 445 3389 8080 \
    --resolve \
    --verbose \
    --output task1_hosts.json
```

Expected hosts: 10.10.10.1 (gateway), 10.10.10.2 (DNS), 10.10.10.10 (DC), 10.10.10.20 (web), 10.10.10.30 (file server), 10.10.10.50 (workstation)

### Task 2 Solution

```bash
# Scan each host
for ip in 10.10.10.1 10.10.10.2 10.10.10.10 10.10.10.20 10.10.10.30 10.10.10.50; do
    python3 /path/to/port-scanner/tool.py $ip --ports top100 --output task2_$ip.json
done
```

### Task 3 Solution

Key version findings:
- 10.10.10.10: Windows Server 2019, Kerberos, LDAP, DNS
- 10.10.10.20: Apache 2.4.41, PHP 7.4
- 10.10.10.30: Samba 4.11, SSH OpenSSH 8.2

### Task 4 Solution

```bash
# Zone transfer (if successful)
python3 /path/to/dns-enumerator/tool.py corp.local -n 10.10.10.2 --zone-transfer

# Subdomain enum
python3 /path/to/dns-enumerator/tool.py corp.local -n 10.10.10.2 -r A,MX,NS,TXT,CNAME
```

Expected: mail.corp.local, web.corp.local, dc.corp.local, files.corp.local

### Challenge 1 Solution

Domain Controller: 10.10.10.10

Evidence:
- Port 88 (Kerberos)
- Port 389 (LDAP)
- Port 636 (LDAPS)
- Port 53 (DNS)
- Port 445 (SMB)
- Port 135 (RPC)

### Challenge 2 Solution

Hidden service on port 31337:
```bash
python3 /path/to/port-scanner/tool.py 10.10.10.20 --ports 10000-65535 --threads 200
```

</details>

---

## Assessment Criteria

| Criteria | Points | Description |
|----------|--------|-------------|
| Host Discovery | 20 | All live hosts identified |
| Port Scanning | 20 | Complete port inventory |
| Service Fingerprinting | 20 | Version info extracted |
| DNS Enumeration | 15 | DNS records documented |
| Stealth Approach | 10 | Demonstrated OPSEC awareness |
| Documentation | 15 | Clear, complete reporting |

**Total: 100 points**

---

## Extension Challenges

For those who complete early:

1. **Automated Workflow**: Write a script that chains all tools together for automated reconnaissance.

2. **Output Correlation**: Parse JSON outputs and correlate findings across tools.

3. **Time Trial**: Repeat the exercise attempting to complete in half the time.

---

## Cleanup

After completing the lab:

```bash
# Remove output files if not needed
rm -f task*.json

# Clear terminal history if desired
history -c
```

---

## Next Lab

Proceed to **Lab 02: Service Exploitation** to learn how to leverage your reconnaissance findings.
