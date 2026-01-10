# Network Scanning Cheatsheet

Quick reference for reconnaissance and enumeration.

---

## Host Discovery

### Quick Discovery (Speed)

```bash
# Fast scan on common ports
python3 network-scanner/tool.py <range> \
    --methods tcp \
    --ports 22,80,443,445,3389 \
    --threads 50 \
    --timeout 1
```

### Thorough Discovery (Accuracy)

```bash
# Multiple methods, more ports
python3 network-scanner/tool.py <range> \
    --methods tcp dns \
    --ports 21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,8080,8443 \
    --resolve \
    --verbose
```

### Stealth Discovery (Evasion)

```bash
# Slow and quiet
python3 network-scanner/tool.py <range> \
    --methods tcp \
    --ports 80,443 \
    --delay-min 5 \
    --delay-max 15 \
    --threads 1
```

---

## Port Scanning

### Scan Presets

| Preset | Ports | Use Case |
|--------|-------|----------|
| `top20` | Most common 20 | Quick survey |
| `top100` | Most common 100 | Standard scan |
| `1-1024` | Privileged ports | Service discovery |
| `all` | 1-65535 | Comprehensive |

### Quick Scans

```bash
# Default (top 20)
python3 port-scanner/tool.py <target>

# Common services
python3 port-scanner/tool.py <target> --ports 21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,8080

# Full scan
python3 port-scanner/tool.py <target> --ports all --threads 200
```

### Targeted Scans

```bash
# Web servers
python3 port-scanner/tool.py <target> --ports 80,443,8000,8080,8443,8888

# Databases
python3 port-scanner/tool.py <target> --ports 1433,1521,3306,5432,27017,6379

# Windows services
python3 port-scanner/tool.py <target> --ports 135,139,445,3389,5985,5986

# Linux services
python3 port-scanner/tool.py <target> --ports 22,111,2049
```

---

## Service Fingerprinting

### Basic Fingerprinting

```bash
python3 service-fingerprinter/tool.py <target> --ports <discovered_ports>
```

### Aggressive (Unknown Services)

```bash
python3 service-fingerprinter/tool.py <target> --ports <ports> --aggressive --timeout 10
```

### Banner Grabbing

```bash
python3 port-scanner/tool.py <target> --ports <ports> --banner --verbose
```

---

## DNS Enumeration

### Quick Enum

```bash
python3 dns-enumerator/tool.py <domain> -r A,MX,NS,TXT
```

### Zone Transfer

```bash
python3 dns-enumerator/tool.py <domain> --zone-transfer
```

### Subdomain Brute

```bash
python3 dns-enumerator/tool.py <domain> -w /path/to/wordlist.txt --threads 20
```

---

## SMB Enumeration

### Null Session

```bash
python3 smb-enumerator/tool.py <target> --null-session
```

### Authenticated

```bash
python3 smb-enumerator/tool.py <target> -u <user> -P <pass> -d <domain>
```

---

## Common Port Reference

### Critical Ports

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | File transfer, check anonymous |
| 22 | SSH | Linux admin, key auth |
| 23 | Telnet | Legacy, cleartext |
| 25 | SMTP | Email, relay testing |
| 53 | DNS | Zone transfers |
| 80 | HTTP | Web apps |
| 88 | Kerberos | Windows auth |
| 110 | POP3 | Email |
| 135 | RPC | Windows |
| 139 | NetBIOS | Legacy SMB |
| 143 | IMAP | Email |
| 389 | LDAP | Directory services |
| 443 | HTTPS | Secure web |
| 445 | SMB | File shares |
| 636 | LDAPS | Secure LDAP |
| 1433 | MSSQL | Microsoft SQL |
| 1521 | Oracle | Oracle DB |
| 3306 | MySQL | MySQL DB |
| 3389 | RDP | Remote Desktop |
| 5432 | PostgreSQL | PostgreSQL DB |
| 5985 | WinRM | Windows Remote Mgmt |
| 8080 | HTTP-Alt | Alt web |

### High-Value Targets

| Finding | Priority | Why |
|---------|----------|-----|
| Port 445 open | HIGH | SMB, shares, potential exploits |
| Port 3389 open | HIGH | RDP, brute force target |
| Port 1433/3306/5432 | HIGH | Database access |
| Port 8080/8443 | HIGH | Dev/admin interfaces |
| Port 21 anonymous | HIGH | File access |
| Port 23 open | HIGH | Legacy, weak auth |

---

## Workflow Templates

### Standard CTF Recon

```bash
# 1. Quick discovery
python3 network-scanner/tool.py <range> --ports 22,80,443,445,3389 -o hosts.json

# 2. Full port scan each host
python3 port-scanner/tool.py <host> --ports all --threads 200 -o ports.json

# 3. Fingerprint
python3 service-fingerprinter/tool.py <host> --ports <open_ports> --aggressive

# 4. DNS enum (if applicable)
python3 dns-enumerator/tool.py <domain> --zone-transfer
```

### Time-Critical Recon

```bash
# 1. Fast discovery + port scan
python3 network-scanner/tool.py <range> --ports 21,22,80,443,445,3389,8080 --threads 100

# 2. Quick fingerprint
python3 service-fingerprinter/tool.py <host> --ports <open> --threads 20
```

### Stealth Recon

```bash
# 1. Slow discovery
python3 network-scanner/tool.py <range> \
    --ports 80,443 \
    --delay-min 10 \
    --delay-max 30 \
    --threads 1

# 2. Slow port scan
python3 port-scanner/tool.py <host> \
    --ports top20 \
    --delay-min 5 \
    --delay-max 15 \
    --threads 1
```

---

## Output Parsing

### Extract Live Hosts from JSON

```bash
cat hosts.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join([r['ip'] for r in d['results'] if r['is_alive']]))"
```

### Extract Open Ports from JSON

```bash
cat ports.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join([str(r['port']) for r in d['results'] if r['state']=='open']))"
```

---

## OPSEC Notes

### What Gets Logged

| Action | Visibility |
|--------|------------|
| TCP Connect | Full connection logs |
| Port scan | Connection attempts logged |
| Banner grab | Application logs |
| DNS query | DNS server logs |
| SMB enum | Windows Security logs |

### Detection Triggers

| Pattern | Detection |
|---------|-----------|
| Sequential port scan | IDS alert |
| High volume | Rate limiting |
| Full port scan | Firewall alert |
| SMB enum | SIEM correlation |

### Minimizing Detection

- Use delays between probes
- Randomize port order (default)
- Lower thread count
- Target only necessary ports
- Use planning mode first

---

## Quick Reference Card

```
+------------------------------------------+
|         NETWORK SCANNING QUICK REF       |
+------------------------------------------+
| DISCOVER HOSTS:                          |
| python3 network-scanner/tool.py <range>  |
|                                          |
| SCAN PORTS:                              |
| python3 port-scanner/tool.py <target>    |
|                                          |
| FINGERPRINT:                             |
| python3 service-fingerprinter/tool.py    |
|   <target> --ports <ports>               |
|                                          |
| DNS ENUM:                                |
| python3 dns-enumerator/tool.py <domain>  |
|                                          |
| SMB ENUM:                                |
| python3 smb-enumerator/tool.py <target>  |
+------------------------------------------+
| ALWAYS USE --plan FIRST!                 |
+------------------------------------------+
```
