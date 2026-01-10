# Threat Actor TTPs Intelligence Report

**Classification:** CPTC Competition Preparation
**Date:** January 2026
**Analyst:** Docker Threat Intel Team

---

## Executive Summary

This report maps penetration testing tools and techniques to the MITRE ATT&CK framework, providing a structured understanding of offensive capabilities. Understanding these TTP (Tactics, Techniques, and Procedures) mappings enables teams to emulate realistic threat actors and understand detection opportunities.

---

## 1. MITRE ATT&CK Framework Overview

### 1.1 Relevant Tactics for Container Environments

| Tactic | ID | Description |
|--------|-----|-------------|
| Reconnaissance | TA0043 | Gathering target information |
| Resource Development | TA0042 | Establishing infrastructure |
| Initial Access | TA0001 | Getting into the network |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining access |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Exploring the environment |
| Lateral Movement | TA0008 | Moving through network |
| Collection | TA0009 | Gathering target data |
| Exfiltration | TA0010 | Stealing data |
| Impact | TA0040 | Disruption/destruction |

---

## 2. Tool-to-TTP Mapping

### 2.1 Reconnaissance Tools

**Nmap**
```
Techniques:
- T1046: Network Service Discovery
- T1595.001: Active Scanning: IP Blocks
- T1595.002: Active Scanning: Vulnerability Scanning

Commands:
nmap -sV -sC target       # T1046
nmap -sn 10.0.0.0/24      # T1595.001
nmap --script vuln target # T1595.002
```

**Gobuster/Dirb**
```
Techniques:
- T1595.003: Active Scanning: Wordlist Scanning
- T1083: File and Directory Discovery

Commands:
gobuster dir -u http://target -w wordlist.txt
```

**Shodan/Censys**
```
Techniques:
- T1596.005: Search Open Technical Databases
- T1592: Gather Victim Host Information
```

### 2.2 Initial Access Tools

**Metasploit**
```
Techniques:
- T1190: Exploit Public-Facing Application
- T1133: External Remote Services
- T1078: Valid Accounts

Modules:
exploit/multi/http/apache_*    # T1190
exploit/windows/smb/ms17_010   # T1190
auxiliary/scanner/ssh/ssh_login # T1078
```

**Phishing Frameworks**
```
Techniques:
- T1566.001: Spearphishing Attachment
- T1566.002: Spearphishing Link
- T1598: Phishing for Information
```

**Docker API Exploitation**
```
Techniques:
- T1610: Deploy Container
- T1190: Exploit Public-Facing Application

Attack Path:
curl http://target:2375/containers/create  # T1610
```

### 2.3 Execution Tools

**PowerShell Empire / PowerSploit**
```
Techniques:
- T1059.001: PowerShell
- T1106: Native API
- T1055: Process Injection

Commands:
Invoke-Mimikatz                # T1059.001
Invoke-ReflectivePEInjection   # T1055
```

**Container Execution**
```
Techniques:
- T1609: Container Administration Command
- T1610: Deploy Container

Commands:
docker exec -it container /bin/sh  # T1609
kubectl exec -it pod -- /bin/sh    # T1609
```

### 2.4 Persistence Tools

**Cron/Scheduled Tasks**
```
Techniques:
- T1053.003: Cron
- T1053.005: Scheduled Task

Commands:
echo "* * * * * /tmp/backdoor" >> /etc/crontab  # T1053.003
schtasks /create /tn "Update" /tr "backdoor.exe" # T1053.005
```

**Container Persistence**
```
Techniques:
- T1525: Implant Internal Image
- T1133: External Remote Services

Attack Path:
docker commit compromised_container backdoor_image  # T1525
```

**SSH Keys**
```
Techniques:
- T1098.004: SSH Authorized Keys

Commands:
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### 2.5 Privilege Escalation Tools

**LinPEAS/WinPEAS**
```
Techniques:
- T1068: Exploitation for Privilege Escalation
- T1548.001: Setuid and Setgid
- T1548.002: Bypass UAC

Discovery for:
- SUID binaries           # T1548.001
- Kernel vulnerabilities  # T1068
- Misconfigured services  # T1574
```

**Container Escape**
```
Techniques:
- T1611: Escape to Host

Methods:
- Privileged container abuse     # T1611
- Docker socket exploitation     # T1611
- Kernel exploit from container  # T1611
- Cgroups release_agent          # T1611
```

**Sudo Exploitation**
```
Techniques:
- T1548.003: Sudo and Sudo Caching

Commands:
sudo -l                    # Discovery
sudo vim -c ':!/bin/sh'    # GTFOBins exploitation
```

### 2.6 Defense Evasion Tools

**Obfuscation Tools**
```
Techniques:
- T1027: Obfuscated Files or Information
- T1140: Deobfuscate/Decode Files

Tools:
- Veil-Evasion            # T1027
- Invoke-Obfuscation      # T1027
- Base64 encoding         # T1027.001
```

**Process Injection**
```
Techniques:
- T1055.001: DLL Injection
- T1055.002: PE Injection
- T1055.012: Process Hollowing

Tools:
- Metasploit migrate command
- Cobalt Strike inject
- Manual shellcode injection
```

**Container Evasion**
```
Techniques:
- T1612: Build Image on Host
- T1036.005: Match Legitimate Name

Methods:
- Building minimal images
- Using legitimate base images
- Removing attack artifacts
```

### 2.7 Credential Access Tools

**Mimikatz**
```
Techniques:
- T1003.001: LSASS Memory
- T1003.002: Security Account Manager
- T1003.003: NTDS
- T1558.003: Kerberoasting

Commands:
sekurlsa::logonpasswords  # T1003.001
lsadump::sam              # T1003.002
lsadump::dcsync           # T1003.003
kerberos::list            # Discovery
```

**Responder**
```
Techniques:
- T1557.001: LLMNR/NBT-NS Poisoning
- T1040: Network Sniffing

Commands:
responder -I eth0         # T1557.001
```

**Container Credential Harvesting**
```
Techniques:
- T1552.001: Credentials In Files
- T1552.004: Private Keys
- T1552.007: Container API

Locations:
/proc/*/environ           # Environment variables
~/.docker/config.json     # Docker credentials
~/.kube/config            # Kubernetes credentials
```

### 2.8 Discovery Tools

**BloodHound**
```
Techniques:
- T1087.002: Domain Account
- T1069.002: Domain Groups
- T1482: Domain Trust Discovery

Commands:
SharpHound.exe -c All     # Collect AD data
```

**Container Discovery**
```
Techniques:
- T1613: Container and Resource Discovery
- T1046: Network Service Discovery

Commands:
docker ps -a              # T1613
kubectl get pods --all-namespaces  # T1613
```

### 2.9 Lateral Movement Tools

**PSExec/WMI**
```
Techniques:
- T1021.002: SMB/Windows Admin Shares
- T1047: Windows Management Instrumentation

Commands:
psexec.py domain/user@target  # T1021.002
wmiexec.py domain/user@target # T1047
```

**SSH**
```
Techniques:
- T1021.004: SSH

Commands:
ssh -i stolen_key user@target
```

**Container Lateral Movement**
```
Techniques:
- T1021.004: SSH (between containers)
- T1210: Exploitation of Remote Services

Methods:
- Container network pivoting
- Kubernetes service account abuse
- Docker API access from containers
```

---

## 3. Common TTP Chains

### 3.1 Web Application to Domain Admin

```
Chain: T1190 -> T1059 -> T1003 -> T1078 -> T1021 -> T1068

1. T1190: SQL Injection on web app
2. T1059: Command execution via SQLi
3. T1003: Credential dumping (Mimikatz)
4. T1078: Use discovered domain creds
5. T1021: Lateral move to DC
6. T1068: DCSync or domain privesc
```

### 3.2 Container Escape Chain

```
Chain: T1190 -> T1609 -> T1611 -> T1068

1. T1190: Exploit vulnerable container app
2. T1609: Execute commands in container
3. T1611: Escape via privileged access/socket
4. T1068: Kernel exploit for root on host
```

### 3.3 Kubernetes Compromise Chain

```
Chain: T1078 -> T1613 -> T1552 -> T1610 -> T1611

1. T1078: Compromised service account token
2. T1613: Enumerate cluster resources
3. T1552: Extract secrets from API
4. T1610: Deploy privileged pod
5. T1611: Escape to node
```

### 3.4 Cloud Metadata Attack Chain

```
Chain: T1190 -> T1552 -> T1078 -> T1580

1. T1190: SSRF vulnerability
2. T1552: Access metadata service
3. T1078: Use IAM credentials
4. T1580: Cloud infrastructure discovery
```

---

## 4. Detection Opportunities

### 4.1 Network-Based Detection

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| T1046 | Port scan detection | Firewall logs |
| T1021 | Lateral movement traffic | Network flow |
| T1041 | Unusual outbound data | Proxy logs |
| T1071 | C2 communication patterns | IDS/IPS |

### 4.2 Host-Based Detection

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| T1003 | LSASS access | Sysmon Event 10 |
| T1059 | Script execution | PowerShell logs |
| T1055 | Process injection | Sysmon Event 8 |
| T1053 | Scheduled task creation | Windows Events |

### 4.3 Container-Based Detection

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| T1609 | Container exec commands | Container runtime logs |
| T1610 | Container creation | Docker/K8s audit logs |
| T1611 | Escape indicators | Kernel audit, seccomp |
| T1613 | API enumeration | API server logs |

---

## 5. Threat Actor Emulation Profiles

### 5.1 APT-Style Attack Profile

**Characteristics:**
- Low and slow approach
- Minimal tool footprint
- Living off the land
- Long-term persistence

**Key TTPs:**
- T1566: Spearphishing
- T1059.001: PowerShell
- T1003: Credential Dumping
- T1078: Valid Accounts
- T1071: Standard Application Layer Protocol

### 5.2 Opportunistic Attacker Profile

**Characteristics:**
- Fast exploitation
- Known CVEs and exploits
- Automated scanning
- Quick monetization

**Key TTPs:**
- T1190: Exploit Public-Facing App
- T1110: Brute Force
- T1486: Data Encrypted for Impact
- T1496: Resource Hijacking (cryptomining)

### 5.3 Container-Focused Attacker Profile

**Characteristics:**
- Targets container infrastructure
- Supply chain attacks
- Cryptomining focus
- Rapid lateral movement

**Key TTPs:**
- T1525: Implant Container Image
- T1610: Deploy Container
- T1611: Escape to Host
- T1496: Resource Hijacking

---

## 6. ATT&CK Navigator Layers

### 6.1 Container Security Focus Layer

```json
{
  "name": "Container Attack Techniques",
  "techniques": [
    {"techniqueID": "T1609", "score": 100, "comment": "Container exec"},
    {"techniqueID": "T1610", "score": 100, "comment": "Deploy container"},
    {"techniqueID": "T1611", "score": 100, "comment": "Container escape"},
    {"techniqueID": "T1613", "score": 100, "comment": "Container discovery"},
    {"techniqueID": "T1525", "score": 80, "comment": "Implant image"},
    {"techniqueID": "T1552.007", "score": 80, "comment": "Container API creds"}
  ]
}
```

### 6.2 Penetration Test Coverage Layer

High-priority techniques to cover:
1. Initial Access (T1190, T1078)
2. Execution (T1059, T1609)
3. Privilege Escalation (T1068, T1611)
4. Credential Access (T1003, T1552)
5. Lateral Movement (T1021, T1210)

---

## 7. Tool Selection by TTP

### 7.1 Quick Reference Table

| Tactic | Primary Tools | Backup Tools |
|--------|---------------|--------------|
| Recon | Nmap, Gobuster | Masscan, Nikto |
| Initial Access | Metasploit, SQLMap | Manual exploitation |
| Execution | PowerShell, Python | Bash, compiled binaries |
| Persistence | Cron, SSH keys | Systemd services |
| Priv Esc | LinPEAS, GTFOBins | Manual enumeration |
| Credential | Mimikatz, Responder | Manual dumping |
| Lateral | PSExec, SSH | WMI, RDP |
| Collection | Custom scripts | Native tools |
| Exfiltration | HTTPS, DNS | ICMP, steganography |

---

## 8. References

- MITRE ATT&CK Framework (attack.mitre.org)
- MITRE ATT&CK for Containers
- ATT&CK Navigator
- Atomic Red Team Tests
- Red Canary Threat Detection Report
- CISA Known Exploited Vulnerabilities

---

**Document Version:** 1.0
**Next Review:** Quarterly
