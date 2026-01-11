# Service Enumeration Tools Training Guide

## Module Overview

**Purpose:** This module provides comprehensive training on service enumeration tools essential for the reconnaissance phase of penetration testing engagements.

**Learning Objectives:**
- Understand the role of service enumeration in penetration testing methodology
- Master four critical enumeration tools: Service Fingerprinter, DNS Enumerator, SMB Enumerator, and Web Directory Enumerator
- Develop practical skills through hands-on lab exercises
- Learn tool chaining techniques for comprehensive target assessment

**Prerequisites:**
- Basic understanding of TCP/IP networking
- Familiarity with common network protocols (HTTP, DNS, SMB)
- Command line proficiency
- Access to authorized lab environment

**Estimated Time:** 4-6 hours

---

## Section 1: Service Enumeration Theory

### 1.1 The Importance of Service Enumeration

Service enumeration represents the systematic process of identifying and cataloging services running on target systems. This phase bridges initial discovery (port scanning) and vulnerability assessment, transforming raw port data into actionable intelligence.

```
+------------------+     +---------------------+     +----------------------+
|   Port Scanning  | --> | Service Enumeration | --> | Vulnerability        |
|   (Discovery)    |     | (Identification)    |     | Assessment           |
+------------------+     +---------------------+     +----------------------+
        |                         |                           |
   Open ports              Service names              Known CVEs
   Protocol hints          Version numbers            Misconfigurations
                           Configuration data         Attack vectors
```

**Why Enumeration Matters:**

1. **Version-Specific Vulnerabilities** - Knowing that a target runs Apache 2.4.49 (vulnerable to CVE-2021-41773) versus 2.4.51 (patched) fundamentally changes your attack approach.

2. **Attack Surface Mapping** - Discovering an exposed SMB share or hidden web directory reveals potential entry points invisible to basic scanning.

3. **Operational Planning** - Understanding service configurations helps predict detection risks and plan engagement timing.

4. **Evidence Collection** - Detailed enumeration data supports comprehensive reporting and remediation guidance.

### 1.2 Information Gathering Methodology

Effective enumeration follows a structured methodology:

```
                    +-------------------+
                    |  Target Scoping   |
                    +-------------------+
                            |
            +---------------+---------------+
            |               |               |
            v               v               v
    +-------------+  +-------------+  +-------------+
    |    DNS      |  |   Service   |  |    Web      |
    | Enumeration |  | Fingerprint |  | Directories |
    +-------------+  +-------------+  +-------------+
            |               |               |
            +---------------+---------------+
                            |
                            v
                    +-------------------+
                    |   SMB/Protocol    |
                    |    Enumeration    |
                    +-------------------+
                            |
                            v
                    +-------------------+
                    |  Data Correlation |
                    +-------------------+
```

**Phase 1: Passive Reconnaissance**
- DNS record analysis reveals infrastructure relationships
- Historical data from archives and certificate transparency logs

**Phase 2: Active Service Identification**
- Banner grabbing and protocol-specific probes
- Version extraction through response analysis

**Phase 3: Deep Enumeration**
- Share enumeration, user discovery
- Web content discovery and application mapping

**Phase 4: Data Correlation**
- Cross-reference findings across tools
- Build comprehensive target profile

---

## Section 2: Service Fingerprinter

### 2.1 Tool Overview

The Service Fingerprinter performs advanced service detection and version identification through protocol-specific probes and banner analysis.

**Core Capabilities:**
- Protocol-specific service probes (HTTP, SSH, FTP, SMTP, MySQL, RDP)
- SSL/TLS detection and certificate analysis
- Version extraction from service banners
- Confidence scoring for identification accuracy
- Planning mode for operational preview

### 2.2 Architecture

```
+----------------------------------------------------------+
|                  Service Fingerprinter                     |
+----------------------------------------------------------+
|  +----------------+    +------------------+               |
|  | FingerprintConfig |  | ServiceInfo      |               |
|  | - target       |    | - port           |               |
|  | - ports[]      |    | - service_name   |               |
|  | - timeout      |    | - version        |               |
|  | - threads      |    | - banner         |               |
|  | - aggressive   |    | - ssl_enabled    |               |
|  | - ssl_check    |    | - confidence     |               |
|  +----------------+    +------------------+               |
|                                                           |
|  +-----------------------------------------------------+ |
|  |              Protocol Probes                         | |
|  | +--------+ +--------+ +--------+ +--------+         | |
|  | |  HTTP  | |  SSH   | |  FTP   | |  SMTP  |         | |
|  | +--------+ +--------+ +--------+ +--------+         | |
|  | +--------+ +--------+ +--------+                    | |
|  | | MySQL  | |  RDP   | |Generic |                    | |
|  | +--------+ +--------+ +--------+                    | |
|  +-----------------------------------------------------+ |
|                                                           |
|  +------------------+                                     |
|  |   SSL Detector   |                                     |
|  | - Version        |                                     |
|  | - Cipher Suite   |                                     |
|  | - Certificate    |                                     |
|  +------------------+                                     |
+----------------------------------------------------------+
```

### 2.3 Protocol-Specific Probes

Each probe implements specialized detection logic:

**HTTP Probe (Ports: 80, 8080, 8000, 8008, 8443, 443)**
```
Request: HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n
Response Analysis:
  - HTTP version from status line
  - Server header extraction (Apache/2.4.41, nginx/1.18.0)
  - Version number parsing via regex patterns
```

**SSH Probe (Ports: 22, 2222, 22222)**
```
Banner Format: SSH-protoversion-softwareversion
Example: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
Extraction:
  - Protocol version (2.0)
  - Software (OpenSSH)
  - Version (8.2p1)
  - OS hints (Ubuntu)
```

**MySQL Probe (Port: 3306)**
```
Greeting Packet Analysis:
  - Protocol version (byte 5)
  - Version string (null-terminated after protocol version)
  - MariaDB detection via version string content
```

### 2.4 SSL/TLS Detection

The SSL Detector performs handshake analysis:

```python
# Detection Process
1. Attempt SSL/TLS connection with permissive context
2. Extract negotiated parameters:
   - Protocol version (TLS 1.2, TLS 1.3)
   - Cipher suite name and bit strength
3. Parse certificate (if available):
   - Subject Common Name (CN)
   - Issuer organization
   - Validity period (notBefore, notAfter)
```

**Security Implications:**
- Expired certificates indicate poor maintenance
- Self-signed certificates suggest internal/dev systems
- Weak cipher suites represent vulnerability vectors

### 2.5 Command Reference

```bash
# Basic fingerprinting with planning preview
python tool.py 192.168.1.100 --ports 22,80,443,3306 --plan

# Execute fingerprinting
python tool.py 192.168.1.100 --ports 22,80,443,3306 -v

# Aggressive mode (try all probes on all ports)
python tool.py 192.168.1.100 --ports 21,22,25,80,443,3306,3389 --aggressive

# Adjust timing for stealth
python tool.py 192.168.1.100 --ports 22,80,443 --delay-min 1 --delay-max 3 -T 5

# Skip SSL detection (faster)
python tool.py 192.168.1.100 --ports 80,8080 --no-ssl

# Save results to JSON
python tool.py 192.168.1.100 --ports 22,80,443 -o fingerprint_results.json
```

**Key Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-P, --ports` | Comma-separated port list | Required |
| `-t, --timeout` | Connection timeout (seconds) | 5.0 |
| `-T, --threads` | Concurrent threads | 10 |
| `-a, --aggressive` | Try all probes on all ports | False |
| `--no-ssl` | Skip SSL/TLS detection | False |
| `--delay-min/max` | Jitter range for stealth | 0.1-0.5s |
| `-p, --plan` | Preview mode (no execution) | False |

### 2.6 Version Extraction Techniques

The tool employs multiple extraction strategies:

**Banner Parsing:**
```
Input:  "220 vsFTPd 3.0.3"
Output: Product=vsftpd, Version=3.0.3

Input:  "SSH-2.0-OpenSSH_8.2p1"
Output: Product=OpenSSH, Version=8.2p1
```

**Header Analysis:**
```
Input:  "Server: Apache/2.4.41 (Ubuntu)"
Output: Product=Apache, Version=2.4.41
```

**Protocol-Specific Parsing:**
```
MySQL greeting packet byte structure:
[4 bytes: packet length][1 byte: protocol][n bytes: version string\0]
```

---

## Section 3: DNS Enumeration

### 3.1 Tool Overview

The DNS Enumerator performs comprehensive DNS reconnaissance including subdomain discovery, zone transfer attempts, and record enumeration.

**Core Capabilities:**
- Multiple record type queries (A, AAAA, NS, MX, TXT, SOA, CNAME)
- Subdomain bruteforcing with built-in or custom wordlists
- Zone transfer (AXFR) attempts
- Custom nameserver support
- Configurable query delays for stealth

### 3.2 DNS Record Types and Meanings

Understanding record types is essential for effective DNS enumeration:

```
+--------+------------------+----------------------------------------+
| Type   | Name             | Intelligence Value                     |
+--------+------------------+----------------------------------------+
| A      | Address          | IPv4 address mapping                   |
| AAAA   | IPv6 Address     | IPv6 address mapping                   |
| NS     | Name Server      | Authoritative DNS servers              |
| MX     | Mail Exchange    | Email infrastructure, priority values  |
| TXT    | Text             | SPF, DKIM, verification tokens         |
| SOA    | Start of Auth    | Primary NS, admin email, zone serial   |
| CNAME  | Canonical Name   | Aliases reveal relationships           |
| SRV    | Service          | Service locations (Kerberos, SIP)      |
| PTR    | Pointer          | Reverse DNS mappings                   |
+--------+------------------+----------------------------------------+
```

**Strategic Record Analysis:**

```
MX Record Analysis:
  example.com  MX  10  mail.example.com
  example.com  MX  20  backup-mail.example.com

  Intelligence:
  - Primary mail server: mail.example.com
  - Backup mail server: backup-mail.example.com
  - Priority 10 < 20 indicates preference order

TXT Record Analysis:
  example.com  TXT  "v=spf1 include:_spf.google.com ~all"

  Intelligence:
  - Organization uses Google Workspace for email
  - SPF policy in "soft fail" mode (~all)
```

### 3.3 Zone Transfer Attacks

Zone transfers (AXFR) are the most powerful DNS enumeration technique when successful:

```
Normal DNS Query:                 Zone Transfer:
+----------+     +----------+    +----------+     +----------+
|  Client  |---->|  NS      |    |  Client  |---->|  NS      |
+----------+     +----------+    +----------+     +----------+
     |                |               |                |
     | Q: A record    |               | Q: AXFR        |
     | for www        |               | for zone       |
     |<---------------|               |<---------------|
     | A: 1 record    |               | A: ALL records |
     |                |               |                |
```

**Attack Process:**
1. Enumerate NS records for target domain
2. Resolve each nameserver to IP address
3. Attempt TCP connection to port 53
4. Send AXFR query packet
5. Parse response for complete zone data

**Why It Often Succeeds:**
- Legacy configurations permitting any source
- Split-horizon DNS misconfigurations
- Forgotten secondary nameservers

### 3.4 Subdomain Bruteforcing

The tool includes a built-in wordlist of 80+ common subdomains:

```
www, mail, remote, blog, webmail, server, ns1, ns2,
smtp, secure, vpn, m, shop, ftp, mail2, test, portal,
admin, store, cdn, api, exchange, app, staging, beta,
intranet, extranet, demo, mobile, gateway, dns, backup...
```

**Bruteforce Process:**
```
For each subdomain in wordlist:
  1. Construct FQDN: {subdomain}.{target_domain}
  2. Query configured record types (A, AAAA, CNAME)
  3. Record responses with TTL values
  4. Apply configurable delay
  5. Continue with threading for performance
```

### 3.5 Command Reference

```bash
# Basic enumeration with planning preview
python tool.py example.com --plan

# Execute with zone transfer attempt
python tool.py example.com --zone-transfer -v

# Custom wordlist
python tool.py example.com -w /path/to/subdomains.txt

# Specific nameserver
python tool.py example.com -n 8.8.8.8

# Multiple record types
python tool.py example.com -r A,AAAA,MX,TXT

# Stealth configuration
python tool.py example.com --delay-min 0.5 --delay-max 2 -t 5

# Save results
python tool.py example.com -o dns_results.json
```

**Key Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-n, --nameserver` | DNS server to query | System resolver |
| `-w, --wordlist` | Subdomain wordlist file | Built-in (80 entries) |
| `-r, --record-types` | Record types to query | A,AAAA,CNAME |
| `-z, --zone-transfer` | Attempt AXFR | False |
| `--no-brute` | Skip subdomain bruteforce | False |
| `-t, --threads` | Concurrent threads | 10 |
| `--delay-min/max` | Query delay range | 0.0-0.1s |

### 3.6 DNS-Based Reconnaissance Techniques

**Reverse DNS Enumeration:**
```bash
# For discovered IP 192.168.1.100
# Construct PTR query: 100.1.168.192.in-addr.arpa
# Result reveals internal hostname
```

**Wildcard Detection:**
```bash
# Query random non-existent subdomain
# If resolves: wildcard DNS configured
# Adjust enumeration strategy accordingly
```

**Certificate Transparency Correlation:**
```
DNS findings + CT logs = comprehensive subdomain list
CT logs may reveal subdomains not in wordlists
```

---

## Section 4: SMB Enumeration

### 4.1 Tool Overview

The SMB Enumerator discovers shares, users, and system information via the SMB/CIFS protocol.

**Core Capabilities:**
- SMB protocol negotiation and version detection
- Null session authentication attempts
- Share enumeration (20 common share names)
- OS and domain information extraction
- SMB signing status detection

### 4.2 SMB Protocol Background

```
+------------------+     +------------------+     +------------------+
|   TCP Connect    | --> |    Negotiate     | --> | Session Setup    |
|   (Port 445)     |     | (Version/Caps)   |     | (Auth)           |
+------------------+     +------------------+     +------------------+
                                |                         |
                         OS Version              User ID
                         SMB Version             Session Key
                         Signing Status
                                                          |
                                                          v
                                                 +------------------+
                                                 |  Tree Connect    |
                                                 |  (Share Access)  |
                                                 +------------------+
```

**SMB Versions:**
- SMB1 (NT LM 0.12) - Legacy, often vulnerable
- SMB2.0 - Windows Vista/Server 2008
- SMB2.1 - Windows 7/Server 2008 R2
- SMB3.0+ - Windows 8/Server 2012+

### 4.3 Share Enumeration

The tool tests 20 common share names:

```
Administrative Shares:          User Shares:
+------------+                  +------------+
| IPC$       | (Named pipes)    | Users      |
| ADMIN$     | (Remote admin)   | Public     |
| C$         | (C: drive)       | Shared     |
| D$         | (D: drive)       | Data       |
| NETLOGON   | (DC logon)       | Backup     |
| SYSVOL     | (DC policies)    +------------+
| print$     | (Print drivers)
+------------+

Application Shares:
+------------+
| IT         |
| Finance    |
| HR         |
| Software   |
+------------+
```

**Share Type Indicators:**
- `$` suffix = Hidden administrative share
- No suffix = User-created/visible share
- IPC$ = Always exists, enables RPC enumeration

### 4.4 Null Session Attacks

Null sessions allow anonymous enumeration on misconfigured systems:

```
Authentication Comparison:

Normal Auth:                    Null Session:
Username: administrator         Username: (empty)
Password: P@ssw0rd!            Password: (empty)
Domain: CORP                    Domain: (empty)

Result: Full access            Result: Limited enumeration
```

**What Null Sessions Reveal:**
- Share listings
- User account names (sometimes)
- Password policy information (sometimes)
- Domain/workgroup membership

**Windows Security Evolution:**
- Windows 2000: Null sessions permitted by default
- Windows XP SP2+: Restricted by default
- Modern Windows: RestrictAnonymous settings control access

### 4.5 OS Detection via SMB

The negotiate response contains OS fingerprinting data:

```
Negotiate Response Structure:
+------------------+
| Security Mode    | -> Signing required/enabled
| Capabilities     | -> Feature flags
| OS String        | -> "Windows Server 2019..."
| LAN Manager      | -> "Windows Server 2019..."
| Domain String    | -> "CORP" or "WORKGROUP"
+------------------+
```

**Version Correlation:**

| OS String Pattern | Likely OS |
|-------------------|-----------|
| Windows 6.1 | Windows 7 / Server 2008 R2 |
| Windows 6.3 | Windows 8.1 / Server 2012 R2 |
| Windows 10.0 | Windows 10/11 / Server 2016+ |

### 4.6 Command Reference

```bash
# Basic enumeration with planning preview
python tool.py 192.168.1.100 --plan

# Execute with null session
python tool.py 192.168.1.100 --null-session -v

# Authenticated enumeration
python tool.py 192.168.1.100 -u admin -P password -d DOMAIN

# Skip user enumeration (shares only)
python tool.py 192.168.1.100 --no-users

# Custom timeout
python tool.py 192.168.1.100 --timeout 15

# Save results
python tool.py 192.168.1.100 -o smb_results.json
```

**Key Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--port` | SMB port | 445 |
| `-u, --username` | Authentication username | None (null) |
| `-P, --password` | Authentication password | None |
| `-d, --domain` | Domain name | Empty |
| `-n, --null-session` | Attempt null session | True |
| `--no-shares` | Skip share enumeration | False |
| `--no-users` | Skip user enumeration | False |
| `--timeout` | Connection timeout | 10.0s |

### 4.7 User Enumeration Techniques

RID cycling reveals user accounts:

```
Well-Known RIDs:
+------+----------------------+
| RID  | Account              |
+------+----------------------+
| 500  | Administrator        |
| 501  | Guest                |
| 502  | KRBTGT (DC only)     |
| 512  | Domain Admins        |
| 513  | Domain Users         |
| 514  | Domain Guests        |
| 515  | Domain Computers     |
| 516  | Domain Controllers   |
| 519  | Enterprise Admins    |
| 544  | Local Administrators |
+------+----------------------+
```

---

## Section 5: Web Directory Enumeration

### 5.1 Tool Overview

The Web Directory Enumerator discovers hidden files and directories through systematic content bruteforcing.

**Core Capabilities:**
- Built-in wordlist (70+ common paths)
- Extension bruteforcing
- Soft 404 detection via baseline calibration
- Custom headers and cookie support
- Configurable status code filtering
- Response analysis (content length, page titles)

### 5.2 Wordlist Selection

**Built-in Wordlist Categories:**

```
Admin/Auth Paths:       Technology-Specific:    Sensitive Files:
- admin                 - wp-admin              - .git
- administrator         - wp-login.php          - .svn
- login                 - phpinfo.php           - .htaccess
- dashboard             - phpmyadmin            - .env
- console               - adminer               - web.config
- manage                - wp-config.php         - config.php
                        - server-status

API/Development:        File Storage:           Backup/Temp:
- api                   - uploads               - backup
- v1, v2                - files                 - temp, tmp
- graphql               - images                - cache
- swagger               - assets                - log, logs
- api-docs              - static                - .bak, .old
```

**Custom Wordlist Strategy:**
- Technology-specific lists (WordPress, Drupal, etc.)
- Industry-specific paths (healthcare, finance)
- Target-derived words (company name, products)

### 5.3 Extension Bruteforcing

For each wordlist entry, append configured extensions:

```
Wordlist Entry: "config"
Extensions: .php, .bak, .old

Generated Paths:
- /config
- /config.php
- /config.bak
- /config.old
```

**Common Extensions by Technology:**

| Technology | Extensions |
|------------|------------|
| PHP | .php, .phtml, .php5 |
| ASP.NET | .aspx, .asp, .ashx |
| Java | .jsp, .jspx, .do |
| Backup | .bak, .old, .orig, .backup |
| Config | .conf, .cfg, .ini |

### 5.4 Soft 404 Handling

Many applications return 200 OK for non-existent pages (soft 404s):

```
Traditional 404:                Soft 404:
Request: /nonexistent          Request: /nonexistent
Response: 404 Not Found        Response: 200 OK
Content: Error page            Content: Custom error page

Problem: Soft 404s create false positives
```

**Baseline Calibration Process:**
```python
1. Request random non-existent paths:
   - /nonexistent_12345
   - /definitely_not_here_67890

2. Record response characteristics:
   - Content length
   - Response content hash

3. Calculate baseline:
   - Average content length
   - Allow 5% variance for dynamic content

4. Filter results:
   - If 200 response matches baseline -> soft 404
   - Exclude from results
```

### 5.5 Command Reference

```bash
# Basic enumeration with planning preview
python tool.py http://target.com --plan

# Execute with extensions
python tool.py http://target.com -x php,html,txt -v

# Custom wordlist
python tool.py http://target.com -w /path/to/wordlist.txt

# Filter specific status codes
python tool.py http://target.com -s 200,301,403

# Exclude known false positives
python tool.py http://target.com --exclude-length 1234

# Add authentication cookie
python tool.py http://target.com -c "session=abc123; auth=xyz"

# Custom headers
python tool.py http://target.com -H "Authorization: Bearer token123"

# Stealth mode
python tool.py http://target.com --delay-min 1 --delay-max 3 -t 5

# Save results
python tool.py http://target.com -o web_results.json
```

**Key Parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-w, --wordlist` | Path to wordlist | Built-in (70 entries) |
| `-x, --extensions` | Extensions to append | None |
| `-t, --threads` | Concurrent threads | 10 |
| `--timeout` | Request timeout | 10.0s |
| `-s, --status-codes` | Codes to report | 200,201,204,301,302,307,401,403 |
| `-e, --exclude-codes` | Codes to ignore | None |
| `--exclude-length` | Content lengths to ignore | None |
| `-H, --header` | Custom headers | None |
| `-c, --cookie` | Session cookies | None |
| `-a, --user-agent` | Custom User-Agent | Chrome-like |
| `--delay-min/max` | Request delay range | 0.0-0.1s |

### 5.6 Recursive Enumeration

When directories are discovered, recursive enumeration explores deeper:

```
Initial Scan:
/admin -> 301 (Directory)
/api   -> 301 (Directory)

Recursive Scan (Depth 1):
/admin/config  -> 200
/admin/users   -> 403
/api/v1        -> 301 (Directory)
/api/v2        -> 301 (Directory)

Recursive Scan (Depth 2):
/api/v1/users  -> 200
/api/v2/docs   -> 200
```

---

## Section 6: Hands-On Labs

### Lab 1: Service Fingerprinting a Multi-Service Host

**Objective:** Identify all services and versions running on a target system.

**Environment Setup:**
```bash
# Start CORE lab environment
docker-compose -f /path/to/core-lab.yml up -d

# Target: 172.17.0.2 (lab-services container)
# Open ports: 21, 22, 25, 80, 443, 3306
```

**Tasks:**

1. **Planning Phase**
   ```bash
   python /path/to/service-fingerprinter/tool.py 172.17.0.2 \
       --ports 21,22,25,80,443,3306 --plan
   ```

   *Expected: Review probe selection, timing estimates, risk assessment*

2. **Execute Fingerprinting**
   ```bash
   python /path/to/service-fingerprinter/tool.py 172.17.0.2 \
       --ports 21,22,25,80,443,3306 -v -o lab1_results.json
   ```

3. **Analyze Results**
   - Document each service name and version
   - Note SSL/TLS status for applicable ports
   - Record confidence levels

**Validation Criteria:**
- [ ] Identified FTP service (vsftpd or ProFTPD)
- [ ] Extracted SSH version (OpenSSH x.x)
- [ ] Detected SMTP server type
- [ ] Found HTTP server header
- [ ] Confirmed SSL on port 443
- [ ] Identified MySQL/MariaDB version

**Extension Challenge:**
Run aggressive mode and compare results. Document any additional findings.

---

### Lab 2: DNS Infrastructure Mapping

**Objective:** Map the complete DNS infrastructure of a target domain.

**Environment Setup:**
```bash
# Target domain: lab.local (configured in lab DNS server)
# Lab DNS server: 172.17.0.3
```

**Tasks:**

1. **Base Domain Enumeration**
   ```bash
   python /path/to/dns-enumerator/tool.py lab.local \
       -n 172.17.0.3 --no-brute -v
   ```

   *Document: NS, MX, TXT, SOA records*

2. **Zone Transfer Attempt**
   ```bash
   python /path/to/dns-enumerator/tool.py lab.local \
       -n 172.17.0.3 --zone-transfer -v
   ```

   *Expected: Zone transfer success in lab environment*

3. **Subdomain Bruteforce**
   ```bash
   python /path/to/dns-enumerator/tool.py lab.local \
       -n 172.17.0.3 -r A,AAAA,CNAME -v -o lab2_results.json
   ```

4. **Result Correlation**
   - Compile unique IP addresses discovered
   - Map subdomains to IP relationships
   - Identify potential segmentation

**Validation Criteria:**
- [ ] Retrieved NS records
- [ ] Extracted MX records with priorities
- [ ] Found TXT records (SPF, etc.)
- [ ] Zone transfer returned data (or documented denial)
- [ ] Discovered 5+ subdomains via bruteforce
- [ ] Extracted unique IP list

**Extension Challenge:**
Create a custom wordlist based on observed naming patterns and re-run enumeration.

---

### Lab 3: SMB Share Discovery

**Objective:** Enumerate SMB shares and system information from a Windows target.

**Environment Setup:**
```bash
# Target: 172.17.0.4 (Windows lab VM or Samba container)
# Ensure SMB port 445 is accessible
```

**Tasks:**

1. **Planning Phase**
   ```bash
   python /path/to/smb-enumerator/tool.py 172.17.0.4 --plan
   ```

2. **Null Session Enumeration**
   ```bash
   python /path/to/smb-enumerator/tool.py 172.17.0.4 \
       --null-session -v -o lab3_null.json
   ```

3. **Authenticated Enumeration** (if credentials provided)
   ```bash
   python /path/to/smb-enumerator/tool.py 172.17.0.4 \
       -u labuser -P labpassword -d WORKGROUP -v -o lab3_auth.json
   ```

4. **Compare Results**
   - Document differences between null and authenticated sessions
   - Note share permissions

**Validation Criteria:**
- [ ] Retrieved OS version information
- [ ] Identified SMB protocol version
- [ ] Determined signing status
- [ ] Found IPC$ share (should always exist)
- [ ] Discovered accessible shares
- [ ] Documented authentication status

**Extension Challenge:**
If null session fails, document the error and research modern Windows hardening settings that prevent it.

---

### Lab 4: Web Application Content Discovery

**Objective:** Discover hidden content on a web application.

**Environment Setup:**
```bash
# Target: http://172.17.0.5 (DVWA or similar web app container)
# Ensure HTTP port 80 is accessible
```

**Tasks:**

1. **Baseline Analysis**
   ```bash
   python /path/to/web-directory-enumerator/tool.py \
       http://172.17.0.5 --plan
   ```

2. **Initial Enumeration**
   ```bash
   python /path/to/web-directory-enumerator/tool.py \
       http://172.17.0.5 -v -o lab4_initial.json
   ```

3. **Extension-Based Discovery**
   ```bash
   python /path/to/web-directory-enumerator/tool.py \
       http://172.17.0.5 -x php,txt,bak -v -o lab4_extensions.json
   ```

4. **Authenticated Scan** (after obtaining session)
   ```bash
   python /path/to/web-directory-enumerator/tool.py \
       http://172.17.0.5 -c "PHPSESSID=abc123" -v -o lab4_auth.json
   ```

5. **False Positive Analysis**
   - Identify baseline 404 content length
   - Note any soft 404s filtered
   - Document interesting status codes

**Validation Criteria:**
- [ ] Baseline calibration completed
- [ ] Found admin/login paths
- [ ] Discovered backup or config files
- [ ] Identified 401/403 protected areas
- [ ] Extracted page titles where available
- [ ] Results saved to JSON

**Extension Challenge:**
Create a custom wordlist targeting the specific application type and re-run with recursive enumeration enabled.

---

## Section 7: Tool Chaining Workflows

### 7.1 Complete Enumeration Methodology

Effective penetration testing chains tool outputs systematically:

```
+------------------+
|   1. DNS Enum    |
|   (Infrastructure|
|    Discovery)    |
+--------+---------+
         |
         | Subdomains, IPs
         v
+------------------+
|  2. Port Scan    |
| (Not covered -   |
|  use nmap/core)  |
+--------+---------+
         |
         | Open ports
         v
+------------------+
|   3. Service     |
|   Fingerprinter  |
+--------+---------+
         |
         | Service versions
         v
+--------+---------+--------+
         |                  |
   HTTP Services       SMB Services
         |                  |
         v                  v
+------------------+ +------------------+
| 4. Web Directory | | 5. SMB Enum      |
|    Enumerator    | |                  |
+------------------+ +------------------+
         |                  |
         v                  v
+------------------------------------------+
|          6. Correlation & Analysis       |
+------------------------------------------+
```

### 7.2 Automated Workflow Script

```bash
#!/bin/bash
# enumeration_workflow.sh
# Complete enumeration workflow for a target domain

TARGET_DOMAIN="$1"
OUTPUT_DIR="./enum_results"
TOOLS_DIR="/path/to/tools"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting enumeration workflow for $TARGET_DOMAIN"

# Step 1: DNS Enumeration
echo "[*] Phase 1: DNS Enumeration"
python "$TOOLS_DIR/dns-enumerator/tool.py" "$TARGET_DOMAIN" \
    --zone-transfer -v \
    -o "$OUTPUT_DIR/dns_results.json"

# Extract unique IPs from DNS results
TARGETS=$(python -c "
import json
with open('$OUTPUT_DIR/dns_results.json') as f:
    data = json.load(f)
    ips = set()
    for r in data.get('records', []):
        if r['type'] in ['A', 'AAAA']:
            ips.add(r['value'])
    print(' '.join(ips))
")

echo "[*] Discovered targets: $TARGETS"

# Step 2: Service Fingerprinting (for each discovered IP)
echo "[*] Phase 2: Service Fingerprinting"
for TARGET_IP in $TARGETS; do
    echo "[*] Fingerprinting $TARGET_IP"
    python "$TOOLS_DIR/service-fingerprinter/tool.py" "$TARGET_IP" \
        --ports 21,22,25,80,443,445,3306,3389,8080 \
        -v -o "$OUTPUT_DIR/fingerprint_${TARGET_IP}.json"
done

# Step 3: Web Directory Enumeration (for HTTP services)
echo "[*] Phase 3: Web Directory Enumeration"
for TARGET_IP in $TARGETS; do
    # Check for HTTP services in fingerprint results
    python -c "
import json
with open('$OUTPUT_DIR/fingerprint_${TARGET_IP}.json') as f:
    data = json.load(f)
    for r in data.get('results', []):
        if r['service_name'] in ['http', 'https']:
            print(r['port'])
" | while read PORT; do
        SCHEME="http"
        [[ "$PORT" == "443" || "$PORT" == "8443" ]] && SCHEME="https"

        echo "[*] Enumerating $SCHEME://$TARGET_IP:$PORT"
        python "$TOOLS_DIR/web-directory-enumerator/tool.py" \
            "$SCHEME://$TARGET_IP:$PORT" \
            -x php,html,txt -v \
            -o "$OUTPUT_DIR/webdir_${TARGET_IP}_${PORT}.json"
    done
done

# Step 4: SMB Enumeration (for SMB services)
echo "[*] Phase 4: SMB Enumeration"
for TARGET_IP in $TARGETS; do
    python -c "
import json
with open('$OUTPUT_DIR/fingerprint_${TARGET_IP}.json') as f:
    data = json.load(f)
    for r in data.get('results', []):
        if r['port'] == 445:
            print('yes')
            break
" | grep -q yes && {
        echo "[*] Enumerating SMB on $TARGET_IP"
        python "$TOOLS_DIR/smb-enumerator/tool.py" "$TARGET_IP" \
            --null-session -v \
            -o "$OUTPUT_DIR/smb_${TARGET_IP}.json"
    }
done

echo "[*] Enumeration complete. Results in $OUTPUT_DIR/"
```

### 7.3 Output Parsing for Automation

**Extracting Key Data from JSON Results:**

```python
#!/usr/bin/env python3
# parse_enum_results.py
# Consolidate enumeration results into actionable intelligence

import json
import glob
from pathlib import Path

def parse_dns_results(filepath):
    """Extract key DNS intelligence."""
    with open(filepath) as f:
        data = json.load(f)

    intel = {
        'subdomains': [],
        'ips': set(),
        'mail_servers': [],
        'nameservers': []
    }

    for record in data.get('records', []):
        if record['type'] == 'A':
            intel['ips'].add(record['value'])
            intel['subdomains'].append(record['name'])
        elif record['type'] == 'MX':
            intel['mail_servers'].append({
                'host': record['value'],
                'priority': record.get('priority')
            })
        elif record['type'] == 'NS':
            intel['nameservers'].append(record['value'])

    intel['ips'] = list(intel['ips'])
    return intel

def parse_fingerprint_results(filepath):
    """Extract service versions for vulnerability correlation."""
    with open(filepath) as f:
        data = json.load(f)

    services = []
    for result in data.get('results', []):
        if result['confidence'] > 0:
            services.append({
                'port': result['port'],
                'service': result['service_name'],
                'product': result['product'],
                'version': result['version'],
                'ssl': result['ssl_enabled']
            })

    return services

def parse_web_results(filepath):
    """Extract discovered web paths."""
    with open(filepath) as f:
        data = json.load(f)

    paths = []
    for result in data.get('results', []):
        paths.append({
            'path': result['path'],
            'status': result['status_code'],
            'size': result['content_length'],
            'title': result.get('title')
        })

    return paths

def parse_smb_results(filepath):
    """Extract SMB enumeration data."""
    with open(filepath) as f:
        data = json.load(f)

    return {
        'system_info': data.get('system_info'),
        'shares': data.get('shares', []),
        'users': data.get('users', [])
    }

# Main consolidation
if __name__ == '__main__':
    results_dir = Path('./enum_results')

    consolidated = {
        'dns': None,
        'services': {},
        'web_content': {},
        'smb': {}
    }

    # Parse DNS
    dns_files = list(results_dir.glob('dns_*.json'))
    if dns_files:
        consolidated['dns'] = parse_dns_results(dns_files[0])

    # Parse fingerprints
    for fp_file in results_dir.glob('fingerprint_*.json'):
        ip = fp_file.stem.replace('fingerprint_', '')
        consolidated['services'][ip] = parse_fingerprint_results(fp_file)

    # Parse web results
    for web_file in results_dir.glob('webdir_*.json'):
        key = web_file.stem.replace('webdir_', '')
        consolidated['web_content'][key] = parse_web_results(web_file)

    # Parse SMB results
    for smb_file in results_dir.glob('smb_*.json'):
        ip = smb_file.stem.replace('smb_', '')
        consolidated['smb'][ip] = parse_smb_results(smb_file)

    # Output consolidated intelligence
    print(json.dumps(consolidated, indent=2))
```

### 7.4 Integration with Vulnerability Databases

Once version information is extracted, correlate with CVE databases:

```python
def generate_searchsploit_queries(services):
    """Generate searchsploit commands for discovered services."""
    queries = []
    for svc in services:
        if svc['product'] and svc['version']:
            queries.append(f"searchsploit {svc['product']} {svc['version']}")
        elif svc['product']:
            queries.append(f"searchsploit {svc['product']}")
    return queries

# Example output:
# searchsploit OpenSSH 8.2
# searchsploit Apache 2.4.41
# searchsploit vsftpd 3.0.3
```

---

## Quick Reference Card

### Service Fingerprinter Commands
```bash
# Plan mode
python tool.py TARGET --ports PORTS --plan

# Basic scan
python tool.py TARGET --ports 22,80,443 -v

# Aggressive (all probes)
python tool.py TARGET --ports 1-1000 --aggressive

# Stealth mode
python tool.py TARGET --ports 22,80 --delay-min 2 --delay-max 5 -T 3
```

### DNS Enumerator Commands
```bash
# Plan mode
python tool.py DOMAIN --plan

# Zone transfer
python tool.py DOMAIN --zone-transfer

# Custom wordlist
python tool.py DOMAIN -w wordlist.txt -r A,AAAA,MX,TXT

# Stealth mode
python tool.py DOMAIN --delay-min 1 --delay-max 3 -t 5
```

### SMB Enumerator Commands
```bash
# Plan mode
python tool.py TARGET --plan

# Null session
python tool.py TARGET --null-session -v

# Authenticated
python tool.py TARGET -u USER -P PASS -d DOMAIN
```

### Web Directory Enumerator Commands
```bash
# Plan mode
python tool.py URL --plan

# With extensions
python tool.py URL -x php,html,txt -v

# Custom wordlist + auth
python tool.py URL -w wordlist.txt -c "session=abc123"

# Stealth mode
python tool.py URL --delay-min 1 --delay-max 3 -t 5
```

---

## Assessment Checklist

Before considering this module complete, verify you can:

- [ ] Explain the role of service enumeration in penetration testing
- [ ] Use the Service Fingerprinter to identify services and versions
- [ ] Perform DNS enumeration including zone transfer attempts
- [ ] Execute SMB enumeration for share and system discovery
- [ ] Conduct web directory enumeration with soft 404 handling
- [ ] Chain tool outputs for comprehensive target assessment
- [ ] Parse JSON results for automation and correlation
- [ ] Apply stealth configurations to minimize detection

---

## Appendix A: Troubleshooting

### Common Issues

**Service Fingerprinter:**
- "Connection refused" - Port not open or filtered
- Timeout errors - Increase `--timeout` value
- Low confidence results - Try `--aggressive` mode

**DNS Enumerator:**
- "No records found" - Check nameserver accessibility
- Zone transfer denied - Expected on hardened servers
- Empty subdomain results - Try larger wordlist

**SMB Enumerator:**
- "Null session failed" - Modern Windows restricts anonymous access
- No shares found - May require authentication
- Connection timeout - Check firewall/port accessibility

**Web Directory Enumerator:**
- Many false positives - Adjust `--exclude-length` based on baseline
- 403 on everything - May need authentication cookies
- Slow performance - Reduce `--threads` if target rate limits

### OPSEC Considerations

1. **Planning Mode First** - Always run `--plan` before execution
2. **Timing Adjustments** - Increase delays in production environments
3. **Thread Reduction** - Fewer threads = slower but stealthier
4. **Log Awareness** - All tools generate server-side logs
5. **Authorization Verification** - Confirm scope before enumeration

---

*Training materials prepared for authorized security assessment training purposes only. Unauthorized use of these tools or techniques may violate applicable laws and regulations.*
