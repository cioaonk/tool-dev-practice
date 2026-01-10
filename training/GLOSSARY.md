# CPTC Training Glossary

A comprehensive reference for technical terms used throughout the training materials.

**Skill Level Key:** [B] Beginner | [I] Intermediate | [A] Advanced

---

## A

### AMSI (Antimalware Scan Interface) [I]
A Windows security feature that allows applications to send content to antimalware solutions for scanning before execution. Commonly intercepts PowerShell scripts, VBScript, and .NET assembly loads. See also: EDR, AV.

### ARP (Address Resolution Protocol) [B]
A network protocol used to map IP addresses to MAC (hardware) addresses on a local network. ARP scanning can discover hosts on the same network segment without using TCP/IP connections.

### AV (Antivirus) [B]
Software designed to detect and remove malicious programs. Traditional AV primarily uses signature-based detection (matching known bad patterns), while modern solutions include behavioral analysis. See also: EDR.

### Attack Surface [B]
The total number of points (entry points, vulnerabilities, services) where an attacker could try to enter or extract data from a system or network.

---

## B

### Banner [B]
Text information sent by a service when a connection is established. Banners often reveal software name and version (e.g., "SSH-2.0-OpenSSH_8.2p1"). Banner grabbing is a reconnaissance technique.

### Bind Shell [I]
A type of shell where the target system opens a listening port and waits for the attacker to connect. Opposite of a reverse shell. Less common because firewalls typically block inbound connections.

### Bruteforce [B]
An attack method that systematically tries all possible combinations (passwords, keys, etc.) until the correct one is found. Dictionary attacks use wordlists; pure bruteforce tries every possibility.

---

## C

### C2 (Command and Control) [I]
Infrastructure used by attackers to communicate with compromised systems. Also called C&C. Includes servers, protocols, and channels for sending commands and receiving data.

### CIDR (Classless Inter-Domain Routing) [B]
Notation for specifying IP address ranges. Example: 192.168.1.0/24 means all addresses from 192.168.1.0 to 192.168.1.255 (256 addresses). The number after the slash indicates how many bits are fixed.

| CIDR | Addresses | Common Name |
|------|-----------|-------------|
| /32 | 1 | Single host |
| /24 | 256 | Class C |
| /16 | 65,536 | Class B |
| /8 | 16,777,216 | Class A |

### Callback [I]
When a compromised system initiates a connection back to the attacker's infrastructure. Used in reverse shells and C2 communications to bypass firewalls that block inbound connections.

### Credential Stuffing [I]
Attack technique using stolen username/password pairs from one breach to attempt access on other services, exploiting password reuse.

---

## D

### DLL (Dynamic Link Library) [I]
A Windows file containing code and data that can be used by multiple programs simultaneously. Many system functions are provided through DLLs like kernel32.dll and ntdll.dll.

### DNS (Domain Name System) [B]
The system that translates human-readable domain names (example.com) into IP addresses (93.184.216.34). DNS enumeration reveals subdomains and infrastructure.

### Domain Controller (DC) [I]
A Windows server that manages security authentication within a Windows domain network. Contains user accounts, passwords (as hashes), and Group Policy. High-value target in penetration tests.

---

## E

### EDR (Endpoint Detection and Response) [I]
Advanced security software that monitors endpoints (computers, servers) for suspicious activity. Unlike traditional AV, EDR focuses on behavior patterns, can respond to threats, and provides forensic data. Examples: CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne.

### Encoding [B]
Converting data from one format to another. In security context, often used to avoid special character issues (Base64) or evade basic detection. Encoding is NOT encryption - encoded data can be easily decoded.

### Enumeration [B]
The process of extracting detailed information about a target: usernames, shares, services, versions, configurations. Goes beyond discovery to gather actionable intelligence.

### ETW (Event Tracing for Windows) [A]
A Windows kernel-level tracing facility that provides detailed system events. Used by security tools for detection. Cannot be fully bypassed from user mode.

### Exfiltration [I]
The unauthorized transfer of data out of a target environment. Techniques include DNS tunneling, HTTP/S uploads, and encrypted channels.

---

## F

### Fingerprinting [B]
Identifying specific software, versions, and configurations of services. Service fingerprinting determines what application is running on an open port and its version number.

### Firewall [B]
Network security device/software that monitors and controls incoming and outgoing traffic based on rules. Can block ports, IP addresses, or protocols.

---

## G

### Gateway [B]
A network device (usually a router) that serves as an access point to another network. The default gateway is the device that routes traffic from a local network to the internet.

---

## H

### Handler [I]
In payload context, a listener that waits for and manages incoming connections from reverse shells. Receives the callback and provides an interactive session.

### Hash [B]
A fixed-size string generated from input data using a mathematical function. Used for password storage (instead of plaintext). Common types: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars), NTLM (32 chars).

### Hook (API Hook) [A]
A technique to intercept function calls. EDR solutions "hook" Windows API functions by modifying their code to redirect execution through monitoring code before the actual function runs.

### Host Discovery [B]
The process of finding which IP addresses in a range have active systems. Methods include ping sweeps, TCP probes, and ARP requests.

---

## I

### IDS/IPS (Intrusion Detection/Prevention System) [I]
Security systems that monitor network traffic for suspicious activity. IDS alerts on threats; IPS actively blocks them. Can detect port scans, known attack patterns, and anomalies.

---

## J

### JSON (JavaScript Object Notation) [B]
A lightweight data format commonly used for storing and transmitting structured data. Many tools output results in JSON for easy parsing and automation.

---

## K

### Kerberos [I]
The authentication protocol used in Windows Active Directory environments. Uses tickets instead of transmitting passwords. Attacks include Kerberoasting and Pass-the-Ticket.

### Kernel [I]
The core component of an operating system that manages system resources and hardware. Kernel mode has full system access; user mode is restricted. EDR kernel components cannot be bypassed from user mode.

---

## L

### Lateral Movement [I]
Techniques attackers use to move through a network after initial access, pivoting from one compromised system to access others.

### Living off the Land (LOLBins) [I]
Using legitimate system tools (certutil, powershell, wmic) for malicious purposes, reducing the need for custom malware and avoiding detection.

### LHOST/LPORT [I]
Listener Host/Listener Port - the attacker's IP address and port number where a reverse shell handler is running. Must be reachable from the target.

---

## M

### MAC Address [B]
A unique hardware identifier assigned to network interfaces. Used in ARP for local network communication. Format: XX:XX:XX:XX:XX:XX (six pairs of hex digits).

### MITRE ATT&CK [I]
A knowledge base of adversary tactics and techniques based on real-world observations. Provides a common framework for describing attacks. Referenced by ID numbers (e.g., T1059 - Command and Scripting Interpreter).

---

## N

### NAT (Network Address Translation) [B]
Technique that allows multiple devices on a private network to share a single public IP address. Complicates inbound connections (hence why reverse shells are preferred).

### Null Session [I]
An anonymous connection to Windows systems (particularly SMB). Historically allowed enumeration of users, shares, and system information without authentication. Modern systems typically restrict this.

### ntdll.dll [A]
A critical Windows DLL that provides the interface between user-mode applications and the Windows kernel. Contains the actual syscall instructions. Primary target for EDR hooks.

---

## O

### Obfuscation [I]
Techniques to make code harder to analyze or detect. Includes variable renaming, string encryption, control flow changes. Does NOT provide security - determined analysis will reveal the original functionality.

### OPSEC (Operational Security) [I]
Practices to avoid detection and maintain stealth during operations. Includes considering what logs are generated, what traffic patterns are created, and what artifacts are left behind.

---

## P

### Payload [I]
Code designed to execute on a target system, typically to provide access (shell) or perform specific actions. "Payload" does NOT mean "malware" - it simply means the code that does the work after delivery.

### Pivot [I]
Using a compromised system as a jumping point to attack other systems that are not directly accessible from the attacker's network.

### Port [B]
A virtual endpoint for network communication. Think of an IP address as a building address and a port as an apartment number. Services listen on specific ports (HTTP=80, HTTPS=443, SSH=22, SMB=445). Range: 0-65535.

| Port Range | Description |
|------------|-------------|
| 0-1023 | Well-known/privileged ports |
| 1024-49151 | Registered ports |
| 49152-65535 | Dynamic/private ports |

### Privilege Escalation (PrivEsc) [I]
Techniques to gain higher-level permissions on a system, such as moving from a regular user to administrator/root access.

### Protocol [B]
A set of rules governing how data is transmitted. Network protocols include TCP, UDP, HTTP, DNS, SMB. Each has specific behaviors and use cases.

### PTY (Pseudo-Terminal) [I]
A software interface that emulates a hardware terminal. Shell connections need PTY allocation for proper interactive features (command editing, job control).

---

## R

### Reconnaissance (Recon) [B]
The information-gathering phase of an engagement. Passive recon uses public information; active recon directly probes targets. Quality reconnaissance directly impacts success rate.

### Reverse Shell [I]
A type of shell where the target system initiates an outbound connection to the attacker. Works around firewalls that block inbound connections but allow outbound traffic.

```
Normal Connection:    Attacker --> Target (often blocked by firewall)
Reverse Shell:        Target --> Attacker (usually allowed)
```

### Root/Administrator [B]
The highest privilege level on a system. Root (Linux/Unix) and Administrator (Windows) can access all files and execute any command. Many security techniques require these privileges.

### RPC (Remote Procedure Call) [I]
A protocol for executing code on remote systems. Windows uses MSRPC extensively. Port 135 is the RPC endpoint mapper.

---

## S

### Shell [B]
A command-line interface for interacting with an operating system. bash (Linux), cmd.exe (Windows), and PowerShell (Windows) are common shells.

### Shellcode [A]
Low-level machine code (often in hexadecimal format) designed to be injected and executed in memory. Called "shellcode" because it traditionally spawned command shells, though modern shellcode performs various functions.

### SMB (Server Message Block) [I]
A Windows protocol for file sharing, printer access, and inter-process communication. Port 445 (modern) and 139 (legacy). SMB enumeration reveals shares, users, and system information.

### SOCKS Proxy [I]
A protocol for routing network traffic through an intermediary server. Used for pivoting through compromised systems.

### Syscall (System Call) [A]
The interface between user-mode applications and the operating system kernel. Direct syscalls execute kernel functions without going through hooked API functions, bypassing user-mode EDR hooks.

---

## T

### TCP (Transmission Control Protocol) [B]
A connection-oriented network protocol that ensures reliable, ordered data delivery. Uses a three-way handshake (SYN, SYN-ACK, ACK) to establish connections.

### TTL (Time to Live) [B]
A field in network packets that limits how many network hops a packet can traverse. Also refers to how long data should be cached.

### TTY (Teletypewriter) [I]
Historical term for terminal devices. In modern context, refers to terminal interfaces. "Getting a TTY" means upgrading a basic shell to a fully interactive terminal.

---

## U

### UDP (User Datagram Protocol) [B]
A connectionless network protocol that sends data without establishing a connection or guaranteeing delivery. Faster but less reliable than TCP. Used by DNS (port 53), DHCP, and some games.

### User-mode vs Kernel-mode [A]
Two privilege levels in operating systems. User-mode has restricted access; kernel-mode has full hardware access. EDR user-mode hooks can be bypassed; kernel-mode protections cannot (from user mode).

---

## V

### Virtual Host (vhost) [I]
Web server configuration that allows multiple websites to run on a single server/IP address. Enumeration can discover hidden sites by testing different Host headers.

### VPN (Virtual Private Network) [B]
Encrypted tunnel between your device and a server, making your traffic appear to originate from the VPN server's location.

---

## W

### Web Shell [I]
A script uploaded to a web server that provides command execution through HTTP requests. Allows interaction through a browser or curl. Example: `http://target/shell.php?cmd=whoami`

### Wordlist [B]
A file containing words, phrases, or patterns used for dictionary attacks against passwords, usernames, or web directories. Common lists: rockyou.txt, SecLists.

---

## X

### XOR Encoding [I]
A simple encoding technique where each byte is XORed with a key. Easily reversible (XOR with same key decodes). Used to avoid simple signature detection but not truly secure.

---

## Z

### Zone Transfer (AXFR) [I]
A DNS query type that requests a copy of all DNS records for a domain. When misconfigured, reveals complete infrastructure. Usually blocked on properly configured servers.

---

## Common Abbreviations Reference

| Abbreviation | Full Form |
|--------------|-----------|
| AD | Active Directory |
| APT | Advanced Persistent Threat |
| AV | Antivirus |
| C2/C&C | Command and Control |
| CVE | Common Vulnerabilities and Exposures |
| DC | Domain Controller |
| DLL | Dynamic Link Library |
| DNS | Domain Name System |
| EDR | Endpoint Detection and Response |
| FTP | File Transfer Protocol |
| HTTP/S | Hypertext Transfer Protocol (Secure) |
| IDS | Intrusion Detection System |
| IPS | Intrusion Prevention System |
| LDAP | Lightweight Directory Access Protocol |
| NTLM | NT LAN Manager |
| OPSEC | Operational Security |
| OS | Operating System |
| RCE | Remote Code Execution |
| RDP | Remote Desktop Protocol |
| SMB | Server Message Block |
| SQL | Structured Query Language |
| SSH | Secure Shell |
| SSL/TLS | Secure Sockets Layer / Transport Layer Security |
| TCP | Transmission Control Protocol |
| UDP | User Datagram Protocol |

---

## Port Quick Reference

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | File transfer, check for anonymous access |
| 22 | SSH | Secure remote access |
| 23 | Telnet | Insecure remote access (legacy) |
| 25 | SMTP | Email sending |
| 53 | DNS | Name resolution, zone transfers |
| 80 | HTTP | Web traffic |
| 88 | Kerberos | Windows authentication |
| 110 | POP3 | Email retrieval |
| 135 | RPC | Windows services |
| 139 | NetBIOS | Legacy Windows networking |
| 143 | IMAP | Email retrieval |
| 389 | LDAP | Directory services |
| 443 | HTTPS | Secure web traffic |
| 445 | SMB | Windows file sharing |
| 636 | LDAPS | Secure LDAP |
| 1433 | MSSQL | Microsoft SQL Server |
| 3306 | MySQL | MySQL database |
| 3389 | RDP | Windows Remote Desktop |
| 5432 | PostgreSQL | PostgreSQL database |
| 5985 | WinRM | Windows Remote Management |

---

*Last updated: January 2026*
*For questions about specific terms, consult the relevant walkthrough document.*
