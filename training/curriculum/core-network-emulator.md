# CORE Network Emulator Training

**Skill Level**: Intermediate to Advanced [I/A]

A comprehensive guide to using the CORE Network Emulator for penetration testing practice with the CPTC11 network topologies.

> **New to network emulation?** Review the [Glossary](../GLOSSARY.md) for definitions of technical terms used in this training module.

---

## Prerequisites

Before starting this module, ensure you:

- [ ] Have CORE/IMUNES installed on a Linux system (Ubuntu 20.04+ recommended)
- [ ] Understand basic networking concepts (IP addressing, subnets, routing)
- [ ] Are familiar with command-line Linux operations
- [ ] Have root/sudo access on the emulation host
- [ ] Understand TCP/IP fundamentals and common services

**Recommended Reading**: [Glossary](../GLOSSARY.md) entries for: VLAN, Subnet, Firewall, DMZ, ICS, SCADA, Modbus

---

## Module Overview

### Purpose

Master the CORE Network Emulator to create realistic network environments for penetration testing practice. This module covers installation, configuration, and practical use of the CPTC11 network topologies designed for offensive security training.

### Learning Objectives

By completing this training, you will be able to:

- Install and configure the CORE Network Emulator
- Load and operate the four CPTC11 network topologies
- Understand each topology's architecture, services, and attack surfaces
- Configure and customize service scripts for varied training scenarios
- Connect external attack tools to emulated networks
- Capture and analyze network traffic during assessments
- Create custom topologies for specialized training needs

### Time Estimate

- Reading: 2 hours
- Hands-on Practice: 4-6 hours

---

## Part 1: Introduction to CORE Network Emulator

### What is CORE/IMUNES?

The Common Open Research Emulator (CORE) is a network emulation tool that creates virtual networks using lightweight Linux containers. Originally developed by Boeing and the Naval Research Laboratory, CORE enables security professionals to build realistic network environments without the hardware costs of physical labs. IMUNES (Integrated Multiprotocol Network Emulator/Simulator) is the predecessor technology that CORE builds upon, and the `.imn` file format originates from IMUNES.

Unlike network simulators that model network behavior mathematically, CORE creates actual network stacks running real applications. Each emulated node runs a separate network namespace with its own interfaces, routing tables, and process space. This means you can run actual penetration testing tools against emulated targets and observe genuine network traffic and service responses.

CORE represents networks using the IMN (IMUNES Network) file format, a text-based configuration that defines nodes, links, services, and canvas layouts. The CPTC11 project provides four pre-built IMN topologies representing common enterprise environments you will encounter in Collegiate Penetration Testing Competitions and real-world engagements.

The emulator operates by creating Linux network namespaces connected via virtual Ethernet pairs. When you start an emulation session, CORE instantiates each node as an isolated container, configures its network interfaces according to the IMN specification, and executes any defined startup scripts. This architecture allows nodes to run actual services like Apache, MySQL, or custom scripts that respond authentically to network probes.

### Benefits for Security Training

CORE provides significant advantages for offensive security education that other approaches cannot match:

**Realistic Network Behavior**: Because CORE uses actual network stacks and real services, penetration testing tools produce authentic results. Nmap scans return genuine service banners, vulnerability scanners detect real misconfigurations, and exploit attempts succeed or fail based on actual service behavior rather than simulated responses.

**Safe Isolated Environment**: All emulated traffic remains within the host machine's memory and network namespaces. There is no risk of accidentally scanning production systems or triggering alerts on external networks. Students can practice aggressive techniques safely.

**Reproducible Scenarios**: IMN files define complete network states. Instructors can distribute identical lab environments to all students, ensuring consistent training experiences. Topologies can be reset instantly by stopping and restarting the emulation session.

**Resource Efficiency**: A single laptop can emulate networks with dozens of nodes, each running multiple services. This efficiency enables complex enterprise topologies without requiring expensive hardware labs or cloud infrastructure.

**Rapid Iteration**: Modifying topologies takes seconds rather than hours of physical reconfiguration. Instructors can adjust difficulty levels, add vulnerabilities, or expand networks dynamically during training sessions.

**Traffic Capture Integration**: CORE integrates with tcpdump and Wireshark, enabling students to capture and analyze all network traffic. This capability supports both offensive technique development and defensive analysis training.

### Installation and Setup

#### System Requirements

- **Operating System**: Ubuntu 20.04 LTS or newer (Ubuntu 22.04 recommended)
- **Memory**: Minimum 4GB RAM (8GB+ recommended for larger topologies)
- **Storage**: 2GB for CORE plus space for captured traffic
- **Processor**: Multi-core x86_64 processor
- **Privileges**: Root access required for network namespace creation

#### Installation Steps

**Step 1: Install Dependencies**

```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-tk \
    iproute2 bridge-utils ebtables \
    xterm lxterminal \
    tcpdump wireshark \
    quagga openssh-server \
    vsftpd apache2 \
    net-tools iptables
```

**Step 2: Install CORE from Package**

```bash
# Download the latest CORE release
wget https://github.com/coreemu/core/releases/download/release-9.0.3/core_9.0.3_amd64.deb

# Install the package
sudo dpkg -i core_9.0.3_amd64.deb

# Fix any dependency issues
sudo apt --fix-broken install
```

**Step 3: Install Python Dependencies**

```bash
sudo pip3 install \
    grpcio==1.54.2 \
    grpcio-tools==1.54.2 \
    pyproj \
    lxml
```

**Step 4: Start CORE Daemon**

```bash
# Start the daemon
sudo systemctl start core-daemon

# Enable on boot
sudo systemctl enable core-daemon

# Verify status
sudo systemctl status core-daemon
```

**Step 5: Launch CORE GUI**

```bash
# Launch the graphical interface
core-gui
```

#### Verifying Installation

After installation, verify CORE operates correctly:

```bash
# Check daemon is running
sudo systemctl status core-daemon

# Test creating a simple namespace
sudo ip netns add test-ns
sudo ip netns list
sudo ip netns delete test-ns

# Launch GUI and create a two-node test
core-gui
```

Create two PC nodes, connect them with a link, and start the session. Open terminals on each node and verify ping connectivity. If this succeeds, your installation is ready for the CPTC11 topologies.

---

## Part 2: CPTC11 Network Topologies

The CPTC11 project includes four network topologies representing common enterprise environments. Each topology features intentionally vulnerable configurations designed for penetration testing practice.

### Topology 1: Corporate Network (corporate-network.imn)

#### Full Topology Diagram

```
                            INTERNET
                               |
                        [isp-router]
                        203.0.113.254
                               |
                               | 203.0.113.0/24
                               |
                        [fw-external]
                        203.0.113.1
                        10.100.1.1  (DMZ)
                        10.100.2.1  (Internal)
                        10.100.3.1  (Database)
                               |
          +--------------------+--------------------+
          |                    |                    |
    [sw-dmz]            [sw-internal]        [sw-database]
          |                    |                    |
    +-----+-----+        +-----+-----+        +-----+-----+
    |           |        |     |     |        |           |
[web-srv]  [mail-srv]  [ws1] [ws2] [ws3]  [db-srv]  [backup-srv]
10.100.1.10 10.100.1.20 .10   .11   .12   10.100.3.10 10.100.3.20

                    DMZ ZONE: 10.100.1.0/24
            +---------------------------------------+
            |  web-server     mail-server           |
            |  10.100.1.10    10.100.1.20           |
            |  HTTP/80        SMTP/25              |
            |  SSH/22         SSH/22               |
            +---------------------------------------+

                INTERNAL ZONE: 10.100.2.0/24
            +---------------------------------------+
            |  workstation-1  workstation-2  ws-3   |
            |  10.100.2.10    10.100.2.11    .12    |
            |  SSH/22         SSH/22        SSH/22  |
            +---------------------------------------+

                DATABASE ZONE: 10.100.3.0/24
            +---------------------------------------+
            |  db-server         backup-server      |
            |  10.100.3.10       10.100.3.20        |
            |  MySQL/3306        FTP/21             |
            |  SSH/22            SSH/22             |
            +---------------------------------------+
```

#### Node Descriptions and IP Assignments

| Node | Hostname | IP Address(es) | Role | Services |
|------|----------|---------------|------|----------|
| n1 | fw-external | 203.0.113.1, 10.100.1.1, 10.100.2.1, 10.100.3.1 | Perimeter Firewall | IPForward, iptables |
| n2 | sw-dmz | - | DMZ Switch | L2 switching |
| n3 | sw-internal | - | Internal Switch | L2 switching |
| n4 | sw-database | - | Database Switch | L2 switching |
| n5 | web-server | 10.100.1.10 | Web Application Server | HTTP/80, SSH/22 |
| n6 | mail-server | 10.100.1.20 | Email Server | SMTP/25, SSH/22 |
| n7 | workstation-1 | 10.100.2.10 | Employee Workstation | SSH/22 |
| n8 | workstation-2 | 10.100.2.11 | Employee Workstation | SSH/22 |
| n9 | workstation-3 | 10.100.2.12 | Employee Workstation | SSH/22 |
| n10 | db-server | 10.100.3.10 | Database Server | MySQL/3306, SSH/22 |
| n11 | backup-server | 10.100.3.20 | Backup Storage | FTP/21, SSH/22 |
| n12 | isp-router | 203.0.113.254 | ISP Gateway | IPForward |

#### Service Configurations

**Web Server (10.100.1.10)**
- Python HTTP server on port 80
- Corporate portal with login form
- PHP info disclosure page
- Intentionally missing input validation

**Mail Server (10.100.1.20)**
- Postfix banner simulation on port 25
- Server name disclosure in banner
- No authentication required for banner grab

**Database Server (10.100.3.10)**
- MySQL 5.7.32 banner response
- Database credentials potentially accessible from web server
- Contains simulated customer data

**Backup Server (10.100.3.20)**
- FTP service with anonymous login enabled
- Banner reveals hostname and software version
- Backup files visible in directory listing

#### Firewall Rules Analysis

The fw-external router implements stateful packet filtering:

```
Policy: Default FORWARD DROP

Inbound Allowed (eth0 -> DMZ):
- TCP 80 (HTTP to web server)
- TCP 443 (HTTPS to web server)
- TCP 25 (SMTP to mail server)

DMZ to Database (eth1 -> eth3):
- TCP 3306 (MySQL from DMZ servers)

Internal to DMZ (eth2 -> eth1):
- All traffic allowed (full access)

Internal to Database (eth2 -> eth3):
- All traffic allowed (full access)

Outbound: Masqueraded via eth0
```

#### Attack Surface Analysis

**External Attack Surface** (from ISP router perspective):
1. Web application on 10.100.1.10:80 - Potential SQLi, XSS, authentication bypass
2. Mail server on 10.100.1.20:25 - User enumeration via VRFY, relay testing
3. Firewall itself - Limited services exposed

**DMZ Attack Surface** (after initial compromise):
1. Database connectivity from web/mail servers
2. Potential credential harvesting from web application configs
3. Lateral movement opportunities to internal network via firewall misconfiguration

**Internal Attack Surface** (pivot opportunities):
1. Workstations with SSH enabled - Password attacks
2. Full database access from internal network
3. Backup server with FTP - Credential theft from backup files

#### Recommended Exercises

**Exercise 1: External Reconnaissance**
- Perform port scanning from simulated external position
- Enumerate services and versions on DMZ hosts
- Identify firewall rules through probe responses

**Exercise 2: Web Application Testing**
- Test login form for SQL injection
- Discover hidden directories via robots.txt
- Attempt to access database from web server context

**Exercise 3: Lateral Movement**
- Compromise DMZ host and pivot to database segment
- Extract credentials from backup files
- Escalate from workstation to server access

---

### Topology 2: Small Business Network (small-business.imn)

#### Topology Diagram

```
                          INTERNET
                              |
                       [isp-gateway]
                       192.168.100.254
                              |
                              | 192.168.100.0/24
                              |
                        [fw-router]
                        192.168.100.1
                        10.0.0.1
                              |
                              | 10.0.0.0/24
                              |
                       [main-switch]
                              |
    +------------+------------+------------+------------+
    |            |            |            |            |
[file-srv]  [print-srv]  [nas-backup]  [Workstations x7]
10.0.0.10   10.0.0.11    10.0.0.12     10.0.0.20-26

         FLAT NETWORK TOPOLOGY: 10.0.0.0/24
    +------------------------------------------------+
    |                                                |
    |   SERVERS:                                     |
    |   file-server    10.0.0.10  SMB/445, SSH/22    |
    |   print-server   10.0.0.11  IPP/631, SSH/22    |
    |   nas-backup     10.0.0.12  FTP/21, HTTP/5000  |
    |                                                |
    |   WORKSTATIONS:                                |
    |   ws-reception     10.0.0.20  (no services)    |
    |   ws-accounting-1  10.0.0.21  SSH/22           |
    |   ws-accounting-2  10.0.0.22  SSH/22           |
    |   ws-manager       10.0.0.23  SSH/22           |
    |   ws-sales-1       10.0.0.24  (no services)    |
    |   ws-sales-2       10.0.0.25  (no services)    |
    |   ws-warehouse     10.0.0.26  (no services)    |
    |                                                |
    +------------------------------------------------+
```

#### Topology and Design Rationale

This topology represents a typical small business with limited IT resources and budget constraints. Key characteristics include:

**Flat Network Architecture**: All systems reside on a single subnet without segmentation. This common SMB mistake allows any compromised system to directly attack all others.

**Minimal Firewall Rules**: The router implements permissive default policies with only basic inbound filtering. External SSH and SMB are blocked, but internal traffic flows freely.

**Consumer-Grade Equipment Simulation**: The NAS device exposes a web management interface with default credentials, simulating common SOHO equipment vulnerabilities.

**Mixed Security Awareness**: Some workstations run SSH (tech-savvy users), others have no remote services (standard users). This represents realistic organizational security variance.

#### Common SMB Vulnerabilities Represented

| Vulnerability | Location | Impact |
|--------------|----------|--------|
| Flat network design | Network architecture | Full lateral movement from any host |
| Default NAS credentials | nas-backup:5000 | Administrative access to backup device |
| SMB null sessions | file-server:445 | Share enumeration without authentication |
| Weak firewall rules | fw-router | Limited traffic filtering |
| Anonymous FTP | nas-backup:21 | Backup file access |
| Sensitive data in shares | file-server SMB | Credential and data exposure |
| Print server web UI | print-server:631 | CUPS exploitation potential |

#### Service Details

**File Server (10.0.0.10)**
```
Ports: 139/tcp, 445/tcp, 22/tcp
Shares:
  - public (guest read access)
  - accounting (restricted)
  - hr (restricted)
Vulnerabilities:
  - SMBv1 enabled for compatibility
  - NTLMv1 authentication accepted
  - Sensitive files in shares
```

**NAS Backup (10.0.0.12)**
```
Ports: 21/tcp, 5000/tcp, 22/tcp
Services:
  - FTP: Anonymous access enabled
  - HTTP: "QuickNAS Pro" web interface
  - Default credentials: admin/admin
Vulnerabilities:
  - Default credentials displayed on login page
  - FTP backup file exposure
  - Weak session management
```

**Print Server (10.0.0.11)**
```
Ports: 631/tcp, 22/tcp
Service: CUPS 2.3.3 administration interface
Vulnerabilities:
  - Web interface exposed
  - Potential command injection in printer config
  - Information disclosure in error pages
```

#### Testing Scenarios

**Scenario 1: Network Discovery and Enumeration**
- Map all live hosts on 10.0.0.0/24
- Enumerate SMB shares without authentication
- Discover NAS default credentials
- Extract employee information from HR share

**Scenario 2: Credential Harvesting**
- Access FTP backup files anonymously
- Extract database credentials from backup scripts
- Parse network documentation from IT share
- Build username list from employee records

**Scenario 3: Lateral Movement Chain**
- Compromise NAS via default credentials
- Pivot to file server using harvested credentials
- Access accounting data with escalated privileges
- Demonstrate business impact of flat network

---

### Topology 3: University Network (university-network.imn)

#### Segmentation Architecture

```
                              INTERNET
                                  |
                           [isp-border]
                           198.51.100.1
                                  |
                                  | 198.51.100.0/24
                                  |
                           [core-router]
                           198.51.100.2
                     172.16.0-4.1 (all segments)
                                  |
         +----------+-------------+-------------+----------+
         |          |             |             |          |
   [rtr-student] [rtr-faculty] [rtr-guest] [rtr-servers]
   172.16.1.254  172.16.2.254  172.16.3.254 172.16.4.254
   172.16.10.1   172.16.20.1   172.16.30.1  172.16.40.1
         |          |             |             |
   [sw-student] [sw-faculty]  [sw-guest]  [sw-servers]
         |          |             |             |
    +----+----+  +--+--+      +--+--+     +----+----+----+
    |    |    |  |     |      |     |     |    |    |    |
  [PC1][PC2][PC3][F1] [F2]  [G1]  [G2]  [Web][DB][LDAP][DNS][Mail]

    STUDENT NETWORK: 172.16.10.0/24
    +------------------------------------------+
    |  student-pc-1  172.16.10.10  (no svcs)   |
    |  student-pc-2  172.16.10.11  (no svcs)   |
    |  student-pc-3  172.16.10.12  (no svcs)   |
    |  ** BLOCKED from Server Farm **          |
    +------------------------------------------+

    FACULTY NETWORK: 172.16.20.0/24
    +------------------------------------------+
    |  faculty-pc-1  172.16.20.10  SSH/22      |
    |  faculty-pc-2  172.16.20.11  SSH/22      |
    |  ** Full campus access **                |
    +------------------------------------------+

    GUEST WIFI: 172.16.30.0/24
    +------------------------------------------+
    |  guest-device-1  172.16.30.100 (no svcs) |
    |  guest-device-2  172.16.30.101 (no svcs) |
    |  ** Misconfigured isolation **           |
    +------------------------------------------+

    SERVER FARM: 172.16.40.0/24
    +------------------------------------------+
    |  dns-server    172.16.40.5   DNS/53      |
    |  web-portal    172.16.40.10  HTTP/80,443 |
    |  db-server     172.16.40.20  MySQL/3306  |
    |  ldap-server   172.16.40.30  LDAP/389    |
    |  mail-server   172.16.40.40  SMTP/25,143 |
    +------------------------------------------+
```

#### Multiple User Populations

The university network serves distinct user communities with different access requirements:

**Students (172.16.10.0/24)**
- Largest population with least privileges
- Internet access only
- Blocked from direct server farm access
- Dynamic DHCP assignments simulated

**Faculty (172.16.20.0/24)**
- Elevated privileges for teaching/research
- SSH access enabled on workstations
- Full campus network access
- Static IP assignments

**Guests (172.16.30.0/24)**
- Temporary visitors and conference attendees
- Supposed to be isolated from internal resources
- Misconfigured firewall rules create bypass opportunity

**Infrastructure (172.16.40.0/24)**
- Critical university services
- Should be accessible only through proper channels
- Contains sensitive authentication and data systems

#### Research/Admin/Student Zones

| Zone | Network | Access Policy | Security Posture |
|------|---------|--------------|------------------|
| Student | 172.16.10.0/24 | Internet only | Isolated from servers |
| Faculty | 172.16.20.0/24 | Full campus | Trusted network |
| Guest | 172.16.30.0/24 | Internet only (intended) | Misconfigured isolation |
| Servers | 172.16.40.0/24 | Restricted access | High-value targets |
| Core | 172.16.0-4.0/24 | Infrastructure | Routing only |

#### Complex Routing Scenarios

The university topology features multi-hop routing with security implications:

**Core Router Rules**
```
# Block student direct access to servers
iptables -A FORWARD -s 172.16.1.0/24 -d 172.16.4.0/24 -j DROP

# Allow established connections (stateful)
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT outbound traffic
iptables -t nat -A POSTROUTING -o eth5 -j MASQUERADE
```

**Guest Router Misconfiguration**
```
# Intended: Block guest access to internal networks
iptables -A FORWARD -s 172.16.30.0/24 -d 172.16.0.0/16 -j DROP

# BUG: Rule added AFTER routing decision, allowing some bypass
# Traffic forwarded before rule evaluation in certain conditions
```

#### Attack Vectors

**Vector 1: Guest Network Escape**
- Exploit misconfigured guest isolation
- Reach internal services through timing/routing bugs
- Pivot from guest to faculty network

**Vector 2: Web Application to Database**
- Attack web portal at 172.16.40.10
- Discover hardcoded credentials in config.php
- Connect to database at 172.16.40.20

**Vector 3: LDAP Enumeration**
- Query LDAP server for user information
- Build comprehensive user directory
- Identify high-value targets for phishing

**Vector 4: Student to Faculty Escalation**
- Compromise student machine through social engineering
- Discover faculty credentials in shared resources
- Lateral movement to privileged network segment

#### Key Services

**Web Portal (172.16.40.10)**
- Student login portal with PHP backend
- Contains hardcoded database credentials:
  - Host: 172.16.40.20
  - User: webapp
  - Pass: Univ2024!
- SQL injection potential in login form

**LDAP Server (172.16.40.30)**
- Base DN: dc=university,dc=edu
- Unauthenticated query access
- Contains user directory information

**Mail Server (172.16.40.40)**
- Postfix SMTP on port 25
- Dovecot IMAP on port 143
- User enumeration via VRFY command

---

### Topology 4: ICS Network (ics-network.imn)

#### Industrial Control System Architecture

```
                     CORPORATE IT NETWORK
                        10.0.0.0/24
                    +------------------+
                    | it-workstation   |
                    | 10.0.0.10        |
                    | it-admin         |
                    | 10.0.0.11        |
                    +--------+---------+
                             |
                       [sw-corporate]
                             |
                       [fw-corporate]
                       10.0.0.1
                       192.168.1.1
                             |
                    +--------+---------+
                    |                  |
              [fw-dmz]           [sw-dmz]
         192.168.1.254              |
         192.168.100.1         DMZ SYSTEMS
                    |        192.168.1.0/24
                    |     +------------------+
                    |     | historian        |
                    |     | 192.168.1.10     |
                    |     | HTTP/80, PI/5450 |
                    |     +------------------+
                    |     | hmi-server       |
                    |     | 192.168.1.20     |
                    |     | HTTP/80, VNC/5900|
                    |     +------------------+
                    |     | eng-workstation  |
                    |     | 192.168.1.50     |
                    |     | ** OVERLY PRIV **|
                    |     +------------------+
                    |     | jump-server      |
                    |     | 192.168.1.100    |
                    |     | RDP/3389, SSH/22 |
                    |     +------------------+
                    |
              [sw-ot]
                    |
         OT NETWORK: 192.168.100.0/24
    +----------------------------------------------+
    |                                              |
    |  scada-master    192.168.100.10              |
    |  Modbus/502, DNP3/20000                      |
    |  Schneider ClearSCADA                        |
    |                                              |
    |  plc-1           192.168.100.20              |
    |  Modbus/502, S7comm/102                      |
    |  Siemens S7-1200 (FW 4.4)                    |
    |                                              |
    |  plc-2           192.168.100.21              |
    |  Modbus/502, EtherNet-IP/44818              |
    |  Allen-Bradley ControlLogix                  |
    |                                              |
    |  rtu-1           192.168.100.30              |
    |  Modbus/502, DNP3/20000                      |
    |  SEL-3530 RTAC                               |
    |                                              |
    |  field-hmi       192.168.100.40              |
    |  HTTP/80, VNC/5900                           |
    |                                              |
    +----------------------------------------------+

         AIR-GAPPED SAFETY SYSTEM: 192.168.200.0/24
    +----------------------------------------------+
    |  [sw-airgap] -- PHYSICALLY ISOLATED          |
    |                                              |
    |  safety-plc      192.168.200.10              |
    |  Modbus/502                                  |
    |  Triconex Tricon CX                          |
    |                                              |
    |  safety-hmi      192.168.200.20              |
    |  HTTP/80                                     |
    |  Emergency Shutdown System                   |
    |                                              |
    +----------------------------------------------+
```

#### Modbus TCP Implementation

The ICS topology implements Modbus TCP protocol simulation for penetration testing practice:

**Modbus Function Codes Supported**

| Function Code | Name | Description |
|--------------|------|-------------|
| 0x01 | Read Coils | Read discrete outputs (digital) |
| 0x02 | Read Discrete Inputs | Read digital inputs |
| 0x03 | Read Holding Registers | Read analog outputs |
| 0x04 | Read Input Registers | Read analog inputs |
| 0x05 | Write Single Coil | Write digital output |
| 0x06 | Write Single Register | Write analog output |

**Simulated Register Map**

```
Holding Registers (40001-40010):
  40001: 1234  - Process Value 1
  40002: 5678  - Process Value 2
  40003: 100   - Setpoint 1
  40004: 200   - Setpoint 2
  40005: 1     - Operating Mode (0=Manual, 1=Auto)
  40006: 0     - Alarm Status
  40007: 72    - Temperature (deg F)
  40008: 147   - Pressure (x10 PSI)
  40009: 2503  - Flow Rate (GPM)
  40010: 85    - Tank Level (%)

Coils (00001-00008):
  00001: 1 - Pump 1 Running
  00002: 0 - Pump 2 Running
  00003: 1 - Valve 1 Open
  00004: 0 - Valve 2 Open
  00005: 0 - Emergency Stop Active
  00006: 1 - System Ready
  00007: 0 - Alarm Active
  00008: 1 - Remote Mode Enabled
```

#### OT/IT Convergence Points

The topology highlights critical IT/OT boundary vulnerabilities:

**Convergence Point 1: Historian Server**
- Bridges IT (receives data requests) and OT (collects PLC data)
- PI SDK port 5450 exposed to DMZ
- Web interface for data visualization
- Attack path: Web vuln -> Historian -> OT network

**Convergence Point 2: Engineering Workstation**
- Has unrestricted access to OT network (firewall misconfiguration)
- Used for PLC programming and configuration
- Contains project files with hardcoded credentials
- Attack path: Compromise eng-ws -> Direct OT access

**Convergence Point 3: HMI Server**
- VNC access for remote operations
- Web interface for monitoring
- Often uses weak/default credentials
- Attack path: VNC brute force -> Process manipulation

**Convergence Point 4: Jump Server**
- Intended secure access point
- RDP and SSH exposed
- May cache credentials for downstream access
- Attack path: Jump -> Engineer -> OT

#### ICS-Specific Attack Vectors

**Vector 1: Modbus Reconnaissance**
```bash
# Scan for Modbus devices
nmap -p 502 192.168.100.0/24 --script modbus-discover

# Read holding registers
modbus-cli read 192.168.100.20 40001 10
```

**Vector 2: S7comm Exploitation**
```bash
# Identify Siemens PLCs
nmap -p 102 192.168.100.0/24 --script s7-info

# Attempt to stop PLC
s7comm-stop 192.168.100.20
```

**Vector 3: DNP3 Protocol Abuse**
```bash
# DNP3 enumeration
nmap -p 20000 192.168.100.0/24

# Craft malicious DNP3 packets
dnp3-exploit --target 192.168.100.30
```

**Vector 4: HMI Web Application**
- Access http://192.168.1.20 (control center HMI)
- Access http://192.168.100.40 (field HMI)
- Test for default credentials (admin/admin)
- Attempt command injection in configuration pages

#### Safety Considerations

**CRITICAL WARNING**: The air-gapped safety system (192.168.200.0/24) represents a Safety Instrumented System (SIS). In real-world environments:

1. **Never attack SIS systems** without explicit authorization and safety controls
2. SIS exists to prevent catastrophic failures (explosions, chemical releases, deaths)
3. Compromising SIS can have life-safety implications
4. The air-gapped network demonstrates proper SIS isolation

**Training Boundaries**:
- The safety network is NOT connected to the main OT network
- Exercises should focus on IT->DMZ->OT attack paths
- SIS isolation validates proper segmentation
- Document SIS as out-of-scope in assessment reports

#### ICS Protocol Reference

| Protocol | Port | Common Vendors | Security Notes |
|----------|------|----------------|----------------|
| Modbus TCP | 502 | Schneider, Many | No authentication |
| S7comm | 102 | Siemens | Proprietary, some auth |
| EtherNet/IP | 44818 | Rockwell/AB | CIP protocol encapsulated |
| DNP3 | 20000 | Power utilities | Optional authentication |
| OPC-UA | 4840 | Multi-vendor | Modern, security options |
| BACnet | 47808 | Building automation | Broadcast discovery |

---

## Part 3: Service Scripts Deep Dive

The CPTC11 project includes reusable service scripts that can be deployed on any CORE node. These scripts simulate common enterprise services with intentional vulnerabilities for training purposes.

### http-service.sh Usage and Customization

**Location**: `/Users/ic/cptc11/networks/services/http-service.sh`

**Purpose**: Deploy a web server with common vulnerabilities for testing.

#### Basic Usage

```bash
# Default: port 80, webroot /var/www/html
./http-service.sh

# Custom port and webroot
./http-service.sh 8080 /var/www/custom
```

#### Features Created

The script automatically creates:

1. **Login Form** (`index.html`)
   - Username/password form for injection testing
   - No CSRF protection

2. **Vulnerable PHP** (`login.php`)
   - SQL injection vulnerable (commented for reference)
   - Hardcoded credentials: admin/admin123

3. **robots.txt** with sensitive paths
   ```
   Disallow: /admin/
   Disallow: /backup/
   Disallow: /config/
   Disallow: /api/internal/
   ```

4. **Hidden directories**
   - `/admin/` - Administrative interface
   - `/backup/` - Database backup files with credentials

#### Customization Example

To add a custom vulnerable endpoint:

```bash
# After running the script, add to webroot:
cat > /var/www/html/api/users.php << 'EOF'
<?php
// Vulnerable to path traversal
$file = $_GET['file'];
include("/var/www/data/" . $file);
?>
EOF
```

---

### ftp-service.sh Configuration

**Location**: `/Users/ic/cptc11/networks/services/ftp-service.sh`

**Purpose**: Simulate an FTP server with anonymous access and information disclosure.

#### Basic Usage

```bash
# Default: port 21, ftproot /var/ftp
./ftp-service.sh

# Custom configuration
./ftp-service.sh 2121 /opt/ftp
```

#### Directory Structure Created

```
/var/ftp/
  README.txt          # Welcome message with admin contact
  pub/
    welcome.txt       # Public files notice
  incoming/           # Upload directory
  backup/
    files.txt         # Backup file listing
    config.txt        # Leaked credentials!
  .htpasswd           # Hidden password file
  .users              # User enumeration data
```

#### Leaked Credentials

The backup/config.txt contains:
```
db_host=10.100.3.10
db_user=webapp
db_pass=W3bApp2024!
admin_email=admin@company.local
```

---

### ssh-service.sh Hardening Options

**Location**: `/Users/ic/cptc11/networks/services/ssh-service.sh`

**Purpose**: Deploy SSH with configurable security levels.

#### Basic Usage

```bash
# Default: port 22, weak configuration
./ssh-service.sh

# Custom port
./ssh-service.sh 2222
```

#### Intentional Weaknesses

The default configuration includes:

- `PermitRootLogin yes` - Root login allowed
- `MaxAuthTries 10` - High brute force threshold
- Weak ciphers enabled for compatibility attacks
- Legacy algorithms (3des-cbc)

#### Pre-created Users

| Username | Password | Notes |
|----------|----------|-------|
| root | toor | System administrator |
| admin | admin123 | Administrative user |
| user | password | Standard user |
| backup | backup | Backup account |
| guest | guest | Guest access |

---

### smb-service.sh Share Setup

**Location**: `/Users/ic/cptc11/networks/services/smb-service.sh`

**Purpose**: Create SMB file shares with sensitive data leakage.

#### Basic Usage

```bash
# Default share path
./smb-service.sh

# Custom share path
./smb-service.sh /srv/custom-shares
```

#### Share Configuration

| Share | Path | Access | Content |
|-------|------|--------|---------|
| public | /srv/samba/public | Guest | Company information |
| private | /srv/samba/private | admin | Passwords file! |
| it | /srv/samba/it | @it | Network documentation |
| hr | /srv/samba/hr | @hr | Employee records |
| finance | /srv/samba/finance | @finance | Budget, bank info |
| backup | /srv/samba/backup | backup | Backup scripts with creds |

#### Critical Files

**private/passwords.txt**:
```
admin / P@ssw0rd123!
backup / BackupUser2024
service / Svc_Account_2024
```

**it/network_diagram.txt**:
```
Internal: 10.100.2.0/24
DMZ: 10.100.1.0/24
Database: 10.100.3.0/24
Domain Controller: 10.100.2.5
```

**backup/backup_script.sh**:
```bash
DB_HOST="10.100.3.10"
DB_USER="backup_user"
DB_PASS="Backup2024!"
```

---

### mysql-service.sh Database Config

**Location**: `/Users/ic/cptc11/networks/services/mysql-service.sh`

**Purpose**: Simulate MySQL server with test databases and weak authentication.

#### Basic Usage

```bash
# Default: port 3306
./mysql-service.sh

# Custom port
./mysql-service.sh 3307
```

#### Databases Created

| Database | Tables | Purpose |
|----------|--------|---------|
| webapp_db | users, sessions | Web application data |
| customer_data | customers | Sensitive PII |

#### Test Credentials

| Username | Password | Privileges |
|----------|----------|------------|
| admin | admin123 | ALL PRIVILEGES |
| webapp | webapp123 | SELECT,INSERT,UPDATE on webapp_db |

#### Sensitive Data

The customer_data.customers table contains simulated PII:
- Names, emails, phone numbers
- Social Security Numbers (fake)
- Credit card numbers (test numbers)

---

### dns-service.sh Zone Management

**Location**: `/Users/ic/cptc11/networks/services/dns-service.sh`

**Purpose**: Create DNS server with zone transfer enabled for enumeration practice.

#### Basic Usage

```bash
# Default domain
./dns-service.sh

# Custom domain
./dns-service.sh target.local 53
```

#### Zone Records Created

```
; Servers
www             IN  A   10.100.1.10
mail            IN  A   10.100.1.20
db              IN  A   10.100.3.10
dc              IN  A   10.100.2.5

; Development (interesting!)
dev             IN  A   10.100.2.50
test            IN  A   10.100.2.51
staging         IN  A   10.100.2.52
jenkins         IN  A   10.100.2.60
gitlab          IN  A   10.100.2.61

; Management interfaces
mgmt            IN  A   10.100.99.1
ilo             IN  A   10.100.99.20
idrac           IN  A   10.100.99.21
```

#### Zone Transfer Testing

```bash
# Request zone transfer
dig axfr company.local @<dns-server-ip>

# Expected: Full zone dump revealing all hostnames
```

---

### smtp-service.sh Relay Config

**Location**: `/Users/ic/cptc11/networks/services/smtp-service.sh`

**Purpose**: SMTP server with user enumeration and open relay for testing.

#### Basic Usage

```bash
# Default configuration
./smtp-service.sh

# Custom hostname
./smtp-service.sh 25 mail.target.local
```

#### Enumeration Features

**VRFY Command** (enabled):
```bash
telnet mail.target.local 25
VRFY admin
252 2.0.0 admin@company.local  # User exists

VRFY nonexistent
550 5.1.1 <nonexistent>: Recipient address rejected
```

**EXPN Command** (enabled):
```bash
EXPN postmaster
250-admin@company.local
250 postmaster@company.local
```

#### Valid Users for Enumeration

```
admin, administrator, postmaster, webmaster,
root, info, support, sales, hr, it, backup,
noreply, test
```

---

### modbus-service.sh PLC Simulation

**Location**: `/Users/ic/cptc11/networks/services/modbus-service.sh`

**Purpose**: Simulate industrial control devices with Modbus TCP protocol.

#### Basic Usage

```bash
# Siemens PLC simulation
./modbus-service.sh 502 plc

# RTU simulation
./modbus-service.sh 502 rtu

# SCADA master
./modbus-service.sh 502 scada
```

#### Device Types

| Type | Simulated Device | Additional Protocols |
|------|-----------------|---------------------|
| plc | Siemens S7-1200 | S7comm on port 102 |
| rtu | SEL-3530 RTAC | DNP3 on port 20000 |
| scada | Schneider ClearSCADA | DNP3 on port 20000 |

#### Modbus Interaction

```bash
# Read holding registers (Python example)
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.100.20', port=502)
client.connect()

# Read 10 holding registers starting at 40001
result = client.read_holding_registers(0, 10, unit=1)
print(result.registers)
# [1234, 5678, 100, 200, 1, 0, 72, 147, 2503, 85]

# Write single coil (WARNING: Process impact!)
client.write_coil(0, False, unit=1)  # Stop Pump 1
```

---

## Part 4: Running Penetration Tests in CORE

### Starting Topologies

#### Loading an IMN File

**Method 1: GUI**
1. Launch CORE: `core-gui`
2. File -> Open -> Navigate to topology
3. Select the `.imn` file
4. Click "Start" button (or press F5)

**Method 2: Command Line**

```bash
# Start CORE daemon if not running
sudo systemctl start core-daemon

# Load and start topology
core-cli start -f /Users/ic/cptc11/networks/corporate-network.imn
```

#### Verifying Topology Status

```bash
# List running sessions
core-cli session list

# Show session details
core-cli session show -s <session-id>

# Get node information
core-cli node list -s <session-id>
```

### Connecting Attack Tools

#### Method 1: Direct Namespace Execution

Execute tools directly in a node's network namespace:

```bash
# Get the node's namespace name (usually nodeX.session)
core-cli node list -s 1

# Execute command in node namespace
sudo ip netns exec n5.1 nmap -sV 10.100.1.0/24
```

#### Method 2: Adding Attack Node

1. In CORE GUI, add a new PC node
2. Connect to appropriate network segment
3. Configure IP address in target subnet
4. Right-click -> Open Terminal
5. Run attack tools from terminal

#### Method 3: Bridge to Physical Interface

Connect CORE network to host system for external tool use:

```bash
# In CORE, add a "WLAN" or "RJ45" node
# Configure as bridge to eth0 or tap interface
# Assign IP to host interface in target subnet
sudo ip addr add 10.100.1.100/24 dev tap0
```

### Capturing Traffic

#### Per-Node Capture

Right-click on a link in CORE GUI and select "Start Capture" to capture traffic on that segment.

#### Command Line Capture

```bash
# Find interface name in node
sudo ip netns exec n5.1 ip link

# Start capture
sudo ip netns exec n5.1 tcpdump -i eth0 -w /tmp/capture.pcap

# Capture specific traffic
sudo ip netns exec n1.1 tcpdump -i eth1 'port 80 or port 443' -w /tmp/web.pcap
```

#### Wireshark Integration

```bash
# Live capture with Wireshark
sudo ip netns exec n5.1 tcpdump -i eth0 -U -w - | wireshark -k -i -

# Open saved capture
wireshark /tmp/capture.pcap
```

### Logging and Evidence Collection

#### Organizing Assessment Data

```bash
# Create evidence directory structure
mkdir -p /assessment/{scans,captures,screenshots,notes}

# Save scan results
sudo ip netns exec attack.1 nmap -sV -oA /assessment/scans/dmz 10.100.1.0/24

# Capture traffic during exploitation
sudo ip netns exec n1.1 tcpdump -i eth1 -w /assessment/captures/exploit.pcap &
```

#### Node Activity Logging

```bash
# Enable command logging in terminal
script /assessment/notes/session_$(date +%Y%m%d).log

# Record all commands with timestamps
export PROMPT_COMMAND='echo "$(date +%Y-%m-%d_%H:%M:%S) $(history 1)" >> /assessment/notes/commands.log'
```

---

## Part 5: Creating Custom Topologies

### IMN File Format Explanation

The IMUNES Network (IMN) format is a text-based configuration file defining network topology, node configuration, and visual layout.

#### Basic Structure

```tcl
# Node definitions
node n1 {
    type <node-type>
    model <model-type>
    network-config {
        hostname <name>
        !
        interface <iface>
            ip address <ip>/<prefix>
        !
    }
    canvas c1
    iconcoords {x y}
    labelcoords {x y}
    services {<service-list>}
}

# Link definitions
link l1 {
    nodes {n1 n2}
    bandwidth <bps>
}

# Canvas definition
canvas c1 {
    name {<topology-name>}
    size {width height}
}

# Global options
option global {
    interface_names no
    ip_addresses yes
    node_labels yes
}
```

#### Node Types

| Type | Description | Use Case |
|------|-------------|----------|
| router | Linux router with forwarding | Firewalls, gateways |
| host | Linux host | Servers |
| PC | Linux workstation | Endpoints |
| lanswitch | Layer 2 switch | Network switching |
| hub | Layer 1 hub | Traffic mirroring |

#### Model Types (for routers)

| Model | Description |
|-------|-------------|
| router | Generic Linux router |
| host | Server model with services |
| PC | Workstation model |

### Node Configuration

#### Creating a Web Server Node

```tcl
node n10 {
    type router
    model host
    network-config {
        hostname webserver
        !
        interface eth0
            ip address 192.168.1.10/24
        !
    }
    canvas c1
    iconcoords {400.0 300.0}
    labelcoords {400.0 332.0}
    services {DefaultRoute SSH HTTP}
    custom-config {
        custom-config-id service:HTTP
        custom-command HTTP
        config {
            files=('http.sh', )
            startidx=1
        }
    }
    custom-config {
        custom-config-id service:HTTP:http.sh
        custom-command http.sh
        config {
            #!/bin/sh
            mkdir -p /var/www/html
            echo "<h1>Custom Web Server</h1>" > /var/www/html/index.html
            python3 -m http.server 80 &
        }
    }
}
```

#### Creating a Firewall Node

```tcl
node n1 {
    type router
    model router
    network-config {
        hostname firewall
        !
        interface eth0
            ip address 10.0.0.1/24
        !
        interface eth1
            ip address 192.168.1.1/24
        !
    }
    services {IPForward DefaultRoute}
    custom-config {
        custom-config-id service:IPForward:ipforward.sh
        custom-command ipforward.sh
        config {
            #!/bin/sh
            sysctl -w net.ipv4.ip_forward=1

            # Default deny
            iptables -P FORWARD DROP

            # Allow established
            iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

            # Allow specific services
            iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
            iptables -A FORWARD -p tcp --dport 443 -j ACCEPT

            # NAT outbound
            iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        }
    }
}
```

### Link Setup

#### Basic Link

```tcl
link l1 {
    nodes {n1 n2}
    bandwidth 1000000000  # 1 Gbps
}
```

#### Link with Delay and Loss

```tcl
link l2 {
    nodes {n3 n4}
    bandwidth 100000000   # 100 Mbps
    delay 50000           # 50ms delay
    loss 1                # 1% packet loss
}
```

### Service Integration

#### Adding Custom Services

Create a custom service by defining configuration blocks:

```tcl
node n5 {
    services {DefaultRoute SSH CustomService}
    custom-config {
        custom-config-id service:CustomService
        custom-command CustomService
        config {
            files=('custom.sh', )
            startidx=1
        }
    }
    custom-config {
        custom-config-id service:CustomService:custom.sh
        custom-command custom.sh
        config {
            #!/bin/sh
            # Custom service startup script
            /opt/myapp/start.sh &
        }
    }
}
```

#### Using External Service Scripts

Reference the project service scripts in your topology:

```tcl
custom-config {
    custom-config-id service:HTTP:http.sh
    custom-command http.sh
    config {
        #!/bin/sh
        /path/to/cptc11/networks/services/http-service.sh 80 /var/www/html
    }
}
```

### Complete Custom Topology Example

```tcl
# Custom Penetration Testing Lab
# Three-tier architecture with DMZ

node n1 {
    type router
    model router
    network-config {
        hostname fw-edge
        !
        interface eth0
            ip address 203.0.113.1/24
        !
        interface eth1
            ip address 10.10.1.1/24
        !
        interface eth2
            ip address 10.10.2.1/24
        !
    }
    canvas c1
    iconcoords {400.0 100.0}
    services {IPForward}
    custom-config {
        custom-config-id service:IPForward:ipforward.sh
        custom-command ipforward.sh
        config {
            #!/bin/sh
            sysctl -w net.ipv4.ip_forward=1
            iptables -P FORWARD DROP
            iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
            iptables -A FORWARD -p tcp --dport 443 -j ACCEPT
            iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        }
    }
}

node n2 {
    type lanswitch
    network-config {
        hostname sw-dmz
    }
    canvas c1
    iconcoords {400.0 200.0}
}

node n3 {
    type lanswitch
    network-config {
        hostname sw-internal
    }
    canvas c1
    iconcoords {400.0 350.0}
}

node n4 {
    type router
    model host
    network-config {
        hostname web-server
        !
        interface eth0
            ip address 10.10.1.10/24
        !
    }
    canvas c1
    iconcoords {300.0 200.0}
    services {DefaultRoute HTTP SSH}
}

node n5 {
    type router
    model host
    network-config {
        hostname db-server
        !
        interface eth0
            ip address 10.10.2.10/24
        !
    }
    canvas c1
    iconcoords {400.0 450.0}
    services {DefaultRoute MySQL SSH}
}

node n6 {
    type router
    model PC
    network-config {
        hostname attacker
        !
        interface eth0
            ip address 203.0.113.100/24
        !
    }
    canvas c1
    iconcoords {400.0 20.0}
    services {DefaultRoute}
}

link l1 {
    nodes {n6 n1}
    bandwidth 100000000
}

link l2 {
    nodes {n1 n2}
    bandwidth 1000000000
}

link l3 {
    nodes {n1 n3}
    bandwidth 1000000000
}

link l4 {
    nodes {n2 n4}
    bandwidth 1000000000
}

link l5 {
    nodes {n3 n5}
    bandwidth 1000000000
}

canvas c1 {
    name {Custom Pentest Lab}
    size {800 500}
}

option global {
    interface_names no
    ip_addresses yes
    node_labels yes
}

annotation a1 {
    iconcoords {250 160 550 250}
    type rectangle
    label {DMZ (10.10.1.0/24)}
    color #ffcccc
    canvas c1
}

annotation a2 {
    iconcoords {250 310 550 500}
    type rectangle
    label {Internal (10.10.2.0/24)}
    color #ccffcc
    canvas c1
}
```

---

## Part 6: Assessment Exercises

### Exercise 1: Corporate Network Assessment

**Objective**: Perform a full penetration test of the corporate network topology.

**Scenario**: You have been hired to assess the security of a corporate network. Your entry point is an internet-facing position at 203.0.113.0/24.

**Tasks**:
1. Perform external reconnaissance from the ISP router perspective
2. Identify publicly accessible services in the DMZ
3. Exploit a vulnerability to gain initial access
4. Pivot from the DMZ to internal network segments
5. Extract sensitive data from the database server
6. Document all findings with evidence

**Success Criteria**:
- [ ] Discovered all DMZ services
- [ ] Identified firewall rules through probing
- [ ] Compromised at least one DMZ host
- [ ] Demonstrated lateral movement capability
- [ ] Retrieved credentials or sensitive data

### Exercise 2: ICS Security Assessment

**Objective**: Assess the security of an Industrial Control System network.

**Scenario**: A water treatment facility has hired you to test their OT network security. You must identify vulnerabilities while avoiding any actions that could impact physical processes.

**Tasks**:
1. Map the IT/OT network boundary
2. Identify all ICS protocols in use
3. Enumerate Modbus devices without writing data
4. Discover HMI systems and assess their security
5. Document IT->OT attack paths
6. Identify the air-gapped safety system (verify isolation)

**Safety Rules**:
- DO NOT write to Modbus registers
- DO NOT stop/start PLCs
- READ ONLY operations on control systems
- Document potential impact without demonstrating

**Success Criteria**:
- [ ] Identified all Modbus-enabled devices
- [ ] Enumerated PLC models and firmware versions
- [ ] Discovered HMI default credentials
- [ ] Mapped complete IT->OT attack path
- [ ] Verified safety system isolation

### Exercise 3: Multi-Topology Pivot Challenge

**Objective**: Chain exploits across network boundaries.

**Scenario**: The small business network has a VPN connection to the corporate network. Compromise both environments.

**Tasks**:
1. Gain initial access to small business network
2. Discover VPN credentials or connection details
3. Use SMB shares to find corporate network information
4. Pivot to corporate network via harvested credentials
5. Achieve domain admin equivalent access

**Success Criteria**:
- [ ] Compromised NAS or file server
- [ ] Retrieved VPN/corporate credentials
- [ ] Successfully pivoted to corporate network
- [ ] Demonstrated privilege escalation

---

## Summary

This training module covered the CORE Network Emulator and the four CPTC11 network topologies designed for penetration testing practice. Key takeaways include:

1. **CORE Fundamentals**: Installation, configuration, and operation of the network emulator
2. **Topology Understanding**: Detailed architecture knowledge of corporate, SMB, university, and ICS networks
3. **Service Configuration**: Deployment and customization of vulnerable services
4. **Attack Integration**: Connecting tools and capturing evidence within emulated environments
5. **Custom Development**: Creating specialized topologies for targeted training

### Next Steps

After completing this training:

1. Complete the assessment exercises to validate your understanding
2. Modify topologies to add new vulnerabilities or services
3. Create custom scenarios for your specific training needs
4. Progress to the tool-specific walkthroughs using these lab environments

### Quick Reference

| Topology | File | Primary Focus |
|----------|------|---------------|
| Corporate | corporate-network.imn | DMZ segmentation, web apps |
| Small Business | small-business.imn | Flat networks, credential theft |
| University | university-network.imn | Multi-zone, LDAP, user populations |
| ICS | ics-network.imn | OT protocols, IT/OT convergence |

---

## Appendix: Troubleshooting

### Common Issues

**Issue: Nodes fail to start**
```bash
# Check for existing namespaces
sudo ip netns list

# Clean up stale namespaces
sudo ip netns delete <namespace>

# Restart CORE daemon
sudo systemctl restart core-daemon
```

**Issue: No network connectivity between nodes**
```bash
# Verify links in GUI (should show green)
# Check interface status in node
ip link show
ip addr show

# Verify routing
ip route show
```

**Issue: Services not starting**
```bash
# Check service script errors
# Open node terminal and run manually
cat /var/log/startup.log
/path/to/service/script.sh
```

**Issue: Cannot capture traffic**
```bash
# Verify tcpdump is installed
which tcpdump

# Run with elevated privileges
sudo tcpdump -i any -w /tmp/capture.pcap
```
