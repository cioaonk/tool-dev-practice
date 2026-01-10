# CPTC11 Docker Test Environment

This directory contains a complete Docker-based testing environment for the CPTC11 offensive security toolkit. All services are intentionally configured with vulnerabilities for authorized security testing and tool development.

## Warning

**This environment contains intentionally vulnerable services.** It should only be used in isolated networks for authorized security testing and development purposes. Never expose these services to untrusted networks or the public internet.

## Quick Start

```bash
# Start all services
cd /Users/ic/cptc11/docker
docker-compose up -d

# View running containers
docker-compose ps

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Stop and remove all data
docker-compose down -v
```

## Network Topology

```
                    +-------------------+
                    |    INTERNET       |
                    +-------------------+
                            |
                    +-------------------+
                    |   Host Machine    |
                    |   (Port Mapping)  |
                    +-------------------+
                            |
        +-------------------+-------------------+
        |                                       |
+-------+-------+                       +-------+-------+
|  DMZ Network  |                       |   Internal    |
| 10.10.10.0/24 |                       |   Network     |
+---------------+                       | 10.10.20.0/24 |
|               |                       +---------------+
| vulnerable-web|<--------------------->| vulnerable-web|
| (10.10.10.10) |                       | (10.10.20.10) |
|               |                       |               |
| ftp-server    |                       | smb-server    |
| (10.10.10.20) |                       | (10.10.20.50) |
|               |                       |               |
| smtp-server   |<--------------------->| smtp-server   |
| (10.10.10.30) |                       | (10.10.20.30) |
|               |                       |               |
| dns-server    |<--------------------->| dns-server    |
| (10.10.10.40) |                       | (10.10.20.40) |
|               |                       |               |
| attack-platform                       | mysql-server  |
| (10.10.10.100)|<--------------------->| (10.10.20.60) |
|               |                       |               |
+---------------+                       | workstation-1 |
                                        | (10.10.20.101)|
                                        |               |
                                        | workstation-2 |
                                        | (10.10.20.102)|
                                        |               |
                                        | server-1      |
                                        | (10.10.20.111)|
                                        |               |
                                        | dc01          |
                                        | (10.10.20.5)  |
                                        +---------------+
                                                |
                                        +-------+-------+
                                        |  Management   |
                                        |   Network     |
                                        | 10.10.30.0/24 |
                                        | (Internal)    |
                                        +---------------+
```

## Services

### Vulnerable Web Application
- **Container**: `cptc11-vulnerable-web`
- **IP**: 10.10.10.10 (DMZ), 10.10.20.10 (Internal)
- **Ports**: 8080 (HTTP), 8443 (HTTPS)
- **Purpose**: Web directory enumeration, credential testing, SQL injection
- **Test Credentials**:
  - HTTP Basic Auth: `admin:admin123`, `testuser:testpass`
  - Form Login: `admin:admin123`, `user:password`, `webmaster:webmaster1`

### FTP Server
- **Container**: `cptc11-ftp-server`
- **IP**: 10.10.10.20
- **Port**: 2121
- **Purpose**: FTP credential testing
- **Test Credentials**:
  - `ftpuser:ftppass123`
  - `admin:admin123`
  - `backup:backup2024`
  - Anonymous access enabled

### SMTP Server
- **Container**: `cptc11-smtp-server`
- **IP**: 10.10.10.30 (DMZ), 10.10.20.30 (Internal)
- **Ports**: 2525 (SMTP), 587 (Submission)
- **Purpose**: SMTP credential testing, relay testing
- **Test Credentials**:
  - `smtpuser:smtppass123`
  - `mailuser:mailpass456`
  - `admin:admin123`

### DNS Server
- **Container**: `cptc11-dns-server`
- **IP**: 10.10.10.40 (DMZ), 10.10.20.40 (Internal)
- **Port**: 5353 (UDP/TCP)
- **Purpose**: DNS enumeration, zone transfer testing
- **Domain**: `testlab.local`
- **Features**: Zone transfer (AXFR) enabled

### SMB Server
- **Container**: `cptc11-smb-server`
- **IP**: 10.10.20.50
- **Ports**: 4445 (SMB), 1139 (NetBIOS)
- **Purpose**: SMB share enumeration, null session testing
- **Test Credentials**:
  - `smbuser:smbpass123`
  - `admin:admin123`
  - `backup:backup2024`
- **Shares**: public, private, backup, it, hr, finance, admin$

### MySQL Database
- **Container**: `cptc11-mysql-server`
- **IP**: 10.10.20.60
- **Port**: 3307
- **Purpose**: Database backend, credential testing
- **Credentials**:
  - Root: `root:rootpass123`
  - App: `webuser:webpass123`

### Target Workstations
- **Containers**: `cptc11-workstation-1`, `cptc11-workstation-2`
- **IPs**: 10.10.20.101, 10.10.20.102
- **Purpose**: Network enumeration targets
- **SSH Credentials**: Various weak passwords

### Target Server
- **Container**: `cptc11-server-1`
- **IP**: 10.10.20.111 (Internal), 10.10.30.111 (Management)
- **Port**: 2222 (SSH)
- **Purpose**: Linux server target
- **SSH Credentials**:
  - `admin:admin123`
  - `sysadmin:sysadmin1`
  - `root:r00t`

### Domain Controller
- **Container**: `cptc11-dc`
- **IP**: 10.10.20.5 (Internal), 10.10.30.5 (Management)
- **Purpose**: Active Directory enumeration testing
- **Credentials**:
  - `Administrator:AdminPass123!`
  - `Domain_Admin:DomAdmin2024`

### Attack Platform
- **Container**: `cptc11-attack-platform`
- **IP**: 10.10.10.100 (DMZ), 10.10.20.100 (Internal)
- **Purpose**: Attack station with tools
- **Tools**: nmap, smbclient, Python + security libraries
- **CPTC11 Tools**: Mounted at `/opt/tools`

## Port Mappings (Host to Container)

| Host Port | Container | Service |
|-----------|-----------|---------|
| 8080 | vulnerable-web | HTTP |
| 8443 | vulnerable-web | HTTPS |
| 2121 | ftp-server | FTP |
| 2525 | smtp-server | SMTP |
| 587 | smtp-server | Submission |
| 5353 | dns-server | DNS |
| 4445 | smb-server | SMB |
| 1139 | smb-server | NetBIOS |
| 3307 | mysql-server | MySQL |
| 2222 | server-1 | SSH |

## Testing with CPTC11 Tools

### From Host Machine

```bash
# Web directory enumeration
cd /Users/ic/cptc11/python/tools/web-directory-enumerator
python tool.py http://localhost:8080 --plan
python tool.py http://localhost:8080 -v

# FTP credential testing
cd /Users/ic/cptc11/python/tools/credential-validator
python tool.py localhost --protocol ftp --port 2121 -u ftpuser -P ftppass123

# DNS enumeration
cd /Users/ic/cptc11/python/tools/dns-enumerator
python tool.py testlab.local -n localhost --plan
python tool.py testlab.local -n 127.0.0.1:5353 -z

# SMB enumeration
cd /Users/ic/cptc11/python/tools/smb-enumerator
python tool.py localhost --port 4445 --plan
```

### From Attack Platform Container

```bash
# Access the attack platform
docker exec -it cptc11-attack-platform bash

# Run tools from inside
cd /opt/tools/tools/dns-enumerator
python tool.py testlab.local -n 10.10.10.40 -v

# Network scanning
nmap -sn 10.10.10.0/24
nmap -sV 10.10.10.10
```

## Troubleshooting

### Container Fails to Start

```bash
# Check container logs
docker-compose logs <service-name>

# Rebuild a specific service
docker-compose build --no-cache <service-name>
docker-compose up -d <service-name>
```

### Network Connectivity Issues

```bash
# Check network configuration
docker network ls
docker network inspect docker_dmz_network

# Test connectivity from attack platform
docker exec -it cptc11-attack-platform ping 10.10.10.10
```

### Reset Environment

```bash
# Full reset
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

## Directory Structure

```
docker/
├── docker-compose.yml          # Main compose file
├── README.md                   # This file
├── vulnerable-web/
│   ├── Dockerfile
│   ├── apache/
│   │   ├── default.conf
│   │   └── default-ssl.conf
│   └── www/
│       ├── index.php
│       ├── login.php
│       ├── robots.txt
│       └── ...
├── ftp-server/
│   ├── Dockerfile
│   └── vsftpd.conf
├── smtp-server/
│   ├── Dockerfile
│   ├── postfix/
│   │   ├── main.cf
│   │   └── master.cf
│   ├── sasl/
│   │   └── smtpd.conf
│   └── supervisord.conf
├── dns-server/
│   ├── Dockerfile
│   └── config/
│       ├── named.conf
│       └── zones/
│           ├── db.testlab.local
│           └── ...
├── smb-server/
│   ├── Dockerfile
│   └── smb.conf
├── target-network/
│   ├── Dockerfile.workstation
│   ├── Dockerfile.server
│   ├── Dockerfile.dc
│   ├── scripts/
│   └── configs/
└── attack-platform/
    ├── Dockerfile
    └── scripts/
```

## Security Considerations

1. **Isolation**: All containers run in isolated Docker networks
2. **No External Exposure**: Services are only accessible via port mappings on localhost
3. **Intentional Vulnerabilities**: All weak configurations are deliberate for testing
4. **Data Persistence**: Volumes can be removed with `docker-compose down -v`

## Integration with CI/CD

See `python/tests/docker_integration/` for automated tests that run against this environment.

## License

This environment is for authorized security testing only. Use responsibly and only on systems you have permission to test.
