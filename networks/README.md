# CPTC Practice Network Environments

This directory contains CORE (Common Open Research Emulator) network topology files designed for penetration testing practice, specifically targeting CPTC-style competitions.

## Prerequisites

- CORE Network Emulator (version 7.x or 8.x recommended)
- Linux host system (Ubuntu 20.04+ recommended)
- Root/sudo access for network namespace creation
- Python 3.x for service scripts

### Installing CORE

```bash
# Ubuntu/Debian
sudo apt-get install core-network core-gui

# Or build from source
git clone https://github.com/coreemu/core.git
cd core
./bootstrap.sh
./configure
make
sudo make install
```

## Network Topologies

### 1. Corporate Network (corporate-network.imn)

A traditional enterprise network with DMZ, internal network, and database segments.

```
                    [ISP Router]
                         |
                    203.0.113.1
                         |
                  [fw-external]
                    /    |    \
                   /     |     \
            10.100.1.x  10.100.2.x  10.100.3.x
                 |        |          |
            [sw-dmz]  [sw-internal] [sw-database]
               /\         |  |  \        |  \
              /  \        |  |   \       |   \
         [web] [mail]   [ws1][ws2][ws3] [db] [backup]
```

**Network Segments:**
| Segment | Subnet | Purpose |
|---------|--------|---------|
| External | 203.0.113.0/24 | Internet-facing |
| DMZ | 10.100.1.0/24 | Public-facing servers |
| Internal | 10.100.2.0/24 | Employee workstations |
| Database | 10.100.3.0/24 | Backend data servers |

**Key Hosts:**
| Host | IP Address | Services |
|------|------------|----------|
| web-server | 10.100.1.10 | HTTP (80), HTTPS (443) |
| mail-server | 10.100.1.20 | SMTP (25) |
| workstation-1/2/3 | 10.100.2.10-12 | SSH |
| db-server | 10.100.3.10 | MySQL (3306) |
| backup-server | 10.100.3.20 | FTP (21), SSH |

**Attack Surface:**
- Web application vulnerabilities on portal
- SMTP user enumeration
- FTP anonymous access on backup server
- Weak MySQL credentials
- Firewall rule bypass between segments

---

### 2. Small Business Network (small-business.imn)

A flat network typical of small businesses with minimal segmentation.

```
            [ISP Gateway]
                  |
            192.168.100.1
                  |
            [fw-router]
                  |
              10.0.0.1
                  |
            [main-switch]
           /   |   |   \
          /    |   |    \
    [file] [print][NAS] [workstations x7]
```

**Network:** 10.0.0.0/24 (flat network)

**Key Hosts:**
| Host | IP Address | Services |
|------|------------|----------|
| file-server | 10.0.0.10 | SMB (139, 445) |
| print-server | 10.0.0.11 | IPP/CUPS (631) |
| nas-backup | 10.0.0.12 | FTP (21), HTTP (5000) |
| ws-reception | 10.0.0.20 | None |
| ws-accounting-1/2 | 10.0.0.21-22 | SSH |
| ws-manager | 10.0.0.23 | SSH |
| ws-sales-1/2 | 10.0.0.24-25 | None |
| ws-warehouse | 10.0.0.26 | None |

**Attack Surface:**
- SMB shares with sensitive data
- Default credentials on NAS web interface (admin/admin)
- CUPS administration interface
- Weak firewall rules (flat network)
- Lateral movement opportunities

---

### 3. University Network (university-network.imn)

A segmented academic network with multiple user populations.

```
                    [ISP Border]
                         |
                    198.51.100.2
                         |
                   [core-router]
                  /    |    |    \
                 /     |    |     \
        172.16.1.x  172.16.2.x  172.16.3.x  172.16.4.x
              |         |         |          |
       [router-  [router-  [router-   [router-
        student]  faculty]  guest]    servers]
           |         |         |          |
       [sw-student] [sw-fac] [sw-guest] [sw-servers]
          / | \      / \       / \      / | | | \
         /  |  \    /   \     /   \    /  | | |  \
      [PCs]     [PCs]    [devices] [web][db][ldap][dns][mail]
```

**Network Segments:**
| Segment | Subnet | Purpose |
|---------|--------|---------|
| Core | 172.16.0.0/24 | Backbone routing |
| Student | 172.16.10.0/24 | Student computers |
| Faculty | 172.16.20.0/24 | Faculty/staff |
| Guest WiFi | 172.16.30.0/24 | Guest wireless |
| Server Farm | 172.16.40.0/24 | Central services |

**Key Hosts:**
| Host | IP Address | Services |
|------|------------|----------|
| web-portal | 172.16.40.10 | HTTP (80, 443) |
| db-server | 172.16.40.20 | MySQL (3306) |
| ldap-server | 172.16.40.30 | LDAP (389, 636) |
| dns-server | 172.16.40.5 | DNS (53) |
| mail-server | 172.16.40.40 | SMTP (25), IMAP (143) |

**Attack Surface:**
- Web portal with hardcoded credentials in config.php
- LDAP enumeration
- DNS zone transfer
- Misconfigured guest WiFi isolation
- Student to server farm access restrictions (misconfigured)

---

### 4. Industrial Control System Network (ics-network.imn)

An OT/ICS environment simulating a water treatment facility.

```
        [Corporate IT]
        10.0.0.0/24
             |
       [fw-corporate]
             |
        192.168.1.x
             |
         [fw-dmz]
        /         \
       /           \
[DMZ/Control]    [OT Network]
192.168.1.x     192.168.100.x
      |              |
[historian]    [sw-ot]--------
[hmi-server]     /  |  \  \   \
[eng-ws]      [scada][plc1][plc2][rtu][field-hmi]
[jump]


               [sw-airgap] (Air-Gapped)
                  /    \
           [safety-plc][safety-hmi]
           192.168.200.x
```

**Network Segments:**
| Segment | Subnet | Purpose |
|---------|--------|---------|
| Corporate IT | 10.0.0.0/24 | Business network |
| DMZ/Control | 192.168.1.0/24 | Control center |
| OT Network | 192.168.100.0/24 | Operational technology |
| Safety (Air-Gap) | 192.168.200.0/24 | Safety systems |

**Key Hosts:**
| Host | IP Address | Services |
|------|------------|----------|
| historian | 192.168.1.10 | HTTP (80), PI SDK (5450) |
| hmi-server | 192.168.1.20 | HTTP (80), VNC (5900) |
| eng-workstation | 192.168.1.50 | SSH |
| jump-server | 192.168.1.100 | SSH, RDP (3389) |
| scada-master | 192.168.100.10 | Modbus (502), DNP3 (20000) |
| plc-1 | 192.168.100.20 | Modbus (502), S7comm (102) |
| plc-2 | 192.168.100.21 | Modbus (502), EtherNet/IP (44818) |
| rtu-1 | 192.168.100.30 | Modbus (502), DNP3 (20000) |
| field-hmi | 192.168.100.40 | HTTP (80), VNC (5900) |
| safety-plc | 192.168.200.10 | Modbus (502) |

**Attack Surface:**
- Overly permissive engineering workstation access
- VNC without authentication
- Modbus/DNP3 lack of authentication
- HMI web interfaces with default credentials
- Historian with exposed process data
- Jump server as pivot point

---

## Service Scripts

Located in `services/` directory:

| Script | Purpose | Usage |
|--------|---------|-------|
| http-service.sh | HTTP web server | `./http-service.sh [port] [webroot]` |
| ftp-service.sh | FTP file server | `./ftp-service.sh [port] [ftproot]` |
| ssh-service.sh | SSH daemon | `./ssh-service.sh [port]` |
| smb-service.sh | SMB/CIFS shares | `./smb-service.sh [sharepath]` |
| mysql-service.sh | MySQL database | `./mysql-service.sh [port]` |
| dns-service.sh | DNS server | `./dns-service.sh [domain] [port]` |
| smtp-service.sh | SMTP mail server | `./smtp-service.sh [port] [hostname]` |
| modbus-service.sh | Modbus TCP/ICS | `./modbus-service.sh [port] [device_type]` |

### Making Scripts Executable

```bash
chmod +x services/*.sh
```

---

## Usage Instructions

### Starting a Network

1. Launch CORE GUI:
   ```bash
   core-gui
   ```

2. Open File > Open and select the `.imn` file

3. Click the green "Start" button to initialize the network

4. Right-click on nodes to open terminals or configure services

### Running Services Manually

From a node's terminal:
```bash
# Start HTTP server
/path/to/services/http-service.sh 80 /var/www/html

# Start FTP server
/path/to/services/ftp-service.sh 21 /var/ftp
```

### Testing Connectivity

From attacker node:
```bash
# Ping sweep
nmap -sn 10.100.1.0/24

# Service discovery
nmap -sV -sC 10.100.1.10

# Full vulnerability scan
nmap -sV -sC --script=vuln 10.100.1.0/24
```

---

## Intentional Vulnerabilities

Each network includes intentional security weaknesses for practice:

### Authentication Weaknesses
- Default credentials (admin/admin, admin/admin123)
- Weak passwords on SSH users
- Hardcoded credentials in config files

### Configuration Issues
- Anonymous FTP access
- SMB shares with sensitive data
- SMTP VRFY/EXPN enabled
- DNS zone transfer allowed
- Open relay configurations

### Network Security
- Firewall rule bypass opportunities
- Insufficient network segmentation
- Missing ICS protocol authentication

### Information Disclosure
- Robots.txt revealing directories
- Backup files in web directories
- Config files with database credentials
- Debug information in error pages

---

## Competition Tips

1. **Reconnaissance First**: Use nmap, dig, and SMB enumeration before exploitation
2. **Document Everything**: Keep notes on IP addresses, credentials, and findings
3. **Check for Low-Hanging Fruit**: Default credentials, anonymous access, info disclosure
4. **Understand the Business**: ICS networks require understanding of process control
5. **Pivoting**: Use compromised hosts to reach restricted networks
6. **Time Management**: Prioritize quick wins over deep dives

---

## File Structure

```
networks/
├── README.md                    # This file
├── corporate-network.imn        # Corporate topology
├── small-business.imn           # Small business topology
├── university-network.imn       # University topology
├── ics-network.imn              # Industrial control system
├── services/
│   ├── http-service.sh          # HTTP server script
│   ├── ftp-service.sh           # FTP server script
│   ├── ssh-service.sh           # SSH configuration script
│   ├── smb-service.sh           # SMB server script
│   ├── mysql-service.sh         # MySQL server script
│   ├── dns-service.sh           # DNS server script
│   ├── smtp-service.sh          # SMTP server script
│   └── modbus-service.sh        # Modbus/ICS service script
└── configs/
    └── (node configuration files)
```

---

## Troubleshooting

### Services Not Starting
- Check that required daemons are installed in the CORE node
- Verify Python 3 is available for HTTP services
- Use netcat fallback if native services unavailable

### Network Connectivity Issues
- Verify IP forwarding is enabled on routers
- Check iptables rules on firewall nodes
- Ensure switches are properly connected

### Performance Issues
- Reduce number of running nodes if system is slow
- Use smaller canvas sizes
- Close unnecessary node terminals

---

## References

- [CORE Network Emulator Documentation](https://coreemu.github.io/core/)
- [CPTC Competition Rules](https://www.nationalcptc.org/)
- [NIST ICS Security Guide](https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

---

## License

These network topologies are provided for educational and training purposes only. Do not use these configurations in production environments.

Created for CPTC penetration testing practice.

---

*Last updated: January 2026*
