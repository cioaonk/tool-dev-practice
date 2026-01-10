# CPTC Competition Intelligence Report

**Classification:** CPTC Competition Preparation
**Date:** January 2026
**Analyst:** Docker Threat Intel Team

---

## Executive Summary

The Collegiate Penetration Testing Competition (CPTC) is the premier ethical hacking competition for university students. This report provides strategic intelligence on common target environments, typical vulnerabilities, recommended methodologies, and time management strategies based on historical competition patterns.

---

## 1. Common CPTC Target Environments

### 1.1 Infrastructure Patterns

CPTC consistently features realistic corporate environments with:

**Network Architecture**
- DMZ with public-facing services
- Internal corporate network segments
- Development/staging environments
- Cloud infrastructure components
- Active Directory domains

**Typical Topology**
```
[Internet] --> [Firewall] --> [DMZ: Web, Mail, DNS]
                    |
                    +--> [Internal: AD, File, DB]
                    |
                    +--> [Dev/Staging Environment]
                    |
                    +--> [Cloud: AWS/Azure Services]
```

### 1.2 Common Services Encountered

**Web Services**
- Custom web applications (PHP, Python, Node.js)
- WordPress/Drupal/Joomla CMS
- API endpoints (REST, GraphQL)
- Web-based admin panels

**Infrastructure Services**
- Active Directory/LDAP
- DNS (internal and external)
- SMTP/IMAP mail servers
- File shares (SMB, NFS)
- Database servers (MySQL, PostgreSQL, MSSQL)

**Container/Cloud Services**
- Docker hosts with multiple containers
- Kubernetes clusters
- Jenkins/GitLab CI/CD pipelines
- Container registries

### 1.3 Industry Themes

CPTC rotates through industry scenarios:
- Healthcare (HIPAA considerations)
- Financial services (PCI-DSS)
- Technology startups
- Manufacturing/ICS
- Educational institutions
- Government contractors

---

## 2. Typical Vulnerabilities Found

### 2.1 High-Frequency Findings

**Web Application Vulnerabilities**
| Vulnerability | Frequency | Impact |
|--------------|-----------|--------|
| SQL Injection | Very High | Critical |
| Cross-Site Scripting (XSS) | High | Medium |
| Insecure Direct Object Reference | High | High |
| Authentication Bypass | Medium | Critical |
| Command Injection | Medium | Critical |
| File Upload Vulnerabilities | Medium | High |
| SSRF | Medium | High |

**Infrastructure Vulnerabilities**
| Vulnerability | Frequency | Impact |
|--------------|-----------|--------|
| Default Credentials | Very High | Critical |
| Outdated Software | High | Varies |
| Misconfigurations | High | Varies |
| Weak Passwords | High | High |
| Missing Patches | Medium | High |
| Exposed Management Interfaces | Medium | Critical |

### 2.2 Container-Specific Findings

- Docker API exposed without authentication
- Privileged containers
- Sensitive data in image layers
- Mounted Docker sockets
- Outdated base images with known CVEs
- Secrets in environment variables
- Overly permissive container networks

### 2.3 Active Directory Findings

- Kerberoastable service accounts
- AS-REP roastable users
- Weak domain passwords
- GPP passwords (legacy)
- Unconstrained delegation
- Print spooler vulnerabilities
- Certificate services misconfigurations

### 2.4 Cloud Misconfigurations

- Overly permissive IAM policies
- Exposed S3 buckets / Azure blobs
- Metadata service access from containers
- Hardcoded cloud credentials
- Missing encryption at rest
- Insecure API endpoints

---

## 3. Recommended Attack Methodology

### 3.1 Phase 1: Reconnaissance (First 30 minutes)

**Network Discovery**
```bash
# Fast network scan
nmap -sn -T4 target_range -oG discovery.txt

# Service enumeration on discovered hosts
nmap -sV -sC -p- --min-rate 1000 -oA full_scan target_list
```

**Web Enumeration**
```bash
# Directory brute forcing
gobuster dir -u http://target -w /path/to/wordlist -t 50

# Virtual host discovery
gobuster vhost -u http://target -w subdomains.txt
```

**Information Gathering**
- Review provided documentation
- Identify in-scope IP ranges
- Map network topology
- Document all discovered services

### 3.2 Phase 2: Vulnerability Assessment (Next 60 minutes)

**Automated Scanning**
```bash
# Vulnerability scanning
nmap --script vuln target_list

# Web vulnerability scanning
nikto -h http://target
nuclei -u http://target -t cves/
```

**Manual Testing**
- Test default credentials
- Check for SQL injection
- Test authentication mechanisms
- Review source code if accessible

**Prioritization**
1. Critical services (AD, databases, Docker)
2. Web applications with forms
3. Legacy/outdated systems
4. Management interfaces

### 3.3 Phase 3: Exploitation (60-90 minutes)

**Initial Access Priority**
1. Default/weak credentials
2. Known CVEs with public exploits
3. SQL injection to RCE
4. File upload vulnerabilities
5. Command injection

**Lateral Movement**
1. Credential harvesting from compromised systems
2. SSH key reuse
3. Password spraying with discovered creds
4. Pivot through container networks

**Privilege Escalation**
1. Check sudo permissions
2. SUID binaries
3. Kernel exploits (if allowed)
4. Misconfigurations (writable paths, cron jobs)

### 3.4 Phase 4: Post-Exploitation (Ongoing)

**Evidence Collection**
- Screenshot access proof
- Export sensitive data samples
- Document privilege levels
- Map trust relationships

**Persistence (if in scope)**
- SSH key placement
- Scheduled tasks
- Service creation
- Container modifications

---

## 4. Time Management Strategies

### 4.1 Competition Time Allocation

**8-Hour Competition Day**
```
Hour 1:    Reconnaissance and scanning
Hour 2:    Vulnerability assessment
Hours 3-4: Initial exploitation
Hours 5-6: Lateral movement and escalation
Hour 7:    Documentation and cleanup
Hour 8:    Report writing and presentation prep
```

### 4.2 Team Role Distribution

**Suggested Roles (6-person team)**
| Role | Primary Tasks |
|------|---------------|
| Lead | Coordination, scope management, reporting |
| Web Specialist | Web app testing, API analysis |
| Infrastructure | AD, network services, databases |
| Container/Cloud | Docker, Kubernetes, cloud services |
| Exploitation | Active exploitation, lateral movement |
| Documentation | Real-time notes, evidence collection |

### 4.3 Documentation Standards

**Real-Time Notes Template**
```markdown
## [Timestamp] - [System/Service]
### Discovery
- IP: x.x.x.x
- Service: [service]
- Version: [version]

### Vulnerability
- Type: [vuln type]
- Evidence: [screenshot/command output]

### Exploitation
- Method: [technique]
- Access Level: [user/admin/root]
- Credentials: [if applicable]
```

### 4.4 Efficiency Tips

1. **Parallelize** - Run scans while testing manually
2. **Scripted enumeration** - Automate repetitive tasks
3. **Centralized notes** - Shared documentation platform
4. **Communication** - Regular status updates
5. **Timeboxing** - Move on if stuck (15-20 min max)
6. **Low-hanging fruit** - Default creds first, always

---

## 5. Report Writing Guidelines

### 5.1 Finding Format

```markdown
## Finding: [Descriptive Title]

**Severity:** Critical/High/Medium/Low
**CVSS Score:** [if applicable]
**Affected System:** [IP/hostname]

### Description
[What the vulnerability is]

### Impact
[Business and technical impact]

### Evidence
[Screenshots, command output]

### Remediation
[Specific fix recommendations]

### References
[CVE links, vendor advisories]
```

### 5.2 Executive Summary Points

- Total findings by severity
- Critical attack paths identified
- Business risk assessment
- Top 3 priority remediations
- Positive security observations

### 5.3 Technical Report Sections

1. Executive Summary
2. Scope and Methodology
3. Findings Summary Table
4. Detailed Findings
5. Attack Path Narrative
6. Recommendations
7. Appendices (evidence, tools used)

---

## 6. Competition-Specific Tips

### 6.1 Scoring Considerations

CPTC scoring typically includes:
- Technical findings (severity-weighted)
- Report quality and professionalism
- Client interaction (presentation, questions)
- Methodology documentation
- Business impact analysis

### 6.2 Common Mistakes to Avoid

1. **Scope violations** - Stay within defined boundaries
2. **Poor time management** - Spending too long on one target
3. **Inadequate documentation** - Screenshot everything
4. **Missing the obvious** - Always try default creds
5. **Tunnel vision** - Rotate team members if stuck
6. **Unprofessional reports** - Spelling, grammar, formatting
7. **Ignoring provided intel** - Read all documentation

### 6.3 Professional Conduct

- Treat it as a real engagement
- Professional communication with "clients"
- No destructive actions
- Respect data sensitivity
- Follow rules of engagement strictly

---

## 7. Tool Preparation Checklist

### 7.1 Pre-Competition Setup

**Essential Tools**
- [ ] Nmap with scripts
- [ ] Burp Suite configured
- [ ] Metasploit updated
- [ ] Custom wordlists
- [ ] Credential databases
- [ ] Screenshot tools
- [ ] Note-taking platform

**Container/Cloud Tools**
- [ ] Docker CLI
- [ ] kubectl
- [ ] Cloud CLI tools (aws, az, gcloud)
- [ ] Container scanning tools

**Documentation**
- [ ] Report templates
- [ ] Finding templates
- [ ] Evidence organization system
- [ ] Shared drive access

### 7.2 Environment Testing

Before competition:
- Test all tools on practice environment
- Verify VPN connectivity
- Confirm team communication channels
- Review network architecture diagrams
- Practice timed exercises

---

## 8. Historical Patterns

### 8.1 Vulnerability Trends

Recent CPTC competitions have emphasized:
- Container security misconfigurations
- CI/CD pipeline vulnerabilities
- Cloud infrastructure weaknesses
- API security issues
- Supply chain attack vectors

### 8.2 Scoring Trends

Higher scores correlate with:
- Clear attack path narratives
- Business-focused recommendations
- Professional presentation delivery
- Comprehensive but concise reports
- Creative but ethical techniques

---

## 9. References

- CPTC Official Rules and Guidelines
- PTES (Penetration Testing Execution Standard)
- OWASP Testing Guide
- CIS Benchmarks
- NIST Cybersecurity Framework
- Previous CPTC writeups (public)

---

**Document Version:** 1.0
**Next Review:** Pre-competition
