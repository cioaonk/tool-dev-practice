# Threat Intelligence Fundamentals

**Module:** Threat Intelligence Fundamentals
**Version:** 1.0
**Target Audience:** Beginner to Intermediate Security Practitioners
**Duration:** 8 hours (instruction + labs)
**Prerequisites:** Basic networking concepts, familiarity with Linux command line

---

## Module Overview

### Purpose

This module provides comprehensive training on threat intelligence concepts, methodologies, and practical applications for offensive security operations. Learners will understand how to gather, analyze, and operationalize threat intelligence to inform penetration testing activities and security assessments.

### Learning Objectives

Upon completion of this module, learners will be able to:

1. Define threat intelligence and articulate its role in security operations
2. Distinguish between strategic, tactical, and operational intelligence types
3. Apply the intelligence lifecycle to real-world scenarios
4. Identify and evaluate threat intelligence sources
5. Map threat actor techniques to the MITRE ATT&CK framework
6. Create actionable threat briefs for operational use
7. Understand how offensive tools are detected and apply evasion considerations

---

## Section 1: Threat Intelligence Fundamentals

### 1.1 What is Threat Intelligence?

Threat intelligence is the collection, processing, analysis, and dissemination of information about current and potential attacks that threaten an organization. Unlike raw security data, threat intelligence is contextualized, relevant, and actionable information that supports decision-making at multiple organizational levels.

**Key Characteristics of Quality Threat Intelligence:**

- **Accurate**: Based on verified, reliable sources
- **Timely**: Delivered when it can still influence decisions
- **Relevant**: Applicable to the specific organization or operation
- **Actionable**: Provides clear guidance for response or prevention
- **Complete**: Contains sufficient context for understanding

**The Distinction Between Data, Information, and Intelligence:**

```
+------------------+----------------------------------------+---------------------------+
| Level            | Description                            | Example                   |
+------------------+----------------------------------------+---------------------------+
| Raw Data         | Unprocessed observations               | 192.168.1.50 connected    |
|                  |                                        | to port 443               |
+------------------+----------------------------------------+---------------------------+
| Information      | Processed and organized data           | IP 192.168.1.50 made 500  |
|                  |                                        | HTTPS requests in 1 hour  |
+------------------+----------------------------------------+---------------------------+
| Intelligence     | Analyzed information with context      | The traffic pattern       |
|                  | and recommended actions                | indicates C2 beaconing    |
|                  |                                        | consistent with Cobalt    |
|                  |                                        | Strike; recommend         |
|                  |                                        | isolation and             |
|                  |                                        | investigation             |
+------------------+----------------------------------------+---------------------------+
```

Effective threat intelligence transforms overwhelming volumes of security data into focused, prioritized insights that enable defenders to anticipate threats rather than merely react to them. For offensive security professionals, understanding threat intelligence helps in emulating realistic adversaries and anticipating defensive responses.

### 1.2 Types of Threat Intelligence

Threat intelligence exists at multiple levels, each serving different audiences and purposes within an organization.

#### Strategic Intelligence

Strategic intelligence addresses high-level, long-term concerns and is typically consumed by executive leadership and board members. This intelligence type informs organizational strategy, budget allocation, and risk management decisions.

**Characteristics:**
- Long-term focus (months to years)
- Non-technical presentation
- Focuses on trends, motivations, and risks
- Supports business decisions

**Examples:**
- Annual threat landscape reports
- Industry-specific threat assessments
- Geopolitical risk analyses
- Emerging attack trend forecasts

**Application in Penetration Testing:**
Strategic intelligence helps security teams prioritize which threats to emulate during assessments. If an organization operates in the healthcare sector, strategic intelligence indicating increased ransomware targeting of medical facilities would inform the selection of TTPs to test.

#### Tactical Intelligence

Tactical intelligence provides detailed information about threat actor techniques, tactics, and procedures (TTPs). Security teams use this intelligence to configure defenses, develop detection rules, and understand adversary behavior patterns.

**Characteristics:**
- Medium-term focus (weeks to months)
- Technical in nature
- Focuses on how attacks are conducted
- Supports defensive configuration

**Examples:**
- MITRE ATT&CK technique mappings
- Attack playbooks and kill chain analyses
- Malware behavior reports
- Indicator patterns and signatures

**Application in Penetration Testing:**
Tactical intelligence directly informs attack methodology. Understanding that APT groups commonly use PowerShell for execution (T1059.001) and credential dumping via LSASS access (T1003.001) allows penetration testers to emulate realistic attack chains.

#### Operational Intelligence

Operational intelligence provides specific, time-sensitive information about imminent or ongoing attacks. This intelligence enables immediate defensive action and incident response.

**Characteristics:**
- Short-term focus (hours to days)
- Highly specific and technical
- Focuses on active campaigns and indicators
- Supports immediate response

**Examples:**
- Active campaign alerts
- Indicators of Compromise (IOCs)
- Exploit availability notices
- Zero-day vulnerability disclosures

**Application in Penetration Testing:**
Operational intelligence helps testers identify which vulnerabilities are actively being exploited in the wild, prioritizing these for testing. If a new Docker escape CVE is being actively exploited, it should be included in container security assessments.

```
                    INTELLIGENCE TYPES PYRAMID

                           /\
                          /  \
                         /    \
                        / STRAT \     <-- Executive Leadership
                       / EGIC    \        Long-term, Non-technical
                      /------------\
                     /              \
                    /   TACTICAL     \   <-- Security Teams
                   /                  \      Medium-term, TTPs
                  /--------------------\
                 /                      \
                /     OPERATIONAL        \  <-- SOC/IR Teams
               /                          \    Short-term, IOCs
              /----------------------------\
```

### 1.3 The Intelligence Lifecycle

The intelligence lifecycle is a systematic process for transforming raw information into actionable intelligence. Understanding this cycle is essential for both producing and consuming threat intelligence effectively.

#### Phase 1: Planning and Direction

This phase establishes intelligence requirements and priorities based on organizational needs.

**Key Activities:**
- Identify intelligence consumers and their needs
- Define Priority Intelligence Requirements (PIRs)
- Establish collection priorities
- Allocate resources

**For Penetration Testing:**
Planning determines which threat actors and TTPs are most relevant to the target organization. A financial services company may prioritize intelligence on FIN groups, while a defense contractor focuses on nation-state APTs.

#### Phase 2: Collection

Collection involves gathering raw data from multiple sources based on established requirements.

**Collection Sources:**
- Open Source Intelligence (OSINT)
- Technical intelligence from security tools
- Human intelligence from industry contacts
- Commercial threat feeds
- Dark web monitoring

**Collection Discipline Matrix:**

```
+---------------+---------------------------+--------------------------------+
| Source Type   | Examples                  | Use Cases                      |
+---------------+---------------------------+--------------------------------+
| OSINT         | News, social media,       | Threat landscape, actor        |
|               | public databases          | profiles, vulnerability        |
|               |                           | information                    |
+---------------+---------------------------+--------------------------------+
| TECHINT       | IDS/IPS logs, malware     | IOCs, attack patterns,         |
|               | samples, network captures | technical indicators           |
+---------------+---------------------------+--------------------------------+
| HUMINT        | Industry contacts,        | Emerging threats, insider      |
|               | information sharing       | knowledge, unpublished         |
|               | groups                    | intelligence                   |
+---------------+---------------------------+--------------------------------+
| SIGINT        | Network traffic           | C2 communication patterns,     |
|               | analysis, encrypted       | protocol analysis              |
|               | traffic metadata          |                                |
+---------------+---------------------------+--------------------------------+
```

#### Phase 3: Processing

Processing converts raw collected data into formats suitable for analysis.

**Key Activities:**
- Data normalization and standardization
- Translation and decryption
- Deduplication
- Initial filtering and triage

#### Phase 4: Analysis and Production

Analysis transforms processed information into finished intelligence products.

**Analytical Techniques:**
- Structured Analytic Techniques (ACH, Red Team Analysis)
- Pattern analysis and correlation
- Trend identification
- Threat actor profiling

**Output Products:**
- Threat briefs
- Intelligence reports
- IOC feeds
- TTP documentation

#### Phase 5: Dissemination

Dissemination delivers finished intelligence to consumers in appropriate formats.

**Considerations:**
- Audience-appropriate formatting
- Classification and handling requirements
- Timeliness of delivery
- Feedback mechanisms

#### Phase 6: Feedback and Evaluation

This phase assesses intelligence effectiveness and informs future collection.

**Evaluation Criteria:**
- Did the intelligence meet requirements?
- Was it timely and actionable?
- What gaps remain?
- How can the process improve?

```
            INTELLIGENCE LIFECYCLE

        +----> Planning & ----+
        |     Direction       |
        |                     v
    Feedback &           Collection
    Evaluation               |
        ^                    v
        |              Processing
        |                    |
        +---- Dissemi- <-----+
              nation    Analysis &
                       Production
```

### 1.4 Sources and Collection

Effective threat intelligence requires diverse sources to provide comprehensive coverage and enable cross-validation of findings.

#### Open Source Intelligence (OSINT)

OSINT comprises publicly available information that can be legally obtained.

**Key Sources:**
- Security vendor blogs and reports
- CVE databases (NVD, MITRE)
- Social media platforms
- Paste sites and code repositories
- News and industry publications
- Academic research

**OSINT Tools and Resources:**
- Shodan/Censys for internet-exposed assets
- VirusTotal for malware analysis
- MITRE ATT&CK for TTP documentation
- AlienVault OTX for IOC sharing
- SecurityTrails for DNS/domain history

#### Commercial Intelligence

Commercial threat intelligence provides curated, analyzed intelligence products.

**Advantages:**
- Professional analysis
- Broader visibility
- Timely updates
- Standardized formats

**Considerations:**
- Cost
- Relevance to your environment
- Integration capabilities
- Coverage gaps

#### Information Sharing Communities

Industry-specific sharing groups enable peer intelligence exchange.

**Examples:**
- ISACs (Information Sharing and Analysis Centers)
- FIRST (Forum of Incident Response and Security Teams)
- Sector-specific working groups
- Regional partnerships

#### Technical Collection

Internal security tools provide organizational context for external intelligence.

**Sources:**
- SIEM logs and alerts
- EDR telemetry
- Network traffic analysis
- Honeypots and deception technologies

---

## Section 2: CPTC Competition Intelligence

### 2.1 Competition Format and Objectives

The Collegiate Penetration Testing Competition (CPTC) is the premier ethical hacking competition for university students, simulating real-world penetration testing engagements. Understanding the competition format is essential for effective preparation.

**Competition Structure:**

- **Duration**: Typically 8-hour competition days
- **Team Size**: Usually 6-person teams
- **Environment**: Realistic corporate networks with multiple segments
- **Deliverables**: Technical findings and professional reports

**Scoring Components:**

| Component | Weight | Description |
|-----------|--------|-------------|
| Technical Findings | High | Severity-weighted vulnerability discovery |
| Report Quality | High | Professional documentation standards |
| Client Interaction | Medium | Presentation and Q&A performance |
| Methodology | Medium | Documented approach and process |
| Business Impact | Medium | Risk contextualization |

### 2.2 Historical Attack Patterns

Analysis of past CPTC competitions reveals consistent patterns in target environments.

**Common Network Topology:**

```
    [Internet]
        |
    [Firewall]
        |
    +---+---+---+---+
    |   |   |   |   |
   DMZ INT DEV CLD

DMZ: Web servers, Mail, DNS (public-facing)
INT: Active Directory, File servers, Databases
DEV: CI/CD pipelines, Container infrastructure
CLD: AWS/Azure services, Container registries
```

**High-Frequency Vulnerability Categories:**

1. **Web Applications**
   - SQL Injection (very high frequency)
   - Cross-Site Scripting
   - Insecure Direct Object References
   - Authentication bypasses

2. **Infrastructure**
   - Default credentials (extremely common)
   - Outdated software
   - Misconfigurations
   - Exposed management interfaces

3. **Active Directory**
   - Kerberoastable accounts
   - Weak domain passwords
   - Delegation misconfigurations
   - Certificate services vulnerabilities

4. **Container/Cloud**
   - Exposed Docker APIs
   - Privileged containers
   - Secrets in environment variables
   - Overly permissive IAM policies

### 2.3 Common Infrastructure Targets

**Priority Target Matrix:**

| Target Type | Typical Services | Common Vulnerabilities |
|-------------|------------------|----------------------|
| Web Servers | Apache, Nginx, IIS | SQLi, XSS, File Upload |
| Databases | MySQL, PostgreSQL, MSSQL | Default creds, SQLi |
| Docker Hosts | Docker API, Portainer | Unauthenticated API, privileged containers |
| AD Domain Controllers | Kerberos, LDAP | Kerberoasting, GPP passwords |
| CI/CD Systems | Jenkins, GitLab | Default credentials, code injection |

### 2.4 Scoring Considerations

**Maximize Points Through:**

1. **Comprehensive Coverage**: Test all in-scope systems
2. **Severity Prioritization**: Focus on critical/high findings first
3. **Clear Documentation**: Detailed evidence with screenshots
4. **Business Context**: Explain impact in business terms
5. **Professional Presentation**: Quality report formatting

**Common Mistakes to Avoid:**

- Scope violations (automatic penalties)
- Poor time management (incomplete testing)
- Inadequate documentation
- Missing default credential checks
- Unprofessional report presentation

---

## Section 3: Docker Container Threats

### 3.1 Container-Specific Attack Vectors

Containerized environments present unique attack surfaces that differ from traditional infrastructure.

**Container Attack Surface Diagram:**

```
    +------------------------------------------+
    |              HOST SYSTEM                 |
    |  +------------------------------------+  |
    |  |         CONTAINER RUNTIME          |  |
    |  |  +----------+  +----------+        |  |
    |  |  |Container1|  |Container2|  ...   |  |
    |  |  |          |  |          |        |  |
    |  |  +----------+  +----------+        |  |
    |  +------------------------------------+  |
    |                                          |
    |  Attack Vectors:                         |
    |  1. Application vulnerabilities          |
    |  2. Container configuration             |
    |  3. Runtime vulnerabilities              |
    |  4. Host kernel exploits                 |
    |  5. Network misconfigurations           |
    +------------------------------------------+
```

**Primary Attack Vectors:**

1. **Application Layer**: Exploiting vulnerabilities in containerized applications
2. **Container Configuration**: Abusing misconfigurations (privileged mode, excessive capabilities)
3. **Volume Mounts**: Accessing sensitive host paths mounted into containers
4. **Network Exposure**: Exploiting container network configurations
5. **Supply Chain**: Compromised base images or dependencies

### 3.2 Escape Techniques

Container escapes allow attackers to break out of container isolation and access the host system.

**Technique 1: Privileged Container Escape**

When containers run with `--privileged`, they have full access to host devices:

```
Detection Check:
cat /proc/1/status | grep CapEff
# CapEff: 0000003fffffffff indicates privileged

Attack Path:
1. Mount host filesystem
2. Access host via chroot
3. Full host compromise
```

MITRE ATT&CK Mapping: T1611 - Escape to Host

**Technique 2: Docker Socket Escape**

If `/var/run/docker.sock` is mounted inside a container:

```
Detection Check:
ls -la /var/run/docker.sock

Attack Path:
1. Use Docker CLI to create privileged container
2. Mount host root filesystem
3. Escape to host
```

**Technique 3: Kernel Exploits**

Notable CVEs for container escape:

| CVE | Name | Impact | CVSS |
|-----|------|--------|------|
| CVE-2024-21626 | runc Escape | Container escape via /proc/self/fd | 8.6 |
| CVE-2022-0847 | Dirty Pipe | Arbitrary file write as root | 7.8 |
| CVE-2022-0185 | FSConfig Overflow | Kernel code execution | 8.4 |

### 3.3 Misconfigurations

**Dangerous Docker Run Flags:**

| Flag | Risk Level | Impact |
|------|------------|--------|
| `--privileged` | Critical | Full host access |
| `--net=host` | High | Network namespace escape |
| `--pid=host` | High | Process injection capability |
| `-v /:/host` | Critical | Host filesystem access |
| `--cap-add=ALL` | Critical | All Linux capabilities |

**Sensitive Mount Points to Monitor:**

```yaml
# High-risk volume mounts:
volumes:
  - /var/run/docker.sock:/var/run/docker.sock  # Container escape
  - /etc:/host/etc                              # Config access
  - /root/.ssh:/root/.ssh                       # SSH key theft
  - /proc:/host/proc                            # Process info leak
```

### 3.4 Detection Opportunities

**Container Security Monitoring Points:**

1. **Runtime Events**: Container creation with dangerous flags
2. **System Calls**: Mount syscalls from containers
3. **File Access**: Access to /dev or sensitive paths
4. **API Calls**: Docker API requests from container networks
5. **Network Traffic**: Unusual inter-container communication

---

## Section 4: Network Attack Vectors

### 4.1 Common Network Attacks

Network-based attacks remain foundational to penetration testing, especially in containerized environments where services are interconnected.

**Attack Vector Overview:**

```
+------------------+------------------+------------------+
|   Reconnaissance |   Exploitation   | Post-Exploitation|
+------------------+------------------+------------------+
| Port scanning    | Service exploits | Lateral movement |
| Service enum     | Default creds    | Privilege escal  |
| Version detect   | Web app attacks  | Data exfil       |
| Vuln scanning    | Protocol abuse   | Persistence      |
+------------------+------------------+------------------+
```

**Exposed Management Interfaces (High-Value Targets):**

| Service | Port | Risk | Attack Vector |
|---------|------|------|---------------|
| Docker API | 2375/2376 | Critical | Unauthenticated container control |
| Kubernetes API | 6443/8443 | Critical | Cluster compromise |
| etcd | 2379/2380 | Critical | Secret extraction |
| Portainer | 9000 | High | Web UI exploitation |
| Redis | 6379 | High | Unauthenticated access, SSH key injection |
| MongoDB | 27017 | High | No auth by default |

### 4.2 Protocol Exploitation

**Redis Exploitation (Port 6379):**

When Redis lacks authentication, attackers can write files to the system:

```
Attack Chain:
1. Connect to Redis
2. Write SSH key to authorized_keys
3. SSH to target as compromised user
```

**SSRF Targets in Containerized Environments:**

```
# Cloud metadata endpoints
http://169.254.169.254/latest/meta-data/    # AWS
http://metadata.google.internal/             # GCP

# Internal services
http://localhost:2375/containers/json        # Docker API
http://kubernetes.default.svc/               # K8s API
```

### 4.3 Lateral Movement Patterns

**Container-to-Container Movement:**

```
Discovery Methods:
1. Network scanning of container subnets
2. DNS enumeration via Docker DNS
3. Service discovery in Kubernetes

Pivot Techniques:
1. SSH between containers
2. Docker socket exploitation
3. Kubernetes service account abuse
4. Network namespace escape
```

**Network Pivoting Tools:**

| Tool | Protocol | Use Case |
|------|----------|----------|
| SSH Tunnels | SSH | Encrypted port forwarding |
| Chisel | HTTP | HTTP-based tunneling |
| Ligolo-ng | Multiple | Advanced pivoting |
| Proxychains | SOCKS | Traffic proxying |

### 4.4 Data Exfiltration Methods

**Exfiltration Channels:**

1. **HTTPS**: Blends with normal traffic
2. **DNS**: Tunneling data in queries
3. **ICMP**: Encoding data in ping packets
4. **Legitimate Services**: Cloud storage uploads

**Detection Considerations:**

- Large outbound transfers
- Off-hours data movement
- Encrypted traffic to unusual destinations
- DNS query volume anomalies

---

## Section 5: Threat Actor TTPs

### 5.1 APT Methodology

Advanced Persistent Threat (APT) groups employ sophisticated, long-term attack campaigns with specific objectives.

**APT Characteristics:**

- Low and slow approach to avoid detection
- Living off the land (using built-in tools)
- Long-term persistence mechanisms
- Specific intelligence objectives

**Typical APT Kill Chain:**

```
1. Reconnaissance  -->  2. Weaponization  -->  3. Delivery
        |
        v
4. Exploitation  -->  5. Installation  -->  6. Command & Control
        |
        v
7. Actions on Objectives
```

### 5.2 Criminal Threat Actors

Criminal groups focus on financial gain through various monetization strategies.

**Common Criminal TTPs:**

| Objective | Techniques | Tools |
|-----------|------------|-------|
| Ransomware | T1486 (Data Encrypted for Impact) | Various RaaS platforms |
| Cryptomining | T1496 (Resource Hijacking) | Mining software |
| Data Theft | T1041 (Exfiltration Over C2) | Custom exfil tools |
| Credential Theft | T1003 (Credential Dumping) | Mimikatz variants |

### 5.3 Insider Threats

Insider threats leverage authorized access for unauthorized purposes.

**Detection Challenges:**
- Legitimate credentials and access
- Knowledge of security controls
- Ability to avoid monitoring
- Access to sensitive systems

### 5.4 TTP Mapping to MITRE ATT&CK

**Container-Focused Attack Techniques:**

| Technique ID | Name | Description |
|--------------|------|-------------|
| T1609 | Container Administration Command | Exec into containers |
| T1610 | Deploy Container | Create malicious containers |
| T1611 | Escape to Host | Break container isolation |
| T1613 | Container and Resource Discovery | Enumerate container environment |
| T1525 | Implant Container Image | Backdoor images |
| T1552.007 | Container API Credentials | Steal container secrets |

**Common TTP Chains:**

```
Web Application to Domain Admin:
T1190 --> T1059 --> T1003 --> T1078 --> T1021 --> T1068
(SQLi)    (Exec)    (Creds)   (Valid)   (Lateral) (PrivEsc)

Container Escape Chain:
T1190 --> T1609 --> T1611 --> T1068
(Exploit) (Exec)    (Escape)  (PrivEsc)
```

---

## Section 6: Tool Detection Strategies

### 6.1 How Offensive Tools Are Detected

Understanding detection mechanisms is essential for both offensive and defensive security professionals.

**Detection Layers:**

```
+------------------------+
|   Network Detection    |  <-- IDS/IPS, Traffic Analysis
+------------------------+
|   Endpoint Detection   |  <-- EDR, AV, HIDS
+------------------------+
|   Log Analysis         |  <-- SIEM, Log Correlation
+------------------------+
|   Behavioral Analysis  |  <-- UEBA, Anomaly Detection
+------------------------+
```

### 6.2 Signatures and Behaviors

**Network Signatures:**

| Tool | Detection Method | Evasion |
|------|------------------|---------|
| Nmap | SYN scan patterns, timing | Slow scan, fragmentation |
| Metasploit | Stage patterns, URIs | Custom profiles |
| Cobalt Strike | Beacon patterns, certificates | Malleable C2 |
| Responder | Broadcast response timing | N/A (inherently detectable) |

**Host-Based Detection:**

| Tool | Artifacts | Detection Source |
|------|-----------|------------------|
| Mimikatz | LSASS access | Sysmon Event 10 |
| PowerSploit | Script blocks | PowerShell logging |
| LinPEAS | Distinctive output | File monitoring |

### 6.3 Defensive Countermeasures

**Common Defense Technologies:**

1. **EDR Solutions**: CrowdStrike, Carbon Black, Microsoft Defender
2. **Network Monitoring**: Zeek, Suricata, Snort
3. **SIEM Platforms**: Splunk, Elastic, Sentinel
4. **Container Security**: Falco, Aqua, Twistlock

### 6.4 Evasion Considerations

**General Principles:**

1. Know the defensive stack before tool selection
2. Use built-in tools (living off the land) when possible
3. Operate during high-traffic periods
4. Match legitimate traffic patterns
5. Stage reconnaissance before heavy tools

**Tool Modification Approaches:**

- Rename binaries and scripts
- Modify string signatures
- Change default ports and URIs
- Compile from source with modifications
- Use memory-only execution

---

## Section 7: Creating Threat Briefs (Tutorial)

### 7.1 Research Methodology

A structured approach to threat research ensures comprehensive, consistent intelligence products.

**Research Process:**

```
Step 1: Define Scope
   |
   v
Step 2: Collect Information
   |
   v
Step 3: Analyze and Correlate
   |
   v
Step 4: Produce Intelligence
   |
   v
Step 5: Validate and Review
```

**Source Evaluation Criteria (CRAAP Test):**

| Criterion | Questions to Ask |
|-----------|------------------|
| Currency | When was it published? Is it current? |
| Relevance | Does it address your requirements? |
| Authority | Who is the author? What are their credentials? |
| Accuracy | Is the information verifiable? |
| Purpose | Why does this information exist? |

### 7.2 Documentation Format

**Standard Threat Brief Template:**

```markdown
# Threat Brief: [Threat Name/Campaign]

**Classification:** [Handling instructions]
**Date:** [Publication date]
**Analyst:** [Author]

## Executive Summary
[2-3 sentence overview of key findings]

## Threat Overview
### Actor Profile
- Attribution
- Motivation
- Capability level

### Target Profile
- Industries targeted
- Geographic focus
- Target selection criteria

## Technical Analysis
### TTPs (MITRE ATT&CK Mapping)
| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|

### Indicators of Compromise
| Type | Value | Context |
|------|-------|---------|

### Attack Chain
[Visual or textual kill chain]

## Impact Assessment
- Potential business impact
- Risk rating

## Recommendations
1. Immediate actions
2. Short-term mitigations
3. Long-term improvements

## References
- [Source links]
```

### 7.3 Actionable Recommendations

Recommendations must be specific, prioritized, and implementable.

**Good vs. Bad Recommendations:**

| Bad | Good |
|-----|------|
| "Improve security" | "Deploy network segmentation between container networks and AD domain controllers" |
| "Patch systems" | "Apply Microsoft security update KB5034441 to all domain controllers within 72 hours" |
| "Monitor for threats" | "Create Splunk alert for Event ID 10 targeting lsass.exe with source processes from container networks" |

---

## Section 8: Hands-On Labs

### Lab 1: CTI Research Workflow

**Objective:** Conduct open-source threat intelligence research on a specified threat actor or campaign.

**Duration:** 60 minutes

**Environment Requirements:**
- Internet access
- Web browser
- Note-taking application

**Scenario:**
Your organization has received reports of increased targeting of Docker environments by opportunistic attackers. You have been tasked with researching current container security threats to inform defensive priorities.

**Tasks:**

1. **Source Identification (15 minutes)**
   - Identify at least 5 reliable sources for container security threat intelligence
   - Document source URLs and assess reliability using CRAAP criteria

2. **Information Collection (20 minutes)**
   - Research current container-specific CVEs (2024-2025)
   - Document at least 3 active exploitation campaigns
   - Collect IOCs if available

3. **Analysis (15 minutes)**
   - Identify common attack patterns
   - Map techniques to MITRE ATT&CK
   - Assess relevance to your environment

4. **Documentation (10 minutes)**
   - Create a brief summary of findings
   - Prioritize threats by risk level

**Hints System:**

<details>
<summary>Hint 1: Where to start</summary>
Begin with NVD (nvd.nist.gov) for CVE information. Filter by keyword "docker" or "container" and date range.
</details>

<details>
<summary>Hint 2: Finding campaigns</summary>
Security vendor blogs (Aqua Security, Sysdig, Palo Alto Unit 42) regularly publish container threat research.
</details>

<details>
<summary>Hint 3: MITRE mapping</summary>
Reference the Containers ATT&CK matrix at attack.mitre.org/matrices/enterprise/containers/
</details>

**Validation Criteria:**
- [ ] Minimum 5 sources identified with reliability assessment
- [ ] At least 3 current CVEs documented with severity ratings
- [ ] At least 3 attack campaigns identified
- [ ] MITRE ATT&CK techniques mapped for each campaign
- [ ] Summary document completed with prioritized findings

---

### Lab 2: TTP Mapping Exercise

**Objective:** Map a realistic attack scenario to the MITRE ATT&CK framework.

**Duration:** 45 minutes

**Environment Requirements:**
- Access to MITRE ATT&CK Navigator (mitre-attack.github.io/attack-navigator/)
- Lab documentation

**Scenario:**
An incident response team has provided the following observations from a recent breach. Your task is to map these activities to the MITRE ATT&CK framework.

**Observed Activities:**

```
1. Initial access occurred through SQL injection on public-facing web application
2. Attacker executed system commands through database functions
3. Attacker enumerated running containers and Docker configuration
4. Attacker created a new privileged container mounting the host filesystem
5. Attacker escaped container to gain host access
6. Credentials were extracted from /etc/shadow on the host
7. SSH keys were installed for persistence
8. Attacker pivoted to internal network via SSH
9. Data was exfiltrated over HTTPS to external server
```

**Tasks:**

1. **Technique Identification (15 minutes)**
   - Map each observed activity to a MITRE ATT&CK technique
   - Document technique ID, name, and tactic

2. **Attack Chain Visualization (15 minutes)**
   - Create an ATT&CK Navigator layer showing the attack path
   - Color-code by phase or severity

3. **Detection Opportunity Analysis (15 minutes)**
   - For each technique, identify potential detection methods
   - Recommend data sources needed for detection

**Expected Mapping:**

| Activity | Technique ID | Technique Name | Tactic |
|----------|--------------|----------------|--------|
| 1. SQL Injection | T1190 | Exploit Public-Facing Application | Initial Access |
| 2. Command execution | T1059 | Command and Scripting Interpreter | Execution |
| 3. Container enumeration | T1613 | Container and Resource Discovery | Discovery |
| 4. Privileged container | T1610 | Deploy Container | Execution |
| 5. Container escape | T1611 | Escape to Host | Privilege Escalation |
| 6. Credential extraction | T1003.008 | /etc/passwd and /etc/shadow | Credential Access |
| 7. SSH key persistence | T1098.004 | SSH Authorized Keys | Persistence |
| 8. Lateral movement | T1021.004 | Remote Services: SSH | Lateral Movement |
| 9. Data exfiltration | T1041 | Exfiltration Over C2 Channel | Exfiltration |

**Validation Criteria:**
- [ ] All 9 activities mapped to appropriate techniques
- [ ] ATT&CK Navigator layer created
- [ ] Detection recommendations documented for each technique

---

### Lab 3: Threat Brief Creation

**Objective:** Create a complete threat intelligence brief following professional standards.

**Duration:** 90 minutes

**Environment Requirements:**
- Access to threat intel documentation (provided)
- Document editor
- Reference materials from Labs 1 and 2

**Scenario:**
Using the CPTC threat intelligence documentation provided, create a threat brief focused on Docker container security threats for a penetration testing team preparing for competition.

**Tasks:**

1. **Executive Summary (10 minutes)**
   - Write a 3-4 sentence summary of key container threats
   - Highlight the most critical risks

2. **Threat Overview (20 minutes)**
   - Document relevant threat actors targeting containers
   - Describe attack motivations and objectives
   - Identify target selection criteria

3. **Technical Analysis (30 minutes)**
   - Map relevant TTPs to MITRE ATT&CK
   - Document specific CVEs and exploitation methods
   - Create an attack chain diagram

4. **Impact Assessment (10 minutes)**
   - Describe potential business impact
   - Assign risk ratings to identified threats

5. **Recommendations (15 minutes)**
   - Provide specific, actionable recommendations
   - Prioritize by effectiveness and feasibility

6. **Review and Polish (5 minutes)**
   - Proofread for clarity and completeness
   - Verify all references are cited

**Template Structure:**

```markdown
# Threat Brief: Docker Container Security Threats

**Classification:** CPTC Competition Preparation
**Date:** [Current Date]
**Analyst:** [Your Name]

## Executive Summary
[Your summary here]

## Threat Overview
### Attack Surface
[Description of container attack vectors]

### Relevant Threat Actors
[Actor profiles and motivations]

## Technical Analysis
### Attack Techniques (MITRE ATT&CK)
[TTP table]

### Critical Vulnerabilities
[CVE documentation]

### Attack Chain
[Visual diagram]

## Impact Assessment
[Risk analysis]

## Recommendations
[Prioritized actions]

## References
[Source citations]
```

**Validation Criteria:**
- [ ] Executive summary is clear and concise
- [ ] At least 5 TTPs mapped with proper MITRE IDs
- [ ] At least 3 CVEs documented with severity ratings
- [ ] Attack chain diagram included
- [ ] Minimum 5 specific, actionable recommendations
- [ ] Professional formatting and presentation
- [ ] All sources properly cited

**Extension Challenge:**
Create an ATT&CK Navigator layer that can be imported to visualize the threat actor TTPs documented in your brief.

---

## Assessment and Knowledge Check

### Module Quiz

1. What are the three types of threat intelligence and their primary consumers?

2. List the six phases of the intelligence lifecycle.

3. What MITRE ATT&CK technique ID corresponds to container escape?

4. Name three dangerous Docker run flags and explain their risk.

5. What is the difference between IOCs and TTPs?

6. Describe two methods for detecting credential dumping tools.

7. What makes a threat intelligence recommendation "actionable"?

### Practical Assessment Rubric

| Criterion | Excellent (4) | Good (3) | Adequate (2) | Needs Improvement (1) |
|-----------|---------------|----------|--------------|----------------------|
| Technical Accuracy | All information verified and correct | Minor errors that don't affect conclusions | Some errors affecting analysis | Significant inaccuracies |
| MITRE Mapping | Complete, accurate mappings with context | Accurate mappings, limited context | Partial mappings | Incorrect or missing mappings |
| Actionability | Specific, prioritized, implementable | Mostly specific and actionable | Generic but relevant | Vague or impractical |
| Documentation | Professional, complete, well-organized | Clear and organized | Adequate structure | Disorganized or incomplete |
| Analysis Depth | Comprehensive with novel insights | Thorough analysis | Adequate coverage | Superficial treatment |

---

## Quick Reference Card

### Intelligence Types

| Type | Audience | Timeframe | Focus |
|------|----------|-----------|-------|
| Strategic | Executives | Months-Years | Trends, Risks |
| Tactical | Security Teams | Weeks-Months | TTPs |
| Operational | SOC/IR | Hours-Days | IOCs |

### Key MITRE ATT&CK Techniques for Containers

- T1609: Container Administration Command
- T1610: Deploy Container
- T1611: Escape to Host
- T1613: Container and Resource Discovery
- T1525: Implant Container Image

### Container Escape Checklist

- [ ] Check for privileged mode: `cat /proc/1/status | grep CapEff`
- [ ] Check for Docker socket: `ls -la /var/run/docker.sock`
- [ ] Check for dangerous mounts: `mount | grep -E 'docker|host'`
- [ ] Check capabilities: `capsh --print`

### Threat Brief Components

1. Executive Summary
2. Threat Overview
3. Technical Analysis (TTPs, IOCs)
4. Impact Assessment
5. Recommendations
6. References

---

## References and Further Reading

### Primary Sources
- MITRE ATT&CK Framework: https://attack.mitre.org
- MITRE ATT&CK for Containers: https://attack.mitre.org/matrices/enterprise/containers/
- NVD (National Vulnerability Database): https://nvd.nist.gov
- CIS Docker Benchmark: https://cisecurity.org

### Threat Intelligence Resources
- CISA Known Exploited Vulnerabilities: https://cisa.gov/known-exploited-vulnerabilities
- AlienVault OTX: https://otx.alienvault.com
- VirusTotal: https://virustotal.com
- SANS Reading Room: https://sans.org/reading-room

### Container Security Documentation
- Docker Security Documentation: https://docs.docker.com/engine/security/
- NIST Container Security Guide (SP 800-190)
- Kubernetes Security Documentation: https://kubernetes.io/docs/concepts/security/

### Competition Resources
- CPTC Official Site: https://cp.tc
- PTES (Penetration Testing Execution Standard): http://ptes.org
- OWASP Testing Guide: https://owasp.org/testing-guide

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Next Review:** Pre-competition
**Author:** Docker Security Training Team
