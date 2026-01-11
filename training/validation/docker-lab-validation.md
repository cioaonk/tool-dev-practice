# CPTC11 Docker Lab Environment Training Guide - Validation Report

**Document Reviewed:** `/Users/ic/cptc11/training/curriculum/docker-lab-environment.md`
**Validation Date:** 2026-01-10
**Validator:** QA Test Engineer
**Document Version:** 1.0

---

## Executive Summary

**Overall Quality Score: 9/10**

The Docker Lab Environment Training Guide is a comprehensive, professionally written document that provides excellent coverage of the CPTC11 testing environment. The technical accuracy is high, with network configurations, credentials, and service details matching the actual Docker implementation. Minor issues were identified and documented below.

**Recommendation:** APPROVED for use with minor corrections recommended.

---

## Validation Checklist Results

### 1. Technical Accuracy - Docker Commands and Configurations

**Score: 9/10**

| Item | Status | Notes |
|------|--------|-------|
| Docker Compose syntax | PASS | Commands use correct `docker compose` (v2) syntax |
| Port mappings documented | PASS | All mappings match docker-compose.yml |
| Network subnets accurate | PASS | DMZ (10.10.10.0/24), Internal (10.10.20.0/24), Management (10.10.30.0/24) verified |
| Container names correct | PASS | All container names match actual configuration |
| Volume configurations | PASS | Documented volumes align with docker-compose.yml |
| Health check commands | PASS | Verification commands are valid and functional |

**Issues Found:**

1. **Minor Issue - Line 709-718:** The `docker compose ps` output example shows network names as `docker_dmz_network` but the actual compose file uses relative naming. The output will show names based on the project directory name (e.g., `cptc11_dmz_network` if run from `/Users/ic/cptc11/docker`).

2. **Minor Issue - Line 819:** Reference to `dns-server/config/zones/` should be clarified that this path is relative to the docker directory.

### 2. Professional Tone and Writing Quality

**Score: 10/10**

| Aspect | Status | Notes |
|--------|--------|-------|
| Consistent terminology | PASS | Technical terms used consistently throughout |
| Clear explanations | PASS | Complex concepts explained well for target audience |
| No grammatical errors | PASS | Writing is grammatically correct |
| Appropriate technical depth | PASS | Balances accessibility with technical detail |
| Professional formatting | PASS | Well-structured with clear sections |
| Active voice usage | PASS | Commands and instructions use appropriate active voice |

**Observations:**
- The document maintains an excellent educational tone throughout
- Security warnings are appropriately emphasized
- Prerequisites are clearly stated
- Time estimates provided for scenarios are reasonable

### 3. Network Topology Accuracy

**Score: 9/10**

| Element | Document | Actual | Status |
|---------|----------|--------|--------|
| vulnerable-web DMZ | 10.10.10.10 | 10.10.10.10 | MATCH |
| vulnerable-web Internal | 10.10.20.10 | 10.10.20.10 | MATCH |
| ftp-server | 10.10.10.20 | 10.10.10.20 | MATCH |
| smtp-server DMZ | 10.10.10.30 | 10.10.10.30 | MATCH |
| smtp-server Internal | 10.10.20.30 | 10.10.20.30 | MATCH |
| dns-server DMZ | 10.10.10.40 | 10.10.10.40 | MATCH |
| dns-server Internal | 10.10.20.40 | 10.10.20.40 | MATCH |
| smb-server | 10.10.20.50 | 10.10.20.50 | MATCH |
| mysql-server | 10.10.20.60 | 10.10.20.60 | MATCH |
| target-dc Internal | 10.10.20.5 | 10.10.20.5 | MATCH |
| target-dc Management | 10.10.30.5 | 10.10.30.5 | MATCH |
| workstation-1 | 10.10.20.101 | 10.10.20.101 | MATCH |
| workstation-2 | 10.10.20.102 | 10.10.20.102 | MATCH |
| target-server-1 Internal | 10.10.20.111 | 10.10.20.111 | MATCH |
| target-server-1 Management | 10.10.30.111 | 10.10.30.111 | MATCH |
| attack-platform DMZ | 10.10.10.100 | 10.10.10.100 | MATCH |
| attack-platform Internal | 10.10.20.100 | 10.10.20.100 | MATCH |

**Issues Found:**

1. **Minor Issue - Network Diagram (Line 88-89):** The diagram shows `vulnerable-web` at 10.10.20.10 in the internal network section, but this appears duplicated in the DMZ section as well. While technically accurate (dual-homed), the visual representation could be clearer.

2. **Observation:** The DNS zone file contains additional IP mappings (staging at 10.10.20.101, which conflicts with ws01) that students may encounter during enumeration. This is actually good for realism but could be noted as intentional overlap.

### 4. Service Configurations - Credentials and Ports

**Score: 9/10**

#### Port Mappings Verification

| Service | Documented | docker-compose.yml | Status |
|---------|------------|-------------------|--------|
| Web HTTP | 8080:80 | 8080:80 | MATCH |
| Web HTTPS | 8443:443 | 8443:443 | MATCH |
| FTP | 2121:21 | 2121:21 | MATCH |
| FTP Passive | 30000-30009 | 30000-30009 | MATCH |
| SMTP | 2525:25 | 2525:25 | MATCH |
| Submission | 587:587 | 587:587 | MATCH |
| DNS | 5353:53 | 5353:53/udp, 5353:53/tcp | MATCH |
| SMB | 4445:445 | 4445:445 | MATCH |
| NetBIOS | 1139:139 | 1139:139 | MATCH |
| MySQL | 3307:3306 | 3307:3306 | MATCH |
| SSH | 2222:22 | 2222:22 | MATCH |

#### Credentials Verification

| Service | Username | Document Password | Actual Config | Status |
|---------|----------|-------------------|---------------|--------|
| Web | admin | admin123 | admin123 (MySQL init) | MATCH |
| FTP | ftpuser | ftppass123 | ftppass123 (env var) | MATCH |
| FTP | anonymous | (none) | Enabled (vsftpd.conf) | MATCH |
| SMTP | smtpuser | smtppass123 | smtppass123 (env var) | MATCH |
| SMB | smbuser | smbpass123 | smbpass123 (env var) | MATCH |
| MySQL | root | rootpass123 | rootpass123 (env var) | MATCH |
| MySQL | webuser | webpass123 | webpass123 (env var) | MATCH |
| MySQL | dbadmin | dbadmin123 | dbadmin123 (SQL init) | MATCH |
| SSH (srv01) | admin | admin123 | admin123 (env var) | MATCH |
| DC | Administrator | AdminPass123! | AdminPass123! (env var) | MATCH |

**Issues Found:**

1. **Minor Discrepancy - Line 197:** Document lists `backup` FTP user with password `backup2024`. This user is not defined in the FTP server environment variables or Dockerfile visible in the codebase. Verify if this user is created dynamically.

2. **Minor Addition Needed:** The `database.php.bak` file contains `superadmin:supersecret123` credentials not documented in the credential tables (Line 185-230). Consider adding these for completeness.

3. **Minor Issue - Line 228-229:** Document mentions `sysadmin:sysadmin1` for SSH access but this is not visible in the docker-compose.yml environment variables.

### 5. Lab Scenarios - Realism Assessment

**Score: 9/10**

| Scenario | Realism | Progression | Achievability | Notes |
|----------|---------|-------------|---------------|-------|
| 1: Reconnaissance | HIGH | Appropriate for Level 1 | ACHIEVABLE | Good foundation scenario |
| 2: Credential Spraying | HIGH | Good Level 2 progression | ACHIEVABLE | Tools and paths verified |
| 3: Lateral Movement | HIGH | Complex Level 3 | ACHIEVABLE | Pivot points well documented |
| 4: Data Exfiltration | HIGH | Appropriate Level 3 | ACHIEVABLE | Multiple vectors covered |
| 5: Full Kill Chain | HIGH | Comprehensive Level 4 | ACHIEVABLE | Excellent capstone |

**Observations:**
- Scenarios follow realistic attack methodologies
- Difficulty progression is appropriate (Foundation to Mastery)
- Time estimates appear reasonable
- Validation criteria are measurable and specific
- Commands and tool paths are accurate

**Issues Found:**

1. **Minor Issue - Line 980-987:** FTP credential testing shows port 21 when attacking from attack platform, but from host machine should use port 2121. The context should clarify which environment the command runs in.

2. **Suggestion:** Consider adding expected outputs for more commands to help learners verify success.

### 6. Troubleshooting Sections

**Score: 9/10**

| Coverage Area | Status | Notes |
|---------------|--------|-------|
| Container startup failures | COVERED | Good diagnostic commands |
| Network connectivity | COVERED | Comprehensive troubleshooting |
| DNS resolution | COVERED | Correct path references |
| Database connection | COVERED | Accurate mysqladmin commands |
| Port conflicts | COVERED | Appropriate lsof/netstat commands |
| Reset procedures | COVERED | docker compose down -v documented |

**Issues Found:**

1. **Enhancement Opportunity:** Consider adding troubleshooting for common macOS-specific issues (e.g., Docker Desktop resource limits, filesystem sharing permissions).

2. **Minor Issue - Line 791:** The `docker network ls | grep cptc11` command assumes network naming - should use `grep docker_` or the actual project name prefix.

### 7. Formatting and Markdown Structure

**Score: 10/10**

| Element | Status | Notes |
|---------|--------|-------|
| Heading hierarchy | PASS | Consistent H1 through H4 usage |
| Code block formatting | PASS | Proper language hints (bash, sql, php, dockerfile) |
| Table formatting | PASS | All tables render correctly |
| List formatting | PASS | Consistent bullet and numbered lists |
| ASCII diagram | PASS | Network topology diagram is clear |
| Links and references | PASS | Internal references are correct |
| Line length | PASS | No excessively long lines |

**Observations:**
- Document uses consistent formatting throughout
- Code examples are properly fenced and highlighted
- Tables are well-structured and informative
- Checkboxes for validation criteria are correctly formatted

---

## Issues Summary

### Critical Issues (Must Fix)
None identified.

### Major Issues (Should Fix)
None identified.

### Minor Issues (Recommended Fixes)

| ID | Location | Description | Recommendation |
|----|----------|-------------|----------------|
| M1 | Line 197 | `backup:backup2024` FTP credentials not verified in config | Verify user creation or remove from documentation |
| M2 | Lines 228-229 | `sysadmin:sysadmin1` SSH credentials not in compose file | Verify source or update documentation |
| M3 | Lines 980-987 | Port 21 vs 2121 confusion for FTP testing | Clarify execution context (attack platform vs host) |
| M4 | Line 791 | Network naming assumption in grep command | Use more flexible pattern matching |

### Enhancement Suggestions

| ID | Description | Priority |
|----|-------------|----------|
| E1 | Add `superadmin:supersecret123` from database.php.bak to credential tables | Low |
| E2 | Add macOS-specific troubleshooting section | Low |
| E3 | Include expected output examples for more commands | Low |
| E4 | Note intentional IP conflicts in DNS zone (educational value) | Low |

---

## Verification Summary

### Docker Configuration Cross-Reference

| Configuration File | Reviewed | Aligned with Documentation |
|--------------------|----------|---------------------------|
| docker-compose.yml | YES | YES |
| vsftpd.conf | YES | YES |
| smb.conf | YES | YES |
| main.cf (Postfix) | YES | YES |
| db.testlab.local (DNS zone) | YES | YES |
| 01-init.sql (MySQL) | YES | YES |
| robots.txt | YES | YES |
| database.php.bak | YES | PARTIAL (missing credential) |

### Security and Disclaimer Review

| Element | Present | Adequate |
|---------|---------|----------|
| Security warnings | YES | YES |
| Credential reuse warnings | YES | YES |
| Network isolation guidance | YES | YES |
| Educational purpose disclaimer | YES | YES |
| Production deployment warnings | YES | YES |

---

## Conclusion

The CPTC11 Docker Lab Environment Training Guide is a high-quality, professionally written document that accurately represents the Docker-based testing environment. The technical content is comprehensive and well-organized, with clear progression from foundational concepts through advanced attack scenarios.

**Strengths:**
- Comprehensive coverage of all services and configurations
- Accurate network topology and credential documentation
- Well-structured attack scenarios with realistic progression
- Professional writing with appropriate technical depth
- Effective troubleshooting guidance

**Areas for Improvement:**
- Minor credential documentation discrepancies should be verified
- Some command examples could benefit from clearer context specification
- Additional expected output examples would enhance usability

**Final Assessment:** The document meets professional quality standards and is suitable for deployment in a training curriculum. The minor issues identified do not significantly impact the document's usability or educational value.

---

**Validation Completed:** 2026-01-10
**Report Generated By:** QA Test Engineer
**Next Review Recommended:** Upon any changes to docker-compose.yml or service configurations
