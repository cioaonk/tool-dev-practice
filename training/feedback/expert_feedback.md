# Expert Security Review: CPTC Training Materials

**Reviewer:** Dr. Sam Rivera
**Credentials:** OSCP, OSCE, 8+ years senior penetration testing experience
**Role:** Red Team Lead, former CPTC competitor and mentor
**Date:** January 2026

---

## Executive Summary

After conducting a comprehensive review of the training materials in `/training/`, cross-referenced against the actual tool implementations in `/python/tools/`, threat intelligence in `/threat-intel/`, and YARA detection rules in `/yara/`, I must provide a mixed assessment.

**Overall Rating: 6.5/10**

The materials provide a solid foundation for beginners but fall significantly short of what CPTC competitors at the regional and national levels will face. Several critical gaps exist that could leave teams unprepared for modern defensive environments.

---

## Detailed Analysis

### 1. Technical Accuracy (7/10)

**Strengths:**
- The network scanning walkthrough accurately describes TCP connect scanning mechanics
- Payload generator documentation correctly explains reverse shell architecture
- EDR evasion concepts are technically accurate regarding user-mode hooks

**Critical Issues:**

1. **Syscall Numbers Are OS-Version Dependent**

   The training materials and `edr_evasion.py` hardcode syscall numbers:
   ```python
   "NtAllocateVirtualMemory": SyscallInfo(
       syscall_number_win10=0x18,
       syscall_number_win11=0x18,  # INCORRECT - Win11 varies by build
   ```

   **Reality:** Windows 11 syscall numbers differ across builds. The materials should teach dynamic syscall resolution (e.g., reading from ntdll on disk, Halo's Gate, Hell's Gate) rather than hardcoding values. In a real engagement or CPTC environment running a different Windows build, these hardcoded values will fail.

2. **ARP Scan Implementation is a Stub**

   The training promises ARP scanning but the code falls back to TCP:
   ```python
   def scan(self, ip: str, config: ScanConfig) -> ScanResult:
       # Note: Full ARP implementation requires raw sockets and elevated privileges
       # This is a placeholder that falls back to TCP scanning
       tcp_scan = TCPConnectScan()
   ```

   This is misleading. Students should know they need tools like `scapy` or `arping` for true ARP scanning.

3. **AMSI Bypass Techniques Are Outdated**

   The AMSI bypass techniques documented (`amsi_bypass.py`) are well-known signatures that Microsoft Defender and modern EDRs detect immediately:
   ```python
   $bypass_3 = "[Ref].Assembly.GetType" ascii wide
   ```

   Your own YARA rules in `evasion_techniques.yar` (lines 33-37) would catch every bypass technique your training teaches. This is a significant red flag.

---

### 2. OPSEC Considerations (5/10)

**What's Good:**
- The network scanner walkthrough does mention stealth considerations
- Planning mode (`--plan`) is a good OPSEC feature
- In-memory result storage is mentioned

**Critical Gaps:**

1. **No Network Traffic Fingerprinting Discussion**

   The materials never discuss how Python socket operations differ from legitimate traffic. Your `network_indicators.yar` rules would catch the tools' traffic patterns. Students need to understand:
   - User-Agent strings in HTTP requests
   - TCP window sizes and timing
   - TLS fingerprinting (JA3/JA4 hashes)
   - DNS query patterns

2. **No Process Ancestry Chain Coverage**

   EDRs heavily monitor parent-child process relationships. The training never addresses:
   - Why `python3.exe` spawning `cmd.exe` is suspicious
   - Process injection alternatives
   - Living-off-the-land binaries (LOLBins)

   Your `evasion_techniques.yar` has an entire `Evasion_Living_Off_The_Land` rule (lines 443-494) that students should study.

3. **Logging Artifacts Not Addressed**

   No mention of:
   - PowerShell ScriptBlock Logging (Event ID 4104)
   - Sysmon logging (Event IDs 1, 10, 11, etc.)
   - ETW providers that persist after ETW "bypass"
   - Command line logging in Windows Security logs

4. **Time-Based Detection Missing**

   Your `tool-detection.md` intelligence report mentions beaconing interval detection, but training materials never discuss:
   - Jitter implementation beyond simple delays
   - Avoiding predictable C2 patterns
   - Sleep patterns that evade behavioral analysis

---

### 3. Detection Avoidance (4/10)

**This is the weakest area of the training materials.**

**Critical Problems:**

1. **Obfuscation is Trivial**

   The payload generator's "obfuscation levels" are laughably weak:
   ```python
   if config.obfuscation_level >= 1:
       # Simple variable name obfuscation
       basic = basic.replace("socket", "__import__('socket').socket")
   ```

   Any security product would still detect this. Real obfuscation requires:
   - String encryption with runtime decryption
   - Control flow flattening
   - Dead code insertion
   - Metamorphic code generation

2. **Shellcode Encoders Use Known Signatures**

   Your `shellcode_encoder.py` generates XOR stubs that your own YARA rules detect:
   ```yara
   // From shellcode_patterns.yar, line 219
   $decoder_1 = { EB ?? 5? 31 C9 B1 ?? 80 ?? ?? ?? ?? E2 }
   ```

   The training should emphasize that shikata_ga_nai and similar encoders have been signature-based detected since 2015.

3. **No Memory Scanner Evasion**

   Modern EDRs scan process memory. The training mentions sleep encryption conceptually but:
   - No actual implementation guidance
   - No heap/stack encryption techniques
   - No discussion of gargoyle-style ROP sleep
   - No coverage of memory permission management

4. **Direct Syscalls Are Not Enough**

   The materials present direct syscalls as a silver bullet. Reality check from your own training:

   > "Kernel-mode telemetry still applies. ETW (Event Tracing for Windows) and kernel callbacks can still detect activity."

   Yet no alternatives or layered approaches are taught.

---

### 4. Real-World Applicability (6/10)

**Concerns for Actual Engagements:**

1. **Tool Dependencies Not Realistic**

   The tools assume Python is available on target systems. In reality:
   - Corporate Windows environments rarely have Python
   - Linux servers may have restricted Python versions
   - Compiled payloads are more operational

   **Recommendation:** Add compiled payload generation, or at minimum, discuss PyInstaller/py2exe for Windows operations.

2. **No Staged Payload Discussion**

   Real engagements use staged payloads to minimize initial footprint. The training only shows full payloads delivered at once.

3. **Missing Common Protocols**

   No coverage of:
   - DNS exfiltration/C2
   - ICMP tunneling
   - HTTP/S C2 with domain fronting
   - SMB named pipe communication

4. **Credential Attack Tools Are Basic**

   Your `threat-intel/tool-detection.md` extensively covers Mimikatz, Responder, and Hashcat detection. The training tools don't prepare students for:
   - DPAPI credential extraction
   - LSA secrets dumping
   - Kerberoasting/AS-REP roasting
   - Pass-the-hash/Pass-the-ticket

---

### 5. Missing Advanced Topics (Critical for CPTC)

**Topics completely absent that national-level CPTC teams need:**

1. **Active Directory Attacks**
   - No BloodHound/SharpHound coverage
   - No AD privilege escalation paths
   - No Group Policy abuse
   - No delegation attacks (constrained/unconstrained)
   - No certificate services (AD CS) attacks

2. **Cloud and Container Security**
   - Your `threat-intel/docker-container-threats.md` and `cptc-intel.md` suggest container environments are expected
   - Zero training on container escape techniques
   - No Kubernetes security testing
   - No cloud metadata service exploitation (169.254.169.254)

3. **Web Application Testing**
   - The `web-directory-enumerator` tool exists but no training
   - No SQL injection techniques
   - No deserialization attacks
   - No SSRF/CSRF coverage
   - No API security testing

4. **Wireless and Network Protocol Attacks**
   - No LLMNR/NBT-NS poisoning (your Responder detection shows this is expected)
   - No ARP spoofing/MitM attacks
   - No 802.1x bypass techniques

5. **Forensics Awareness**
   - Students need to understand what artifacts they leave
   - Windows Prefetch, SRUM, Amcache
   - Registry artifacts
   - Event log entries
   - Memory forensics traces

---

### 6. Comparison to Professional Training

**vs. SANS SEC560/SEC660:**
- SANS provides hands-on labs with enterprise-grade defenses
- Your materials lack defensive interaction scenarios
- SANS teaches defense-aware offense; your materials teach offense in isolation

**vs. Offensive Security (PWK/OSCP):**
- OffSec requires students to enumerate and adapt
- Your step-by-step walkthroughs may create "script kiddie" mentality
- OffSec teaches persistence and pivoting extensively

**vs. Zero-Point Security (CRTO):**
- CRTO focuses entirely on EDR evasion with modern techniques
- Your EDR training is conceptual, not operational
- CRTO includes Cobalt Strike malleable profiles; you have no C2 framework training

**Recommendation:** These materials are appropriate for absolute beginners (1-2 years experience), but CPTC competitors need intermediate-to-advanced content.

---

## Specific File-by-File Feedback

### `/training/walkthroughs/network-scanner-walkthrough.md`

**Positives:**
- Good conceptual foundation
- Clear TCP handshake diagrams
- Useful troubleshooting section

**Issues:**
- Page 19 claims ARP is "fastest" but implementation doesn't work
- No mention of IDS/IPS signatures for scan patterns
- Stealth scanning section is too simplistic (2-10 second delays aren't stealthy for serious environments)

**Add:**
- Nmap NSE script equivalent functionality
- Integration with other recon tools (not just this toolkit)
- Real-world case studies of scan detection

### `/training/walkthroughs/payload-generator-walkthrough.md`

**Positives:**
- Clear shell type comparison
- Good detection vector documentation
- Useful encoding explanation

**Issues:**
- PowerShell payloads will be caught by AMSI without the bypass
- No discussion of AV sandbox detection
- Obfuscation examples are inadequate

**Add:**
- Staged payload concepts
- Custom shellcode development basics
- Living-off-the-land payload alternatives
- Payload testing against VirusTotal (and why not to use it)

### `/training/walkthroughs/edr-evasion-walkthrough.md`

**Positives:**
- Best technical depth of the three walkthroughs
- Good hook explanation with diagrams
- Acknowledges kernel-level limitations

**Issues:**
- Syscall numbers will be wrong on many targets
- AMSI bypass section is outdated
- No discussion of EDR-specific behaviors (each EDR is different)

**Add:**
- Dynamic syscall resolution techniques
- EDR vendor-specific quirks (CrowdStrike vs. Defender vs. SentinelOne)
- Call stack spoofing techniques
- Indirect syscalls
- Hardware breakpoint abuse

### `/training/labs/lab-01-network-reconnaissance.md`

**Positives:**
- Good progressive difficulty structure
- Realistic scenario framing
- Useful documentation templates

**Issues:**
- Lab environment (10.10.10.0/24) is unrealistically clean
- No simulated IDS/IPS to avoid
- No requirement to evade detection

**Add:**
- Blue team simulation (have students' scans detected and logged)
- Requirement to achieve objectives without triggering X alerts
- Competitive element (first to find all hosts without detection wins)

---

## Recommendations

### Immediate (Before Competition)

1. **Update syscall handling** - Implement dynamic syscall resolution or document limitations clearly
2. **Add AMSI bypass testing** - Your bypasses should be tested against current Windows Defender
3. **Cross-reference with YARA rules** - Have students run their payloads against your own detection rules as a validation exercise

### Short-Term (1-2 Months)

1. **Add Active Directory module** - Critical for any enterprise environment
2. **Create container security training** - Based on your existing threat intel
3. **Develop EDR lab** - Students need hands-on EDR evasion practice
4. **Add web application module** - CPTC consistently includes web apps

### Long-Term

1. **Develop adversary simulation framework** - Move beyond individual tools to coordinated attack chains
2. **Create purple team exercises** - Integrate with detection engineering
3. **Build CTF-style challenges** - Gamify the learning for engagement

---

## Anti-Pattern Alert

**Security Anti-Patterns Found in Materials:**

1. **Hardcoded credentials in examples** - Bad habit formation
2. **No input validation in tools** - Vulnerable to injection themselves
3. **Plaintext storage of results** - JSON output files are forensic evidence
4. **No cleanup procedures** - Students not taught to remove artifacts
5. **Over-reliance on Python** - Not operationally viable in many environments

---

## Final Assessment

These training materials provide a reasonable introduction to offensive security concepts but are **insufficient for competitive CPTC performance**. The gap between what's taught and what modern blue teams detect is significant.

**Key Deficiency:** The materials teach "how to use tools" rather than "how to think like an attacker." CPTC judges look for methodology, creativity, and adaptation - not tool proficiency.

**My Recommendation:**
- Use these materials for team members with less than 1 year experience
- Supplement with external resources for intermediate/advanced members
- Most importantly, test everything against your own detection capabilities before competition

The threat intelligence and YARA rules in this repository are actually more valuable than the training materials themselves. Have students study the detection side to understand what they're up against.

---

**Dr. Sam Rivera**
*"The best offense understands the defense."*

---

## Appendix: Quick Reference - What to Study Beyond This Material

| Topic | Resource |
|-------|----------|
| Modern EDR Evasion | MDSec blog, Zero-Point Security |
| Active Directory | SpecterOps, Harmj0y's blog |
| Container Security | Kubernetes Goat, OWASP Docker Guide |
| Web Application | PortSwigger Web Academy |
| Shellcode Development | Sektor7 courses |
| Red Team Ops | Cobalt Strike documentation, Outflank blog |

---

*This review was conducted in good faith to improve team preparedness. All criticisms are actionable and intended to strengthen the training program.*
