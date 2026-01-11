# YARA Detection Engineering Training

## Module Overview

**Training Module:** YARA Detection Engineering
**Duration:** 8-10 hours (self-paced)
**Skill Level:** Intermediate to Advanced
**Prerequisites:** Basic understanding of malware concepts, familiarity with hex editors, command-line proficiency

### Learning Objectives

Upon completion of this module, participants will be able to:

1. Understand YARA's architecture and role in threat detection
2. Write effective YARA rules using strings, conditions, and metadata
3. Analyze and interpret the CPTC11 detection rule set
4. Use the YARA scanner tool for file, directory, and process scanning
5. Develop detection rules following industry best practices
6. Optimize rules for performance and accuracy

---

## Section 1: Introduction to YARA

### 1.1 What is YARA and Why It Matters

YARA (Yet Another Recursive Acronym, or "Yet Another Ridiculous Acronym" depending on who you ask) is a pattern-matching tool designed primarily for malware identification and classification. Created by Victor Alvarez of VirusTotal, YARA has become the de facto standard for threat researchers, incident responders, and security operations teams worldwide. Its power lies in its simplicity: YARA allows you to create descriptions of malware families based on textual or binary patterns, then scan files, memory, or processes to find matches.

At its core, YARA operates on a simple premise: malware, despite its authors' best obfuscation efforts, contains identifiable patterns. These patterns might be unique strings embedded in the binary, specific sequences of bytes that represent distinctive functionality, or structural characteristics that betray the malware's origin or purpose. YARA provides a flexible, expressive language for describing these patterns and a high-performance engine for detecting them across large datasets.

The importance of YARA in modern security operations cannot be overstated. Consider a scenario where your threat intelligence team identifies a new malware family targeting your industry. Within hours, they can develop YARA rules capturing the malware's distinctive characteristics. These rules can then be deployed across your endpoint detection systems, email gateways, and file scanning infrastructure, providing immediate protection while traditional signature-based antivirus vendors work to update their databases. This agility transforms threat intelligence from a reactive report into an active defense mechanism.

YARA's adoption spans the entire security ecosystem. Major antivirus vendors incorporate YARA rules into their detection engines. Security Information and Event Management (SIEM) platforms use YARA for log and artifact analysis. Digital forensics tools leverage YARA for evidence triage. Malware sandboxes employ YARA to classify submitted samples. The Common Vulnerability Scoring System (CVSS) and MITRE ATT&CK framework communities share YARA rules as part of threat intelligence exchanges. Understanding YARA is therefore essential for any security professional involved in threat detection, incident response, or malware analysis.

Beyond detection, YARA serves as a common language for describing threats. When a researcher publishes YARA rules alongside their malware analysis, other practitioners can immediately operationalize that research. This standardization accelerates the security community's collective response to emerging threats and enables organizations of all sizes to benefit from world-class threat research.

### 1.2 YARA in Offensive vs Defensive Contexts

Understanding YARA from both offensive and defensive perspectives provides crucial insights for security practitioners.

**Defensive Applications:**

From a defensive standpoint, YARA is primarily a detection and classification tool. Security teams deploy YARA rules to identify known malware, detect suspicious patterns in files and memory, and classify threats for prioritized response. Defensive YARA usage includes:

- **Endpoint Detection:** Scanning files as they enter the environment
- **Memory Forensics:** Identifying malicious code in process memory
- **Threat Hunting:** Proactively searching for indicators of compromise
- **Incident Response:** Rapidly triaging systems for known threats
- **Malware Classification:** Organizing samples by family, actor, or capability

The defensive practitioner aims to write rules that are both comprehensive (catching all variants of a threat) and precise (avoiding false positives that waste analyst time). They must balance detection coverage against performance impact, especially when rules run on production systems.

**Offensive Awareness:**

From an offensive perspective, YARA represents one of many detection mechanisms that must be evaded. Red team operators and penetration testers benefit from understanding YARA for several reasons:

- **Evasion Testing:** Understanding how payloads might be detected
- **Rule Analysis:** Examining defensive rules to identify coverage gaps
- **Payload Development:** Designing tools that avoid common signatures
- **Detection Validation:** Testing whether defenses catch simulated attacks

Offensive practitioners study YARA rules to understand what patterns defenders are looking for. This knowledge informs payload development decisions: avoiding hardcoded strings that appear in public rules, varying encoding schemes, and structuring tools to evade pattern matching.

**The Detection Arms Race:**

YARA exists within a continuous cycle of detection and evasion. Defenders create rules to detect malicious patterns; attackers modify their tools to evade those rules; defenders update their rules or develop new detection approaches; and the cycle continues. This dynamic means that static YARA rules have a shelf life. Yesterday's high-confidence detection rule may be useless against today's variant if the attacker has adapted.

Effective detection engineering recognizes this reality. Rules should target fundamental characteristics that are difficult for attackers to change without breaking functionality, rather than superficial patterns that are trivially modified. Understanding the offensive perspective helps defenders write more resilient rules.

### 1.3 Rule Syntax Fundamentals

A YARA rule consists of three primary sections: metadata (meta), string definitions (strings), and conditions (condition). Understanding each section is essential for writing effective rules.

**Basic Rule Structure:**

```
rule Rule_Name {
    meta:
        author = "Your Name"
        description = "What this rule detects"
        date = "2026-01-10"

    strings:
        $string1 = "suspicious text"
        $hex_pattern = { 4D 5A 90 00 }
        $regex = /pattern[0-9]+/

    condition:
        any of them
}
```

**Rule Naming Conventions:**

Rule names must be identifiers: they start with a letter or underscore and contain only alphanumeric characters and underscores. Best practices include:

- Use descriptive, hierarchical names: `Malware_Family_Variant`
- Include category prefixes: `Trojan_`, `Ransomware_`, `Tool_`
- Avoid spaces and special characters
- Keep names concise but informative

**The Meta Section:**

Metadata provides context about the rule but does not affect matching. Common metadata fields include:

```
meta:
    author = "Detection Engineering Team"
    description = "Detects XYZ malware family"
    date = "2026-01-10"
    version = "1.0"
    reference = "https://example.com/analysis"
    tlp = "amber"              // Traffic Light Protocol classification
    confidence = "high"        // Rule confidence level
    severity = "critical"      // Threat severity
    category = "payload"       // Rule category
    hash = "abc123..."         // Sample hash reference
```

**String Definitions:**

YARA supports three types of string patterns:

1. **Text Strings:** Plain ASCII or Unicode text
   ```
   $text = "malicious string"
   $wide = "unicode" wide       // UTF-16 encoding
   $nocase = "CaSe InSeNsItIvE" nocase
   $both = "both" ascii wide    // Match either encoding
   ```

2. **Hexadecimal Strings:** Raw byte patterns
   ```
   $hex = { 4D 5A 90 00 }              // Exact bytes
   $wildcard = { 4D 5A ?? 00 }          // Single byte wildcard
   $jump = { 4D 5A [2-4] 00 }           // Variable length jump
   $alternatives = { 4D ( 5A | 5B ) }   // Byte alternatives
   ```

3. **Regular Expressions:** Pattern matching with regex
   ```
   $regex = /http:\/\/[a-z]+\.com/
   $regex_nocase = /pattern/i           // Case insensitive
   $regex_wide = /pattern/s             // Single-line mode
   ```

**Conditions:**

Conditions define the logic for when a rule matches. They support:

- Boolean operators: `and`, `or`, `not`
- Comparison operators: `==`, `!=`, `<`, `>`, `<=`, `>=`
- String counting: `#string_name` (count of matches)
- String offsets: `@string_name[1]` (offset of first match)
- File properties: `filesize`, `entrypoint`
- Special functions: `uint16()`, `uint32()` for reading file bytes

```
condition:
    // At least 2 of the defined strings
    2 of ($string*)

    // All strings from a set
    all of ($important_*)

    // File starts with MZ header
    uint16(0) == 0x5A4D

    // Size constraints
    filesize < 1MB
```

---

## Section 2: CPTC11 YARA Rules Deep Dive

The CPTC11 rule set provides comprehensive detection coverage across five categories. This section analyzes each rule file in detail, explaining the detection logic and operational significance.

### 2.1 Payload Signatures (payload_signatures.yar)

This rule file focuses on detecting common payload types used in offensive operations, from Metasploit Meterpreter to custom webshells.

**Meterpreter Detection Strategy:**

The `Meterpreter_Reverse_TCP_Staged` rule demonstrates multi-layered detection:

```
rule Meterpreter_Reverse_TCP_Staged {
    strings:
        $metsrv = "metsrv" ascii wide nocase
        $reflective_1 = "ReflectiveLoader" ascii wide
        $reflective_2 = { 4D 5A ?? ?? ... 50 45 00 00 }
        $stdapi = "stdapi" ascii wide
        $socket_pattern = { 6A 00 6A 01 6A 02 FF 15 }

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        filesize < 5MB and
        (
            ($metsrv or $met_dll) or
            (2 of ($met_*, $stdapi, $priv, $migrate)) or
            ($reflective_1 and $reflective_2)
        )
}
```

**Key Detection Elements:**
- **Module names:** `metsrv`, `stdapi`, `priv` are Meterpreter extension names
- **Reflective loading:** The `ReflectiveLoader` export combined with PE header pattern
- **Socket initialization:** The hex pattern `6A 00 6A 01 6A 02` represents `push 0, push 1, push 2` for socket creation (AF_INET, SOCK_STREAM)

**Cobalt Strike Beacon Detection:**

```
rule Cobalt_Strike_Beacon {
    strings:
        $beacon_config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $sleep_mask = { 48 8B ?? 48 31 ?? 48 31 ?? 48 8B }
        $str_1 = "%s (admin)" ascii wide
        $pipe_1 = "\\\\.\\pipe\\" ascii wide
        $pipe_2 = "MSSE-" ascii wide
```

**Analysis Points:**
- The beacon configuration block has a distinctive structure
- Sleep mask routines use specific XOR patterns for obfuscation
- Named pipe patterns like `MSSE-` are default Cobalt Strike indicators
- Admin format string `%s (admin)` appears in beacon console output

**Webshell Detection:**

The `Webshell_Generic` rule targets PHP, ASP, and JSP webshells:

```
strings:
    $php_exec_1 = "eval(" ascii nocase
    $php_exec_2 = "system(" ascii nocase
    $php_exec_3 = "shell_exec(" ascii nocase
    $param_1 = "$_GET" ascii
    $param_2 = "$_POST" ascii
    $decode_1 = "base64_decode" ascii nocase

condition:
    ($php_1 and any of ($php_exec_*) and any of ($param_*))
```

**Detection Logic:**
- Combines dangerous functions (`eval`, `system`, `shell_exec`) with user input (`$_GET`, `$_POST`)
- Looks for encoding functions often used to obfuscate webshell code
- Low filesize threshold reduces false positives on legitimate applications

### 2.2 Shellcode Patterns (shellcode_patterns.yar)

Shellcode detection requires identifying both raw assembly patterns and encoding schemes.

**Windows x86 Reverse Shell Shellcode:**

```
rule Shellcode_Windows_x86_Reverse_Shell {
    strings:
        $api_wsastartup = { 68 33 32 00 00 68 77 73 32 5F }  // push 'ws2_32'
        $socket_create = { 6A 00 6A 01 6A 02 }               // socket params
        $peb_access = { 64 A1 30 00 00 00 }                  // fs:[0x30]
        $cmd_2 = { 63 6D 64 2E 65 78 65 }                    // 'cmd.exe'
```

**Technical Breakdown:**
- `68 33 32 00 00 68 77 73 32 5F` pushes the string "ws2_32" for Winsock loading
- `64 A1 30 00 00 00` accesses the Process Environment Block (PEB) via the FS segment register
- PEB access is the foundation for API resolution without import tables

**XOR Encoded Shellcode:**

```
rule Shellcode_Encoded_XOR {
    strings:
        $decoder_1 = { EB ?? 5? 31 C9 B1 ?? 80 ?? ?? ?? ?? E2 }
        $decoder_3 = { D9 74 24 F4 5? 29 C9 B1 ?? 31 }
        $getpc_call = { E8 00 00 00 00 }
        $getpc_fpu = { D9 EE D9 74 24 F4 }
```

**Decoder Stub Analysis:**
- `EB ?? 5?` is the classic jmp-call-pop GetPC technique
- `D9 74 24 F4` is `fnstenv [esp-0xc]` for FPU-based GetPC
- `E8 00 00 00 00` calls the next instruction, pushing EIP to stack

**Shikata Ga Nai Detection:**

The Metasploit polymorphic encoder has identifiable patterns despite its randomization:

```
rule Shellcode_Metasploit_Shikata {
    strings:
        $shikata_1 = { D9 74 24 F4 5? 29 C9 B1 ?? 31 ?? 17 83 ?? 04 03 }
        $fpu_1 = { D9 74 24 F4 }  // fnstenv
        $fpu_2 = { D9 EE }        // fldz
```

The FPU instructions are required for the encoder's GetPC mechanism, making them reliable detection points.

### 2.3 Tool Artifacts (tool_artifacts.yar)

Detecting offensive tools by their artifacts, strings, and behavioral patterns.

**Mimikatz Detection:**

```
rule Tool_Mimikatz_Strings {
    strings:
        $banner_1 = "mimikatz" ascii wide nocase
        $banner_2 = "gentilkiwi" ascii wide
        $cmd_1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd_4 = "lsadump::dcsync" ascii wide nocase
        $str_1 = "* Username : " ascii wide
        $str_4 = "* NTLM     : " ascii wide
```

**Detection Layers:**
1. **Banner strings:** Author and tool names
2. **Command strings:** Module commands reveal capability
3. **Output strings:** The formatted output is distinctive
4. **Binary patterns:** Internal function naming conventions (`kuhl_m_`, `kull_m_`)

**BloodHound/SharpHound Detection:**

```
rule Tool_BloodHound_Collector {
    strings:
        $collect_1 = "CollectionMethods" ascii wide
        $output_1 = "_BloodHound.zip" ascii wide nocase
        $ldap_1 = "(&(objectCategory=person)(objectClass=user))"
```

**Key Indicators:**
- Configuration options like `CollectionMethods`, `SessionCollection`
- Output filenames following BloodHound naming conventions
- LDAP query patterns used for Active Directory enumeration

**Impacket Detection:**

```
rule Tool_Impacket_Strings {
    strings:
        $lib_1 = "impacket" ascii
        $tool_1 = "secretsdump" ascii nocase
        $proto_1 = "SMBConnection" ascii
        $proto_4 = "DRSUAPI" ascii
```

The DRSUAPI string is particularly significant as it indicates DCSync capability.

### 2.4 Network Indicators (network_indicators.yar)

Network-focused rules detect C2 communication patterns, tunneling, and lateral movement.

**C2 Beacon Patterns:**

```
rule Network_C2_Beacon_Pattern {
    strings:
        $checkin_1 = "checkin" ascii wide nocase
        $checkin_3 = "heartbeat" ascii wide nocase
        $task_1 = "gettask" ascii wide nocase
        $sleep_1 = "sleeptime" ascii wide nocase
        $session_1 = /session[_-]?id/i ascii wide
```

**Behavioral Indicators:**
- Check-in and heartbeat terminology
- Task retrieval patterns
- Sleep/jitter configuration (indicates beacon behavior)
- Session identifier patterns

**DNS Tunneling Detection:**

```
rule Network_DNS_Tunneling_Indicators {
    strings:
        $tool_1 = "dnscat" ascii wide nocase
        $tool_2 = "iodine" ascii wide nocase
        $encode_1 = /[a-z0-9]{50,}\.(com|net|org|info)/i
```

**Detection Strategy:**
- Known tool names (dnscat, iodine, dns2tcp)
- Unusually long subdomain labels (encoded data)
- DNS library usage combined with suspicious patterns

**SMB Lateral Movement:**

```
rule Network_SMB_Lateral_Movement {
    strings:
        $smb_2 = "\\C$" ascii wide
        $smb_3 = "\\ADMIN$" ascii wide
        $psexec_1 = "PSEXESVC" ascii wide
        $wmi_1 = "Win32_Process" ascii wide
```

Administrative share access combined with remote execution indicators.

### 2.5 Evasion Techniques (evasion_techniques.yar)

Rules targeting defense evasion methods used by advanced attackers.

**AMSI Bypass Detection:**

```
rule Evasion_AMSI_Bypass {
    strings:
        $amsi_2 = "AmsiScanBuffer" ascii wide
        $ps_bypass_1 = "System.Management.Automation.AmsiUtils"
        $patch_1 = { B8 57 00 07 80 C3 }  // mov eax, E_INVALIDARG; ret
        $obf_2 = "'am'+'si'" ascii wide nocase
```

**Bypass Indicators:**
- Direct AMSI function references
- PowerShell reflection to access AMSI internals
- Patch patterns that return error codes
- String concatenation obfuscation of "amsi"

**Process Hollowing Detection:**

```
rule Evasion_Process_Hollowing {
    strings:
        $api_1 = "NtUnmapViewOfSection" ascii wide
        $api_3 = "NtSetContextThread" ascii wide
        $api_8 = "WriteProcessMemory" ascii wide
        $suspended_1 = "CREATE_SUSPENDED" ascii wide
```

**Technique Sequence:**
1. Create process in suspended state
2. Unmap the legitimate image
3. Write malicious code
4. Set thread context to new entry point
5. Resume execution

**UAC Bypass Detection:**

```
rule Evasion_UAC_Bypass {
    strings:
        $autoelevate_1 = "fodhelper" ascii wide nocase
        $autoelevate_3 = "sdclt" ascii wide nocase
        $reg_1 = "Software\\Classes\\ms-settings"
        $reg_4 = "shell\\open\\command" ascii wide
```

Combines auto-elevating binaries with registry hijacking techniques.

---

## Section 3: Writing Effective YARA Rules

### 3.1 Meta Section Best Practices

Well-structured metadata improves rule maintainability and operational utility.

**Essential Metadata Fields:**

```
meta:
    // Identification
    author = "Your Name / Team"
    description = "Clear, concise description of what this rule detects"
    date = "2026-01-10"
    version = "1.0"

    // References
    reference = "https://link-to-analysis.com"
    hash = "sha256:abc123..."  // Reference sample

    // Classification
    tlp = "amber"              // TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED
    confidence = "high"        // low, medium, high
    severity = "critical"      // low, medium, high, critical
    category = "payload"       // payload, shellcode, tool, network, evasion

    // MITRE ATT&CK
    mitre_attack = "T1055.012"
    mitre_tactic = "Defense Evasion"
```

**Documentation Standards:**

1. **Descriptions should be actionable:** "Detects Cobalt Strike beacon shellcode" not "Suspicious file"
2. **Include context:** Why does this pattern matter? What threat does it represent?
3. **Version tracking:** Update version and date when modifying rules
4. **Reference samples:** Include hashes of known-matching samples for validation

### 3.2 String Definitions: Text, Hex, and Regex

**Text String Optimization:**

```
// Good: Specific, unique strings
$specific = "sekurlsa::logonpasswords" ascii wide nocase

// Bad: Common strings with high FP rate
$generic = "password" ascii  // Will match legitimate software

// Modifiers for coverage
$comprehensive = "meterpreter" ascii wide nocase fullword
```

**Hexadecimal Pattern Design:**

```
// Exact match for specific functionality
$exact = { 64 A1 30 00 00 00 }  // PEB access (mov eax, fs:[0x30])

// Wildcards for variable portions
$flexible = { 64 A1 30 00 00 00 8B ?? 0C }  // Account for register variation

// Jump ranges for variable-length code
$jump = { 68 ?? ?? ?? ?? [0-10] FF 15 }  // push addr, optional code, call [addr]

// Alternatives for compiler variations
$alternatives = { ( 6A 00 | 68 00 00 00 00 ) }  // push 0 (1-byte or 5-byte)
```

**Regular Expression Guidelines:**

```
// Anchored patterns for performance
$anchored = /^MZ/  // Match at start

// Character classes over alternation
$efficient = /[a-f0-9]{32}/  // Better than (a|b|c|d|e|f|0|1|...)

// Avoid catastrophic backtracking
$safe = /[A-Za-z0-9+\/]{50,100}/  // Bounded quantifier
$dangerous = /.*pattern.*/       // Avoid .* when possible

// Practical examples
$ip_port = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/
$base64_blob = /[A-Za-z0-9+\/]{100,}={0,2}/
```

### 3.3 Conditions and Logic

**Basic Condition Patterns:**

```
condition:
    // Any string matches
    any of them

    // All strings must match
    all of them

    // Specific count
    2 of ($string*)
    3 of ($important_1, $important_2, $important_3)

    // Percentage
    50% of them
```

**File Property Conditions:**

```
condition:
    // PE file check
    uint16(0) == 0x5A4D

    // ELF file check
    uint32(0) == 0x464c457f

    // File size constraints
    filesize < 1MB
    filesize > 100 and filesize < 500KB

    // PE entry point (requires PE module)
    pe.entry_point == 0x1000
```

**Complex Logic Examples:**

```
condition:
    // Layered detection
    uint16(0) == 0x5A4D and                    // Must be PE
    filesize < 5MB and                          // Size constraint
    (
        (all of ($critical_*)) or               // All critical strings
        (2 of ($suspicious_*) and $unique) or   // Combination
        ($rare_pattern)                         // Single high-confidence
    )

    // Negation for excluding FPs
    any of them and not $legitimate_software

    // Position-based matching
    $header at 0 and $payload in (100..filesize)
```

### 3.4 Performance Optimization

**String Selection Impact:**

```
// SLOW: Generic patterns
$slow = /./          // Matches everything
$slow2 = { ?? ?? }   // Two-byte wildcard matches everywhere

// FAST: Specific patterns
$fast = "UniqueStringInMalware"
$fast2 = { 4D 5A 90 00 03 00 00 00 }  // Specific byte sequence

// Rule of thumb: Lead with specific strings
strings:
    $anchor = "SpecificUnique"   // Fast anchor
    $variable = { ?? ?? 90 00 }  // Variable pattern

condition:
    $anchor and $variable  // Anchor evaluated first
```

**Condition Ordering:**

```
condition:
    // Fast checks first (short-circuit evaluation)
    filesize < 1MB and          // Instant check
    uint16(0) == 0x5A4D and     // Single read
    any of ($strings*)          // String matching last
```

**Module Usage Considerations:**

```
import "pe"
import "math"

condition:
    // PE module adds overhead - use judiciously
    pe.number_of_sections > 3 and
    pe.imports("kernel32.dll", "VirtualAlloc")

    // Math entropy is expensive
    math.entropy(0, filesize) > 7.5
```

### 3.5 Reducing False Positives

**Contextual Constraints:**

```
// Add file type requirements
condition:
    uint16(0) == 0x5A4D and  // Only PE files
    any of them

// Size bounds
condition:
    filesize > 1KB and filesize < 10MB and  // Reasonable malware sizes
    any of them

// Require multiple indicators
condition:
    2 of ($suspicious_*) and  // Single string insufficient
    any of ($confirming_*)    // Need corroboration
```

**Exclusion Patterns:**

```
strings:
    $malicious = "suspicious_function"
    $legitimate_1 = "Microsoft Corporation"
    $legitimate_2 = "Signed by: Symantec"

condition:
    $malicious and
    not any of ($legitimate_*)
```

**Testing Methodology:**

```
ASCII Diagram: False Positive Testing Workflow

+-------------------+     +--------------------+     +-------------------+
|   Write Rule      | --> | Test Against Known | --> | Test Against      |
|                   |     |    Malware Set     |     |   Clean Set       |
+-------------------+     +--------------------+     +-------------------+
         ^                         |                         |
         |                         v                         v
         |                +----------------+         +----------------+
         |                | Detection Rate |         | False Positive |
         |                |    > 95%?      |         |    Rate < 1%?  |
         |                +----------------+         +----------------+
         |                         |                         |
         |         No              |             No          |
         +-------------------------+-------------------------+
                                   | Yes (both)
                                   v
                          +----------------+
                          |  Deploy Rule   |
                          +----------------+
```

---

## Section 4: YARA Scanner Tool Usage

The CPTC11 YARA scanner (`yara_scanner.py`) provides a comprehensive Python wrapper for YARA scanning operations.

### 4.1 CLI Reference

**Basic Syntax:**

```
python yara_scanner.py [OPTIONS] --file|--directory|--process|--plan TARGET
```

**Command Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--file` | `-f` | Scan a single file |
| `--directory` | `-d` | Scan a directory |
| `--process` | `-p` | Scan process memory (requires root/admin) |
| `--plan` | | Show scan plan without executing |
| `--rules` | `-r` | Custom rules path (default: ./rules) |
| `--recursive` | | Scan subdirectories (default: true) |
| `--no-recursive` | | Don't scan subdirectories |
| `--format` | | Output format: json, text, csv |
| `--output` | `-o` | Write output to file |
| `--quiet` | `-q` | Suppress banner and info messages |
| `--verbose` | `-v` | Show all matched strings |

### 4.2 File vs Directory vs Memory Scanning

**Single File Scanning:**

```bash
# Basic file scan with text output
python yara_scanner.py --file /path/to/suspicious.exe

# JSON output for integration
python yara_scanner.py -f sample.exe --format json -o results.json

# With custom rules
python yara_scanner.py -f malware.bin -r /custom/rules/
```

**Directory Scanning:**

```bash
# Recursive scan (default)
python yara_scanner.py --directory /path/to/samples/

# Non-recursive scan
python yara_scanner.py -d /downloads/ --no-recursive

# Large-scale scanning with CSV output
python yara_scanner.py -d /malware_zoo/ --format csv -o scan_results.csv
```

**Process Memory Scanning:**

```bash
# Scan specific process (requires elevated privileges)
sudo python yara_scanner.py --process 1234

# Example output
[*] Scanning process: 1234
[MATCH] Meterpreter_Reverse_HTTPS
  Namespace: payload_signatures
  File: pid:1234
```

**Note:** Process scanning requires:
- Root/Administrator privileges
- Target process must be accessible
- yara-python compiled with process scanning support

### 4.3 Output Formats

**Text Format (Default):**

```
============================================================
YARA SCAN REPORT
============================================================
Scan Time: 2026-01-10T14:30:00
Rules Loaded: 5
Scan Mode: file
Total Files Scanned: 1
Files with Matches: 1
Total Matches: 2

------------------------------------------------------------
MATCHES
------------------------------------------------------------

[MATCH] Cobalt_Strike_Beacon
  Namespace: payload_signatures
  File: /samples/beacon.exe
  Hash: a1b2c3d4e5...
  Size: 287744 bytes
  Metadata:
    author: Detection Engineering Team
    severity: critical
    confidence: high
  Matched Strings:
    0x00001234: $beacon_config = 00010001000200...
    0x00002000: $str_1 = %s (admin)

============================================================
```

**JSON Format:**

```json
{
  "scan_time": "2026-01-10T14:30:00",
  "total_files": 1,
  "files_with_matches": 1,
  "total_matches": 2,
  "rules_loaded": 5,
  "scan_mode": "file",
  "matches": [
    {
      "rule": "Cobalt_Strike_Beacon",
      "namespace": "payload_signatures",
      "file_path": "/samples/beacon.exe",
      "file_hash": "a1b2c3d4e5...",
      "file_size": 287744,
      "meta": {
        "severity": "critical",
        "confidence": "high"
      },
      "strings": [...]
    }
  ],
  "errors": []
}
```

**CSV Format:**

```
rule,namespace,file_path,file_hash,severity,confidence,timestamp
Cobalt_Strike_Beacon,payload_signatures,/samples/beacon.exe,a1b2c3...,critical,high,2026-01-10T14:30:00
Tool_Mimikatz_Strings,tool_artifacts,/samples/mimi.exe,b2c3d4...,critical,high,2026-01-10T14:30:01
```

### 4.4 Planning Mode

The `--plan` flag shows what would be scanned without executing:

```bash
python yara_scanner.py --plan
```

**Output:**

```json
{
  "action": "YARA Scan Plan",
  "timestamp": "2026-01-10T14:30:00",
  "rules_directory": "/path/to/rules",
  "rules_files": [
    "/path/to/rules/payload_signatures.yar",
    "/path/to/rules/shellcode_patterns.yar",
    "/path/to/rules/tool_artifacts.yar",
    "/path/to/rules/network_indicators.yar",
    "/path/to/rules/evasion_techniques.yar"
  ],
  "total_rules_estimated": 45,
  "capabilities": [
    "File scanning with pattern matching",
    "Directory recursive scanning",
    "Process memory scanning (requires elevated privileges)",
    "Raw data/bytes scanning",
    "Multiple output formats (JSON, CSV, TEXT)"
  ],
  "rule_categories": [
    "payload_signatures",
    "shellcode_patterns",
    "tool_artifacts",
    "network_indicators",
    "evasion_techniques"
  ]
}
```

### 4.5 Integration Examples

**Automation Script:**

```bash
#!/bin/bash
# Automated malware scanning pipeline

SAMPLES_DIR="/incoming/samples"
RESULTS_DIR="/analysis/yara_results"
SCANNER="/opt/cptc11/yara/yara_scanner.py"

# Scan new samples
for sample in "$SAMPLES_DIR"/*; do
    filename=$(basename "$sample")
    python "$SCANNER" -f "$sample" --format json \
        -o "$RESULTS_DIR/${filename}.json" -q

    # Check exit code (2 = matches found)
    if [ $? -eq 2 ]; then
        echo "[ALERT] Matches found in: $filename"
        # Trigger additional analysis, alerting, etc.
    fi
done
```

**Python Integration:**

```python
from yara_scanner import YaraScanner, ScanResult

# Initialize scanner
scanner = YaraScanner(rules_dir="/opt/cptc11/yara/rules")

# Scan file
matches = scanner.scan_file("/path/to/sample.exe")
for match in matches:
    print(f"Detected: {match.rule} (severity: {match.meta.get('severity')})")

# Scan raw data
with open("shellcode.bin", "rb") as f:
    data = f.read()
matches = scanner.scan_data(data, identifier="shellcode.bin")
```

---

## Section 5: Detection Engineering Workflow

### 5.1 Rule Development Lifecycle

```
ASCII Diagram: Detection Engineering Lifecycle

    +------------------+
    |  Threat Intel    |
    |  Collection      |
    +--------+---------+
             |
             v
    +------------------+
    |  Sample          |
    |  Analysis        |
    +--------+---------+
             |
             v
    +------------------+
    |  Pattern         |
    |  Identification  |
    +--------+---------+
             |
             v
    +------------------+
    |  Rule            |
    |  Development     |
    +--------+---------+
             |
             v
    +------------------+
    |  Testing &       |<----+
    |  Validation      |     |
    +--------+---------+     |
             |               |
             v               |
    +------------------+     |
    |  Review &        |     |
    |  Approval        |     |
    +--------+---------+     |
             |               |
             v               |
    +------------------+     |
    |  Deployment      |     |
    +--------+---------+     |
             |               |
             v               |
    +------------------+     |
    |  Monitoring &    |-----+
    |  Feedback        |
    +------------------+
```

**Phase 1: Threat Intelligence Collection**

- Monitor threat feeds, vendor reports, and security research
- Track emerging malware families and TTPs
- Collect samples from malware repositories and incident response
- Document threat actor behaviors and tooling

**Phase 2: Sample Analysis**

- Static analysis: strings, imports, resources, entropy
- Dynamic analysis: behavioral patterns, network indicators
- Code analysis: identify unique functionality
- Compare variants to identify stable patterns

**Phase 3: Pattern Identification**

- Extract distinctive strings and byte sequences
- Identify structural characteristics
- Document encoding and obfuscation methods
- Prioritize patterns by uniqueness and stability

**Phase 4: Rule Development**

- Write initial rule with comprehensive strings
- Add appropriate metadata
- Design condition logic for accuracy
- Consider performance implications

**Phase 5: Testing and Validation**

- Test against known malicious samples (detection rate)
- Test against clean file corpus (false positive rate)
- Validate across different environments
- Performance benchmarking

**Phase 6: Review and Approval**

- Peer review for technical accuracy
- Security review for sensitive patterns
- Documentation review
- Approval for production deployment

**Phase 7: Deployment**

- Stage deployment to test environment
- Gradual rollout to production
- Monitor for unexpected behavior
- Prepare rollback procedure

**Phase 8: Monitoring and Feedback**

- Track detection statistics
- Investigate false positives
- Monitor for evasion attempts
- Update rules based on feedback

### 5.2 Testing and Validation

**Test Data Requirements:**

1. **Positive Test Set:** Known malicious samples that should match
   - Original samples used for rule development
   - Variant samples to test coverage
   - Packed/encoded versions to test robustness

2. **Negative Test Set:** Legitimate files that should not match
   - Common applications and utilities
   - System files from clean installations
   - Files similar to malware but legitimate

**Validation Metrics:**

```
True Positive Rate (TPR) = TP / (TP + FN)
False Positive Rate (FPR) = FP / (FP + TN)

Detection Rate Goal: > 95%
False Positive Rate Goal: < 0.1%
```

**Validation Script Example:**

```bash
#!/bin/bash
# Rule validation script

RULE_FILE="$1"
MALWARE_DIR="/test/malware"
CLEAN_DIR="/test/clean"

echo "Testing rule: $RULE_FILE"

# Count malware detections
MALWARE_COUNT=$(find "$MALWARE_DIR" -type f | wc -l)
DETECTED=$(yara "$RULE_FILE" "$MALWARE_DIR" 2>/dev/null | wc -l)
echo "Detection rate: $DETECTED / $MALWARE_COUNT"

# Count false positives
CLEAN_COUNT=$(find "$CLEAN_DIR" -type f | wc -l)
FALSE_POS=$(yara "$RULE_FILE" "$CLEAN_DIR" 2>/dev/null | wc -l)
echo "False positives: $FALSE_POS / $CLEAN_COUNT"
```

### 5.3 Continuous Improvement

**Rule Maintenance Triggers:**

1. **New variants discovered** - Extend patterns to cover
2. **False positives reported** - Add exclusions or refine conditions
3. **Evasion detected** - Update or supplement rules
4. **Performance issues** - Optimize strings and conditions
5. **Retired threats** - Archive or deprecate rules

**Version Control Best Practices:**

```
rules/
  payload_signatures.yar    # Current production rules
  changelog.md              # Change history
  archive/                  # Deprecated rules
  development/              # Rules in development
  tests/
    malware/               # Positive test samples
    clean/                 # Negative test samples
    validation.py          # Automated testing
```

**Feedback Loop Integration:**

```
ASCII Diagram: Continuous Improvement Cycle

+------------------+     +------------------+     +------------------+
|    Detection     | --> |    Analyst       | --> |    Rule          |
|    Alert         |     |    Review        |     |    Update        |
+------------------+     +------------------+     +------------------+
         ^                                                 |
         |                                                 |
         +-------------------------------------------------+
                    Improved Detection
```

---

## Section 6: Hands-On Labs

### Lab 1: Basic Rule Writing

**Objective:** Write your first YARA rule to detect a simple pattern.

**Scenario:** You've received a malware sample that creates a file containing the string "MALWARE_BEACON_V1" and makes HTTP requests to domains ending in ".evil.com".

**Environment Setup:**
```bash
mkdir -p /tmp/yara_lab1
cd /tmp/yara_lab1

# Create test sample
echo "This is a test file with MALWARE_BEACON_V1 marker" > sample1.txt
echo "Normal file without markers" > sample2.txt
echo "MALWARE_BEACON_V1 calling home to update.evil.com" > sample3.txt
```

**Task 1:** Create a basic rule

```
// File: lab1_basic.yar
// TODO: Complete this rule

rule Lab1_Malware_Beacon {
    meta:
        author = "Your Name"
        description = "Detects Lab1 malware beacon"
        date = "2026-01-10"

    strings:
        // TODO: Add string for beacon marker
        // TODO: Add regex for evil.com domains

    condition:
        // TODO: Define matching logic
}
```

**Task 2:** Test your rule

```bash
yara lab1_basic.yar sample1.txt
yara lab1_basic.yar sample2.txt
yara lab1_basic.yar sample3.txt
```

**Expected Results:**
- sample1.txt: Match (contains beacon marker)
- sample2.txt: No match
- sample3.txt: Match (contains both patterns)

**Solution Guide:**

```
rule Lab1_Malware_Beacon {
    meta:
        author = "Your Name"
        description = "Detects Lab1 malware beacon"
        date = "2026-01-10"

    strings:
        $beacon = "MALWARE_BEACON_V1" ascii
        $domain = /[a-z0-9]+\.evil\.com/ nocase

    condition:
        any of them
}
```

**Extension Challenge:** Modify the rule to only match when BOTH the beacon marker AND an evil.com domain are present.

---

### Lab 2: Detecting CPTC11 Payloads

**Objective:** Use the CPTC11 scanner to identify malicious payloads in a sample set.

**Environment Setup:**
```bash
mkdir -p /tmp/yara_lab2/samples
cd /tmp/yara_lab2

# Create simulated payload samples (educational patterns only)
# Sample 1: Simulated Meterpreter-like strings
cat > samples/payload1.bin << 'EOF'
MZ....PE..
metsrv.dll
stdapi extension loaded
core_migrate function
EOF

# Sample 2: Simulated webshell
cat > samples/webshell.php << 'EOF'
<?php
$cmd = $_GET['cmd'];
system($cmd);
?>
EOF

# Sample 3: Clean file
echo "This is a legitimate configuration file" > samples/clean.txt
```

**Task 1:** Run the CPTC11 scanner

```bash
# Scan the samples directory
python /Users/ic/cptc11/yara/yara_scanner.py -d /tmp/yara_lab2/samples/ --format text
```

**Task 2:** Analyze JSON output

```bash
# Generate JSON report
python /Users/ic/cptc11/yara/yara_scanner.py -d /tmp/yara_lab2/samples/ \
    --format json -o /tmp/yara_lab2/results.json

# Review results
cat /tmp/yara_lab2/results.json | python -m json.tool
```

**Task 3:** Identify which rules matched

For each match, document:
1. Rule name that matched
2. File that triggered the match
3. Strings that were found
4. Severity rating from metadata

**Validation Criteria:**
- payload1.bin should trigger Meterpreter-related rules
- webshell.php should trigger Webshell_Generic rule
- clean.txt should produce no matches

**Hints:**
- Check the `strings` field in JSON output to see what matched
- Review the original rule files to understand why patterns matched
- Consider why certain patterns were chosen for detection

---

### Lab 3: Shellcode Pattern Matching

**Objective:** Understand and detect common shellcode patterns.

**Environment Setup:**
```bash
mkdir -p /tmp/yara_lab3
cd /tmp/yara_lab3

# Create file with x86 PEB access pattern
printf '\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C' > peb_access.bin

# Create file with NOP sled
printf '\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90' > nop_sled.bin

# Create file with XOR decoder stub pattern
printf '\xEB\x10\x5A\x31\xC9\xB1\x20\x80\x34\x0A\x41\xE2\xFA' > xor_stub.bin

# Create clean binary
printf '\x00\x01\x02\x03\x04\x05' > clean.bin
```

**Task 1:** Write a rule to detect PEB access

```
// File: lab3_peb.yar
rule Lab3_PEB_Access {
    meta:
        description = "Detects x86 PEB access pattern"

    strings:
        // TODO: Add hex pattern for mov eax, fs:[0x30]
        // Hint: 64 A1 30 00 00 00

    condition:
        // TODO: Define condition
}
```

**Task 2:** Write a rule to detect XOR decoder stubs

```
// File: lab3_xor.yar
rule Lab3_XOR_Decoder {
    meta:
        description = "Detects XOR decoder stub"

    strings:
        // TODO: Add pattern for jmp-call-pop XOR decoder
        // Pattern: EB ?? 5? 31 C9 B1 ?? 80
        // EB = jmp, 5? = pop reg, 31 C9 = xor ecx,ecx
        // B1 = mov cl, 80 = xor operation

    condition:
        // TODO: Define condition with filesize limit
}
```

**Task 3:** Test your rules

```bash
yara lab3_peb.yar peb_access.bin
yara lab3_xor.yar xor_stub.bin
yara lab3_peb.yar clean.bin  # Should not match
```

**Solution Discussion:**

The PEB access pattern (`64 A1 30 00 00 00`) is significant because:
1. `64` prefix accesses the FS segment
2. `A1` is MOV EAX, moffs32
3. `30 00 00 00` is offset 0x30 (PEB location in Windows)

Shellcode uses this to find kernel32.dll base address for API resolution without using import tables.

---

### Lab 4: Rule Optimization

**Objective:** Optimize a poorly-performing rule for production use.

**Starting Rule (Inefficient):**

```
// File: lab4_unoptimized.yar
rule Lab4_Unoptimized {
    meta:
        description = "Poorly optimized rule for training"

    strings:
        $generic1 = "the" nocase        // Too common
        $generic2 = "and" nocase        // Too common
        $wildcard = { ?? ?? ?? ?? }     // Matches everything
        $slow_regex = /.*/              // Catastrophic
        $useful = "MalwareSpecificString"

    condition:
        any of them
}
```

**Task 1:** Identify problems

Document each issue with the unoptimized rule:
1. What makes `$generic1` and `$generic2` problematic?
2. Why is `$wildcard` inefficient?
3. What's wrong with `$slow_regex`?
4. How would the condition affect false positives?

**Task 2:** Create optimized version

```
// File: lab4_optimized.yar
rule Lab4_Optimized {
    meta:
        description = "Optimized version of training rule"
        // TODO: Add appropriate metadata

    strings:
        // TODO: Remove or replace problematic patterns
        // TODO: Keep useful patterns
        // TODO: Add additional context patterns

    condition:
        // TODO: Write efficient condition
        // Consider: file type checks, size limits, string combinations
}
```

**Task 3:** Benchmark performance

```bash
# Create test corpus
mkdir -p /tmp/yara_lab4/corpus
for i in {1..100}; do
    dd if=/dev/urandom of=/tmp/yara_lab4/corpus/file$i.bin bs=1K count=100 2>/dev/null
done

# Time unoptimized rule
time yara lab4_unoptimized.yar /tmp/yara_lab4/corpus/

# Time optimized rule
time yara lab4_optimized.yar /tmp/yara_lab4/corpus/
```

**Optimization Checklist:**
- [ ] Removed overly generic strings
- [ ] Removed unbounded wildcards
- [ ] Replaced `.*` with specific patterns
- [ ] Added file type constraints
- [ ] Added file size limits
- [ ] Ordered condition checks efficiently
- [ ] Required multiple indicators for match

**Solution Approach:**

```
rule Lab4_Optimized {
    meta:
        description = "Optimized malware detection rule"
        author = "Student"
        version = "1.0"

    strings:
        $specific1 = "MalwareSpecificString" ascii wide
        $specific2 = "AnotherUniquePattern" ascii
        $hex_pattern = { 4D 5A 90 00 }  // Specific PE header

    condition:
        uint16(0) == 0x5A4D and     // PE file check (fast)
        filesize < 5MB and           // Size constraint (fast)
        2 of ($specific*)            // Require multiple matches
}
```

**Validation:**

Compare results:
- Unoptimized: Likely slower, many false positives
- Optimized: Faster execution, precise matches

---

## Appendix A: Quick Reference Card

### YARA String Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `ascii` | Match ASCII string (default) | `$s = "text" ascii` |
| `wide` | Match UTF-16 encoded | `$s = "text" wide` |
| `nocase` | Case-insensitive | `$s = "TEXT" nocase` |
| `fullword` | Match whole words only | `$s = "mal" fullword` |
| `xor` | Match XOR'd string | `$s = "text" xor` |
| `base64` | Match Base64 encoded | `$s = "text" base64` |

### Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `and` | Logical AND | `$a and $b` |
| `or` | Logical OR | `$a or $b` |
| `not` | Logical NOT | `not $a` |
| `any of` | Any string matches | `any of them` |
| `all of` | All strings match | `all of ($set_*)` |
| `X of` | X strings match | `2 of them` |
| `#` | Count of matches | `#string > 5` |
| `@` | Offset of match | `@string[1]` |

### File Properties

| Property | Description | Example |
|----------|-------------|---------|
| `filesize` | File size in bytes | `filesize < 1MB` |
| `entrypoint` | PE/ELF entry point | `entrypoint == 0x1000` |
| `uint8(X)` | Read byte at offset | `uint8(0) == 0x4D` |
| `uint16(X)` | Read word at offset | `uint16(0) == 0x5A4D` |
| `uint32(X)` | Read dword at offset | `uint32(0) == 0x464c457f` |

### Common Magic Bytes

| Format | Magic Bytes | YARA Check |
|--------|-------------|------------|
| PE (Windows) | `MZ` (4D 5A) | `uint16(0) == 0x5A4D` |
| ELF (Linux) | `\x7fELF` | `uint32(0) == 0x464c457f` |
| PDF | `%PDF` | `uint32(0) == 0x46445025` |
| ZIP | `PK` | `uint16(0) == 0x4B50` |
| Mach-O | `\xcf\xfa\xed\xfe` | `uint32(0) == 0xfeedfacf` |

---

## Appendix B: Troubleshooting

### Common Errors

**Syntax Error: unexpected token**
```
Error: syntax error, unexpected _IDENTIFIER_
```
**Solution:** Check for missing quotes, braces, or invalid characters in strings.

**Rule compilation warning: slow pattern**
```
Warning: rule "X" has slow patterns
```
**Solution:** Review and optimize regex patterns and wildcards.

**No rules loaded**
```
ERROR: No .yar files found in /path/to/rules
```
**Solution:** Verify rules directory path and file extensions (.yar).

**Process scan permission denied**
```
Error: could not attach to process 1234
```
**Solution:** Run with elevated privileges (sudo/Administrator).

### Performance Issues

**Slow directory scanning:**
1. Add file type filters to rules
2. Use filesize constraints
3. Reduce regex complexity
4. Consider scanning in batches

**High memory usage:**
1. Scan smaller directories
2. Reduce rule complexity
3. Use streaming mode for large files

---

## Appendix C: Additional Resources

### Documentation
- YARA Official Documentation: https://yara.readthedocs.io/
- YARA GitHub Repository: https://github.com/VirusTotal/yara
- yara-python: https://github.com/VirusTotal/yara-python

### Rule Repositories
- YARA-Rules Community: https://github.com/Yara-Rules/rules
- Florian Roth's Signature Base: https://github.com/Neo23x0/signature-base
- InQuest YARA Rules: https://github.com/InQuest/yara-rules

### Training Resources
- SANS FOR610: Reverse-Engineering Malware
- MITRE ATT&CK Framework: https://attack.mitre.org/
- LOLBAS Project: https://lolbas-project.github.io/

---

**Document Version:** 1.0
**Last Updated:** 2026-01-10
**Author:** Detection Engineering Team
**Classification:** Training Material - Internal Use
