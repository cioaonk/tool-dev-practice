/*
    YARA Rules: Tool Artifacts
    Purpose: Detect artifacts from common offensive security tools
    Author: Detection Engineering Team
    Date: 2026-01-10

    Educational/CTF Training Resource
    These rules detect artifacts left by common penetration testing tools
*/

rule Tool_Mimikatz_Strings {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Mimikatz credential dumping tool"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://github.com/gentilkiwi/mimikatz"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "tool"

    strings:
        // Mimikatz banner and strings
        $banner_1 = "mimikatz" ascii wide nocase
        $banner_2 = "gentilkiwi" ascii wide
        $banner_3 = "Benjamin DELPY" ascii wide
        $banner_4 = "vincent.letoux" ascii wide

        // Module names
        $module_1 = "sekurlsa" ascii wide
        $module_2 = "kerberos" ascii wide
        $module_3 = "lsadump" ascii wide
        $module_4 = "dpapi" ascii wide
        $module_5 = "privilege::debug" ascii wide

        // Command strings
        $cmd_1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd_2 = "sekurlsa::wdigest" ascii wide nocase
        $cmd_3 = "lsadump::sam" ascii wide nocase
        $cmd_4 = "lsadump::dcsync" ascii wide nocase
        $cmd_5 = "kerberos::golden" ascii wide nocase
        $cmd_6 = "kerberos::ptt" ascii wide nocase

        // Unique error/output strings
        $str_1 = "* Username : " ascii wide
        $str_2 = "* Domain   : " ascii wide
        $str_3 = "* Password : " ascii wide
        $str_4 = "* NTLM     : " ascii wide

    condition:
        filesize < 10MB and
        (
            (any of ($banner_*)) or
            (3 of ($module_*)) or
            (any of ($cmd_*)) or
            (3 of ($str_*))
        )
}

rule Tool_Mimikatz_Binary {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Mimikatz binary patterns"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "tool"

    strings:
        // Export function names
        $export_1 = "powershell_reflective_mimikatz" ascii
        $export_2 = "mimikatz_initOrClean" ascii

        // Internal function patterns
        $func_1 = "kuhl_m_" ascii
        $func_2 = "kull_m_" ascii

        // Crypto patterns used by mimikatz
        $crypto_1 = { 4D 69 63 72 6F 73 6F 66 74 20 45 6E 68 61 6E 63 65 64 }  // "Microsoft Enhanced"

        // Specific byte patterns
        $pattern_1 = { 6B 69 77 69 }  // "kiwi"
        $pattern_2 = { 6D 69 6D 69 }  // "mimi"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($export_*) or
            (2 of ($func_*)) or
            (all of ($pattern_*))
        )
}

rule Tool_Impacket_Strings {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Impacket toolset artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://github.com/SecureAuthCorp/impacket"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "tool"

    strings:
        // Impacket library strings
        $lib_1 = "impacket" ascii
        $lib_2 = "from impacket" ascii
        $lib_3 = "import impacket" ascii

        // Common impacket tools
        $tool_1 = "secretsdump" ascii nocase
        $tool_2 = "psexec" ascii nocase
        $tool_3 = "wmiexec" ascii nocase
        $tool_4 = "smbexec" ascii nocase
        $tool_5 = "atexec" ascii nocase
        $tool_6 = "dcomexec" ascii nocase
        $tool_7 = "GetNPUsers" ascii
        $tool_8 = "GetUserSPNs" ascii

        // Protocol strings
        $proto_1 = "SMBConnection" ascii
        $proto_2 = "DCERPC" ascii
        $proto_3 = "SAMR" ascii
        $proto_4 = "DRSUAPI" ascii

        // Specific impacket patterns
        $pattern_1 = "NTLM_AUTH_" ascii
        $pattern_2 = "getCredentials" ascii

    condition:
        filesize < 5MB and
        (
            (any of ($lib_*) and any of ($tool_*)) or
            (3 of ($tool_*)) or
            (any of ($lib_*) and any of ($proto_*))
        )
}

rule Tool_BloodHound_Collector {
    meta:
        author = "Detection Engineering Team"
        description = "Detects BloodHound/SharpHound data collection tools"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://github.com/BloodHoundAD/BloodHound"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "tool"

    strings:
        // BloodHound strings
        $bh_1 = "BloodHound" ascii wide nocase
        $bh_2 = "SharpHound" ascii wide nocase
        $bh_3 = "Bloodhound.Crypto" ascii wide
        $bh_4 = "Sharphound.Writers" ascii wide

        // Collection methods
        $collect_1 = "CollectionMethods" ascii wide
        $collect_2 = "SessionCollection" ascii wide
        $collect_3 = "LocalAdminCollection" ascii wide
        $collect_4 = "GroupMembership" ascii wide
        $collect_5 = "ACLCollection" ascii wide

        // Output indicators
        $output_1 = "_BloodHound.zip" ascii wide nocase
        $output_2 = "computers.json" ascii wide
        $output_3 = "users.json" ascii wide
        $output_4 = "groups.json" ascii wide
        $output_5 = "domains.json" ascii wide

        // LDAP queries
        $ldap_1 = "(&(objectCategory=person)(objectClass=user))" ascii wide
        $ldap_2 = "(objectClass=computer)" ascii wide

    condition:
        filesize < 10MB and
        (
            (any of ($bh_*)) or
            (3 of ($collect_*)) or
            (3 of ($output_*)) or
            (any of ($bh_*) and any of ($ldap_*))
        )
}

rule Tool_Rubeus_Kerberos {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Rubeus Kerberos attack tool"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://github.com/GhostPack/Rubeus"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "tool"

    strings:
        // Rubeus identification
        $rubeus_1 = "Rubeus" ascii wide
        $rubeus_2 = "GhostPack" ascii wide

        // Rubeus commands
        $cmd_1 = "asktgt" ascii wide nocase
        $cmd_2 = "asktgs" ascii wide nocase
        $cmd_3 = "kerberoast" ascii wide nocase
        $cmd_4 = "asreproast" ascii wide nocase
        $cmd_5 = "s4u" ascii wide nocase
        $cmd_6 = "ptt" ascii wide nocase
        $cmd_7 = "harvest" ascii wide nocase
        $cmd_8 = "tgtdeleg" ascii wide nocase
        $cmd_9 = "dump" ascii wide nocase

        // Kerberos-specific strings
        $kerb_1 = "TGT" ascii wide
        $kerb_2 = "TGS" ascii wide
        $kerb_3 = "krbtgt" ascii wide nocase
        $kerb_4 = "AS-REP" ascii wide
        $kerb_5 = "kirbi" ascii wide nocase

        // Ticket format
        $ticket = "doI" ascii  // Base64 encoded ticket start

    condition:
        filesize < 5MB and
        (
            (any of ($rubeus_*) and any of ($cmd_*)) or
            (4 of ($cmd_*)) or
            (any of ($rubeus_*) and 2 of ($kerb_*))
        )
}

rule Tool_CobaltStrike_Artifacts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Cobalt Strike tool artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://www.cobaltstrike.com/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "tool"

    strings:
        // Cobalt Strike strings
        $cs_1 = "Cobalt Strike" ascii wide nocase
        $cs_2 = "cobaltstrike" ascii wide nocase
        $cs_3 = "BeaconPayload" ascii wide

        // Malleable C2 indicators
        $c2_1 = "sleeptime" ascii
        $c2_2 = "jitter" ascii
        $c2_3 = "useragent" ascii
        $c2_4 = "pipename" ascii
        $c2_5 = "spawnto" ascii

        // Beacon commands
        $beacon_1 = "shell" ascii
        $beacon_2 = "execute" ascii
        $beacon_3 = "inject" ascii
        $beacon_4 = "spawn" ascii
        $beacon_5 = "mimikatz" ascii wide

        // Named pipe patterns
        $pipe_1 = "\\\\?\\pipe\\msagent" ascii wide
        $pipe_2 = "MSSE-" ascii wide
        $pipe_3 = "status_" ascii wide
        $pipe_4 = "postex_" ascii wide

        // Default watermarks (educational - these are well-known)
        $watermark = { 01 00 00 00 ?? 00 00 00 }

    condition:
        filesize < 10MB and
        (
            (any of ($cs_*)) or
            (3 of ($c2_*)) or
            (any of ($pipe_*) and any of ($beacon_*))
        )
}

rule Tool_PowerSploit_Scripts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects PowerSploit offensive PowerShell toolkit"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://github.com/PowerShellMafia/PowerSploit"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "tool"

    strings:
        // PowerSploit identification
        $ps_1 = "PowerSploit" ascii wide nocase
        $ps_2 = "PowerShellMafia" ascii wide nocase

        // Common functions
        $func_1 = "Invoke-Mimikatz" ascii wide nocase
        $func_2 = "Invoke-Shellcode" ascii wide nocase
        $func_3 = "Invoke-DllInjection" ascii wide nocase
        $func_4 = "Invoke-ReflectivePEInjection" ascii wide nocase
        $func_5 = "Invoke-TokenManipulation" ascii wide nocase
        $func_6 = "Get-GPPPassword" ascii wide nocase
        $func_7 = "Get-Keystrokes" ascii wide nocase
        $func_8 = "Invoke-Portscan" ascii wide nocase
        $func_9 = "Find-LocalAdminAccess" ascii wide nocase
        $func_10 = "Invoke-Kerberoast" ascii wide nocase

        // Module references
        $mod_1 = "Exfiltration" ascii wide
        $mod_2 = "Recon" ascii wide
        $mod_3 = "Privesc" ascii wide
        $mod_4 = "CodeExecution" ascii wide
        $mod_5 = "Persistence" ascii wide

    condition:
        filesize < 5MB and
        (
            (any of ($ps_*)) or
            (3 of ($func_*)) or
            (3 of ($mod_*) and any of ($func_*))
        )
}

rule Tool_Nmap_Output {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Nmap scan output files"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://nmap.org/"
        tlp = "green"
        confidence = "high"
        severity = "low"
        category = "tool"

    strings:
        // Nmap output identifiers
        $nmap_1 = "Nmap scan report" ascii
        $nmap_2 = "Starting Nmap" ascii
        $nmap_3 = "nmap.org" ascii
        $nmap_4 = "Nmap done:" ascii

        // XML output
        $xml_1 = "<nmaprun" ascii
        $xml_2 = "scanner=\"nmap\"" ascii

        // Port state indicators
        $state_1 = "open" ascii
        $state_2 = "filtered" ascii
        $state_3 = "closed" ascii

        // Service detection
        $service_1 = "SERVICE VERSION" ascii
        $service_2 = "PORT" ascii wide
        $service_3 = "STATE" ascii wide

    condition:
        filesize < 50MB and
        (
            (2 of ($nmap_*)) or
            (all of ($xml_*)) or
            (any of ($nmap_*) and 2 of ($state_*))
        )
}

rule Tool_Metasploit_Artifacts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Metasploit Framework artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://www.metasploit.com/"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "tool"

    strings:
        // Metasploit identification
        $msf_1 = "metasploit" ascii wide nocase
        $msf_2 = "msfconsole" ascii wide nocase
        $msf_3 = "msfvenom" ascii wide nocase
        $msf_4 = "meterpreter" ascii wide nocase

        // Payload indicators
        $payload_1 = "windows/meterpreter" ascii
        $payload_2 = "linux/x64/meterpreter" ascii
        $payload_3 = "reverse_tcp" ascii
        $payload_4 = "reverse_https" ascii
        $payload_5 = "bind_tcp" ascii

        // Module paths
        $mod_1 = "exploit/" ascii
        $mod_2 = "auxiliary/" ascii
        $mod_3 = "payload/" ascii
        $mod_4 = "encoder/" ascii
        $mod_5 = "post/" ascii

        // Database/workspace
        $db_1 = "workspace" ascii
        $db_2 = "msf_database" ascii

    condition:
        filesize < 50MB and
        (
            (2 of ($msf_*)) or
            (2 of ($payload_*)) or
            (any of ($msf_*) and 2 of ($mod_*))
        )
}

rule Tool_Hashcat_Artifacts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Hashcat password cracking tool artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://hashcat.net/"
        tlp = "green"
        confidence = "medium"
        severity = "medium"
        category = "tool"

    strings:
        // Hashcat identification
        $hc_1 = "hashcat" ascii wide nocase
        $hc_2 = "Hashcat" ascii wide

        // Hash mode indicators
        $mode_1 = "-m 0" ascii   // MD5
        $mode_2 = "-m 1000" ascii  // NTLM
        $mode_3 = "-m 1800" ascii  // sha512crypt
        $mode_4 = "-m 5600" ascii  // NetNTLMv2

        // Attack modes
        $attack_1 = "-a 0" ascii  // Dictionary
        $attack_2 = "-a 3" ascii  // Brute-force
        $attack_3 = "-a 6" ascii  // Hybrid wordlist + mask

        // Pot file patterns
        $pot_1 = ".potfile" ascii
        $pot_2 = "hashcat.potfile" ascii

        // Status output
        $status_1 = "Hash.Mode" ascii
        $status_2 = "Speed.#1" ascii
        $status_3 = "Recovered" ascii

    condition:
        filesize < 50MB and
        (
            (any of ($hc_*) and (any of ($mode_*) or any of ($attack_*))) or
            (any of ($pot_*)) or
            (2 of ($status_*))
        )
}

rule Tool_JohnTheRipper_Artifacts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects John the Ripper password cracking tool artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://www.openwall.com/john/"
        tlp = "green"
        confidence = "medium"
        severity = "medium"
        category = "tool"

    strings:
        // John identification
        $john_1 = "John the Ripper" ascii wide
        $john_2 = "john.pot" ascii
        $john_3 = "john.conf" ascii

        // Format strings
        $format_1 = "--format=raw-md5" ascii
        $format_2 = "--format=nt" ascii
        $format_3 = "--format=sha512crypt" ascii
        $format_4 = "--format=krb5tgs" ascii

        // Mode indicators
        $mode_1 = "--wordlist" ascii
        $mode_2 = "--incremental" ascii
        $mode_3 = "--rules" ascii

        // Status patterns
        $status_1 = "guesses:" ascii
        $status_2 = "g/s" ascii

    condition:
        filesize < 50MB and
        (
            (any of ($john_*)) or
            (any of ($format_*) and any of ($mode_*))
        )
}

rule Tool_Responder_Artifacts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Responder LLMNR/NBT-NS poisoning tool artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://github.com/lgandx/Responder"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "tool"

    strings:
        // Responder identification
        $resp_1 = "Responder" ascii wide
        $resp_2 = "NBT-NS" ascii wide
        $resp_3 = "LLMNR" ascii wide

        // Configuration
        $conf_1 = "Responder.conf" ascii
        $conf_2 = "Responder.db" ascii

        // Captured hash patterns
        $hash_1 = "NTLMv2-SSP" ascii
        $hash_2 = "NTLMv1" ascii
        $hash_3 = ":::" ascii  // Hash format separator

        // Log patterns
        $log_1 = "Poisoned answer" ascii
        $log_2 = "HTTP request from" ascii
        $log_3 = "SMB request from" ascii

    condition:
        filesize < 10MB and
        (
            (any of ($resp_*) and any of ($conf_*)) or
            (any of ($hash_*) and any of ($resp_*)) or
            (2 of ($log_*))
        )
}

rule Tool_Empire_Framework {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Empire/Starkiller C2 framework artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://github.com/BC-SECURITY/Empire"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "tool"

    strings:
        // Empire identification
        $empire_1 = "Empire" ascii wide
        $empire_2 = "BC-Security" ascii wide
        $empire_3 = "Starkiller" ascii wide

        // Agent strings
        $agent_1 = "staging_key" ascii
        $agent_2 = "session_key" ascii
        $agent_3 = "agent_code" ascii

        // Listener strings
        $listener_1 = "listener_type" ascii
        $listener_2 = "launcher" ascii

        // Module patterns
        $mod_1 = "credentials/mimikatz" ascii
        $mod_2 = "situational_awareness" ascii
        $mod_3 = "privesc/" ascii
        $mod_4 = "persistence/" ascii

        // Stager patterns
        $stager_1 = "multi/launcher" ascii
        $stager_2 = "stager" ascii

    condition:
        filesize < 10MB and
        (
            (any of ($empire_*) and any of ($agent_*)) or
            (any of ($listener_*) and any of ($mod_*)) or
            (any of ($stager_*) and any of ($empire_*))
        )
}

rule Tool_SQLMap_Artifacts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects SQLMap SQL injection tool artifacts"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://sqlmap.org/"
        tlp = "green"
        confidence = "high"
        severity = "medium"
        category = "tool"

    strings:
        // SQLMap identification
        $sql_1 = "sqlmap" ascii wide nocase
        $sql_2 = "sqlmapproject" ascii wide nocase

        // Options
        $opt_1 = "--dbs" ascii
        $opt_2 = "--tables" ascii
        $opt_3 = "--dump" ascii
        $opt_4 = "--os-shell" ascii
        $opt_5 = "--sql-shell" ascii

        // Output patterns
        $out_1 = "available databases" ascii nocase
        $out_2 = "Database:" ascii
        $out_3 = "Table:" ascii

        // Technique strings
        $tech_1 = "boolean-based blind" ascii
        $tech_2 = "time-based blind" ascii
        $tech_3 = "UNION query" ascii
        $tech_4 = "error-based" ascii

    condition:
        filesize < 50MB and
        (
            (any of ($sql_*) and 2 of ($opt_*)) or
            (any of ($sql_*) and any of ($out_*)) or
            (2 of ($tech_*))
        )
}

rule Tool_Burp_Suite_Artifacts {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Burp Suite artifacts and configurations"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://portswigger.net/burp"
        tlp = "green"
        confidence = "high"
        severity = "low"
        category = "tool"

    strings:
        // Burp identification
        $burp_1 = "Burp Suite" ascii wide nocase
        $burp_2 = "PortSwigger" ascii wide nocase
        $burp_3 = "BurpSuite" ascii wide nocase

        // Project files
        $proj_1 = ".burp" ascii wide
        $proj_2 = "burp-project" ascii wide

        // Configuration
        $conf_1 = "proxy_history" ascii wide
        $conf_2 = "site_map" ascii wide
        $conf_3 = "intruder" ascii wide
        $conf_4 = "repeater" ascii wide
        $conf_5 = "scanner" ascii wide

        // Export patterns
        $export_1 = "http-request" ascii
        $export_2 = "http-response" ascii

    condition:
        filesize < 100MB and
        (
            (any of ($burp_*)) or
            (any of ($proj_*) and 2 of ($conf_*))
        )
}
