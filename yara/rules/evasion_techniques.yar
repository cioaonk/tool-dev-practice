/*
    YARA Rules: Evasion Techniques
    Purpose: Detect defense evasion and anti-analysis techniques
    Author: Detection Engineering Team
    Date: 2026-01-10

    Educational/CTF Training Resource
    These rules detect techniques used to evade security controls
*/

rule Evasion_AMSI_Bypass {
    meta:
        author = "Detection Engineering Team"
        description = "Detects AMSI bypass techniques including memory patching and reflection"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "evasion"

    strings:
        // AMSI-related strings
        $amsi_1 = "amsi.dll" ascii wide nocase
        $amsi_2 = "AmsiScanBuffer" ascii wide
        $amsi_3 = "AmsiInitialize" ascii wide
        $amsi_4 = "AmsiOpenSession" ascii wide
        $amsi_5 = "AmsiScanString" ascii wide

        // Common bypass patterns
        $bypass_1 = "AmsiScanBuffer" ascii wide
        $bypass_2 = "amsiInitFailed" ascii wide
        $bypass_3 = "[Ref].Assembly.GetType" ascii wide

        // PowerShell AMSI bypass methods
        $ps_bypass_1 = "System.Management.Automation.AmsiUtils" ascii wide
        $ps_bypass_2 = "amsiContext" ascii wide nocase
        $ps_bypass_3 = "amsiSession" ascii wide nocase

        // Memory patching patterns
        $patch_1 = { B8 57 00 07 80 C3 }  // mov eax, 0x80070057; ret (E_INVALIDARG)
        $patch_2 = { 31 C0 C3 }           // xor eax, eax; ret

        // Obfuscated AMSI strings
        $obf_1 = /[aA][\x00]*[mM][\x00]*[sS][\x00]*[iI]/
        $obf_2 = "'am'+'si'" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (3 of ($amsi_*)) or
            (any of ($bypass_*) and any of ($amsi_*)) or
            (any of ($ps_bypass_*)) or
            (any of ($patch_*) and any of ($amsi_*)) or
            (any of ($obf_*))
        )
}

rule Evasion_ETW_Bypass {
    meta:
        author = "Detection Engineering Team"
        description = "Detects ETW (Event Tracing for Windows) bypass techniques"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1562/006/"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "evasion"

    strings:
        // ETW-related strings
        $etw_1 = "EtwEventWrite" ascii wide
        $etw_2 = "NtTraceEvent" ascii wide
        $etw_3 = "EtwEventRegister" ascii wide
        $etw_4 = "ntdll!EtwEventWrite" ascii wide

        // Provider names
        $provider_1 = "Microsoft-Windows-PowerShell" ascii wide
        $provider_2 = "Microsoft-Windows-Kernel" ascii wide
        $provider_3 = "Microsoft-Antimalware" ascii wide

        // Patch patterns for ETW bypass
        $patch_1 = { C2 14 00 }  // ret 0x14
        $patch_2 = { 48 33 C0 C3 }  // xor rax, rax; ret

        // PowerShell ETW bypass
        $ps_1 = "Reflection.FieldInfo" ascii wide
        $ps_2 = "etwProvider" ascii wide nocase
        $ps_3 = "m_enabled" ascii wide

    condition:
        filesize < 5MB and
        (
            (2 of ($etw_*) and any of ($patch_*)) or
            (any of ($etw_*) and any of ($provider_*) and any of ($ps_*)) or
            (all of ($ps_*))
        )
}

rule Evasion_UAC_Bypass {
    meta:
        author = "Detection Engineering Team"
        description = "Detects UAC bypass techniques including fodhelper, sdclt, and CMSTP"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1548/002/"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "evasion"

    strings:
        // Auto-elevate binaries
        $autoelevate_1 = "fodhelper" ascii wide nocase
        $autoelevate_2 = "computerdefaults" ascii wide nocase
        $autoelevate_3 = "sdclt" ascii wide nocase
        $autoelevate_4 = "eventvwr" ascii wide nocase
        $autoelevate_5 = "slui" ascii wide nocase

        // Registry keys for UAC bypass
        $reg_1 = "Software\\Classes\\ms-settings" ascii wide nocase
        $reg_2 = "Software\\Classes\\mscfile" ascii wide nocase
        $reg_3 = "Environment" ascii wide
        $reg_4 = "shell\\open\\command" ascii wide

        // DLL hijacking paths
        $dll_1 = "System32\\sysprep" ascii wide
        $dll_2 = "wusa.exe" ascii wide nocase

        // CMSTP bypass
        $cmstp_1 = "cmstp" ascii wide nocase
        $cmstp_2 = ".inf" ascii wide
        $cmstp_3 = "/au" ascii wide

        // Mock trusted directories
        $mock_1 = "\\\\?\\" ascii wide
        $mock_2 = "WINDOWS \\System32" ascii wide  // Note the space

    condition:
        filesize < 5MB and
        (
            (any of ($autoelevate_*) and any of ($reg_*)) or
            (any of ($dll_*) and any of ($autoelevate_*)) or
            (all of ($cmstp_*)) or
            (any of ($mock_*))
        )
}

rule Evasion_Process_Hollowing {
    meta:
        author = "Detection Engineering Team"
        description = "Detects process hollowing/RunPE technique for code injection"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1055/012/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "evasion"

    strings:
        // API functions used in process hollowing
        $api_1 = "NtUnmapViewOfSection" ascii wide
        $api_2 = "ZwUnmapViewOfSection" ascii wide
        $api_3 = "NtSetContextThread" ascii wide
        $api_4 = "ZwSetContextThread" ascii wide
        $api_5 = "NtResumeThread" ascii wide
        $api_6 = "ResumeThread" ascii wide
        $api_7 = "SetThreadContext" ascii wide
        $api_8 = "WriteProcessMemory" ascii wide
        $api_9 = "VirtualAllocEx" ascii wide

        // Process creation in suspended state
        $suspended_1 = "CREATE_SUSPENDED" ascii wide
        $suspended_2 = { 68 04 00 00 00 }  // push 4 (CREATE_SUSPENDED)

        // RunPE indicators
        $runpe_1 = "RunPE" ascii wide nocase
        $runpe_2 = "ProcessHollowing" ascii wide nocase

    condition:
        filesize < 10MB and
        (
            (($api_1 or $api_2) and any of ($api_3, $api_4) and any of ($api_5, $api_6)) or
            (any of ($suspended_*) and $api_8 and $api_7) or
            (any of ($runpe_*))
        )
}

rule Evasion_DLL_Injection {
    meta:
        author = "Detection Engineering Team"
        description = "Detects DLL injection techniques including classic, APC, and reflective"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1055/001/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "evasion"

    strings:
        // Classic DLL injection APIs
        $api_1 = "VirtualAllocEx" ascii wide
        $api_2 = "WriteProcessMemory" ascii wide
        $api_3 = "CreateRemoteThread" ascii wide
        $api_4 = "NtCreateThreadEx" ascii wide
        $api_5 = "RtlCreateUserThread" ascii wide
        $api_6 = "LoadLibrary" ascii wide

        // APC injection
        $apc_1 = "QueueUserAPC" ascii wide
        $apc_2 = "NtQueueApcThread" ascii wide

        // SetWindowsHookEx injection
        $hook_1 = "SetWindowsHookEx" ascii wide
        $hook_2 = "WH_GETMESSAGE" ascii wide
        $hook_3 = "WH_KEYBOARD" ascii wide

        // Reflective DLL injection
        $reflective_1 = "ReflectiveLoader" ascii wide
        $reflective_2 = "reflective_dll" ascii wide nocase

        // Thread context manipulation
        $context_1 = "GetThreadContext" ascii wide
        $context_2 = "SetThreadContext" ascii wide

    condition:
        filesize < 10MB and
        (
            ($api_1 and $api_2 and ($api_3 or $api_4 or $api_5)) or
            (any of ($apc_*) and $api_1) or
            (any of ($hook_*)) or
            (any of ($reflective_*)) or
            (all of ($context_*) and $api_2)
        )
}

rule Evasion_Anti_Debug {
    meta:
        author = "Detection Engineering Team"
        description = "Detects anti-debugging techniques including API checks, PEB flags, and timing"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1622/"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "evasion"

    strings:
        // API-based anti-debug
        $api_1 = "IsDebuggerPresent" ascii wide
        $api_2 = "CheckRemoteDebuggerPresent" ascii wide
        $api_3 = "NtQueryInformationProcess" ascii wide
        $api_4 = "OutputDebugString" ascii wide
        $api_5 = "GetTickCount" ascii wide
        $api_6 = "QueryPerformanceCounter" ascii wide

        // PEB checks
        $peb_1 = "NtGlobalFlag" ascii wide
        $peb_2 = "BeingDebugged" ascii wide
        $peb_3 = { 64 A1 30 00 00 00 }  // mov eax, fs:[0x30]
        $peb_4 = { 65 48 8B 04 25 60 00 00 00 }  // mov rax, gs:[0x60]

        // Debug register checks
        $dreg_1 = "GetThreadContext" ascii wide
        $dreg_2 = { 0F 23 }  // mov dr*, reg

        // INT 2D / INT 3 tricks
        $int_1 = { CD 03 }  // INT 3
        $int_2 = { CD 2D }  // INT 2D

        // Timing checks
        $time_1 = "rdtsc" ascii
        $time_2 = { 0F 31 }  // rdtsc instruction

    condition:
        filesize < 10MB and
        (
            (3 of ($api_*)) or
            (2 of ($peb_*)) or
            (any of ($dreg_*) and any of ($peb_*)) or
            (any of ($int_*) and any of ($api_*)) or
            (any of ($time_*) and any of ($api_*))
        )
}

rule Evasion_Anti_VM {
    meta:
        author = "Detection Engineering Team"
        description = "Detects anti-VM/sandbox evasion techniques including vendor checks and CPUID"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1497/"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "evasion"

    strings:
        // VM vendor strings
        $vm_1 = "VMware" ascii wide nocase
        $vm_2 = "VirtualBox" ascii wide nocase
        $vm_3 = "VBOX" ascii wide
        $vm_4 = "Hyper-V" ascii wide nocase
        $vm_5 = "QEMU" ascii wide nocase
        $vm_6 = "Xen" ascii wide nocase

        // VM-specific registry keys
        $reg_1 = "SOFTWARE\\VMware, Inc." ascii wide nocase
        $reg_2 = "SOFTWARE\\Oracle\\VirtualBox" ascii wide nocase
        $reg_3 = "HARDWARE\\ACPI\\DSDT\\VBOX" ascii wide nocase

        // VM-specific processes
        $proc_1 = "vmtoolsd.exe" ascii wide nocase
        $proc_2 = "vmwaretray.exe" ascii wide nocase
        $proc_3 = "VBoxService.exe" ascii wide nocase
        $proc_4 = "VBoxTray.exe" ascii wide nocase

        // MAC address prefixes (VM vendors)
        $mac_1 = "00:0C:29" ascii wide  // VMware
        $mac_2 = "00:50:56" ascii wide  // VMware
        $mac_3 = "08:00:27" ascii wide  // VirtualBox

        // CPUID checks
        $cpuid_1 = { 0F A2 }  // cpuid instruction
        $cpuid_2 = "hypervisor" ascii wide nocase

        // Red pill / blue pill
        $pill_1 = { 0F 01 0D }  // sidt
        $pill_2 = { 0F 01 4D }  // sgdt

    condition:
        filesize < 10MB and
        (
            (3 of ($vm_*)) or
            (2 of ($reg_*)) or
            (2 of ($proc_*)) or
            (2 of ($mac_*)) or
            (any of ($cpuid_*) and any of ($vm_*)) or
            (any of ($pill_*) and any of ($vm_*))
        )
}

rule Evasion_Obfuscation_Strings {
    meta:
        author = "Detection Engineering Team"
        description = "Detects string obfuscation techniques including Base64, hex encoding, and concatenation"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1027/"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "evasion"

    strings:
        // Base64 encoded commands
        $b64_1 = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii
        $b64_decode_1 = "base64" ascii wide nocase
        $b64_decode_2 = "FromBase64String" ascii wide
        $b64_decode_3 = "atob" ascii

        // Hex encoded strings
        $hex_1 = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/ ascii
        $hex_2 = /0x[0-9a-fA-F]{2}(,\s*0x[0-9a-fA-F]{2}){10,}/ ascii

        // PowerShell obfuscation
        $ps_obf_1 = "-join" ascii wide
        $ps_obf_2 = "[char]" ascii wide
        $ps_obf_3 = "-replace" ascii wide
        $ps_obf_4 = "iex" ascii wide nocase
        $ps_obf_5 = "`" ascii  // backtick obfuscation

        // String concatenation abuse
        $concat_1 = /['"]\s*\+\s*['"]/ ascii
        $concat_2 = "concat(" ascii nocase
        $concat_3 = ".join(" ascii

        // Character code conversion
        $char_1 = "chr(" ascii nocase
        $char_2 = "String.fromCharCode" ascii
        $char_3 = "[System.Text.Encoding]" ascii wide

    condition:
        filesize < 5MB and
        (
            ($b64_1 and any of ($b64_decode_*)) or
            (any of ($hex_*)) or
            (3 of ($ps_obf_*)) or
            (any of ($concat_*) and any of ($char_*))
        )
}

rule Evasion_Code_Injection_Techniques {
    meta:
        author = "Detection Engineering Team"
        description = "Detects advanced code injection techniques including doppelganging, herpaderping, and atom bombing"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1055/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "evasion"

    strings:
        // Process doppelganging
        $doppel_1 = "NtCreateTransaction" ascii wide
        $doppel_2 = "NtCreateProcessEx" ascii wide
        $doppel_3 = "NtRollbackTransaction" ascii wide

        // Process herpaderping
        $herpa_1 = "NtCreateSection" ascii wide
        $herpa_2 = "NtCreateProcessEx" ascii wide
        $herpa_3 = "FlushFileBuffers" ascii wide

        // Atom bombing
        $atom_1 = "GlobalAddAtom" ascii wide
        $atom_2 = "GlobalGetAtomName" ascii wide
        $atom_3 = "NtQueueApcThread" ascii wide

        // Early bird injection
        $early_1 = "CREATE_SUSPENDED" ascii wide
        $early_2 = "QueueUserAPC" ascii wide
        $early_3 = "NtAlertResumeThread" ascii wide

        // Thread execution hijacking
        $hijack_1 = "SuspendThread" ascii wide
        $hijack_2 = "SetThreadContext" ascii wide
        $hijack_3 = "ResumeThread" ascii wide

        // Mockingjay
        $mock_1 = "RWX" ascii wide
        $mock_2 = "VirtualQuery" ascii wide
        $mock_3 = "memcpy" ascii wide

    condition:
        filesize < 10MB and
        (
            (all of ($doppel_*)) or
            (all of ($herpa_*)) or
            (all of ($atom_*)) or
            (all of ($early_*)) or
            (all of ($hijack_*))
        )
}

rule Evasion_Living_Off_The_Land {
    meta:
        author = "Detection Engineering Team"
        description = "Detects LOLBAS/LOLBIN usage patterns"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://lolbas-project.github.io/"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "evasion"

    strings:
        // Common LOLBAS binaries
        $lol_1 = "certutil" ascii wide nocase
        $lol_2 = "bitsadmin" ascii wide nocase
        $lol_3 = "mshta" ascii wide nocase
        $lol_4 = "regsvr32" ascii wide nocase
        $lol_5 = "rundll32" ascii wide nocase
        $lol_6 = "cscript" ascii wide nocase
        $lol_7 = "wscript" ascii wide nocase
        $lol_8 = "msiexec" ascii wide nocase
        $lol_9 = "installutil" ascii wide nocase
        $lol_10 = "regasm" ascii wide nocase
        $lol_11 = "regsvcs" ascii wide nocase
        $lol_12 = "cmstp" ascii wide nocase
        $lol_13 = "msconfig" ascii wide nocase
        $lol_14 = "msbuild" ascii wide nocase

        // Suspicious arguments
        $arg_1 = "-urlcache" ascii wide nocase
        $arg_2 = "/transfer" ascii wide nocase
        $arg_3 = "javascript:" ascii wide nocase
        $arg_4 = "vbscript:" ascii wide nocase
        $arg_5 = "/i:http" ascii wide nocase
        $arg_6 = "scrobj.dll" ascii wide nocase
        $arg_7 = "-decode" ascii wide nocase
        $arg_8 = "-encode" ascii wide nocase

        // Execution patterns
        $exec_1 = "/c " ascii wide
        $exec_2 = "/k " ascii wide
        $exec_3 = "-ep bypass" ascii wide nocase
        $exec_4 = "-nop" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (any of ($lol_*) and any of ($arg_*)) or
            (2 of ($lol_*) and any of ($exec_*))
        )
}

rule Evasion_Timestomping {
    meta:
        author = "Detection Engineering Team"
        description = "Detects timestomping/timestamp manipulation techniques"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1070/006/"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "evasion"

    strings:
        // Windows timestamp APIs
        $api_1 = "SetFileTime" ascii wide
        $api_2 = "NtSetInformationFile" ascii wide
        $api_3 = "SetFileInformationByHandle" ascii wide

        // PowerShell methods
        $ps_1 = "CreationTime" ascii wide
        $ps_2 = "LastWriteTime" ascii wide
        $ps_3 = "LastAccessTime" ascii wide
        $ps_4 = "[System.IO.File]::" ascii wide

        // Timestomp tools
        $tool_1 = "timestomp" ascii wide nocase
        $tool_2 = "SetMace" ascii wide nocase

        // Linux touch command abuse
        $linux_1 = "touch -d" ascii
        $linux_2 = "touch -t" ascii
        $linux_3 = "touch -r" ascii

    condition:
        filesize < 5MB and
        (
            (any of ($api_*) and 2 of ($ps_*)) or
            (any of ($tool_*)) or
            (2 of ($linux_*))
        )
}

rule Evasion_Log_Tampering {
    meta:
        author = "Detection Engineering Team"
        description = "Detects log tampering and clearing techniques for Windows and Linux"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1070/001/"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "evasion"

    strings:
        // Windows event log clearing
        $wevt_1 = "wevtutil" ascii wide nocase
        $wevt_2 = "cl " ascii wide  // clear
        $wevt_3 = "Clear-EventLog" ascii wide nocase

        // PowerShell log tampering
        $ps_1 = "Clear-EventLog" ascii wide
        $ps_2 = "Remove-EventLog" ascii wide
        $ps_3 = "Limit-EventLog" ascii wide

        // Log files
        $log_1 = "Security.evtx" ascii wide nocase
        $log_2 = "System.evtx" ascii wide nocase
        $log_3 = "Application.evtx" ascii wide nocase

        // Linux log clearing
        $linux_1 = "/var/log" ascii
        $linux_2 = "history -c" ascii
        $linux_3 = "rm -rf /var/log" ascii
        $linux_4 = "shred" ascii

        // USN journal
        $usn_1 = "fsutil usn deletejournal" ascii wide nocase
        $usn_2 = "UsnJrnl" ascii wide

    condition:
        filesize < 5MB and
        (
            (any of ($wevt_*) and any of ($log_*)) or
            (any of ($ps_*)) or
            (2 of ($linux_*)) or
            (any of ($usn_*))
        )
}

rule Evasion_Defense_Disabling {
    meta:
        author = "Detection Engineering Team"
        description = "Detects attempts to disable security defenses including Windows Defender and Firewall"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1562/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "evasion"

    strings:
        // Windows Defender
        $def_1 = "DisableRealtimeMonitoring" ascii wide nocase
        $def_2 = "DisableBehaviorMonitoring" ascii wide nocase
        $def_3 = "DisableOnAccessProtection" ascii wide nocase
        $def_4 = "Set-MpPreference" ascii wide nocase
        $def_5 = "Add-MpPreference" ascii wide nocase
        $def_6 = "DisableIOAVProtection" ascii wide nocase

        // Firewall
        $fw_1 = "netsh advfirewall" ascii wide nocase
        $fw_2 = "firewall set opmode disable" ascii wide nocase
        $fw_3 = "Set-NetFirewallProfile" ascii wide nocase

        // Services
        $svc_1 = "WinDefend" ascii wide
        $svc_2 = "MpsSvc" ascii wide  // Windows Firewall
        $svc_3 = "wscsvc" ascii wide  // Security Center
        $svc_4 = "sc stop" ascii wide nocase
        $svc_5 = "sc config" ascii wide nocase

        // Registry modifications
        $reg_1 = "DisableAntiSpyware" ascii wide nocase
        $reg_2 = "DisableAntiVirus" ascii wide nocase

        // Tamper protection
        $tamper_1 = "TamperProtection" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (2 of ($def_*)) or
            (2 of ($fw_*)) or
            (any of ($svc_*) and (any of ($def_*) or any of ($fw_*))) or
            (any of ($reg_*)) or
            ($tamper_1)
        )
}
