/*
    YARA Rules: Shellcode Patterns
    Purpose: Detect encoded and raw shellcode patterns
    Author: Detection Engineering Team
    Date: 2026-01-10

    Educational/CTF Training Resource
    These rules demonstrate detection of shellcode encoding techniques
*/

rule Shellcode_Windows_x86_Egghunter {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Windows x86 egghunter shellcode"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "shellcode"

    strings:
        // NtAccessCheckAndAuditAlarm egghunter
        $egg_nt = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 }

        // SEH-based egghunter
        $egg_seh = { EB 21 59 B8 ?? ?? ?? ?? 51 6A FF }

        // IsBadReadPtr egghunter
        $egg_bad = { 66 81 CA FF 0F 42 52 6A 08 59 }

        // Common egg patterns (w00t, t00w)
        $egg_marker_1 = "w00tw00t"
        $egg_marker_2 = { 77 30 30 74 77 30 30 74 }

    condition:
        filesize < 100KB and
        (
            any of ($egg_nt, $egg_seh, $egg_bad) or
            any of ($egg_marker_*)
        )
}

rule Shellcode_Windows_x86_Reverse_Shell {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Windows x86 reverse shell shellcode patterns"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "shellcode"

    strings:
        // WSAStartup hash
        $api_wsastartup = { 68 33 32 00 00 68 77 73 32 5F }  // push 'ws2_32'

        // Socket creation pattern
        $socket_create = { 6A 00 6A 01 6A 02 }  // push 0, push 1, push 2 (socket params)

        // Connect pattern with sockaddr_in setup
        $connect = { 68 ?? ?? ?? ?? 68 02 00 ?? ?? }  // push IP, push AF_INET + port

        // CreateProcess with cmd.exe
        $cmd_1 = { 63 6D 64 00 }  // 'cmd\0'
        $cmd_2 = { 63 6D 64 2E 65 78 65 }  // 'cmd.exe'

        // STARTUPINFO with redirected handles
        $startup = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 01 }

        // Common function resolution via PEB
        $peb_access = { 64 A1 30 00 00 00 }  // mov eax, fs:[0x30] - PEB access
        $peb_ldr = { 8B 40 0C 8B 40 14 }     // Navigate to InMemoryOrderModuleList

    condition:
        filesize < 50KB and
        (
            ($api_wsastartup and $socket_create) or
            ($connect and any of ($cmd_*)) or
            ($peb_access and $peb_ldr and any of ($cmd_*))
        )
}

rule Shellcode_Windows_x64_Reverse_Shell {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Windows x64 reverse shell shellcode patterns"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "shellcode"

    strings:
        // x64 PEB access via GS segment
        $peb_x64 = { 65 48 8B 04 25 60 00 00 00 }  // mov rax, gs:[0x60]

        // x64 syscall pattern
        $syscall = { 0F 05 }

        // x64 socket creation (Winsock)
        $socket_x64 = { 48 31 C9 48 31 D2 41 B8 01 00 00 00 }

        // x64 stack string construction for ws2_32
        $ws2_string = { 48 B8 77 73 32 5F 33 32 00 00 }

        // Common x64 shellcode prologue
        $prologue = { 48 83 EC ?? 48 89 ?? 48 89 ?? }

        // API hashing routine (ROR13)
        $hash_ror13 = { C1 CF 0D 01 C7 }  // ror edi, 0xd; add edi, eax

    condition:
        filesize < 50KB and
        (
            ($peb_x64 and $hash_ror13) or
            ($peb_x64 and $syscall) or
            ($socket_x64 and any of ($ws2_*, $prologue))
        )
}

rule Shellcode_Linux_x86_Reverse_Shell {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Linux x86 reverse shell shellcode"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "shellcode"

    strings:
        // int 0x80 syscall
        $int80 = { CD 80 }

        // socket syscall (sys_socketcall = 102)
        $socket_call = { 6A 66 58 }  // push 0x66; pop eax

        // dup2 loop for fd redirection
        $dup2_loop = { 6A 03 59 6A 3F 58 CD 80 49 79 }

        // execve /bin/sh
        $execve_1 = { 68 6E 2F 73 68 68 2F 2F 62 69 }  // push '//bin/sh'
        $execve_2 = { 6A 0B 58 }  // push 0xb; pop eax (execve)

        // Connect with sockaddr_in
        $connect = { 66 68 ?? ?? 66 6A 02 }  // port and AF_INET

    condition:
        filesize < 10KB and
        (
            (#int80 >= 3 and $socket_call) or
            ($dup2_loop and any of ($execve_*)) or
            ($connect and any of ($execve_*))
        )
}

rule Shellcode_Linux_x64_Reverse_Shell {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Linux x64 reverse shell shellcode"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "shellcode"

    strings:
        // syscall instruction
        $syscall = { 0F 05 }

        // socket syscall (41 = 0x29)
        $sys_socket = { 6A 29 58 }  // push 0x29; pop rax
        $sys_socket_2 = { B8 29 00 00 00 }  // mov eax, 0x29

        // connect syscall (42 = 0x2a)
        $sys_connect = { 6A 2A 58 }  // push 0x2a; pop rax

        // dup2 syscall (33 = 0x21)
        $sys_dup2 = { 6A 21 58 }  // push 0x21; pop rax

        // execve syscall (59 = 0x3b)
        $sys_execve = { 6A 3B 58 }  // push 0x3b; pop rax
        $sys_execve_2 = { B8 3B 00 00 00 }

        // /bin/sh string construction
        $binsh_1 = { 48 BB 2F 62 69 6E 2F 73 68 00 }  // movabs rbx, '/bin/sh\0'
        $binsh_2 = { 68 2F 73 68 00 68 2F 62 69 6E }  // push construction

        // x64 dup2 loop
        $dup2_loop = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 }

    condition:
        filesize < 10KB and
        (
            (#syscall >= 3 and $sys_socket and $sys_connect) or
            ($dup2_loop and any of ($sys_execve*)) or
            (any of ($binsh_*) and 2 of ($sys_*))
        )
}

rule Shellcode_Encoded_XOR {
    meta:
        author = "Detection Engineering Team"
        description = "Detects XOR-encoded shellcode with decoder stub"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "shellcode"

    strings:
        // x86 XOR decoder stubs
        $decoder_1 = { EB ?? 5? 31 C9 B1 ?? 80 ?? ?? ?? ?? E2 }  // jmp-call-pop XOR
        $decoder_2 = { 31 C9 ?? B1 ?? 80 3? ?? 74 }              // XOR until null
        $decoder_3 = { D9 74 24 F4 5? 29 C9 B1 ?? 31 }          // fnstenv GetPC

        // x64 XOR decoder stubs
        $decoder_x64_1 = { 48 31 C9 48 81 E9 ?? ?? ?? ?? 48 8D 05 }
        $decoder_x64_2 = { EB ?? 58 48 31 C9 48 FF C1 80 34 08 }

        // Common XOR key applications
        $xor_apply_1 = { 30 ?? 40 }  // xor byte, inc
        $xor_apply_2 = { 80 3? ?? ?? }  // xor [reg+offset], imm8

        // GetPC techniques
        $getpc_call = { E8 00 00 00 00 }  // call $+5
        $getpc_fpu = { D9 EE D9 74 24 F4 }  // fldz; fnstenv

    condition:
        filesize < 50KB and
        (
            any of ($decoder_*) or
            (any of ($xor_apply_*) and any of ($getpc_*))
        )
}

rule Shellcode_Encoded_AlphaNumeric {
    meta:
        author = "Detection Engineering Team"
        description = "Detects alphanumeric encoded shellcode"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "shellcode"

    strings:
        // Alpha2 encoder patterns
        $alpha2_1 = { 56 54 58 36 33 }  // VTX63 - common alpha2 start
        $alpha2_2 = { 68 30 30 30 30 58 }  // hAAAAX - push/pop pattern

        // Mixed alpha encoder
        $mixed_alpha = /[A-Za-z0-9]{50,}/ ascii

        // Common alphanumeric patterns
        $pattern_1 = "PYIIII" ascii  // Alpha2 baseaddress
        $pattern_2 = "jAXP0A0" ascii  // Common alpha pattern
        $pattern_3 = "TYIIIIII" ascii

        // Venetian shellcode patterns
        $venetian = { 00 ?? 00 ?? 00 ?? 00 ?? }

    condition:
        filesize < 100KB and
        (
            any of ($alpha2_*) or
            any of ($pattern_*) or
            ($mixed_alpha and filesize < 10KB)
        )
}

rule Shellcode_Encoded_Base64 {
    meta:
        author = "Detection Engineering Team"
        description = "Detects base64-encoded shellcode patterns"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "shellcode"

    strings:
        // Base64 encoded MZ header
        $b64_mz = "TVqQAA" ascii  // Base64 of 'MZ\x90\x00'
        $b64_mz_2 = "TVpQAA" ascii
        $b64_mz_3 = "TVoAAA" ascii

        // Base64 encoded ELF header
        $b64_elf = "f0VMR" ascii  // Base64 of '\x7fELF'

        // Base64 encoded common shellcode starts
        $b64_shell_1 = "/OiJA" ascii  // Common meterpreter start
        $b64_shell_2 = "6VZq" ascii

        // Base64 decoding in various languages
        $decode_ps = "FromBase64String" ascii wide nocase
        $decode_py = "base64.b64decode" ascii
        $decode_rb = "Base64.decode64" ascii
        $decode_js = "atob(" ascii

        // Large base64 blob pattern
        $large_b64 = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii

    condition:
        filesize < 1MB and
        (
            (any of ($b64_mz*) or any of ($b64_elf*) or any of ($b64_shell_*)) or
            (any of ($decode_*) and $large_b64)
        )
}

rule Shellcode_Staged_Loader {
    meta:
        author = "Detection Engineering Team"
        description = "Detects staged shellcode loader patterns"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "shellcode"

    strings:
        // VirtualAlloc for shellcode execution
        $va_1 = "VirtualAlloc" ascii wide
        $va_2 = { FF 15 ?? ?? ?? ?? [0-20] 89 ?? [0-10] C7 00 }

        // Memory protection change for execution
        $vp_1 = "VirtualProtect" ascii wide
        $vp_2 = { 68 40 00 00 00 }  // push PAGE_EXECUTE_READWRITE

        // Memory copy patterns
        $memcpy_1 = "RtlMoveMemory" ascii wide
        $memcpy_2 = { F3 A4 }  // rep movsb
        $memcpy_3 = { F3 A5 }  // rep movsd

        // Jump to shellcode
        $jmp_1 = { FF D0 }  // call eax
        $jmp_2 = { FF E0 }  // jmp eax
        $jmp_3 = { FF D3 }  // call ebx
        $jmp_4 = { FF 15 }  // call [addr]

        // CreateThread for shellcode
        $thread_1 = "CreateThread" ascii wide
        $thread_2 = "NtCreateThreadEx" ascii wide

        // Heap allocation alternative
        $heap_1 = "HeapAlloc" ascii wide
        $heap_2 = "HeapCreate" ascii wide

    condition:
        filesize < 1MB and
        (
            (any of ($va_*) and any of ($memcpy_*) and any of ($jmp_*)) or
            (any of ($vp_*) and any of ($jmp_*)) or
            (any of ($thread_*) and (any of ($va_*) or any of ($heap_*)))
        )
}

rule Shellcode_NOP_Sled {
    meta:
        author = "Detection Engineering Team"
        description = "Detects NOP sled patterns commonly used in exploits"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "shellcode"

    strings:
        // Classic x86 NOP sled
        $nop_classic = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

        // Alternative NOP equivalents (x86)
        $nop_alt_1 = { 41 41 41 41 41 41 41 41 }  // inc ecx (can act as NOP sled)
        $nop_alt_2 = { 43 43 43 43 43 43 43 43 }  // inc ebx
        $nop_alt_3 = { 4B 4B 4B 4B 4B 4B 4B 4B }  // dec ebx
        $nop_alt_4 = { 40 40 40 40 40 40 40 40 }  // inc eax

        // x64 NOP equivalents
        $nop_x64_1 = { 66 90 66 90 66 90 66 90 }  // 2-byte NOP
        $nop_x64_2 = { 0F 1F 00 0F 1F 00 0F 1F 00 }  // multi-byte NOP

    condition:
        filesize < 1MB and
        (
            #nop_classic >= 2 or
            any of ($nop_alt_*) or
            any of ($nop_x64_*)
        )
}

rule Shellcode_Metasploit_Shikata {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Metasploit shikata_ga_nai encoder"
        date = "2026-01-10"
        version = "1.0"
        reference = "Shikata Ga Nai polymorphic XOR encoder"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "shellcode"

    strings:
        // FPU GetPC + XOR decoder pattern
        $shikata_1 = { D9 74 24 F4 5? 29 C9 B1 ?? 31 ?? 17 83 ?? 04 03 }
        $shikata_2 = { D9 EE D9 74 24 F4 5? 29 C9 B1 }

        // Alternative shikata patterns
        $shikata_3 = { DA ?? D9 74 24 F4 58 29 C9 B1 ?? 31 ?? 13 }
        $shikata_4 = { D9 E8 D9 74 24 F4 5? B? ?? 29 C9 B1 }

        // Common shikata FPU instructions
        $fpu_1 = { D9 74 24 F4 }  // fnstenv [esp-0xc]
        $fpu_2 = { D9 EE }        // fldz
        $fpu_3 = { D9 E8 }        // fld1

    condition:
        filesize < 50KB and
        (
            any of ($shikata_*) or
            (any of ($fpu_*) and filesize < 5KB)
        )
}

rule Shellcode_Cobalt_Strike_Beacon {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Cobalt Strike beacon shellcode patterns"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "shellcode"

    strings:
        // Beacon shellcode start patterns
        $beacon_start_1 = { FC E8 ?? 00 00 00 }  // cld; call
        $beacon_start_2 = { FC 48 83 E4 F0 E8 }  // cld; and rsp,-10h; call

        // API hashing (common in beacon)
        $hash_kernel32 = { 68 8E 4E 0E EC }  // hash for kernel32.dll
        $hash_ntdll = { 68 3C B3 71 A9 }     // hash for ntdll.dll

        // Beacon configuration block
        $config = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 }

        // Sleep mask deobfuscation
        $sleep_mask = { 4C 8B DC 49 89 5B 08 49 89 73 10 57 48 83 EC 40 }

        // x64 beacon loader
        $x64_loader = { 41 B8 ?? ?? ?? ?? 48 8D ?? ?? 41 B9 ?? ?? 00 00 }

    condition:
        filesize < 1MB and
        (
            any of ($beacon_start_*) or
            (any of ($hash_*) and $config) or
            $sleep_mask or
            $x64_loader
        )
}

rule Shellcode_Process_Injection_Setup {
    meta:
        author = "Detection Engineering Team"
        description = "Detects shellcode preparing for process injection"
        date = "2026-01-10"
        version = "1.0"
        tlp = "amber"
        confidence = "medium"
        severity = "critical"
        category = "shellcode"

    strings:
        // OpenProcess for injection target
        $open_proc = "OpenProcess" ascii wide
        $open_proc_hex = { 68 FF 0F 1F 00 }  // PROCESS_ALL_ACCESS

        // VirtualAllocEx for remote allocation
        $va_ex = "VirtualAllocEx" ascii wide

        // WriteProcessMemory
        $wpm = "WriteProcessMemory" ascii wide

        // CreateRemoteThread
        $crt = "CreateRemoteThread" ascii wide

        // NtCreateThreadEx (ntdll)
        $ntcte = "NtCreateThreadEx" ascii wide

        // QueueUserAPC
        $apc = "QueueUserAPC" ascii wide

        // Process hollowing indicators
        $hollow_1 = "NtUnmapViewOfSection" ascii wide
        $hollow_2 = "ZwUnmapViewOfSection" ascii wide

    condition:
        filesize < 5MB and
        (
            ($open_proc and $va_ex and $wpm and ($crt or $ntcte)) or
            (any of ($hollow_*) and $wpm) or
            ($apc and any of ($open_proc*))
        )
}
