/*
    YARA Rules: Payload Signatures
    Purpose: Detect common payload patterns from offensive security tools
    Author: Detection Engineering Team
    Date: 2026-01-10

    Educational/CTF Training Resource
    These rules demonstrate detection techniques for common payload types
*/

rule Meterpreter_Reverse_TCP_Staged {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Metasploit Meterpreter reverse TCP staged payload"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://www.metasploit.com/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "payload"

    strings:
        // Meterpreter stage loading patterns
        $metsrv = "metsrv" ascii wide nocase
        $met_dll = "metsrv.dll" ascii wide nocase
        $met_ext = "ext_server" ascii wide

        // Reflective DLL injection markers
        $reflective_1 = "ReflectiveLoader" ascii wide
        $reflective_2 = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 00 00 }

        // Common Meterpreter strings
        $stdapi = "stdapi" ascii wide
        $priv = "priv" ascii wide
        $migrate = "core_migrate" ascii wide

        // Socket patterns for reverse connection
        $socket_pattern = { 6A 00 6A 01 6A 02 FF 15 }

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and  // PE or ELF
        filesize < 5MB and
        (
            ($metsrv or $met_dll) or
            (2 of ($met_*, $stdapi, $priv, $migrate)) or
            ($reflective_1 and $reflective_2)
        )
}

rule Meterpreter_Reverse_HTTPS {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Metasploit Meterpreter reverse HTTPS payload"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://www.metasploit.com/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "payload"

    strings:
        // HTTPS transport indicators
        $https_1 = "HttpSendRequest" ascii wide
        $https_2 = "InternetConnect" ascii wide
        $https_3 = "InternetOpen" ascii wide

        // Meterpreter HTTPS specific
        $transport = "reverse_https" ascii wide nocase
        $session = "SESSIONID=" ascii wide

        // WinINet API pattern
        $wininet = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? 50 FF 15 }

        // User-agent patterns commonly used
        $ua_1 = "Mozilla/4.0 (compatible; MSIE" ascii wide
        $ua_2 = "Mozilla/5.0" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 5MB and
        (
            all of ($https_*) or
            ($transport and any of ($https_*)) or
            (3 of them)
        )
}

rule Cobalt_Strike_Beacon {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Cobalt Strike Beacon payload signatures"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://www.cobaltstrike.com/"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "payload"

    strings:
        // Beacon configuration markers
        $beacon_config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }

        // Default sleep patterns
        $sleep_mask = { 48 8B ?? 48 31 ?? 48 31 ?? 48 8B }

        // Common beacon strings
        $str_1 = "%s (admin)" ascii wide
        $str_2 = "beacon.dll" ascii wide nocase
        $str_3 = "beacon.x64.dll" ascii wide nocase
        $str_4 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $str_5 = "ReflectiveLoader" ascii

        // Named pipe patterns
        $pipe_1 = "\\\\.\\pipe\\" ascii wide
        $pipe_2 = "MSSE-" ascii wide

        // DNS beacon markers
        $dns_1 = "cdn." ascii wide
        $dns_2 = "www6." ascii wide
        $dns_3 = "api." ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            $beacon_config or
            (2 of ($str_*)) or
            ($sleep_mask and any of ($str_*)) or
            (any of ($str_*) and any of ($pipe_*))
        )
}

rule Generic_Reverse_Shell_Windows {
    meta:
        author = "Detection Engineering Team"
        description = "Detects generic Windows reverse shell payloads"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "payload"

    strings:
        // Common reverse shell patterns
        $cmd_1 = "cmd.exe" ascii wide nocase
        $cmd_2 = "powershell.exe" ascii wide nocase
        $cmd_3 = "cmd /c" ascii wide nocase

        // Socket API calls
        $ws_1 = "WSAStartup" ascii
        $ws_2 = "WSASocket" ascii
        $ws_3 = "connect" ascii
        $ws_4 = "send" ascii
        $ws_5 = "recv" ascii

        // Process creation
        $proc_1 = "CreateProcess" ascii
        $proc_2 = "CreatePipe" ascii

        // Hex patterns for shell spawning with redirected I/O
        $shell_spawn = { 68 00 00 00 00 68 01 01 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (
            (any of ($cmd_*) and 3 of ($ws_*)) or
            (any of ($cmd_*) and all of ($proc_*)) or
            ($shell_spawn and any of ($cmd_*))
        )
}

rule Generic_Reverse_Shell_Linux {
    meta:
        author = "Detection Engineering Team"
        description = "Detects generic Linux reverse shell payloads"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "payload"

    strings:
        // Shell binaries
        $shell_1 = "/bin/sh" ascii
        $shell_2 = "/bin/bash" ascii
        $shell_3 = "/bin/zsh" ascii

        // Socket syscalls in shellcode
        $syscall_socket = { B8 29 00 00 00 }  // socket syscall
        $syscall_connect = { B8 2A 00 00 00 }  // connect syscall
        $syscall_dup2 = { B8 21 00 00 00 }     // dup2 syscall
        $syscall_execve = { B8 3B 00 00 00 }   // execve syscall

        // Common pattern: dup2 loop for stdin/stdout/stderr
        $dup2_loop = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 }

        // Netcat-style connection
        $nc_pattern = "nc -e" ascii

    condition:
        (uint32(0) == 0x464c457f) and  // ELF
        filesize < 1MB and
        (
            (any of ($shell_*) and 2 of ($syscall_*)) or
            $dup2_loop or
            $nc_pattern
        )
}

rule Python_Reverse_Shell {
    meta:
        author = "Detection Engineering Team"
        description = "Detects Python reverse shell scripts"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "payload"

    strings:
        // Python reverse shell patterns
        $import_1 = "import socket" ascii
        $import_2 = "import subprocess" ascii
        $import_3 = "import os" ascii

        // Socket connection
        $socket_1 = "socket.socket" ascii
        $socket_2 = ".connect(" ascii

        // Command execution
        $exec_1 = "subprocess.Popen" ascii
        $exec_2 = "subprocess.call" ascii
        $exec_3 = "os.system" ascii
        $exec_4 = "os.popen" ascii

        // Shell specification
        $shell_1 = "/bin/sh" ascii
        $shell_2 = "/bin/bash" ascii
        $shell_3 = "cmd.exe" ascii wide

        // Pipe redirection patterns
        $redirect_1 = "stdin=subprocess" ascii
        $redirect_2 = "stdout=subprocess" ascii
        $redirect_3 = "stderr=subprocess" ascii

        // Common reverse shell one-liner patterns
        $oneliner_1 = "socket.SOCK_STREAM" ascii
        $oneliner_2 = "dup2" ascii

    condition:
        filesize < 100KB and
        (
            (all of ($import_*) and any of ($socket_*) and any of ($exec_*)) or
            (2 of ($import_*) and any of ($redirect_*)) or
            ($socket_1 and $socket_2 and any of ($shell_*))
        )
}

rule PowerShell_Download_Execute {
    meta:
        author = "Detection Engineering Team"
        description = "Detects PowerShell download and execute patterns (download cradles)"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "payload"

    strings:
        // Download cradles
        $dl_1 = "DownloadString" ascii wide nocase
        $dl_2 = "DownloadFile" ascii wide nocase
        $dl_3 = "DownloadData" ascii wide nocase
        $dl_4 = "Invoke-WebRequest" ascii wide nocase
        $dl_5 = "Net.WebClient" ascii wide nocase
        $dl_6 = "wget" ascii wide nocase
        $dl_7 = "curl" ascii wide nocase
        $dl_8 = "Start-BitsTransfer" ascii wide nocase

        // Execution patterns
        $exec_1 = "Invoke-Expression" ascii wide nocase
        $exec_2 = "IEX" ascii wide
        $exec_3 = "-enc" ascii wide nocase
        $exec_4 = "-encodedcommand" ascii wide nocase
        $exec_5 = "FromBase64String" ascii wide

        // Obfuscation indicators
        $obf_1 = "-join" ascii wide
        $obf_2 = "[char]" ascii wide
        $obf_3 = "-replace" ascii wide
        $obf_4 = "-split" ascii wide

        // Bypass attempts
        $bypass_1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass_2 = "-ep bypass" ascii wide nocase
        $bypass_3 = "Set-ExecutionPolicy" ascii wide nocase

    condition:
        filesize < 1MB and
        (
            (any of ($dl_*) and any of ($exec_*)) or
            (any of ($exec_*) and 2 of ($obf_*)) or
            (any of ($bypass_*) and any of ($exec_*))
        )
}

rule Webshell_Generic {
    meta:
        author = "Detection Engineering Team"
        description = "Detects generic webshell patterns (PHP, ASP, JSP)"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "critical"
        category = "payload"

    strings:
        // PHP webshell patterns
        $php_1 = "<?php" ascii nocase
        $php_exec_1 = "eval(" ascii nocase
        $php_exec_2 = "assert(" ascii nocase
        $php_exec_3 = "system(" ascii nocase
        $php_exec_4 = "exec(" ascii nocase
        $php_exec_5 = "shell_exec(" ascii nocase
        $php_exec_6 = "passthru(" ascii nocase
        $php_exec_7 = "popen(" ascii nocase
        $php_exec_8 = "proc_open(" ascii nocase

        // Parameter access
        $param_1 = "$_GET" ascii
        $param_2 = "$_POST" ascii
        $param_3 = "$_REQUEST" ascii
        $param_4 = "$_COOKIE" ascii

        // Base64 decoding
        $decode_1 = "base64_decode" ascii nocase
        $decode_2 = "gzinflate" ascii nocase
        $decode_3 = "gzuncompress" ascii nocase
        $decode_4 = "str_rot13" ascii nocase

        // ASP/ASPX webshell patterns
        $asp_1 = "Request.Form" ascii nocase
        $asp_2 = "Request.QueryString" ascii nocase
        $asp_exec = "Execute(" ascii nocase

        // JSP webshell patterns
        $jsp_1 = "Runtime.getRuntime().exec" ascii
        $jsp_2 = "ProcessBuilder" ascii

    condition:
        filesize < 500KB and
        (
            // PHP webshell
            ($php_1 and any of ($php_exec_*) and any of ($param_*)) or
            ($php_1 and any of ($decode_*) and any of ($php_exec_*)) or
            // ASP webshell
            (any of ($asp_*) and $asp_exec) or
            // JSP webshell
            (any of ($jsp_*))
        )
}

rule Dropper_Generic {
    meta:
        author = "Detection Engineering Team"
        description = "Detects generic dropper/loader patterns including resource extraction and temp file creation"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "payload"

    strings:
        // Resource extraction
        $res_1 = "FindResource" ascii
        $res_2 = "LoadResource" ascii
        $res_3 = "LockResource" ascii

        // File writing
        $file_1 = "WriteFile" ascii
        $file_2 = "CreateFile" ascii

        // Temp paths
        $temp_1 = "GetTempPath" ascii
        $temp_2 = "%TEMP%" ascii wide
        $temp_3 = "\\Temp\\" ascii wide
        $temp_4 = "\\AppData\\Local\\Temp" ascii wide

        // Process execution
        $exec_1 = "CreateProcess" ascii
        $exec_2 = "ShellExecute" ascii
        $exec_3 = "WinExec" ascii

        // Registry persistence
        $reg_1 = "RegSetValue" ascii
        $reg_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

        // Self-delete patterns
        $del_1 = "DeleteFile" ascii
        $del_2 = ":Zone.Identifier" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($res_*) and any of ($file_*) and any of ($exec_*)) or
            (any of ($temp_*) and any of ($file_*) and any of ($exec_*)) or
            (any of ($reg_*) and any of ($exec_*)) or
            (any of ($del_*) and any of ($exec_*) and any of ($temp_*))
        )
}

rule Payload_XOR_Encoded {
    meta:
        author = "Detection Engineering Team"
        description = "Detects XOR-encoded payload patterns with decoding loops"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "payload"

    strings:
        // XOR decoding loops (x86)
        $xor_loop_1 = { 31 ?? 83 ?? ?? 72 ?? }  // xor, add/sub, jb
        $xor_loop_2 = { 80 3? ?? 74 ?? 80 3? ?? }  // XOR key checking
        $xor_loop_3 = { 30 ?? 40 3D ?? ?? ?? ?? 72 }  // xor byte ptr, inc, cmp, jb

        // XOR decoding loops (x64)
        $xor_loop_64_1 = { 48 31 ?? 48 83 ?? ?? 72 }
        $xor_loop_64_2 = { 44 30 ?? 48 FF ?? 48 3D }

        // Common XOR keys (single byte)
        $xor_key_41 = { 34 41 }  // XOR with 0x41 ('A')
        $xor_key_ff = { 34 FF }  // XOR with 0xFF

        // Suspicious entropy regions (placeholder - would need YARA module)
        $high_entropy = /[\x80-\xff]{100,}/

    condition:
        filesize < 5MB and
        (
            any of ($xor_loop_*) or
            (any of ($xor_key_*) and $high_entropy)
        )
}
