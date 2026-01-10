/*
    YARA Rules: Network Indicators
    Purpose: Detect network-based indicators in files and memory
    Author: Detection Engineering Team
    Date: 2026-01-10

    Educational/CTF Training Resource
    These rules detect patterns related to malicious network activity
*/

rule Network_C2_Beacon_Pattern {
    meta:
        author = "Detection Engineering Team"
        description = "Detects generic C2 beacon communication patterns including check-ins and task retrieval"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "network"

    strings:
        // Common C2 check-in patterns
        $checkin_1 = "checkin" ascii wide nocase
        $checkin_2 = "beacon" ascii wide nocase
        $checkin_3 = "heartbeat" ascii wide nocase
        $checkin_4 = "callback" ascii wide nocase

        // Task/command retrieval
        $task_1 = "gettask" ascii wide nocase
        $task_2 = "getjob" ascii wide nocase
        $task_3 = "taskresult" ascii wide nocase

        // Sleep/jitter patterns
        $sleep_1 = "sleeptime" ascii wide nocase
        $sleep_2 = "jitter" ascii wide nocase
        $sleep_3 = "interval" ascii wide nocase

        // Session identifiers
        $session_1 = /session[_-]?id/i ascii wide
        $session_2 = /agent[_-]?id/i ascii wide
        $session_3 = /beacon[_-]?id/i ascii wide

    condition:
        filesize < 5MB and
        (
            (2 of ($checkin_*) and any of ($task_*)) or
            (any of ($sleep_*) and any of ($session_*)) or
            (any of ($checkin_*) and any of ($session_*))
        )
}

rule Network_HTTP_Suspicious_Headers {
    meta:
        author = "Detection Engineering Team"
        description = "Detects suspicious HTTP header patterns commonly used in C2 communication"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "network"

    strings:
        // Suspicious custom headers often used by malware
        $header_1 = "X-Requested-With: XMLHttpRequest" ascii wide
        $header_2 = "X-Forwarded-For:" ascii wide
        $header_3 = "X-Custom-" ascii wide nocase

        // Common C2 header patterns
        $c2_header_1 = "X-Session:" ascii wide
        $c2_header_2 = "X-Token:" ascii wide
        $c2_header_3 = "X-Auth:" ascii wide
        $c2_header_4 = "X-Request-ID:" ascii wide

        // Cookie patterns with encoded data
        $cookie_1 = /Cookie: [A-Za-z0-9+\/=]{50,}/ ascii
        $cookie_2 = /Set-Cookie: [A-Za-z0-9+\/=]{50,}/ ascii

        // Suspicious user agents (generic patterns)
        $ua_1 = "Mozilla/4.0 (compatible; MSIE" ascii
        $ua_2 = "Mozilla/5.0 (Windows NT" ascii

        // HTTP methods often abused
        $method_1 = "PROPFIND" ascii
        $method_2 = "PROPPATCH" ascii

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_header_*)) or
            (any of ($cookie_*) and any of ($c2_header_*)) or
            (any of ($method_*) and any of ($header_*))
        )
}

rule Network_DNS_Tunneling_Indicators {
    meta:
        author = "Detection Engineering Team"
        description = "Detects DNS tunneling indicators including tools and encoding patterns"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "network"

    strings:
        // DNS tunneling tool strings
        $tool_1 = "dnscat" ascii wide nocase
        $tool_2 = "iodine" ascii wide nocase
        $tool_3 = "dns2tcp" ascii wide nocase

        // DNS record types used for tunneling
        $record_1 = "TXT record" ascii wide nocase
        $record_2 = "NULL record" ascii wide nocase
        $record_3 = "CNAME record" ascii wide nocase

        // Encoding patterns in DNS queries
        $encode_1 = /[a-z0-9]{50,}\.(com|net|org|info)/i ascii
        $encode_2 = /[0-9a-f]{32,}\./i ascii

        // DNS library patterns
        $lib_1 = "dns.resolver" ascii
        $lib_2 = "dnspython" ascii
        $lib_3 = "DnsQuery" ascii

        // Subdomain enumeration patterns
        $enum_1 = /[a-z]{1,3}\d{1,3}\.[a-z]+\./i ascii

    condition:
        filesize < 5MB and
        (
            (any of ($tool_*)) or
            (any of ($record_*) and any of ($lib_*)) or
            (any of ($encode_*) and any of ($lib_*))
        )
}

rule Network_Reverse_Shell_Connection {
    meta:
        author = "Detection Engineering Team"
        description = "Detects reverse shell network connection patterns and netcat usage"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "high"
        severity = "critical"
        category = "network"

    strings:
        // IP:Port patterns (common C2 format)
        $ipport_1 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/ ascii wide

        // Common reverse shell ports (as strings)
        $port_1 = ":4444" ascii wide
        $port_2 = ":1337" ascii wide
        $port_3 = ":8080" ascii wide
        $port_4 = ":443" ascii wide
        $port_5 = ":80" ascii wide

        // Connection functions
        $conn_1 = "socket.connect" ascii
        $conn_2 = "WSAConnect" ascii
        $conn_3 = "connect(" ascii

        // Shell after connection
        $shell_1 = "/bin/sh" ascii wide
        $shell_2 = "/bin/bash" ascii wide
        $shell_3 = "cmd.exe" ascii wide

        // Netcat patterns
        $nc_1 = "nc -e" ascii wide
        $nc_2 = "nc -c" ascii wide
        $nc_3 = "ncat -e" ascii wide

    condition:
        filesize < 5MB and
        (
            ($ipport_1 and any of ($conn_*) and any of ($shell_*)) or
            (any of ($nc_*)) or
            (any of ($port_*) and any of ($shell_*))
        )
}

rule Network_Exfiltration_Patterns {
    meta:
        author = "Detection Engineering Team"
        description = "Detects data exfiltration patterns including cloud upload and steganography"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "network"

    strings:
        // File upload patterns
        $upload_1 = "multipart/form-data" ascii wide
        $upload_2 = "Content-Disposition: form-data" ascii wide
        $upload_3 = "filename=" ascii wide

        // Base64 in URL/requests
        $b64_1 = /[A-Za-z0-9+\/]{100,}={0,2}/ ascii

        // Exfil tool indicators
        $tool_1 = "exfil" ascii wide nocase
        $tool_2 = "upload" ascii wide nocase
        $tool_3 = "sendfile" ascii wide nocase

        // Cloud storage patterns (common exfil targets)
        $cloud_1 = "amazonaws.com" ascii wide nocase
        $cloud_2 = "storage.googleapis.com" ascii wide nocase
        $cloud_3 = "blob.core.windows.net" ascii wide nocase
        $cloud_4 = "dropbox.com" ascii wide nocase
        $cloud_5 = "pastebin.com" ascii wide nocase

        // Steganography indicators
        $steg_1 = "steghide" ascii wide nocase
        $steg_2 = "openstego" ascii wide nocase

        // Archive creation for exfil
        $archive_1 = "ZipFile" ascii wide
        $archive_2 = "tarfile" ascii wide
        $archive_3 = "7z a" ascii wide

    condition:
        filesize < 10MB and
        (
            (any of ($upload_*) and $b64_1) or
            (any of ($tool_*) and any of ($cloud_*)) or
            (any of ($steg_*)) or
            (any of ($archive_*) and any of ($cloud_*))
        )
}

rule Network_Proxy_Tunnel_Config {
    meta:
        author = "Detection Engineering Team"
        description = "Detects proxy and tunnel configuration patterns including SOCKS, SSH, and ngrok"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "network"

    strings:
        // SOCKS proxy patterns
        $socks_1 = "SOCKS4" ascii wide
        $socks_2 = "SOCKS5" ascii wide
        $socks_3 = "socks://" ascii wide nocase

        // HTTP proxy patterns
        $proxy_1 = "http_proxy" ascii wide nocase
        $proxy_2 = "https_proxy" ascii wide nocase
        $proxy_3 = "CONNECT " ascii

        // SSH tunneling
        $ssh_1 = "-L " ascii  // Local port forward
        $ssh_2 = "-R " ascii  // Remote port forward
        $ssh_3 = "-D " ascii  // Dynamic port forward
        $ssh_4 = "ssh -" ascii

        // Ngrok and similar
        $tunnel_1 = "ngrok" ascii wide nocase
        $tunnel_2 = "localtunnel" ascii wide nocase
        $tunnel_3 = "serveo" ascii wide nocase

        // Chisel
        $chisel_1 = "chisel" ascii wide nocase
        $chisel_2 = "client" ascii wide
        $chisel_3 = "server" ascii wide

        // Port forwarding patterns
        $pf_1 = "portfwd" ascii wide nocase
        $pf_2 = "pivot" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (2 of ($socks_*)) or
            (any of ($ssh_*) and any of ($proxy_*)) or
            (any of ($tunnel_*)) or
            (any of ($chisel_*) and (any of ($socks_*) or any of ($proxy_*))) or
            (any of ($pf_*) and any of ($proxy_*))
        )
}

rule Network_SMB_Lateral_Movement {
    meta:
        author = "Detection Engineering Team"
        description = "Detects SMB lateral movement indicators including PsExec and WMI"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "high"
        severity = "high"
        category = "network"

    strings:
        // SMB share patterns
        $smb_1 = "\\\\$" ascii wide  // Admin shares
        $smb_2 = "\\C$" ascii wide
        $smb_3 = "\\ADMIN$" ascii wide
        $smb_4 = "\\IPC$" ascii wide

        // PsExec patterns
        $psexec_1 = "PSEXESVC" ascii wide
        $psexec_2 = "psexec" ascii wide nocase

        // WMI execution
        $wmi_1 = "Win32_Process" ascii wide
        $wmi_2 = "wmic" ascii wide nocase
        $wmi_3 = "wmiprvse" ascii wide

        // Remote service creation
        $svc_1 = "sc \\\\$" ascii wide
        $svc_2 = "CreateService" ascii wide
        $svc_3 = "OpenSCManager" ascii wide

        // Scheduled task creation
        $task_1 = "schtasks" ascii wide nocase
        $task_2 = "/create" ascii wide

        // Named pipe patterns for lateral movement
        $pipe_1 = "\\\\.\\pipe\\" ascii wide

    condition:
        filesize < 10MB and
        (
            (2 of ($smb_*)) or
            (any of ($psexec_*) and any of ($smb_*)) or
            (any of ($wmi_*) and any of ($smb_*)) or
            (any of ($svc_*) and any of ($smb_*)) or
            (any of ($task_*) and any of ($smb_*))
        )
}

rule Network_RDP_Indicators {
    meta:
        author = "Detection Engineering Team"
        description = "Detects RDP tunneling and abuse indicators"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "medium"
        category = "network"

    strings:
        // RDP ports
        $port_1 = ":3389" ascii wide
        $port_2 = "3389" ascii wide

        // RDP related strings
        $rdp_1 = "mstsc" ascii wide nocase
        $rdp_2 = "Remote Desktop" ascii wide nocase
        $rdp_3 = "TermService" ascii wide

        // RDP tunneling tools
        $tunnel_1 = "rdp2tcp" ascii wide nocase
        $tunnel_2 = "xfreerdp" ascii wide nocase
        $tunnel_3 = "rdesktop" ascii wide nocase

        // Credential extraction
        $cred_1 = "rdp_credentials" ascii wide nocase
        $cred_2 = "mstscpassword" ascii wide nocase

        // Registry keys related to RDP
        $reg_1 = "Terminal Server" ascii wide
        $reg_2 = "PortNumber" ascii wide
        $reg_3 = "fDenyTSConnections" ascii wide

    condition:
        filesize < 5MB and
        (
            (any of ($rdp_*) and any of ($tunnel_*)) or
            (any of ($cred_*)) or
            (any of ($port_*) and any of ($tunnel_*)) or
            (2 of ($reg_*))
        )
}

rule Network_Suspicious_Port_Patterns {
    meta:
        author = "Detection Engineering Team"
        description = "Detects suspicious port usage patterns commonly associated with malware"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "low"
        severity = "medium"
        category = "network"

    strings:
        // Common malware ports
        $port_1 = ":4444" ascii wide   // Metasploit default
        $port_2 = ":1337" ascii wide   // Leetspeak port
        $port_3 = ":31337" ascii wide  // Elite
        $port_4 = ":6666" ascii wide
        $port_5 = ":6667" ascii wide   // IRC
        $port_6 = ":9001" ascii wide   // Tor default
        $port_7 = ":9050" ascii wide   // Tor SOCKS
        $port_8 = ":8888" ascii wide
        $port_9 = ":1234" ascii wide
        $port_10 = ":5555" ascii wide
        $port_11 = ":7777" ascii wide

        // Port scanning indicators
        $scan_1 = "port scan" ascii wide nocase
        $scan_2 = "portscan" ascii wide nocase
        $scan_3 = "syn scan" ascii wide nocase
        $scan_4 = "masscan" ascii wide nocase

        // Socket binding patterns
        $bind_1 = "bind(" ascii
        $bind_2 = "listen(" ascii
        $bind_3 = "accept(" ascii

    condition:
        filesize < 5MB and
        (
            (3 of ($port_*)) or
            (any of ($scan_*)) or
            (2 of ($port_*) and any of ($bind_*))
        )
}

rule Network_TOR_Usage {
    meta:
        author = "Detection Engineering Team"
        description = "Detects TOR network usage indicators including .onion addresses and configuration"
        date = "2026-01-10"
        version = "1.0"
        reference = "https://www.torproject.org/"
        tlp = "amber"
        confidence = "high"
        severity = "medium"
        category = "network"

    strings:
        // TOR identification
        $tor_1 = ".onion" ascii wide
        $tor_2 = "torproject.org" ascii wide
        $tor_3 = "tor.exe" ascii wide nocase

        // TOR configuration
        $conf_1 = "torrc" ascii wide
        $conf_2 = "SocksPort" ascii wide
        $conf_3 = "ControlPort" ascii wide
        $conf_4 = "HiddenService" ascii wide

        // TOR ports
        $port_1 = ":9050" ascii wide
        $port_2 = ":9051" ascii wide
        $port_3 = ":9001" ascii wide

        // TOR browser
        $browser_1 = "Tor Browser" ascii wide
        $browser_2 = "torbrowser" ascii wide nocase

        // Stem (TOR controller)
        $stem_1 = "from stem" ascii
        $stem_2 = "stem.control" ascii

    condition:
        filesize < 10MB and
        (
            (2 of ($tor_*)) or
            (2 of ($conf_*)) or
            (any of ($tor_*) and any of ($port_*)) or
            (any of ($stem_*))
        )
}

rule Network_ICMP_Tunneling {
    meta:
        author = "Detection Engineering Team"
        description = "Detects ICMP tunneling indicators including common tools and raw socket usage"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "network"

    strings:
        // ICMP tunnel tools
        $tool_1 = "icmptunnel" ascii wide nocase
        $tool_2 = "ptunnel" ascii wide nocase
        $tool_3 = "icmpsh" ascii wide nocase
        $tool_4 = "icmp_shell" ascii wide nocase

        // ICMP related
        $icmp_1 = "ICMP" ascii wide
        $icmp_2 = "icmp_seq" ascii wide
        $icmp_3 = "echo request" ascii wide nocase
        $icmp_4 = "echo reply" ascii wide nocase

        // Raw socket patterns (needed for ICMP)
        $raw_1 = "SOCK_RAW" ascii
        $raw_2 = "IPPROTO_ICMP" ascii
        $raw_3 = "raw_socket" ascii

        // Ping flood patterns
        $flood_1 = "ping -f" ascii
        $flood_2 = "ping flood" ascii nocase

    condition:
        filesize < 5MB and
        (
            (any of ($tool_*)) or
            (any of ($icmp_*) and any of ($raw_*)) or
            (any of ($flood_*))
        )
}

rule Network_WebSocket_C2 {
    meta:
        author = "Detection Engineering Team"
        description = "Detects WebSocket-based C2 communication patterns"
        date = "2026-01-10"
        version = "1.0"
        reference = "internal"
        tlp = "amber"
        confidence = "medium"
        severity = "high"
        category = "network"

    strings:
        // WebSocket protocols
        $ws_1 = "ws://" ascii wide
        $ws_2 = "wss://" ascii wide
        $ws_3 = "websocket" ascii wide nocase

        // WebSocket upgrade
        $upgrade_1 = "Upgrade: websocket" ascii wide
        $upgrade_2 = "Connection: Upgrade" ascii wide
        $upgrade_3 = "Sec-WebSocket" ascii wide

        // C2 communication patterns over WS
        $c2_1 = "onmessage" ascii wide
        $c2_2 = "send(" ascii wide
        $c2_3 = "onopen" ascii wide
        $c2_4 = "onclose" ascii wide

        // Command execution over WebSocket
        $cmd_1 = "exec" ascii wide
        $cmd_2 = "shell" ascii wide
        $cmd_3 = "command" ascii wide

    condition:
        filesize < 5MB and
        (
            (any of ($ws_*) and any of ($upgrade_*) and any of ($c2_*)) or
            (any of ($ws_*) and any of ($cmd_*))
        )
}
