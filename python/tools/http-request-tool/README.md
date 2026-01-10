# HTTP Request Tool

Flexible HTTP client for security testing and API interaction.

## Overview

This tool provides a command-line HTTP client for crafting custom requests, testing endpoints, and analyzing responses. Supports custom methods, headers, body data, and SSL options.

## Features

- **Custom HTTP Methods**: GET, POST, PUT, DELETE, PATCH, OPTIONS, etc.
- **Custom Headers**: Add any headers to requests
- **Request Body**: From argument or file
- **SSL/TLS**: Certificate inspection, optional verification skip
- **Redirects**: Configurable redirect following
- **Response Timing**: Measure request duration

## Usage

```bash
# Simple GET request
python3 tool.py http://target.com

# POST with data
python3 tool.py http://target.com/api -X POST -d '{"key":"value"}'

# Custom headers
python3 tool.py https://target.com -H "Authorization: Bearer token"

# Follow redirects
python3 tool.py http://target.com -L

# Skip SSL verification
python3 tool.py https://target.com -k
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| url | - | Required | Target URL |
| --method | -X | GET | HTTP method |
| --header | -H | - | Custom header (repeatable) |
| --data | -d | - | Request body |
| --data-file | -f | - | File containing body |
| --follow-redirects | -L | False | Follow redirects |
| --insecure | -k | False | Skip SSL verification |
| --timeout | - | 30.0 | Request timeout |
| --raw | -r | False | Raw output (body only) |
| --plan | -p | False | Show execution plan |
| --output | -o | - | Save body to file |

## Output Format

```
[*] GET https://example.com

============================================================
HTTP/200 OK
Response Time: 0.234s
============================================================

RESPONSE HEADERS:
----------------------------------------
  Content-Type: text/html; charset=UTF-8
  Content-Length: 1256
  Server: nginx/1.18.0

SSL CERTIFICATE:
----------------------------------------
  Subject: {'commonName': 'example.com'}
  Issuer: {'commonName': 'DigiCert'}
  Expires: Dec 15 23:59:59 2024 GMT

RESPONSE BODY (1256 bytes):
----------------------------------------
<!DOCTYPE html>
<html>
...
```

## Version History

- **1.0.0**: Initial release
