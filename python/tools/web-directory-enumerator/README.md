# Web Directory Enumerator

Stealthy web directory and file enumeration tool for authorized penetration testing.

## Overview

This tool performs web content discovery by testing for the presence of directories and files using wordlist-based enumeration. Features intelligent 404 detection, configurable filtering, and operational security options.

## Features

- **Built-in Wordlist**: Ready to use with common paths
- **Extension Bruteforcing**: Append extensions to all words
- **Soft 404 Detection**: Baseline calibration to detect custom error pages
- **Response Filtering**: Filter by status code and content length
- **Custom Headers/Cookies**: Full request customization
- **Stealth Options**: Configurable delays and rate limiting
- **In-Memory Results**: Minimal disk artifacts

## Installation

No external dependencies required. Uses Python 3.6+ standard library.

```bash
python3 --version
chmod +x tool.py
```

## Usage

### Basic Usage

```bash
# Use built-in wordlist
python3 tool.py http://target.com

# Preview operation
python3 tool.py http://target.com --plan

# With custom wordlist
python3 tool.py http://target.com -w /path/to/wordlist.txt
```

### Advanced Options

```bash
# Add extensions
python3 tool.py http://target.com -x php,html,txt

# Custom status codes
python3 tool.py http://target.com -s 200,301,403

# With authentication cookie
python3 tool.py http://target.com -c "session=abc123"

# Custom headers
python3 tool.py http://target.com -H "Authorization: Bearer token"

# Stealth mode with delays
python3 tool.py http://target.com --delay-min 1 --delay-max 3 -t 5
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| url | - | Required | Target URL |
| --wordlist | -w | built-in | Path to wordlist file |
| --extensions | -x | None | Extensions to append (comma-separated) |
| --threads | -t | 10 | Concurrent threads |
| --timeout | - | 10.0 | Request timeout (seconds) |
| --delay-min | - | 0.0 | Minimum delay between requests |
| --delay-max | - | 0.1 | Maximum delay between requests |
| --status-codes | -s | 200,201,204,301,302,307,401,403 | Codes to report |
| --exclude-codes | -e | None | Codes to exclude |
| --exclude-length | - | None | Content lengths to exclude |
| --header | -H | None | Custom header (repeatable) |
| --cookie | -c | None | Cookies to include |
| --user-agent | -a | Mozilla/5.0... | Custom User-Agent |
| --plan | -p | False | Show execution plan |
| --verbose | -v | False | Verbose output |
| --output | -o | None | Output file (JSON) |

## Output Format

### Console Output
```
[*] Web Directory Enumerator starting...
[*] Target: http://target.com
[*] Wordlist: 50 entries
[*] Calibrating baseline response...
[+] admin (301 -> /admin/) [0b]
[+] login (200) [4523b]
[+] robots.txt (200) [125b]

======================================================================
ENUMERATION RESULTS
======================================================================
Total requests:   150
Interesting:      3

STATUS   SIZE       PATH                                     REDIRECT
----------------------------------------------------------------------
200      4523       login                                    -
200      125        robots.txt                               -
301      0          admin                                    /admin/
```

## Wordlist Format

One path per line. Lines starting with # are ignored.

```
# Admin paths
admin
administrator
login

# Backup files
backup
backup.sql
database.sql
```

## Programmatic Usage

```python
from tool import DirectoryEnumerator, EnumConfig

config = EnumConfig(
    target_url="http://target.com",
    wordlist=["admin", "login", "backup"],
    extensions=[".php", ".html"],
    threads=5,
    verbose=True
)

enumerator = DirectoryEnumerator(config)
results = enumerator.enumerate()

for result in results:
    print(f"{result.status_code} - {result.path}")
```

## Operational Security Notes

1. **Logging**: All requests are logged by web servers
2. **WAF Detection**: Web Application Firewalls may block enumeration
3. **Rate Limiting**: Use delays to avoid triggering protection
4. **User-Agent**: Customize to blend with normal traffic

## Version History

- **1.0.0**: Initial release with core enumeration features
