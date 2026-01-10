# DNS Enumerator

Comprehensive DNS enumeration and subdomain discovery tool for authorized penetration testing.

## Overview

This tool performs DNS reconnaissance including subdomain bruteforcing, zone transfer attempts, and record enumeration. Uses raw DNS protocol implementation for minimal dependencies and operational security.

## Features

- **Subdomain Bruteforcing**: Built-in and custom wordlist support
- **Zone Transfer**: Automatic AXFR attempts against nameservers
- **Record Enumeration**: A, AAAA, NS, MX, TXT, SOA, CNAME queries
- **Custom Nameserver**: Specify DNS server to query
- **Raw DNS Implementation**: No external dependencies
- **Stealth Options**: Configurable delays between queries

## Installation

No external dependencies required. Uses Python 3.6+ standard library.

```bash
python3 --version
chmod +x tool.py
```

## Usage

### Basic Usage

```bash
# Enumerate with built-in wordlist
python3 tool.py example.com

# Preview operation
python3 tool.py example.com --plan

# With zone transfer attempt
python3 tool.py example.com --zone-transfer
```

### Advanced Options

```bash
# Custom wordlist
python3 tool.py example.com -w subdomains.txt

# Specific record types
python3 tool.py example.com -r A,MX,TXT

# Custom nameserver
python3 tool.py example.com -n 8.8.4.4

# Stealth mode
python3 tool.py example.com --delay-min 1 --delay-max 3 -t 5
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| domain | - | Required | Target domain |
| --nameserver | -n | System | DNS server to use |
| --wordlist | -w | built-in | Subdomain wordlist |
| --record-types | -r | A,AAAA,CNAME | Record types to query |
| --zone-transfer | -z | False | Attempt zone transfer |
| --no-brute | - | False | Disable bruteforcing |
| --threads | -t | 10 | Concurrent threads |
| --timeout | - | 5.0 | Query timeout |
| --delay-min | - | 0.0 | Minimum delay |
| --delay-max | - | 0.1 | Maximum delay |
| --plan | -p | False | Show execution plan |
| --verbose | -v | False | Verbose output |
| --output | -o | - | Output file (JSON) |

## Output Format

### Console Output
```
[*] DNS Enumerator starting...
[*] Target: example.com
[*] Using nameserver: 8.8.8.8
[*] Querying base domain records...
[+] A: 93.184.216.34
[+] NS: a.iana-servers.net
[*] Bruteforcing 100 subdomains...
[+] www.example.com -> 93.184.216.34
[+] mail.example.com -> 93.184.216.35

======================================================================
DNS ENUMERATION RESULTS
======================================================================
Total records:      15
Unique IPs:         3
Subdomains found:   5

TYPE     NAME                                VALUE
----------------------------------------------------------------------
A        example.com                         93.184.216.34
A        www.example.com                     93.184.216.34
MX       example.com                         mail.example.com
NS       example.com                         a.iana-servers.net
```

## Wordlist Format

One subdomain per line. Lines starting with # are ignored.

```
# Common subdomains
www
mail
ftp
admin
portal
```

## Programmatic Usage

```python
from tool import DNSEnumerator, EnumConfig

config = EnumConfig(
    domain="example.com",
    wordlist=["www", "mail", "ftp", "admin"],
    zone_transfer=True,
    verbose=True
)

enumerator = DNSEnumerator(config)
results = enumerator.enumerate()

for record in results:
    print(f"{record.record_type}: {record.name} -> {record.value}")
```

## Zone Transfer Notes

Zone transfers (AXFR) can expose all DNS records if misconfigured:

1. Tool first queries NS records for the domain
2. Attempts AXFR against each nameserver
3. Most properly configured servers will refuse

Success indicates a DNS misconfiguration that should be reported.

## Operational Security Notes

1. **Query Logging**: All DNS queries are logged by DNS servers
2. **Rate Limiting**: High query volume may trigger limits
3. **Zone Transfer**: AXFR attempts are typically logged/alerted
4. **Delays**: Use delay options for slower, stealthier enumeration

## Version History

- **1.0.0**: Initial release with subdomain enum and zone transfer
