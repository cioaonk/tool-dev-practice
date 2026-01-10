# Hash Cracker

Multi-algorithm hash cracking utility for authorized security testing.

## Overview

This tool performs offline hash cracking using dictionary and bruteforce attacks. Supports multiple hash algorithms and operates entirely in-memory for operational security.

## Features

- **Multiple Algorithms**: MD5, SHA1, SHA256, SHA512, NTLM
- **Dictionary Attacks**: Wordlist-based cracking
- **Bruteforce**: Configurable charset and length
- **Rule Engine**: Password mutations (capitalize, leet, append numbers)
- **Auto-Detection**: Identifies hash types by format
- **In-Memory**: No disk artifacts during cracking

## Supported Hash Types

| Algorithm | Length | Example |
|-----------|--------|---------|
| MD5 | 32 | 5f4dcc3b5aa765d61d8327deb882cf99 |
| SHA1 | 40 | 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 |
| SHA256 | 64 | 5e884898da28... |
| SHA512 | 128 | b109f3bbbc244... |
| NTLM | 32 | 32ed87bdb5fdc5e9cba88547376818d4 |

## Usage

### Dictionary Attack

```bash
# Single hash
python3 tool.py 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

# From file
python3 tool.py -f hashes.txt -w rockyou.txt

# With rules
python3 tool.py -f hashes.txt -w words.txt -r capitalize,append_numbers
```

### Bruteforce Attack

```bash
# Lowercase, length 1-6
python3 tool.py HASH -b -c lowercase --max-length 6

# Alphanumeric
python3 tool.py HASH -b -c alphanumeric --min-length 4 --max-length 8
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| hash | - | - | Single hash to crack |
| --file | -f | - | File with hashes |
| --wordlist | -w | - | Dictionary file |
| --type | -t | auto | Hash type |
| --rules | -r | - | Mutation rules |
| --bruteforce | -b | False | Enable bruteforce |
| --charset | -c | lowercase | Bruteforce charset |
| --min-length | - | 1 | Minimum length |
| --max-length | - | 6 | Maximum length |
| --threads | -T | 4 | Thread count |
| --plan | -p | False | Show execution plan |
| --output | -o | - | Output file |

## Rules

| Rule | Effect |
|------|--------|
| capitalize | password -> Password |
| uppercase | password -> PASSWORD |
| reverse | password -> drowssap |
| append_numbers | password -> password0-99 |
| append_year | password -> password2020-2026 |
| leet | password -> p4ssw0rd |

## Hash File Format

```
# Comments supported
5f4dcc3b5aa765d61d8327deb882cf99
admin:e10adc3949ba59abbe56e057f20f883e
```

## Output Format

```
[*] Hash Cracker starting...
[*] Hashes: 3
[*] Mode: Dictionary
[+] Cracked: 5f4dcc3b5aa765d61d... = password

============================================================
CRACKING RESULTS
============================================================
Total hashes:     3
Cracked:          2
Attempts:         14,233
Duration:         1.23s
Rate:             11,571 H/s

CRACKED HASHES:
------------------------------------------------------------
  5f4dcc3b5aa765d61d8327deb882cf99... = password
  admin:e10adc3949ba59abbe56e057f20... = 123456
```

## Operational Security Notes

- All hash computations are in-memory
- No network activity
- Results only written if -o specified

## Version History

- **1.0.0**: Initial release with dictionary and bruteforce support
