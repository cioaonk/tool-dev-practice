# Honeypot Detector

A defensive security tool for detecting honeypots and deception technologies in network environments.

## Overview

Honeypot Detector helps identify potential honeypot systems by analyzing service banners, response timing, behavior patterns, and network characteristics. This tool is valuable for red teams to avoid detection and for blue teams to validate their deception deployments.

## Features

- **Banner Analysis**: Detect honeypot signatures in service banners
- **Timing Analysis**: Identify suspicious response timing patterns
- **Behavior Analysis**: Detect unusual service behaviors
- **Network Analysis**: Analyze network-level characteristics
- **Known Honeypot Detection**: Fingerprint common honeypot software
- **Probability Scoring**: Calculate likelihood of honeypot detection
- **Multiple Output Formats**: Text and JSON output

## Installation

```bash
# No external dependencies required - uses Python standard library
python3 tool.py --help
```

## Usage

### Planning Mode

Review detection actions before execution:

```bash
python tool.py --plan --target 192.168.1.100 --port 22
```

### Single Target Analysis

```bash
# Analyze SSH service
python tool.py --target 192.168.1.100 --port 22

# Analyze multiple ports
python tool.py --target 192.168.1.100 --ports 22,80,443,2222

# JSON output
python tool.py --target 192.168.1.100 --port 22 --output json
```

### Multiple Targets

```bash
# From file
python tool.py --targets targets.txt

# With JSON output
python tool.py --targets targets.txt --output json > report.json
```

### Target File Format

```
# targets.txt
192.168.1.100:22
192.168.1.101:80
10.0.0.1:2222
# Comment lines start with #
```

## Detection Techniques

### 1. Banner Analysis

Identifies known honeypot signatures in service banners:

| Pattern | Honeypot | Confidence |
|---------|----------|------------|
| SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u* | Cowrie | HIGH |
| SSH-2.0-OpenSSH_5.1p1 Debian-5 | Kippo | HIGH |
| honeyd | HoneyD | HIGH |
| Very old OS versions | Various | MEDIUM |

### 2. Timing Analysis

Detects suspicious timing patterns:
- Instant responses (< 5ms)
- Consistent timing with low variance
- Unrealistic response speeds

### 3. Service Behavior Analysis

Identifies behavioral anomalies:
- Services on unusual ports
- Excessive open ports (> 50)
- Services accepting any credentials

### 4. Network Analysis

Analyzes network characteristics:
- Unusual TTL values
- Identical fingerprints across services
- Suspicious routing patterns

### 5. Known Honeypot Fingerprinting

Detects signatures from common honeypots:
- **Cowrie**: SSH/Telnet honeypot
- **Kippo**: SSH honeypot
- **Dionaea**: Multi-protocol honeypot
- **Glastopf**: Web application honeypot
- **Conpot**: ICS/SCADA honeypot
- **HoneyD**: Network simulation honeypot

## Output Formats

### Text Format (default)

```
============================================================
  HONEYPOT DETECTION REPORT
============================================================

Summary: Analyzed 1 target(s). Detected 1 likely honeypot(s).
Duration: 2.34 seconds

------------------------------------------------------------
Target: 192.168.1.100:22
Service: ssh
Honeypot Probability: 85.0%
Status: LIKELY HONEYPOT

Indicators found:
  [HIGH] cowrie
    Type: banner
    Description: Banner matches known honeypot pattern
    Evidence: SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4...

  [MEDIUM] old_os
    Type: banner
    Description: Banner indicates old OS version
    Evidence: Debian 7 reference detected...
```

### JSON Format

```bash
python tool.py --target 192.168.1.100 --port 22 --output json
```

## Probability Scoring

Indicators are weighted by confidence level:
- **HIGH**: 0.5 weight
- **MEDIUM**: 0.3 weight
- **LOW**: 0.1 weight

Targets with probability >= 60% are flagged as "Likely Honeypot".

## API Usage

```python
from tool import HoneypotDetector, get_documentation

# Get documentation
docs = get_documentation()

# Create detector
detector = HoneypotDetector(timeout=5.0)

# Get plan
targets = [("192.168.1.100", 22)]
print(detector.get_plan(targets, "text"))

# Run detection
result = detector.detect(targets)

# Check results
for analysis in result.analyses:
    print(f"{analysis.target}:{analysis.port}")
    print(f"  Probability: {analysis.honeypot_probability:.1%}")
    print(f"  Is Honeypot: {analysis.is_likely_honeypot}")
    for indicator in analysis.indicators:
        print(f"  - [{indicator.confidence}] {indicator.name}")
```

## Exit Codes

- `0`: Analysis completed, no honeypots detected
- `1`: Honeypots detected or error occurred

## Integration

### With Reconnaissance Tools

```bash
# Scan network, then check for honeypots
nmap -p 22,80,443 192.168.1.0/24 -oG - | \
    grep "open" | \
    awk '{print $2}' | \
    while read ip; do
        python tool.py --target $ip --ports 22,80,443
    done
```

### Automated Scanning

```bash
#!/bin/bash
# check_honeypots.sh
while read target; do
    result=$(python tool.py --target $target --output json --quiet)
    is_honeypot=$(echo "$result" | jq '.analyses[0].is_likely_honeypot')
    if [ "$is_honeypot" = "true" ]; then
        echo "WARNING: $target appears to be a honeypot"
    fi
done < targets.txt
```

## Limitations

- Detection is heuristic-based and not 100% accurate
- Sophisticated honeypots may evade detection
- Network conditions can affect timing analysis
- Requires network access to targets

## Ethical Considerations

This tool should only be used:
- During authorized penetration tests
- To validate your own honeypot deployments
- In legal security research contexts

Do not use this tool to:
- Evade honeypots during unauthorized access
- Map honeypot deployments without permission
- Conduct reconnaissance on networks you don't own

## Author

Defensive Security Toolsmith
