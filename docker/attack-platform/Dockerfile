# =============================================================================
# Attack Platform Container
# =============================================================================
# Provides a Kali-like environment with common offensive security tools
# pre-installed. Mounts the CPTC11 Python tools for testing.
#
# Features:
# - Network scanning tools
# - Python 3 with security libraries
# - Access to all test networks
# - CPTC11 tools mounted at /opt/tools
#
# =============================================================================

FROM python:3.11-slim-bookworm

LABEL maintainer="CPTC11 Team"
LABEL description="Attack platform for security testing"
LABEL cptc11.role="attack-platform"

# Install system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    traceroute \
    tcpdump \
    curl \
    wget \
    # SMB tools
    smbclient \
    # Development tools
    git \
    vim \
    nano \
    # Build dependencies
    build-essential \
    libssl-dev \
    libffi-dev \
    # Misc
    jq \
    tree \
    htop \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python security libraries
RUN pip install --no-cache-dir \
    requests \
    dnspython \
    impacket \
    pycryptodome \
    paramiko \
    scapy \
    python-nmap \
    ldap3 \
    pysmb \
    colorama \
    tabulate \
    pyyaml

# Create working directories
RUN mkdir -p /opt/tools \
    && mkdir -p /root/loot \
    && mkdir -p /root/wordlists

# Download common wordlists
RUN curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
    -o /root/wordlists/subdomains-top5000.txt || echo "Could not download wordlist" \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o /root/wordlists/web-common.txt || echo "Could not download wordlist" \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt \
    -o /root/wordlists/passwords-10k.txt || echo "Could not download wordlist"

# Set up shell configuration
RUN echo 'export PS1="\[\033[01;31m\]attacker\[\033[00m\]@\[\033[01;34m\]cptc11\[\033[00m\]:\[\033[01;32m\]\w\[\033[00m\]# "' >> /root/.bashrc \
    && echo 'alias ll="ls -la"' >> /root/.bashrc \
    && echo 'alias tools="cd /opt/tools"' >> /root/.bashrc \
    && echo 'export PYTHONPATH=/opt/tools:$PYTHONPATH' >> /root/.bashrc

# Copy helper scripts
COPY scripts/ /root/scripts/
RUN chmod +x /root/scripts/*.sh 2>/dev/null || true

WORKDIR /root

# Keep container running
CMD ["tail", "-f", "/dev/null"]
