#!/bin/bash
# SSH Service Script for CORE Network Emulator
# Usage: ssh-service.sh [port]
# Configures SSH for penetration testing

PORT=${1:-22}

# Create SSH directory
mkdir -p /etc/ssh
mkdir -p /root/.ssh
mkdir -p /var/run/sshd

# Generate host keys if they don't exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "[+] Generating SSH host keys..."
    ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N '' -q 2>/dev/null || true
    ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N '' -q 2>/dev/null || true
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -q 2>/dev/null || true
fi

# Create weak sshd_config for pentesting (intentionally vulnerable)
cat > /etc/ssh/sshd_config << EOF
# SSH Configuration - Intentionally Weak for Pentesting
Port $PORT
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication - weak settings for practice
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Weak ciphers for practice
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc

# Banner for enumeration
Banner /etc/ssh/banner.txt

# Logging
SyslogFacility AUTH
LogLevel INFO

# Allow forwarding
AllowTcpForwarding yes
X11Forwarding yes

# Max auth attempts (high for brute force practice)
MaxAuthTries 10

# Keep alive
ClientAliveInterval 120
ClientAliveCountMax 3
EOF

# Create SSH banner
cat > /etc/ssh/banner.txt << 'EOF'
*******************************************
*   AUTHORIZED ACCESS ONLY                *
*   All connections are monitored         *
*   Unauthorized access is prohibited     *
*******************************************
Server: Ubuntu 20.04 LTS
SSH Version: OpenSSH_8.2p1
EOF

# Create test users with weak passwords
echo "[+] Creating test users..."
useradd -m -s /bin/bash admin 2>/dev/null || true
useradd -m -s /bin/bash user 2>/dev/null || true
useradd -m -s /bin/bash backup 2>/dev/null || true
useradd -m -s /bin/bash guest 2>/dev/null || true

# Set weak passwords for practice
echo "admin:admin123" | chpasswd 2>/dev/null || true
echo "user:password" | chpasswd 2>/dev/null || true
echo "backup:backup" | chpasswd 2>/dev/null || true
echo "guest:guest" | chpasswd 2>/dev/null || true
echo "root:toor" | chpasswd 2>/dev/null || true

# Create SSH authorized_keys with a known test key
mkdir -p /home/admin/.ssh
cat > /home/admin/.ssh/authorized_keys << 'EOF'
# Authorized keys for admin user
# Add your test keys here
EOF
chmod 700 /home/admin/.ssh
chmod 600 /home/admin/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh 2>/dev/null || true

# Start SSH daemon
echo "[+] Starting SSH service on port $PORT"

if command -v sshd &> /dev/null; then
    /usr/sbin/sshd -f /etc/ssh/sshd_config
    echo "[+] SSH daemon started"
elif command -v dropbear &> /dev/null; then
    dropbear -p "$PORT" -R
    echo "[+] Dropbear SSH started"
else
    echo "[-] No SSH daemon found, using banner service"
    (
        while true; do
            echo -e "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n" | nc -l -p "$PORT" -q 1
        done
    ) &
fi

echo "[+] SSH service configuration complete"
