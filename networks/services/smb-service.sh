#!/bin/bash
# SMB Service Script for CORE Network Emulator
# Usage: smb-service.sh [sharepath]
# Simulates an SMB/CIFS file server for penetration testing

SHAREPATH=${1:-/srv/samba}

# Create share directories
mkdir -p "$SHAREPATH/public"
mkdir -p "$SHAREPATH/private"
mkdir -p "$SHAREPATH/it"
mkdir -p "$SHAREPATH/hr"
mkdir -p "$SHAREPATH/finance"
mkdir -p "$SHAREPATH/backup"

# Create interesting files for enumeration
cat > "$SHAREPATH/public/README.txt" << 'EOF'
Company File Server
===================
Public share - read access for all users
For support contact: it@company.local
EOF

cat > "$SHAREPATH/private/passwords.txt" << 'EOF'
Network Credentials (CONFIDENTIAL)
==================================
admin / P@ssw0rd123!
backup / BackupUser2024
service / Svc_Account_2024
EOF

cat > "$SHAREPATH/it/network_diagram.txt" << 'EOF'
Network Documentation
=====================
Internal: 10.100.2.0/24
DMZ: 10.100.1.0/24
Database: 10.100.3.0/24
Management: 10.100.99.0/24

Key Systems:
- Domain Controller: 10.100.2.5
- File Server: 10.100.2.10
- Backup Server: 10.100.3.20
EOF

cat > "$SHAREPATH/hr/employee_list.csv" << 'EOF'
ID,Name,Email,Department,Manager
001,John Admin,jadmin@company.local,IT,CEO
002,Jane User,juser@company.local,HR,John Admin
003,Bob Developer,bdev@company.local,Development,John Admin
004,Alice Accountant,aacct@company.local,Finance,CEO
EOF

cat > "$SHAREPATH/finance/budget_2024.txt" << 'EOF'
Annual Budget Summary
=====================
IT Infrastructure: $500,000
Security Software: $150,000
Training: $50,000
Consulting: $200,000

Bank Account: 1234-5678-9012
Routing: 021000021
EOF

cat > "$SHAREPATH/backup/backup_script.sh" << 'EOF'
#!/bin/bash
# Backup script - runs nightly
DB_HOST="10.100.3.10"
DB_USER="backup_user"
DB_PASS="Backup2024!"

mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS --all-databases > /backup/full.sql
EOF

# Create Samba configuration
mkdir -p /etc/samba

cat > /etc/samba/smb.conf << EOF
[global]
    workgroup = WORKGROUP
    server string = File Server
    security = user
    map to guest = Bad User
    guest account = nobody

    # Weak settings for pentesting
    client min protocol = NT1
    server min protocol = NT1
    ntlm auth = yes

    # Logging
    log file = /var/log/samba/%m.log
    max log size = 50

[public]
    path = $SHAREPATH/public
    browseable = yes
    read only = yes
    guest ok = yes
    comment = Public Share

[private]
    path = $SHAREPATH/private
    browseable = yes
    read only = no
    guest ok = no
    valid users = admin
    comment = Private Share

[it]
    path = $SHAREPATH/it
    browseable = yes
    read only = no
    valid users = @it
    comment = IT Department

[hr]
    path = $SHAREPATH/hr
    browseable = no
    read only = yes
    valid users = @hr
    comment = HR Department

[finance]
    path = $SHAREPATH/finance
    browseable = no
    read only = yes
    valid users = @finance
    comment = Finance Department

[backup]
    path = $SHAREPATH/backup
    browseable = no
    read only = no
    valid users = backup
    comment = Backup Share
EOF

# Set permissions
chmod -R 755 "$SHAREPATH/public"
chmod -R 700 "$SHAREPATH/private"
chmod -R 750 "$SHAREPATH/it"
chmod -R 750 "$SHAREPATH/hr"
chmod -R 750 "$SHAREPATH/finance"
chmod -R 700 "$SHAREPATH/backup"

echo "[+] Starting SMB service"
echo "[+] Share path: $SHAREPATH"

# Start Samba if available
if command -v smbd &> /dev/null; then
    mkdir -p /var/log/samba
    mkdir -p /var/run/samba

    # Create samba users
    useradd -M smbuser 2>/dev/null || true
    useradd -M admin 2>/dev/null || true
    useradd -M backup 2>/dev/null || true

    # Set samba passwords (weak for testing)
    (echo "password"; echo "password") | smbpasswd -a -s smbuser 2>/dev/null || true
    (echo "admin123"; echo "admin123") | smbpasswd -a -s admin 2>/dev/null || true
    (echo "backup"; echo "backup") | smbpasswd -a -s backup 2>/dev/null || true

    smbd -D
    nmbd -D
    echo "[+] Samba daemons started"
else
    # Fallback: Simple SMB banner
    echo "[*] Samba not found, using banner service on ports 139/445"
    (
        while true; do
            # Minimal SMB2 negotiate response
            printf '\x00\x00\x00\x55\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00' | nc -l -p 445 -q 1
        done
    ) &
    (
        while true; do
            printf '\x00\x00\x00\x55\xffSMBr\x00\x00\x00\x00' | nc -l -p 139 -q 1
        done
    ) &
fi

echo "[+] SMB service configuration complete"
echo "[+] Shares available:"
echo "    - public (guest access)"
echo "    - private (admin only)"
echo "    - it, hr, finance (restricted)"
echo "    - backup (backup user)"
