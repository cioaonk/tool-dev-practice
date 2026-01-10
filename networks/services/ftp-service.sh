#!/bin/bash
# FTP Service Script for CORE Network Emulator
# Usage: ftp-service.sh [port] [ftproot]
# Simulates an FTP server for penetration testing

PORT=${1:-21}
FTPROOT=${2:-/var/ftp}

# Create FTP root directory
mkdir -p "$FTPROOT"
mkdir -p "$FTPROOT/pub"
mkdir -p "$FTPROOT/incoming"
mkdir -p "$FTPROOT/backup"

# Create some interesting files for enumeration
cat > "$FTPROOT/README.txt" << 'EOF'
FTP Server
==========
Welcome to the FTP server.
For anonymous access, use username: anonymous
For support, contact: admin@company.local
EOF

cat > "$FTPROOT/pub/welcome.txt" << 'EOF'
Public files are available in this directory.
Upload files to /incoming for processing.
EOF

# Create fake backup files
echo "config_backup_2024.tar.gz" > "$FTPROOT/backup/files.txt"
cat > "$FTPROOT/backup/config.txt" << 'EOF'
# Server Configuration Backup
db_host=10.100.3.10
db_user=webapp
db_pass=W3bApp2024!
admin_email=admin@company.local
EOF

# Create hidden files
echo "admin:$6$rounds=5000$salt$hashedpassword" > "$FTPROOT/.htpasswd"
echo "ftp_users: admin, backup, anonymous" > "$FTPROOT/.users"

# Create a simple FTP banner responder
echo "[+] Starting FTP service on port $PORT"
echo "[+] FTP Root: $FTPROOT"

# Check if vsftpd is available
if command -v vsftpd &> /dev/null; then
    # Create minimal vsftpd config
    cat > /tmp/vsftpd.conf << EOF
listen=YES
listen_port=$PORT
anonymous_enable=YES
anon_root=$FTPROOT
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
ftpd_banner=Welcome to FTP Service
EOF
    vsftpd /tmp/vsftpd.conf &
else
    # Fallback: Simple FTP banner using netcat
    echo "[*] vsftpd not found, using simple banner service"
    (
        while true; do
            {
                echo -e "220 FTP Server Ready - vsftpd 3.0.3\r"
                read -t 2 cmd
                case "${cmd^^}" in
                    USER*)
                        echo -e "331 Please specify the password.\r"
                        ;;
                    PASS*)
                        echo -e "230 Login successful.\r"
                        ;;
                    SYST*)
                        echo -e "215 UNIX Type: L8\r"
                        ;;
                    PWD*)
                        echo -e "257 \"/\" is the current directory\r"
                        ;;
                    LIST*|NLST*)
                        echo -e "150 Here comes the directory listing.\r"
                        echo -e "226 Directory send OK.\r"
                        ;;
                    QUIT*)
                        echo -e "221 Goodbye.\r"
                        ;;
                    *)
                        echo -e "500 Unknown command.\r"
                        ;;
                esac
            } | nc -l -p "$PORT" -q 5
        done
    ) &
fi

echo "[+] FTP service started with PID $!"
