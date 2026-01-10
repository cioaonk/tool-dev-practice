#!/bin/bash
# SMTP Service Script for CORE Network Emulator
# Usage: smtp-service.sh [port] [hostname]
# Simulates an SMTP mail server for penetration testing

PORT=${1:-25}
HOSTNAME=${2:-mail.company.local}
MAILDIR="/var/mail"

# Create mail directories
mkdir -p "$MAILDIR"
mkdir -p /var/spool/mail
mkdir -p /etc/postfix

# Create some sample emails for enumeration
cat > "$MAILDIR/admin.mbox" << 'EOF'
From: it@company.local
To: admin@company.local
Subject: Password Reset
Date: Mon, 01 Jan 2024 10:00:00 -0500

Your temporary password is: TempPass123!
Please change it immediately.

---
From: backup@company.local
To: admin@company.local
Subject: Backup Complete
Date: Mon, 01 Jan 2024 02:00:00 -0500

Nightly backup completed successfully.
Database backup location: /backup/db_20240101.sql
Config backup: /backup/config_20240101.tar.gz
EOF

# Create user list for VRFY/EXPN enumeration
cat > "$MAILDIR/valid_users.txt" << 'EOF'
admin
administrator
postmaster
webmaster
root
info
support
sales
hr
it
backup
noreply
test
EOF

echo "[+] Starting SMTP service on port $PORT"
echo "[+] Hostname: $HOSTNAME"

# Check if Postfix is available
if command -v postfix &> /dev/null; then
    # Configure Postfix
    cat > /etc/postfix/main.cf << EOF
myhostname = $HOSTNAME
mydomain = company.local
myorigin = \$mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain
mynetworks = 0.0.0.0/0
smtp_banner = \$myhostname ESMTP Postfix

# Weak settings for pentesting
disable_vrfy_command = no
smtpd_helo_required = no
smtpd_recipient_restrictions = permit_mynetworks, permit

# Open relay for testing (intentionally vulnerable)
smtpd_relay_restrictions = permit
EOF

    postfix start
    echo "[+] Postfix SMTP server started"
else
    # Simple SMTP responder using netcat
    echo "[*] Postfix not found, using simple SMTP responder"
    (
        while true; do
            {
                echo "220 $HOSTNAME ESMTP Postfix (Ubuntu)"
                while read -t 30 line; do
                    cmd=$(echo "$line" | tr -d '\r' | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
                    arg=$(echo "$line" | tr -d '\r' | cut -d' ' -f2-)

                    case "$cmd" in
                        HELO|EHLO)
                            echo "250-$HOSTNAME"
                            echo "250-PIPELINING"
                            echo "250-SIZE 10240000"
                            echo "250-VRFY"
                            echo "250-ETRN"
                            echo "250-STARTTLS"
                            echo "250-AUTH PLAIN LOGIN"
                            echo "250-AUTH=PLAIN LOGIN"
                            echo "250-ENHANCEDSTATUSCODES"
                            echo "250-8BITMIME"
                            echo "250 DSN"
                            ;;
                        VRFY)
                            # Check if user exists (enumeration vulnerability)
                            user=$(echo "$arg" | tr -d '<>' | cut -d'@' -f1)
                            if grep -qi "^$user$" "$MAILDIR/valid_users.txt" 2>/dev/null; then
                                echo "252 2.0.0 $arg"
                            else
                                echo "550 5.1.1 <$arg>: Recipient address rejected"
                            fi
                            ;;
                        EXPN)
                            echo "250-admin@company.local"
                            echo "250 postmaster@company.local"
                            ;;
                        MAIL)
                            echo "250 2.1.0 Ok"
                            ;;
                        RCPT)
                            echo "250 2.1.5 Ok"
                            ;;
                        DATA)
                            echo "354 End data with <CR><LF>.<CR><LF>"
                            ;;
                        RSET)
                            echo "250 2.0.0 Ok"
                            ;;
                        NOOP)
                            echo "250 2.0.0 Ok"
                            ;;
                        QUIT)
                            echo "221 2.0.0 Bye"
                            break
                            ;;
                        ".")
                            echo "250 2.0.0 Ok: queued"
                            ;;
                        *)
                            echo "502 5.5.2 Error: command not recognized"
                            ;;
                    esac
                done
            } | nc -l -p "$PORT" -q 1
        done
    ) &
    echo "[+] Simple SMTP responder started"
fi

# Start submission port (587)
(
    while true; do
        {
            echo "220 $HOSTNAME ESMTP Submission"
            while read -t 30 line; do
                cmd=$(echo "$line" | tr -d '\r' | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
                case "$cmd" in
                    EHLO|HELO)
                        echo "250-$HOSTNAME"
                        echo "250-AUTH PLAIN LOGIN"
                        echo "250 STARTTLS"
                        ;;
                    QUIT)
                        echo "221 Bye"
                        break
                        ;;
                    *)
                        echo "250 Ok"
                        ;;
                esac
            done
        } | nc -l -p 587 -q 1
    done
) &

echo "[+] SMTP service configuration complete"
echo "[+] Ports: 25 (SMTP), 587 (Submission)"
echo "[+] VRFY/EXPN enabled for enumeration practice"
echo "[+] Valid users: admin, postmaster, root, it, backup, etc."
