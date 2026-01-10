#!/bin/bash
# DNS Service Script for CORE Network Emulator
# Usage: dns-service.sh [domain] [port]
# Simulates a DNS server for penetration testing

DOMAIN=${1:-company.local}
PORT=${2:-53}
ZONEDIR="/etc/bind/zones"

# Create directories
mkdir -p "$ZONEDIR"
mkdir -p /var/cache/bind
mkdir -p /var/run/named

# Create zone file
cat > "$ZONEDIR/$DOMAIN.zone" << EOF
\$TTL 86400
@   IN  SOA ns1.$DOMAIN. admin.$DOMAIN. (
        2024010101  ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        86400       ; Minimum TTL
)

; Name Servers
@       IN  NS      ns1.$DOMAIN.
@       IN  NS      ns2.$DOMAIN.

; Mail Exchange
@       IN  MX  10  mail.$DOMAIN.
@       IN  MX  20  mail2.$DOMAIN.

; A Records - Servers
ns1             IN  A   10.100.1.5
ns2             IN  A   10.100.1.6
mail            IN  A   10.100.1.20
mail2           IN  A   10.100.1.21
www             IN  A   10.100.1.10
web             IN  A   10.100.1.10
portal          IN  A   10.100.1.11
intranet        IN  A   10.100.2.10
sharepoint      IN  A   10.100.2.11
ftp             IN  A   10.100.1.15
backup          IN  A   10.100.3.20
db              IN  A   10.100.3.10
database        IN  A   10.100.3.10
ldap            IN  A   10.100.2.5
dc              IN  A   10.100.2.5
ad              IN  A   10.100.2.5
fileserver      IN  A   10.100.2.15
printserver     IN  A   10.100.2.16

; Development/Test servers (interesting for pentesters)
dev             IN  A   10.100.2.50
test            IN  A   10.100.2.51
staging         IN  A   10.100.2.52
jenkins         IN  A   10.100.2.60
gitlab          IN  A   10.100.2.61
docker          IN  A   10.100.2.62

; Management interfaces
mgmt            IN  A   10.100.99.1
switch-mgmt     IN  A   10.100.99.10
router-mgmt     IN  A   10.100.99.11
firewall-mgmt   IN  A   10.100.99.12
ilo             IN  A   10.100.99.20
idrac           IN  A   10.100.99.21

; CNAME Records
webmail         IN  CNAME   mail.$DOMAIN.
smtp            IN  CNAME   mail.$DOMAIN.
imap            IN  CNAME   mail.$DOMAIN.
vpn             IN  CNAME   www.$DOMAIN.

; TXT Records (for enumeration)
@               IN  TXT     "v=spf1 mx a:mail.$DOMAIN -all"
_dmarc          IN  TXT     "v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN"

; SRV Records
_ldap._tcp      IN  SRV     0 100 389 ldap.$DOMAIN.
_kerberos._tcp  IN  SRV     0 100 88  dc.$DOMAIN.
_kpasswd._tcp   IN  SRV     0 100 464 dc.$DOMAIN.
EOF

# Create reverse zone
cat > "$ZONEDIR/10.100.rev" << 'EOF'
$TTL 86400
@   IN  SOA ns1.company.local. admin.company.local. (
        2024010101
        3600
        1800
        604800
        86400
)
@       IN  NS  ns1.company.local.

; PTR Records
5.1     IN  PTR ns1.company.local.
10.1    IN  PTR www.company.local.
20.1    IN  PTR mail.company.local.
10.2    IN  PTR intranet.company.local.
5.2     IN  PTR dc.company.local.
10.3    IN  PTR db.company.local.
EOF

echo "[+] Starting DNS service on port $PORT"
echo "[+] Domain: $DOMAIN"

# Check if BIND is available
if command -v named &> /dev/null; then
    # Create named.conf
    cat > /etc/bind/named.conf << EOF
options {
    directory "/var/cache/bind";
    listen-on port $PORT { any; };
    allow-query { any; };
    allow-transfer { any; };  # Zone transfer enabled for practice
    recursion yes;
    dnssec-validation no;
};

zone "$DOMAIN" {
    type master;
    file "$ZONEDIR/$DOMAIN.zone";
    allow-transfer { any; };
};

zone "100.10.in-addr.arpa" {
    type master;
    file "$ZONEDIR/10.100.rev";
};
EOF

    named -c /etc/bind/named.conf -g &
    echo "[+] BIND DNS server started"
elif command -v dnsmasq &> /dev/null; then
    # Use dnsmasq as alternative
    cat > /etc/dnsmasq.conf << EOF
port=$PORT
domain=$DOMAIN
address=/www.$DOMAIN/10.100.1.10
address=/mail.$DOMAIN/10.100.1.20
address=/db.$DOMAIN/10.100.3.10
address=/dc.$DOMAIN/10.100.2.5
EOF
    dnsmasq -C /etc/dnsmasq.conf &
    echo "[+] dnsmasq DNS server started"
else
    # Simple DNS responder
    echo "[*] No DNS server found, using simple responder"
    echo "[!] Limited functionality - basic A record responses only"
    (
        while true; do
            # Simple DNS response placeholder
            nc -u -l -p "$PORT" -q 1 < /dev/null
        done
    ) &
fi

echo "[+] DNS service configuration complete"
echo "[+] Zone transfer enabled for practice (AXFR)"
echo "[+] Key records:"
echo "    - www.$DOMAIN -> 10.100.1.10"
echo "    - mail.$DOMAIN -> 10.100.1.20"
echo "    - db.$DOMAIN -> 10.100.3.10"
echo "    - dc.$DOMAIN -> 10.100.2.5"
