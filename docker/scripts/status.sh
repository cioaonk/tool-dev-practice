#!/bin/bash
# =============================================================================
# CPTC11 Docker Environment Status Script
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$DOCKER_DIR"

echo "=== CPTC11 Docker Environment Status ==="
echo ""

# Container status
echo "[*] Container Status:"
docker-compose ps

echo ""

# Network status
echo "[*] Networks:"
docker network ls --filter "name=cptc11" --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"

echo ""

# Volume status
echo "[*] Volumes:"
docker volume ls --filter "name=cptc11" --format "table {{.Name}}\t{{.Driver}}"

echo ""

# Port mappings
echo "[*] Port Mappings:"
echo "  Web HTTP:       localhost:8080  -> vulnerable-web:80"
echo "  Web HTTPS:      localhost:8443  -> vulnerable-web:443"
echo "  FTP:            localhost:2121  -> ftp-server:21"
echo "  SMTP:           localhost:2525  -> smtp-server:25"
echo "  SMTP Submit:    localhost:587   -> smtp-server:587"
echo "  DNS:            localhost:5353  -> dns-server:53"
echo "  SMB:            localhost:4445  -> smb-server:445"
echo "  NetBIOS:        localhost:1139  -> smb-server:139"
echo "  MySQL:          localhost:3307  -> mysql-server:3306"
echo "  SSH:            localhost:2222  -> server-1:22"

echo ""

# Service health
echo "[*] Service Health:"

check_port() {
    local host=$1
    local port=$2
    local name=$3

    if nc -z "$host" "$port" 2>/dev/null; then
        echo "  [OK] $name ($host:$port)"
    else
        echo "  [--] $name ($host:$port) - Not responding"
    fi
}

check_port localhost 8080 "Web Application"
check_port localhost 2121 "FTP Server"
check_port localhost 2525 "SMTP Server"
check_port localhost 4445 "SMB Server"
check_port localhost 3307 "MySQL Server"
check_port localhost 2222 "SSH Server"

echo ""
