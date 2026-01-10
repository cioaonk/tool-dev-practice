#!/bin/bash
# =============================================================================
# CPTC11 Docker Environment Start Script
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$DOCKER_DIR"

echo "=== CPTC11 Docker Test Environment ==="
echo ""

# Check Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "[ERROR] Docker is not running. Please start Docker first."
    exit 1
fi

# Build and start containers
echo "[*] Building containers..."
docker-compose build

echo ""
echo "[*] Starting containers..."
docker-compose up -d

echo ""
echo "[*] Waiting for services to initialize..."
sleep 10

# Check container status
echo ""
echo "[*] Container status:"
docker-compose ps

echo ""
echo "=== Service Endpoints ==="
echo ""
echo "Web Application:    http://localhost:8080"
echo "FTP Server:         ftp://localhost:2121"
echo "SMTP Server:        localhost:2525"
echo "DNS Server:         localhost:5353"
echo "SMB Server:         localhost:4445"
echo "MySQL Server:       localhost:3307"
echo "SSH Server:         localhost:2222"
echo ""
echo "=== Attack Platform ==="
echo "Access: docker exec -it cptc11-attack-platform bash"
echo ""
echo "Environment started successfully!"
