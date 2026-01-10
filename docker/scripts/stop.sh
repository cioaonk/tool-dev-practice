#!/bin/bash
# =============================================================================
# CPTC11 Docker Environment Stop Script
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$DOCKER_DIR"

echo "=== Stopping CPTC11 Docker Environment ==="
echo ""

# Stop containers
echo "[*] Stopping containers..."
docker-compose down

echo ""
echo "Environment stopped successfully!"
echo ""
echo "To remove all data volumes, run:"
echo "  docker-compose down -v"
