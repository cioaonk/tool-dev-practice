#!/bin/bash
# =============================================================================
# CPTC11 Docker Environment Reset Script
# =============================================================================
# Completely resets the environment, removing all containers and volumes
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$DOCKER_DIR"

echo "=== Resetting CPTC11 Docker Environment ==="
echo ""
echo "WARNING: This will remove all containers, networks, and volumes!"
echo ""
read -p "Are you sure? (y/N): " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "[*] Stopping and removing containers..."
docker-compose down -v --remove-orphans

echo ""
echo "[*] Removing any orphaned volumes..."
docker volume prune -f 2>/dev/null || true

echo ""
echo "[*] Rebuilding containers..."
docker-compose build --no-cache

echo ""
echo "Environment reset complete!"
echo ""
echo "To start the environment, run:"
echo "  ./scripts/start.sh"
