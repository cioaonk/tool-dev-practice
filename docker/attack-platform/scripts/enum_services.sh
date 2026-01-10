#!/bin/bash
# =============================================================================
# Service Enumeration Helper Script
# =============================================================================

TARGET=${1:-"10.10.10.10"}

echo "=== CPTC11 Service Enumeration ==="
echo "[*] Target: $TARGET"
echo ""

echo "[*] Running port scan..."
nmap -sV -sC -p- --min-rate=1000 "$TARGET" 2>/dev/null

echo ""
echo "[*] Enumeration complete."
