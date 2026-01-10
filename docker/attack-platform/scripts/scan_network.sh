#!/bin/bash
# =============================================================================
# Network Scanner Helper Script
# =============================================================================

echo "=== CPTC11 Network Scanner ==="
echo ""

# DMZ Network
echo "[*] Scanning DMZ Network (10.10.10.0/24)..."
nmap -sn 10.10.10.0/24 2>/dev/null | grep "Nmap scan report"

echo ""

# Internal Network
echo "[*] Scanning Internal Network (10.10.20.0/24)..."
nmap -sn 10.10.20.0/24 2>/dev/null | grep "Nmap scan report"

echo ""
echo "[*] Scan complete."
