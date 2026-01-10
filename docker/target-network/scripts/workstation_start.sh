#!/bin/sh
# =============================================================================
# Workstation Startup Script
# =============================================================================

# Start SSH daemon
/usr/sbin/sshd

# Simulate some open ports (fake services)
# Fake RDP-like service on 3389
socat TCP-LISTEN:3389,fork,reuseaddr SYSTEM:"echo 'RDP Service - Connection Refused'" &

# Fake NetBIOS on 139
socat TCP-LISTEN:139,fork,reuseaddr SYSTEM:"echo 'NetBIOS'" &

# Fake SMB on 445
socat TCP-LISTEN:445,fork,reuseaddr SYSTEM:"echo 'SMB'" &

# Fake RPC on 135
socat TCP-LISTEN:135,fork,reuseaddr SYSTEM:"echo 'RPC'" &

echo "Workstation services started"

# Keep container running
tail -f /dev/null
