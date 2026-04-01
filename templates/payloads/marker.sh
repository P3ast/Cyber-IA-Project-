#!/bin/bash
# Marker Bash script — deployed by lateral movement modules
# This script DOES NOT encrypt files — it only creates a marker.

MARKER_PATH="${1:-/tmp/ransomemu_marker.txt}"
SIM_ID="${2:-default}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)
USER=$(whoami)

cat > "$MARKER_PATH" << EOF
===== RANSOMEMU SIMULATION MARKER =====
Timestamp: $TIMESTAMP
Host: $HOSTNAME
User: $USER
Simulation ID: $SIM_ID
THIS FILE WAS NOT ENCRYPTED — marker only.
===== RANSOMEMU SIMULATION MARKER =====
EOF

# Output system info as JSON
cat << EOF
{
  "hostname": "$HOSTNAME",
  "user": "$USER",
  "os": "$(uname -s -r)",
  "ip": "$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'unknown')",
  "timestamp": "$TIMESTAMP",
  "sim_id": "$SIM_ID"
}
EOF
