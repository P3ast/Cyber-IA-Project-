#!/bin/bash
# Exegol user setup script — auto-installs RansomEmu
# Place this in: ~/.exegol/my-resources/setup/load_user_setup.sh

set -e

RANSOMEMU_DIR="/opt/my-resources/ransomemu"

if [ -d "$RANSOMEMU_DIR" ]; then
    echo "[*] Installing RansomEmu..."
    pip3 install -e "$RANSOMEMU_DIR" 2>/dev/null
    
    # Create symlink in bin (already in PATH)
    ln -sf "$RANSOMEMU_DIR/.venv/bin/ransomemu" /opt/my-resources/bin/ransomemu 2>/dev/null || true
    
    echo "[+] RansomEmu installed. Run 'ransomemu --help' to get started."
else
    echo "[-] RansomEmu not found at $RANSOMEMU_DIR"
fi
