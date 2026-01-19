#Run Script:
#sudo bash install_ece_safecraker.sh
#!/bin/bash
set -e

ECE_ROOT="/opt/ECE"
TOOL_DIR="$ECE_ROOT/bin/safecraker"
SHARED_DIR="$ECE_ROOT/shared"

mkdir -p "$TOOL_DIR" "$SHARED_DIR"

# Copy tool files from current folder into /opt/ECE
cp -f SafeCraker-1.py safecraker_gui.py compare_reports.py lab_mode.py README.md RELEASE_NOTES.md ETHICS.md LICENSE.txt "$TOOL_DIR/"

# Shared copies
cp -f ETHICS.md "$SHARED_DIR/ETHICS.md"
cp -f LICENSE.txt "$SHARED_DIR/LICENSE.txt"

# Launcher
cat > "$TOOL_DIR/SafeCraker" <<'EOF'
#!/bin/bash
cd /opt/ECE/bin/safecraker || exit 1
exec python3 /opt/ECE/bin/safecraker/safecraker_gui.py
EOF
chmod +x "$TOOL_DIR/SafeCraker"

# Desktop entry
cat > /usr/share/applications/safecraker.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=SafeCraker (Blue Team)
Comment=SSH exposure scanner + reporting (authorized use)
Exec=pkexec /opt/ECE/bin/safecraker/SafeCraker
Icon=network-workgroup
Terminal=false
Categories=System;Network;Security;
StartupNotify=true
EOF

echo "[+] Installed SafeCraker to $TOOL_DIR"
echo "[+] Desktop launcher installed: /usr/share/applications/safecraker.desktop"
