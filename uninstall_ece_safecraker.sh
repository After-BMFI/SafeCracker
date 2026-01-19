
#!/bin/bash
set -e

echo "[*] Uninstalling SafeCraker (ECE)"

# Remove desktop entry
rm -f /usr/share/applications/safecraker.desktop
rm -f ~/.local/share/applications/safecraker.desktop

# Remove SafeCraker files
rm -rf /opt/ECE/bin/safecraker

# Remove icons
rm -f /opt/ECE/icons/safecraker.png
rm -rf /usr/share/icons/hicolor/*/apps/safecraker.png

# Update caches
update-desktop-database 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true

echo "[+] SafeCraker uninstalled"
