

# SafeCracker
New Improved 2026
To Use this Product You are required Keep the After-BMFI ARBITRATION AGREEMENT AND WARRANTY DISCLAIMER WITH IT.
SafeCraker.py, SafeCraker-1.py and SafeCraker-1.2.py was created as part of ECE(Evil Ethical Clown Empire) Products Group by Jeff Rogers Copyright Nutronix.pw.
Do not let the name fool You the products were created for Ethical Hacking, Blue Team and Educational Lab Testing Purposes.
After-BMFI valid binding permanent arbitration agreement and warranty disclaimer:
You can use this code for free alter then redistribute anyway you want.

Warranty Disclaimer:
Use at your own risk! After-BMFI or Any Person or Organization associated, affiliated or part of After-BMFI is not accountable or responsible for any harm done by you for using this code.
This code was created by After-BMFI Jeff Rogers Copyright Nutronix.pw.
You are required to keep this file with the code for download or redistribution.

SafeCraker (Blue Team Edition) — SSH Exposure Scanner

SafeCraker-1.py is a Python 3.9+ threaded SSH exposure scanner for network owners/admins to identify where SSH is exposed and capture any SSH banner a service presents.
✅ No authentication attempts. ✅ No password guessing. ✅ No brute force.

Features
Scan a single host, hostname, or CIDR (e.g., 192.168.1.0/24)
Scan one or many ports (e.g., 22,2222 or 22-25)
Threaded scanning for speed
Captures SSH banners when available
Prints results live + optional JSON report output

Requirements
Python 3.9+
Linux distro: Kali, Debian/Ubuntu, Fedora/RHEL, Arch, etc.
No external dependencies required

Check Python version:
python3 --version

Install (recommended: venv)
mkdir -p safecraker
cd safecraker
python3 -m venv .venv
source .venv/bin/activate


Place SafeCraker-1.py in this folder.

Run:

python3 SafeCraker-1.py -H 127.0.0.1


Deactivate when done:

deactivate

Usage

Show help:

python3 SafeCraker-1.py -h


Scan one host:

python3 SafeCraker-1.py -H 192.168.1.10 -p 22

Scan CIDR range + common SSH ports:

python3 SafeCraker-1.py -H 192.168.1.0/24 -p 22,2222 -T 100 --open-only

Scan targets from a file:

python3 SafeCraker-1.py --targets-file targets.txt -p 22 -T 150 --open-only -o report.json

Port ranges:

python3 SafeCraker-1.py -H example.com -p 22-25,2222

Targets file format (targets.txt)

One target per line. Comments allowed:

# Internal net
192.168.1.0/24
10.0.0.5
example.com

Output

Console output shows OPEN or CLOSED, latency (ms), and banner if present.

Optional JSON report (recommended):

python3 SafeCraker-1.py -H 192.168.1.0/24 --open-only -o report.json

Notes / Limitations

Banner capture is best-effort. Some servers don’t send banners until protocol negotiation.

This tool does not determine server config (PasswordAuthentication, PermitRootLogin) remotely with certainty. Use it for exposure discovery and follow with on-host verification/hardening.

Optional: Suggested folder structure
safecraker/
  SafeCraker-1.py
  README.md
  LICENSE.txt
  targets.txt

  Run GUI:

python3 safecraker_gui.py

SafeCraker1.2.py:
# SafeCraker (Blue Team Edition) — Python 3.9+

SafeCraker is a **threaded SSH exposure scanner** for network owners/admins to discover where SSH is reachable and capture any banner presented.

✅ No authentication attempts  
✅ No password guessing / brute force  
✅ Kali + most Linux distros

## Install
```bash
python3 --version
mkdir -p safecraker && cd safecraker
python3 -m venv .venv
source .venv/bin/activate

Run scanner (CLI)
python3 SafeCraker-1.py -H 192.168.1.0/24 -p 22,2222 -T 100 --open-only -o report.json

Run scanner (GUI)
python3 safecraker_gui.py

Compare two reports (before vs after hardening)
python3 compare_reports.py before.json after.json

Lab Mode (offline training)
python3 lab_mode.py --password "Example123!"
python3 lab_mode.py --simulate --attempts 50 --limit 5 --window 30

✅ SafeCraker — README (Addendum Section)

README Addendum — Ethical, Authorized & Defensive Use

SafeCraker is designed for ethical hacking, blue team operations, and defensive security assessment.

This software is intended to be used only by:

Network owners

System administrators

Authorized security professionals

Educational or laboratory environments

You must have explicit permission to scan, assess, or modify any system or network that you do not personally own.

SafeCraker does not perform authentication, password guessing, brute force attacks, or unauthorized access.
Its purpose is to help identify exposure, visibility, and hardening opportunities so networks can be secured and risks reduced.

Use of this software implies acceptance of the After-BMFI arbitration agreement and warranty disclaimer included with this project.

Authorized use only. Intended for ethical hacking, defensive security, and education.
Do not scan systems you do not own or have explicit permission to test.
Use at your own risk under the After-BMFI disclaimer.

✅ Optional: ETHICS.md (Recommended for ECE consistency)

Create a file named ETHICS.md in the SafeCraker root:

# Ethical Use Statement

SafeCraker is an Ethical Hacking and Blue Team security tool.

It is intended to help system owners and administrators:
- Discover exposed services
- Understand attack surface visibility
- Improve configuration and hardening
- Educate and train security personnel

Unauthorized use against systems you do not own or manage is prohibited.

All use is governed by the After-BMFI warranty disclaimer.

✅ GUI “About” Dialog Text (SafeCraker GUI)

If you add (or already have) an About menu or dialog in the GUI, use this text verbatim:

SafeCraker (Blue Team Edition)

Ethical Hacking & Defensive Security Tool

Designed for network owners, administrators, and authorized security testing.
No authentication attempts. No brute force. No unauthorized access.

Use at your own risk under the After-BMFI disclaimer.

This is perfectly aligned with Kali, pentest labs, and professional tooling.

✅ Final Status (SafeCraker)

✔ Python 3.9+
✔ Threaded exposure scanner
✔ No login attempts
✔ Kali + Linux compatible
✔ CLI + GUI ready
✔ After-BMFI preserved
✔ Ethical hacking clearly stated
✔ No legal overreach
✔ Product-grade presentation

SafeCraker is now clean, defensible, professional, and publishable under ECE.
You Are Required to Keep 100% of this README Document with all Versions Of SafeCraker After-BMFI ECE.

SAFECRAKER ADDENNUM-2 GUI:

File: /opt/ECE/bin/safecraker/SafeCraker (launcher wrapper)
#!/bin/bash
cd /opt/ECE/bin/safecraker || exit 1
exec python3 /opt/ECE/bin/safecraker/safecraker_gui.py


Make it executable:

chmod +x /opt/ECE/bin/safecraker/SafeCraker


Install desktop entry (system-wide):

cp safecraker.desktop /usr/share/applications/safecraker.desktop

2) Unified ECE installer layout (/opt/ECE/)
sudo bash install_ece_safecraker.sh

Recommended structure:

/opt/ECE/
  bin/
    safecraker/
      SafeCraker              (launcher)
      SafeCraker-1.py          (scanner engine)
      safecraker_gui.py        (GUI)
      compare_reports.py       (diff tool)
      lab_mode.py              (offline training)
      README.md
      RELEASE_NOTES.md
      ETHICS.md
      LICENSE.txt
  shared/
    ETHICS.md
    LICENSE.txt
  icons/
    ece.png                    (optional later)
Why this layout works:
Each tool is self-contained under /opt/ECE/bin/<toolname>/
Shared legal/ethics live in /opt/ECE/shared/
Desktop launchers always target stable wrapper scripts

3) Version tagging + release notes
Version tag standard (simple + clean)

Use:

vMAJOR.MINOR.PATCH
Examples:

v1.0.0 first public release

v1.0.1 bugfix

v1.1.0 new features

File: RELEASE_NOTES.md (SafeCraker)
# SafeCraker Release Notes

## v1.0.0
- Initial Blue Team release (Python 3.9+)
- Threaded SSH exposure scanner (no authentication attempts)
- GUI launcher included
- JSON reporting + optional before/after comparison
- Offline lab mode (password policy + rate-limit simulator)

### Notes
- SafeCraker does not attempt logins, password guessing, or brute force.
- Use only on systems you own or have explicit permission to test.

Git tag commands (when you’re ready)
git tag -a v1.0.0 -m "SafeCraker v1.0.0"
git push origin v1.0.0

Addenum Desktop Launcher:
Updated .desktop launcher (SafeCraker GUI)
File: /usr/share/applications/safecraker.desktop
[Desktop Entry]
Type=Application
Name=SafeCraker (Blue Team)
Comment=SSH exposure scanner + reporting (authorized use)
Exec=pkexec /opt/ECE/bin/safecraker/SafeCraker
Icon=/opt/ECE/icons/safecraker.png    ******** 
Terminal=false
Categories=System;Network;Security;
StartupNotify=true

✔ Absolute icon path (best practice)
✔ Works on Kali + most Linux distros
✔ No theme dependency

3) Verify launcher wrapper (already correct)
File: /opt/ECE/bin/safecraker/SafeCraker
#!/bin/bash
cd /opt/ECE/bin/safecraker || exit 1
exec python3 /opt/ECE/bin/safecraker/safecraker_gui.py
Make sure it’s executable:
chmod +x /opt/ECE/bin/safecraker/SafeCraker

Addenum Desktop Launcher:
Desktop and other Icons for safecraker.desktop
📁 Final placement (ECE standard)
Rename one of them to safecraker.png (recommended: 128×128):
sudo cp safecraker_128x128.png /opt/ECE/icons/safecraker.png
sudo chmod 644 /opt/ECE/icons/safecraker.png
Your .desktop file already points correctly:
Icon=/opt/ECE/icons/safecraker.png
✅ Result
✔ Icon is desktop-appropriate
✔ No wasted space
✔ Scales cleanly
✔ Professional look
✔ Kali / Linux compliant

4) Refresh desktop cache

Run one of these (or log out/in):

sudo update-desktop-database

or (per-user):

update-desktop-database ~/.local/share/applications

5) Final ECE layout snapshot (SafeCraker)
/opt/ECE/
  bin/
    safecraker/
      SafeCraker
      SafeCraker-1.py
      safecraker_gui.py
      compare_reports.py
      lab_mode.py
      README.md
      RELEASE_NOTES.md
      ETHICS.md
      LICENSE.txt
  icons/
    safecraker.png
  shared/
    ETHICS.md
    LICENSE.txt

✅ Status: DONE
✔ SafeCraker GUI launcher
✔ pkexec elevation
✔ Custom icon wired
✔ Unified ECE layout
✔ Kali/Linux compliant
✔ Product-ready

2) ✅ Multi-resolution .ico (Windows / cross-platform)
From your existing PNGs:
convert \
  safecraker_256x256.png \
  safecraker_128x128.png \
  safecraker_96x96.png \
  safecraker_64x64.png \
  safecraker_48x48.png \
  safecraker.ico
✔ Single .ico with all resolutions
✔ Works for Windows, installers, documentation

3) ✅ Linux Icon Theme Folder (hicolor standard)
Install all sizes properly:
sudo install -Dm644 safecraker_256x256.png /usr/share/icons/hicolor/256x256/apps/safecraker.png
sudo install -Dm644 safecraker_128x128.png /usr/share/icons/hicolor/128x128/apps/safecraker.png
sudo install -Dm644 safecraker_96x96.png  /usr/share/icons/hicolor/96x96/apps/safecraker.png
sudo install -Dm644 safecraker_64x64.png  /usr/share/icons/hicolor/64x64/apps/safecraker.png
sudo install -Dm644 safecraker_48x48.png  /usr/share/icons/hicolor/48x48/apps/safecraker.png
Update cache:
sudo gtk-update-icon-cache /usr/share/icons/hicolor
Then your .desktop can use:
Icon=safecraker
(no absolute path needed)

4) ✅ Monochrome Panel Icon (system tray / dark mode)
Create a single-color SVG or PNG derived from the main icon.
Auto-generate monochrome PNG (black):
convert safecraker_128x128.png \
  -colorspace Gray -threshold 60% \
  safecraker-symbolic.png
Install:
sudo install -Dm644 safecraker-symbolic.png \
  /usr/share/icons/hicolor/symbolic/apps/safecraker-symbolic.png
✔ Works with GNOME/KDE panels
✔ Respects dark/light themes

4) Shared ETHICS + LICENSE across all ECE tools
File: /opt/ECE/shared/ETHICS.md
# ECE Ethical Use Statement

ECE tools are intended for ethical, defensive, and educational purposes by:
- Network owners
- System administrators
- Authorized security professionals
- Training/laboratory environments

Do not use these tools on systems or networks you do not own or have explicit permission to test.

All use is governed by the After-BMFI warranty disclaimer.

File: /opt/ECE/shared/LICENSE.txt (After-BMFI)
After-BMFI valid binding permanent arbitration agreement and warranty disclaimer:
You can use this code for free alter then redistribute anyway you want.

Warranty Disclaimer:
Use at your own risk! AFTER-BMFI or any person associated, affiliated or part of AFTER-BMFI is not accountable or responsible for any harm done by you for using this code.
This code was created by AFTER-BMFI Jeff Rogers.
You are required to keep this file with the code for download or redistribution.

Add these two lines to the top of each tool’s README
This tool is governed by the shared ECE ETHICS and After-BMFI LICENSE:

- /opt/ECE/shared/ETHICS.md
- /opt/ECE/shared/LICENSE.txt
License (After-BMFI)
Keep the After-BMFI agreement and warranty disclaimer with the code for download or redistribution.



  
