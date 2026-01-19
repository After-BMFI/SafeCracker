

# SafeCracker
New Improved 2026
SafeCraker is Part of the ECE(Evil Clown Empire) Products Group Created by Jeff Rogers.
Do not be fooled by the name the Products Group was Created for Ethical Hacking and Blue Team.
Also for Educational and Lab Testing.
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

  
