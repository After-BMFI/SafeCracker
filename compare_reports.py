
#!/usr/bin/env python3
"""
Compare two SafeCraker JSON reports.
Usage:
  python3 compare_reports.py before.json after.json
"""

import json
import sys
from pathlib import Path
from typing import Dict, Tuple


def load(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def key(r: Dict) -> Tuple[str, int]:
    return (r.get("target", ""), int(r.get("port", 0)))


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python3 compare_reports.py before.json after.json")
        return 2

    before = load(Path(sys.argv[1]))
    after = load(Path(sys.argv[2]))

    b = {key(r): r for r in before.get("results", [])}
    a = {key(r): r for r in after.get("results", [])}

    all_keys = sorted(set(b.keys()) | set(a.keys()))

    opened_now = []
    closed_now = []
    changed_banner = []
    changed_risk = []

    for k in all_keys:
        br = b.get(k)
        ar = a.get(k)
        if not br or not ar:
            continue

        if br.get("open") is False and ar.get("open") is True:
            opened_now.append(k)
        if br.get("open") is True and ar.get("open") is False:
            closed_now.append(k)

        if (br.get("banner") or "") != (ar.get("banner") or ""):
            changed_banner.append(k)

        if (br.get("risk_score"), br.get("risk_level")) != (ar.get("risk_score"), ar.get("risk_level")):
            changed_risk.append(k)

    print("=== SafeCraker Report Comparison ===")
    print(f"Before: {sys.argv[1]}")
    print(f"After : {sys.argv[2]}")
    print()

    def fmt(lst, title):
        print(f"{title}: {len(lst)}")
        for host, port in lst:
            print(f"  - {host}:{port}")
        print()

    fmt(closed_now, "Ports closed (improvement)")
    fmt(opened_now, "Ports opened (review)")
    fmt(changed_risk, "Risk changed")
    fmt(changed_banner, "Banner changed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
