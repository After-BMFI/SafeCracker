#SafeCraker-1.2.py (Blue Team Edition) - Python 3.9+ was created as Part of the ECE(Evil Clown Empire) Products Group by Jeff Rogers.
Do not let the name fool You it was created for Ethical Hacking, Blue Team and Educational Lab Testing Purposes.
#!/usr/bin/env python3
"""
SafeCraker-1.2.py (Blue Team Edition) - Python 3.9+

After-BMFI valid binding permanent arbitration agreement and warranty disclaimer:
You can use this code for free alter then redistribute anyway you want.

Warranty Disclaimer:
Use at your own risk! After-BMFI or any person associated, affiliated or part of After-BMFI is not accountable or responsible
for any harm done by you for using this code.
This code was created by After-BMFI Jeff Rogers.
You are required to keep this file with the code for download or redistribution.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Dict, Any


DEFAULT_TIMEOUT = 3.0


@dataclass
class ScanResult:
    target: str
    port: int
    open: bool
    banner: Optional[str] = None
    error: Optional[str] = None
    rtt_ms: Optional[int] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_reasons: Optional[List[str]] = None


def iter_targets(target: str) -> Iterable[str]:
    target = target.strip()
    if not target:
        return

    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            for ip in net.hosts():
                yield str(ip)
            return

        ipaddress.ip_address(target)
        yield target
        return
    except ValueError:
        yield target


def load_targets_from_file(path: Path) -> List[str]:
    targets: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def parse_ports(ports_str: str) -> List[int]:
    ports: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a.strip())
            end = int(b.strip())
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    seen = set()
    out: List[int] = []
    for p in ports:
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def safe_read_banner(sock: socket.socket, max_bytes: int = 256) -> Optional[str]:
    sock.settimeout(1.5)
    try:
        data = sock.recv(max_bytes)
        if not data:
            return None
        text = data.decode("utf-8", errors="replace").strip()
        return text[:200] if text else None
    except Exception:
        return None


def score_risk(open_port: bool, port: int, banner: Optional[str]) -> Tuple[int, str, List[str]]:
    """
    Practical scoring based on *exposure* only.
    We do not claim remote certainty about config (PasswordAuthentication, PermitRootLogin, etc.).
    """
    if not open_port:
        return 0, "NONE", ["Port not open"]

    score = 50
    reasons: List[str] = ["SSH service appears reachable"]

    # Non-standard ports: slightly lower casual exposure, but still risk
    if port != 22:
        score -= 5
        reasons.append("Non-default SSH port may reduce casual scanning (still exposed)")

    if banner:
        b = banner.lower()
        if "openssh" in b:
            reasons.append("Banner indicates OpenSSH (keep patched)")
        if "dropbear" in b:
            reasons.append("Banner indicates Dropbear (verify patch level and config)")
        if "ssh-1" in b or "ssh-1.99" in b:
            score += 25
            reasons.append("Banner suggests legacy SSH compatibility (investigate)")
    else:
        reasons.append("No banner captured (may still be SSH; some servers delay banner)")

    # Clamp score
    score = max(0, min(100, score))

    if score >= 80:
        level = "HIGH"
    elif score >= 55:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, reasons


def scan_one(host: str, port: int, timeout: float) -> ScanResult:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            rtt = int((time.perf_counter() - start) * 1000)
            banner = safe_read_banner(s)
            score, level, reasons = score_risk(True, port, banner)
            return ScanResult(
                target=host, port=port, open=True, banner=banner, rtt_ms=rtt,
                risk_score=score, risk_level=level, risk_reasons=reasons
            )
    except Exception as e:
        rtt = int((time.perf_counter() - start) * 1000)
        score, level, reasons = score_risk(False, port, None)
        return ScanResult(
            target=host, port=port, open=False, error=str(e), rtt_ms=rtt,
            risk_score=score, risk_level=level, risk_reasons=reasons
        )


def hardening_checklist() -> List[str]:
    return [
        "If SSH is not needed externally, restrict it (firewall, VPN, or allowlist).",
        "Prefer SSH keys; disable password authentication where possible.",
        "Disable root SSH login; use sudo with least privilege.",
        "Rate-limit auth attempts (fail2ban/sshguard) and set MaxAuthTries low.",
        "Use AllowUsers/AllowGroups where practical.",
        "Keep SSH server patched; review crypto policy and key sizes.",
        "Consider MFA for administrative access."
    ]


def main() -> int:
    p = argparse.ArgumentParser(
        prog="SafeCraker-1.py",
        description="SafeCraker (Blue Team Edition): Threaded SSH exposure scanner (no authentication).",
    )
    p.add_argument("-H", "--host", help="Target host/IP/CIDR (e.g., 10.0.0.5 or 10.0.0.0/24 or example.com)")
    p.add_argument("--targets-file", help="File containing targets (one per line, # for comments)")
    p.add_argument("-p", "--ports", default="22", help="Ports: '22' or '22,2222' or '22-25,2222' (default: 22)")
    p.add_argument("-T", "--threads", type=int, default=64, help="Worker threads (default: 64)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Connect timeout seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--open-only", action="store_true", help="Only print results where the port is open")
    p.add_argument("-o", "--output", help="Write JSON report to file path")
    args = p.parse_args()

    if not args.host and not args.targets_file:
        p.print_help()
        return 2

    ports = parse_ports(args.ports)
    if not ports:
        print("No valid ports provided.", file=sys.stderr)
        return 2

    targets: List[str] = []
    if args.host:
        targets.extend(list(iter_targets(args.host)))
    if args.targets_file:
        targets.extend(load_targets_from_file(Path(args.targets_file)))

    expanded: List[str] = []
    for t in targets:
        expanded.extend(list(iter_targets(t)))

    # de-dupe
    seen = set()
    final_targets: List[str] = []
    for t in expanded:
        if t not in seen:
            seen.add(t)
            final_targets.append(t)

    jobs: List[Tuple[str, int]] = [(t, port) for t in final_targets for port in ports]

    print(f"[*] Targets: {len(final_targets)} | Ports: {len(ports)} | Jobs: {len(jobs)} | Threads: {args.threads}")
    results: List[ScanResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = [ex.submit(scan_one, host, port, args.timeout) for host, port in jobs]
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            results.append(r)
            if args.open_only and not r.open:
                continue
            status = "OPEN" if r.open else "CLOSED"
            banner = f" | banner: {r.banner}" if (r.open and r.banner) else ""
            err = f" | err: {r.error}" if (not r.open and r.error) else ""
            print(f"[{status}] {r.target}:{r.port} | rtt={r.rtt_ms}ms | risk={r.risk_level}:{r.risk_score}{banner}{err}")

    # summary
    open_results = [r for r in results if r.open]
    open_count = len(open_results)
    print(f"[*] Summary: {open_count}/{len(results)} sockets open")

    if open_count:
        print("\n[*] Hardening checklist (general):")
        for item in hardening_checklist():
            print(f"  - {item}")

    report: Dict[str, Any] = {
        "tool": "SafeCraker (Blue Team Edition)",
        "created_by": "BMFI Jeff Rogers",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": {
            "host": args.host,
            "targets_file": args.targets_file,
            "ports": ports,
            "threads": args.threads,
            "timeout": args.timeout,
        },
        "results": [asdict(r) for r in sorted(results, key=lambda x: (x.target, x.port))],
        "notes": "This scanner does not attempt authentication. It checks exposure and captures any banner presented.",
        "hardening_checklist": hardening_checklist(),
    }

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[*] Wrote report: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
