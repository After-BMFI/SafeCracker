
#!/usr/bin/env python3
"""
SafeCraker-1.py (Blue Team Edition)
Python 3.9+
To Use this Product You are required Keep the After-BMFI ARBITRATION AGREEMENT AND WARRANTY DISCLAIMER WITH IT.
SafeCraker-1.py was created as part of ECE(Evil Clown Empire) Products Group by Jeff Rogers.
Do not let the name fool You the products were created for Ethical Hacking,-
-Blue Team and Educational Lab Testing Purposes.
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
from typing import Iterable, List, Optional, Tuple


DEFAULT_PORTS = [22]
DEFAULT_TIMEOUT = 3.0


@dataclass
class ScanResult:
    target: str
    port: int
    open: bool
    banner: Optional[str] = None
    error: Optional[str] = None
    rtt_ms: Optional[int] = None


def iter_targets(target: str) -> Iterable[str]:
    """
    Accepts:
      - single IP: 192.168.1.10
      - CIDR: 192.168.1.0/24
      - hostname: example.com
    """
    target = target.strip()
    if not target:
        return

    try:
        # If it's an IP or CIDR, expand
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            for ip in net.hosts():
                yield str(ip)
            return
        # Single IP
        ipaddress.ip_address(target)
        yield target
        return
    except ValueError:
        # Not an IP; treat as hostname
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
    """
    Accepts:
      - "22"
      - "22,2222"
      - "22-25,2222"
    """
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
    # de-dupe, keep stable order
    seen = set()
    out: List[int] = []
    for p in ports:
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def safe_read_banner(sock: socket.socket, max_bytes: int = 256) -> Optional[str]:
    """
    SSH servers typically send a banner like: b"SSH-2.0-OpenSSH_8.9p1 ...\r\n"
    We read a small chunk without speaking the protocol.
    """
    sock.settimeout(1.5)
    try:
        data = sock.recv(max_bytes)
        if not data:
            return None
        # Best-effort decode
        text = data.decode("utf-8", errors="replace").strip()
        return text[:200] if text else None
    except Exception:
        return None


def scan_one(host: str, port: int, timeout: float) -> ScanResult:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            rtt = int((time.perf_counter() - start) * 1000)
            banner = safe_read_banner(s)
            return ScanResult(target=host, port=port, open=True, banner=banner, rtt_ms=rtt)
    except Exception as e:
        rtt = int((time.perf_counter() - start) * 1000)
        return ScanResult(target=host, port=port, open=False, error=str(e), rtt_ms=rtt)


def hardening_recommendations(result: ScanResult) -> List[str]:
    """
    These are general recommendations. We do NOT claim remote config certainty.
    """
    recs: List[str] = []
    if result.open:
        recs.append("If not needed, restrict SSH exposure (firewall/VPN/allowlist).")
        recs.append("Disable password authentication; use SSH keys + MFA where possible.")
        recs.append("Disable root SSH login; use sudo with least privilege.")
        recs.append("Rate-limit and ban repeated auth failures (fail2ban/sshguard).")
        recs.append("Set MaxAuthTries low; consider AllowUsers/AllowGroups.")
        recs.append("Keep OpenSSH patched; review crypto policies.")
    return recs


def main() -> int:
    p = argparse.ArgumentParser(
        prog="SafeCraker-1.py",
        description="SafeCraker (Blue Team Edition): Threaded SSH exposure scanner (no credential guessing).",
    )
    p.add_argument("-H", "--host", help="Target host/IP/CIDR (e.g., 10.0.0.5 or 10.0.0.0/24 or example.com)")
    p.add_argument("--targets-file", help="File containing targets (one per line, # for comments)")
    p.add_argument(
        "-p",
        "--ports",
        default="22",
        help="Ports: '22' or '22,2222' or '22-25,2222' (default: 22)",
    )
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
        for t in iter_targets(args.host):
            targets.append(t)
    if args.targets_file:
        targets.extend(load_targets_from_file(Path(args.targets_file)))

    # Expand any CIDRs found inside file too
    expanded: List[str] = []
    for t in targets:
        for x in iter_targets(t):
            expanded.append(x)

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
            print(f"[{status}] {r.target}:{r.port} | rtt={r.rtt_ms}ms{banner}{err}")

    # Write report
    report = {
        "tool": "SafeCraker (Blue Team Edition)",
        "created_by": "BMFI Jeff Rogers",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "results": [asdict(r) for r in sorted(results, key=lambda x: (x.target, x.port))],
        "notes": "This scanner does not attempt authentication. It checks exposure and captures any banner presented.",
    }

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[*] Wrote report: {out_path}")

    # Print a quick summary + recommendations
    open_count = sum(1 for r in results if r.open)
    print(f"[*] Summary: {open_count}/{len(results)} sockets open")

    if open_count:
        print("\n[*] Hardening checklist (general):")
        # Print once (not per-host spam)
        for item in hardening_recommendations(next(r for r in results if r.open)):
            print(f"  - {item}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
