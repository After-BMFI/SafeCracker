
#!/usr/bin/env python3
"""
Lab Mode (Offline) - Python 3.9+
No network actions. Educational only.

- Password policy scoring (offline)
- Simple rate-limit simulator (shows how lockouts protect services)

Usage:
  python3 lab_mode.py --password "Example123!"
  python3 lab_mode.py --simulate --attempts 50 --limit 5 --window 30
"""

import argparse
import math
import time
from dataclasses import dataclass
from typing import List


def password_score(pw: str) -> int:
    # Simple, explainable heuristic
    score = 0
    length = len(pw)
    score += min(40, length * 3)

    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)

    score += 10 if has_lower else 0
    score += 10 if has_upper else 0
    score += 15 if has_digit else 0
    score += 15 if has_symbol else 0

    # penalize repeats
    unique = len(set(pw))
    if length > 0:
        score -= int((1 - (unique / length)) * 20)

    return max(0, min(100, score))


def password_feedback(pw: str) -> List[str]:
    tips = []
    if len(pw) < 12:
        tips.append("Use 12–16+ characters.")
    if not any(c.islower() for c in pw):
        tips.append("Add lowercase letters.")
    if not any(c.isupper() for c in pw):
        tips.append("Add uppercase letters.")
    if not any(c.isdigit() for c in pw):
        tips.append("Add digits.")
    if not any(not c.isalnum() for c in pw):
        tips.append("Add symbols.")
    if len(set(pw)) < max(6, len(pw) // 2):
        tips.append("Avoid repeated characters/patterns.")
    if not tips:
        tips.append("Looks strong by basic policy checks. Prefer MFA + keys where possible.")
    return tips


@dataclass
class RateLimit:
    limit: int
    window_seconds: int
    attempts: List[float]

    def allow(self, now: float) -> bool:
        # keep attempts within window
        self.attempts = [t for t in self.attempts if now - t <= self.window_seconds]
        if len(self.attempts) >= self.limit:
            return False
        self.attempts.append(now)
        return True


def simulate_rate_limit(attempts: int, limit: int, window: int, delay_ms: int):
    rl = RateLimit(limit=limit, window_seconds=window, attempts=[])
    blocked = 0
    allowed = 0
    start = time.time()

    for i in range(1, attempts + 1):
        now = time.time()
        if rl.allow(now):
            allowed += 1
            print(f"[ALLOW] Attempt {i} allowed (in-window={len(rl.attempts)}/{limit})")
        else:
            blocked += 1
            print(f"[BLOCK] Attempt {i} blocked (rate limit reached)")
        time.sleep(max(0, delay_ms) / 1000.0)

    dur = time.time() - start
    print("\n=== Simulation Summary ===")
    print(f"Attempts: {attempts}")
    print(f"Allowed : {allowed}")
    print(f"Blocked : {blocked}")
    print(f"Window  : {window}s, Limit: {limit} per window")
    print(f"Duration: {dur:.2f}s")


def main():
    ap = argparse.ArgumentParser(description="SafeCraker Lab Mode (Offline): password policy + rate-limit simulator.")
    ap.add_argument("--password", help="Score a password offline (no network)")
    ap.add_argument("--simulate", action="store_true", help="Run rate-limit simulator (offline)")
    ap.add_argument("--attempts", type=int, default=30, help="Number of attempts to simulate")
    ap.add_argument("--limit", type=int, default=5, help="Rate limit attempts per window")
    ap.add_argument("--window", type=int, default=30, help="Rate limit window in seconds")
    ap.add_argument("--delay-ms", type=int, default=200, help="Delay between attempts (ms)")
    args = ap.parse_args()

    if args.password:
        s = password_score(args.password)
        level = "WEAK" if s < 45 else "MEDIUM" if s < 75 else "STRONG"
        print(f"Score: {s}/100  Level: {level}")
        for tip in password_feedback(args.password):
            print(f"- {tip}")

    if args.simulate:
        simulate_rate_limit(args.attempts, args.limit, args.window, args.delay_ms)

    if not args.password and not args.simulate:
        ap.print_help()


if __name__ == "__main__":
    main()
