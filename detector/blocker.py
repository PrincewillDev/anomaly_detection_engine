#!/usr/bin/env python3
"""IP blocking via iptables with ban-count tracking for escalating backoff."""

import subprocess
import time


class Blocker:
    """
    Manages iptables DROP rules for anomalous IPs.
    Tracks ban history per IP so callers can escalate ban durations.
    """

    def __init__(self):
        # ip -> (ban_time: float, duration_seconds: int, ban_count: int)
        self.banned_ips: dict[str, tuple[float, int, int]] = {}

    def block(self, ip: str, duration_seconds: int) -> None:
        """
        Insert an iptables DROP rule for ip and record the ban.

        Args:
            ip:               The source IP address to block.
            duration_seconds: How long the ban lasts (-1 means permanent).
        """
        try:
            subprocess.run(
                ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"Failed to block {ip}: {e}")
            return

        existing = self.banned_ips.get(ip)
        ban_count = (existing[2] + 1) if existing else 1
        self.banned_ips[ip] = (time.time(), duration_seconds, ban_count)

    def is_banned(self, ip: str) -> bool:
        """Return True if ip has an active (non-expired) ban."""
        entry = self.banned_ips.get(ip)
        if entry is None:
            return False
        ban_time, duration_seconds, _ = entry
        if duration_seconds == -1:
            return True
        return (time.time() - ban_time) < duration_seconds

    def get_banned_ips(self) -> dict[str, tuple[float, int, int]]:
        """Return the full banned_ips dictionary (ip -> (ban_time, duration, ban_count))."""
        return self.banned_ips
