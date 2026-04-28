#!/usr/bin/env python3
"""Background thread that lifts expired IP bans and notifies on each release."""

import subprocess
import threading
import time
from datetime import datetime, timezone


class Unbanner:
    """
    Periodically checks every 30 seconds whether a banned IP's duration has elapsed
    and removes the iptables DROP rule if so, then calls the notifier with the
    next escalated ban duration based on ban_count.
    """

    def __init__(self, blocker, notifier, config: dict):
        """
        Args:
            blocker:  A Blocker instance whose banned_ips dict is mutated on unban.
            notifier: A Notifier instance with a send_unban_alert(ip, next_duration) method.
            config:   Full config dict (expects blocking.durations_seconds list).
        """
        self._blocker = blocker
        self._notifier = notifier
        self._durations = config.get('blocking', {}).get(
            'durations_seconds', [600, 1800, 7200, -1]
        )
        self._audit_path = config.get('log', {}).get('audit_path', '/var/log/detection/audit.log')

    def _next_duration(self, ban_count: int) -> int:
        """Return the next escalated ban duration for an IP with ban_count prior bans."""
        idx = min(ban_count, len(self._durations) - 1)
        return self._durations[idx]

    def _unban(self, ip: str) -> None:
        """Remove iptables DROP rule for ip."""
        try:
            subprocess.run(
                ['iptables', '-D', 'DOCKER-USER', '-s', ip, '-j', 'DROP'],
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            print(f"Failed to unban {ip}: {e}")

    def _check_loop(self) -> None:
        """Check banned IPs every 30 seconds and release any whose duration has elapsed."""
        while True:
            now = time.time()
            # Snapshot keys to avoid mutating dict during iteration
            for ip, (ban_time, duration_seconds, ban_count) in list(
                self._blocker.banned_ips.items()
            ):
                if duration_seconds == -1:
                    continue
                if now - ban_time >= duration_seconds:
                    self._unban(ip)
                    del self._blocker.banned_ips[ip]
                    next_duration = self._next_duration(ban_count)
                    self._notifier.send_unban_alert(ip, next_duration)
                    with open(self._audit_path, 'a') as f:
                        ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                        f.write(f'[{ts}] UNBAN {ip} | next_duration={next_duration}\n')

            time.sleep(30)

    def start(self) -> None:
        """Start the unban check loop as a background daemon thread."""
        thread = threading.Thread(target=self._check_loop, daemon=True)
        thread.start()
