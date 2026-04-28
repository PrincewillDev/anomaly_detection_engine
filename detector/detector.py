#!/usr/bin/env python3
"""Per-IP and global request-rate anomaly detector."""

import time
from collections import defaultdict, deque
from datetime import datetime


class Detector:
    """
    Detects anomalous request rates by comparing per-IP and global sliding-window
    counts against a rolling Baseline using z-score and rate-multiplier heuristics.
    """

    def __init__(self, baseline, config: dict):
        """
        Args:
            baseline: A Baseline instance providing get_baseline() -> (mean, stddev).
            config:   Full config dict (expects keys window.size_seconds,
                      detection.z_score_threshold, detection.rate_multiplier_threshold,
                      detection.error_surge_multiplier).
        """
        self._baseline = baseline
        self._window_seconds = config.get('window', {}).get('size_seconds', 60)

        detection = config.get('detection', {})
        self._z_threshold = detection.get('z_score_threshold', 3.0)
        self._rate_multiplier = detection.get('rate_multiplier_threshold', 5)
        self._error_surge_multiplier = detection.get('error_surge_multiplier', 3)

        self._ip_windows = defaultdict(deque)   # ip -> deque of Unix timestamps
        self._global_window = deque()           # all requests in window
        self._ip_errors = defaultdict(deque)    # ip -> deque of error timestamps
        self._global_errors = deque()           # all 4xx/5xx in window

    def _evict_old(self, dq: deque, cutoff: float) -> None:
        """Drop timestamps from the left of dq that are older than cutoff."""
        while dq and dq[0] < cutoff:
            dq.popleft()

    def process_entry(self, log_entry: dict) -> dict:
        """
        Evaluate one parsed log entry for anomalous behaviour.

        Args:
            log_entry: Dict with keys source_ip, timestamp, method, path,
                       status, response_size.

        Returns:
            Dict with ip, ip_rate, global_rate, z_score, anomaly (bool), reason (str).
        """
        ip = log_entry.get('source_ip', '')
        status = str(log_entry.get('status', '200'))
        now = time.time()
        cutoff = now - self._window_seconds

        # Record arrival
        self._ip_windows[ip].append(now)
        self._global_window.append(now)

        if status.startswith('4') or status.startswith('5'):
            self._ip_errors[ip].append(now)
            self._global_errors.append(now)

        # Evict stale entries
        self._evict_old(self._ip_windows[ip], cutoff)
        self._evict_old(self._global_window, cutoff)
        self._evict_old(self._ip_errors[ip], cutoff)
        self._evict_old(self._global_errors, cutoff)

        ip_rate = len(self._ip_windows[ip])
        global_rate = len(self._global_window)

        mean, stddev = self._baseline.get_baseline()
        z_score = (ip_rate - mean) / stddev

        # Tighten z-score threshold if this IP's error proportion is surging
        global_error_proportion = len(self._global_errors) / max(global_rate, 1)
        ip_error_proportion = len(self._ip_errors[ip]) / max(ip_rate, 1)
        z_threshold = self._z_threshold
        if ip_error_proportion > self._error_surge_multiplier * global_error_proportion:
            z_threshold = 2.0

        # Anomaly decision
        anomaly = False
        reason = ''

        if z_score > z_threshold:
            anomaly = True
            reason = (
                f'z_score {z_score:.2f} exceeds threshold {z_threshold:.1f}'
            )
        elif ip_rate > self._rate_multiplier * mean:
            anomaly = True
            reason = (
                f'ip_rate {ip_rate} exceeds {self._rate_multiplier}x '
                f'mean ({mean:.1f})'
            )

        return {
            'ip': ip,
            'ip_rate': ip_rate,
            'global_rate': global_rate,
            'z_score': round(z_score, 4),
            'anomaly': anomaly,
            'reason': reason,
        }
