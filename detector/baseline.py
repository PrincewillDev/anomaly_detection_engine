#!/usr/bin/env python3
"""Rolling baseline calculator for per-second request counts."""

import time
import statistics
from collections import deque


class Baseline:
    """
    Tracks request-rate baselines over a 30-minute rolling window
    and per-hour slots, computing mean and stddev for anomaly detection.
    """

    def __init__(self):
        self._window = deque(maxlen=1800)
        self._hourly_slots = {h: [] for h in range(24)}
        self._mean = 1.0
        self._stddev = 1.0
        self._last_recalc = time.time()

    def add_count(self, count: int) -> None:
        """Add a per-second request count to the rolling window and current hour slot."""
        self._window.append(count)
        current_hour = time.localtime().tm_hour
        self._hourly_slots[current_hour].append(count)
        
        # trim to last 3600 entries
        if len(self._hourly_slots[current_hour]) > 3600:
            self._hourly_slots[current_hour] = self._hourly_slots[current_hour][-3600:]

        if time.time() - self._last_recalc >= 60:
            self.recalculate()
            self._last_recalc = time.time()

    def recalculate(self) -> None:
        """Compute mean and stddev from the best available data source."""
        current_hour = time.localtime().tm_hour
        hourly_data = self._hourly_slots[current_hour]

        if len(hourly_data) > 60:
            data = hourly_data
        elif len(self._window) > 1:
            data = list(self._window)
        else:
            return

        self._mean = max(1.0, statistics.mean(data))
        self._stddev = max(1.0, statistics.stdev(data) if len(data) > 1 else 1.0)

    def get_baseline(self) -> tuple[float, float]:
        """Return (mean, stddev) from the current hour slot if it has >60 points, else rolling window."""
        current_hour = time.localtime().tm_hour
        hourly_data = self._hourly_slots[current_hour]

        if len(hourly_data) > 60:
            data = hourly_data
        elif len(self._window) > 1:
            data = list(self._window)
        else:
            return (self._mean, self._stddev)

        mean = max(1.0, statistics.mean(data))
        stddev = max(1.0, statistics.stdev(data) if len(data) > 1 else 1.0)
        return (mean, stddev)
