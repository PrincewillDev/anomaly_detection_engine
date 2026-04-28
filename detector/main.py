#!/usr/bin/env python3
"""Entry point: loads config, wires all components, and runs the monitoring loop."""

import os
import sys
import time
from datetime import datetime, timezone

import yaml

from baseline import Baseline
from blocker import Blocker
from dashboard import Dashboard
from detector import Detector
from monitor import monitor_logs
from notifier import Notifier
from unbanner import Unbanner


def _env_constructor(loader, node) -> str:
    """Resolve !ENV tags by reading the named environment variable."""
    return os.getenv(loader.construct_scalar(node), '')

yaml.add_constructor('!ENV', _env_constructor, Loader=yaml.SafeLoader)


def load_config(path: str = 'config.yaml') -> dict:
    """Load and return the YAML config file, resolving !ENV tags from the environment."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def write_audit(audit_path: str, message: str) -> None:
    """Append a timestamped line to the audit log."""
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    with open(audit_path, 'a') as f:
        f.write(f'[{ts}] {message}\n')


def main() -> None:
    """
    Bootstrap all components and drive the main log-consumption loop.

    Flow per log entry:
      1. Increment per-second counter.
      2. Every second: feed count to baseline, check global z-score.
      3. Pass entry to detector.
      4. If anomaly detected and IP not already banned: ban, alert, audit.
    """
    config = load_config()

    log_path = config['log']['path']
    audit_path = config['log']['audit_path']

    audit_dir = os.path.dirname(audit_path)
    if audit_dir:
        os.makedirs(audit_dir, exist_ok=True)

    # Component instantiation order
    baseline = Baseline()
    notifier = Notifier(config)
    blocker = Blocker()
    unbanner = Unbanner(blocker, notifier, config)
    detector = Detector(baseline, config)
    dashboard = Dashboard(blocker, detector, baseline, config)

    unbanner.start()
    dashboard.start()

    durations = config.get('blocking', {}).get('durations_seconds', [600, 1800, 7200, -1])
    z_threshold = config.get('detection', {}).get('z_score_threshold', 3.0)

    per_second_count = 0
    last_tick = time.time()
    last_baseline_log = 0.0

    print(f'Anomaly detection engine started. Monitoring: {log_path}')

    try:
        for log_entry in monitor_logs(log_path):
            per_second_count += 1
            now = time.time()

            if now - last_tick >= 1.0:
                baseline.add_count(per_second_count)
                per_second_count = 0
                last_tick = now

                # Audit baseline recalculation every 60 seconds
                if now - last_baseline_log >= 60.0:
                    mean, stddev = baseline.get_baseline()
                    write_audit(
                        audit_path,
                        f'BASELINE recalculated | mean={mean:.2f} | stddev={stddev:.2f}',
                    )
                    last_baseline_log = now

                # Global rate anomaly check
                mean, stddev = baseline.get_baseline()
                global_rate = len(detector._global_window)
                global_z = (global_rate - mean) / stddev
                if global_z > z_threshold:
                    condition = f'global z_score {global_z:.2f} exceeds threshold {z_threshold}'
                    notifier.send_global_alert(global_rate, mean, condition)

            result = detector.process_entry(log_entry)

            if result['anomaly']:
                ip = result['ip']
                if not blocker.is_banned(ip):
                    existing = blocker.banned_ips.get(ip)
                    ban_count = existing[2] if existing else 0
                    duration = durations[min(ban_count, len(durations) - 1)]

                    blocker.block(ip, duration)

                    mean, stddev = baseline.get_baseline()
                    notifier.send_ban_alert(
                        ip,
                        result['reason'],
                        result['ip_rate'],
                        mean,
                        duration,
                    )

                    duration_label = 'permanent' if duration == -1 else f'{duration}s'
                    write_audit(
                        audit_path,
                        (
                            f'BAN {ip} | {result["reason"]} | '
                            f'rate={result["ip_rate"]} | mean={mean:.2f} | '
                            f'duration={duration_label}'
                        ),
                    )

    except KeyboardInterrupt:
        print('\nShutting down.')
        sys.exit(0)


if __name__ == '__main__':
    main()
