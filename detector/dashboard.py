#!/usr/bin/env python3
"""Live web dashboard served via http.server showing detector metrics."""

import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import psutil


class Dashboard:
    """
    Serves a plain HTML dashboard over HTTP that auto-refreshes every N seconds.
    Displays uptime, traffic rates, baseline stats, top IPs, banned IPs, and
    system resource usage.
    """

    def __init__(self, blocker, detector, baseline, config: dict):
        """
        Args:
            blocker:  Blocker instance (for banned IP data).
            detector: Detector instance (for per-IP and global window data).
            baseline: Baseline instance (for mean/stddev).
            config:   Full config dict (expects dashboard.port and dashboard.refresh_seconds).
        """
        self._blocker = blocker
        self._detector = detector
        self._baseline = baseline
        self._port = config.get('dashboard', {}).get('port', 8080)
        self._refresh_seconds = config.get('dashboard', {}).get('refresh_seconds', 3)
        self._start_time = time.time()

    def _build_html(self) -> str:
        """Render the dashboard page as an HTML string from current state."""
        now = time.time()

        # Uptime
        uptime_secs = int(now - self._start_time)
        uptime_h = uptime_secs // 3600
        uptime_m = (uptime_secs % 3600) // 60

        # Traffic
        window_seconds = self._detector._window_seconds
        global_rate = len(self._detector._global_window)
        global_rps = round(global_rate / max(window_seconds, 1), 2)

        # Baseline
        mean, stddev = self._baseline.get_baseline()

        # Top 10 IPs by current window count
        top_ips = sorted(
            self._detector._ip_windows.items(),
            key=lambda kv: len(kv[1]),
            reverse=True,
        )[:10]

        # Banned IPs
        banned = self._blocker.get_banned_ips()

        # System resources
        cpu_pct = psutil.cpu_percent(interval=None)
        mem_pct = psutil.virtual_memory().percent

        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        # --- Top IPs table rows ---
        if top_ips:
            top_ip_rows = ''.join(
                f'<tr><td>{ip}</td><td>{len(dq)}</td></tr>'
                for ip, dq in top_ips
            )
        else:
            top_ip_rows = '<tr><td colspan="2">No traffic recorded</td></tr>'

        # --- Banned IPs table rows ---
        if banned:
            banned_rows = ''
            for ip, (ban_time, duration_seconds, ban_count) in banned.items():
                ban_dt = datetime.fromtimestamp(ban_time, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                if duration_seconds == -1:
                    duration_label = 'permanent'
                    remaining_label = 'permanent'
                else:
                    duration_label = f'{duration_seconds}s'
                    remaining = max(0, int(duration_seconds - (now - ban_time)))
                    remaining_label = f'{remaining}s'
                banned_rows += (
                    f'<tr>'
                    f'<td>{ip}</td>'
                    f'<td>{ban_dt}</td>'
                    f'<td>{duration_label}</td>'
                    f'<td>{remaining_label}</td>'
                    f'<td>{ban_count}</td>'
                    f'</tr>'
                )
        else:
            banned_rows = '<tr><td colspan="5">No IPs currently banned</td></tr>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="{self._refresh_seconds}">
  <title>Anomaly Detection Dashboard</title>
  <style>
    body {{ font-family: monospace; margin: 2em; background: #f4f4f4; color: #222; }}
    h1 {{ border-bottom: 2px solid #222; padding-bottom: 0.3em; }}
    h2 {{ margin-top: 1.5em; border-bottom: 1px solid #aaa; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 800px; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4em 0.8em; text-align: left; }}
    th {{ background: #ddd; }}
    .metric {{ display: inline-block; margin: 0.5em 1.5em 0.5em 0; }}
    .label {{ font-weight: bold; }}
    .footer {{ margin-top: 2em; font-size: 0.85em; color: #666; }}
  </style>
</head>
<body>
  <h1>Anomaly Detection Dashboard</h1>

  <h2>System</h2>
  <div>
    <span class="metric"><span class="label">Uptime:</span> {uptime_h}h {uptime_m}m</span>
    <span class="metric"><span class="label">CPU:</span> {cpu_pct}%</span>
    <span class="metric"><span class="label">Memory:</span> {mem_pct}%</span>
  </div>

  <h2>Traffic</h2>
  <div>
    <span class="metric"><span class="label">Global requests in window:</span> {global_rate}</span>
    <span class="metric"><span class="label">Global RPS:</span> {global_rps}</span>
    <span class="metric"><span class="label">Baseline mean:</span> {mean:.2f}</span>
    <span class="metric"><span class="label">Baseline stddev:</span> {stddev:.2f}</span>
  </div>

  <h2>Top 10 Source IPs (current window)</h2>
  <table>
    <tr><th>IP</th><th>Requests in window</th></tr>
    {top_ip_rows}
  </table>

  <h2>Banned IPs</h2>
  <table>
    <tr><th>IP</th><th>Banned at (UTC)</th><th>Duration</th><th>Remaining</th><th>Ban count</th></tr>
    {banned_rows}
  </table>

  <div class="footer">Last updated: {timestamp} | Refreshes every {self._refresh_seconds}s</div>
</body>
</html>"""

    def _make_handler(self):
        """Return a request handler class with a closure over this Dashboard instance."""
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path not in ('/', '/index.html'):
                    self.send_response(404)
                    self.end_headers()
                    return
                body = dashboard._build_html().encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass  # suppress per-request access log noise

        return Handler

    def start(self) -> None:
        """Start the HTTP server in a background daemon thread."""
        server = HTTPServer(('0.0.0.0', self._port), self._make_handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f'Dashboard running on http://0.0.0.0:{self._port}')
