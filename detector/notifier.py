#!/usr/bin/env python3
"""Slack notifier for ban, unban, and global traffic anomaly alerts."""

import json
from datetime import datetime, timezone

import requests


class Notifier:
    """
    Sends plain-text Slack alerts via incoming webhook.
    All methods are fire-and-forget — failures are logged but never re-raised.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Full config dict (expects slack.webhook_url).
        """
        self._webhook_url = config.get('slack', {}).get('webhook_url', '')

    def _post(self, text: str) -> None:
        """Send a plain-text message to the configured Slack webhook."""
        requests.post(
            self._webhook_url,
            data=json.dumps({'text': text}),
            headers={'Content-Type': 'application/json'},
            timeout=5,
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def send_ban_alert(
        self,
        ip: str,
        condition: str,
        rate: int,
        baseline_mean: float,
        duration_seconds: int,
    ) -> None:
        """
        Alert that an IP has been banned.

        Args:
            ip:               Blocked IP address.
            condition:        Human-readable reason for the ban.
            rate:             Observed request rate for this IP.
            baseline_mean:    Current baseline mean request rate.
            duration_seconds: Ban duration (-1 means permanent).
        """
        try:
            duration_label = 'permanent' if duration_seconds == -1 else f'{duration_seconds}s'
            text = (
                f'[BAN] {self._now()}\n'
                f'IP: {ip}\n'
                f'Reason: {condition}\n'
                f'Rate: {rate} req/window | Baseline mean: {baseline_mean:.1f}\n'
                f'Ban duration: {duration_label}'
            )
            self._post(text)
        except Exception as e:
            print(f'Notifier.send_ban_alert failed: {e}')

    def send_unban_alert(self, ip: str, next_duration: int) -> None:
        """
        Alert that a ban has expired and report the next escalated duration.

        Args:
            ip:            Unbanned IP address.
            next_duration: Duration (seconds) that will apply on the next offence (-1 = permanent).
        """
        try:
            next_label = 'permanent' if next_duration == -1 else f'{next_duration}s'
            text = (
                f'[UNBAN] {self._now()}\n'
                f'IP: {ip}\n'
                f'Next ban duration if re-offence: {next_label}'
            )
            self._post(text)
        except Exception as e:
            print(f'Notifier.send_unban_alert failed: {e}')

    def send_global_alert(
        self,
        global_rate: int,
        baseline_mean: float,
        condition: str,
    ) -> None:
        """
        Alert on a fleet-wide traffic anomaly.

        Args:
            global_rate:   Total requests observed in the current window.
            baseline_mean: Current baseline mean request rate.
            condition:     Human-readable description of the anomaly.
        """
        try:
            text = (
                f'[GLOBAL ANOMALY] {self._now()}\n'
                f'Condition: {condition}\n'
                f'Global rate: {global_rate} req/window | Baseline mean: {baseline_mean:.1f}'
            )
            self._post(text)
        except Exception as e:
            print(f'Notifier.send_global_alert failed: {e}')
