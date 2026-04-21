"""
Mimecast Gateway Adapter
=========================
Uses Mimecast REST API v2 (OAuth2) to pull SIEM logs.
Covers: URL protect click events, attachment threats, email rejections.

Docs: https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-siem-logs/

Credentials: Client ID + Client Secret from Mimecast Administration Console.
"""

import json
import logging
from base64 import b64encode
from datetime import datetime, timedelta
from typing import Optional

from .base import BaseGatewayAdapter, GatewayEvent

log = logging.getLogger(__name__)


class MimecastAdapter(BaseGatewayAdapter):
    name = "mimecast"

    def _get_token(self) -> Optional[str]:
        try:
            import urllib.request, urllib.parse
            url = f"{self.config.mc_base_url}/oauth/token"
            data = urllib.parse.urlencode({
                "grant_type":    "client_credentials",
                "client_id":     self.config.mc_client_id,
                "client_secret": self.config.mc_client_secret,
            }).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read())
                return body.get("access_token")
        except Exception as e:
            log.error(f"Mimecast token error: {e}")
            return None

    def test_connection(self) -> tuple[bool, str]:
        token = self._get_token()
        if not token:
            return False, "Failed to obtain Mimecast access token. Check Base URL, Client ID, Client Secret."
        return True, "Mimecast connection successful."

    def pull(self, since: Optional[datetime] = None) -> list[GatewayEvent]:
        token = self._get_token()
        if not token:
            log.error("Mimecast pull: could not obtain token")
            return []

        if since is None:
            since = datetime.utcnow() - timedelta(hours=1)

        events: list[GatewayEvent] = []
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }

        # ── URL Protect click logs ─────────────────────────────────────────
        try:
            import urllib.request

            url = f"{self.config.mc_base_url}/api/audit/get-siem-logs"
            payload = json.dumps({
                "data": [{
                    "type": "MTA",                   # Mail Transfer Agent events
                    "compress": False,
                    "fileFormat": "json",
                }]
            }).encode()

            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=20) as resp:
                content = resp.read().decode()

            # Mimecast returns newline-delimited JSON objects
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:
                    continue

                acc = record.get("acc", "").lower()    # recipient
                if not acc:
                    acc = record.get("rcpt", "").lower()
                if not acc:
                    continue

                # Classify by Mimecast event fields
                act  = (record.get("Act") or "").lower()   # action taken
                threat = (record.get("Threat") or "").lower()
                scan  = (record.get("scanResultInfo") or "").lower()

                event_type = None
                if "phish" in threat or "phish" in scan:
                    event_type = "phish"
                elif "malware" in threat or "virus" in scan or "malware" in scan:
                    event_type = "malware"
                elif "impersonat" in threat or "bec" in threat:
                    event_type = "bec"
                elif "clicked" in act and "malicious" in threat:
                    event_type = "real_click"
                else:
                    continue

                time_str = record.get("datetime", "")
                try:
                    occurred_at = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    occurred_at = datetime.utcnow()

                if occurred_at < since:
                    continue

                events.append(GatewayEvent(
                    email=acc,
                    event_type=event_type,
                    gateway=self.name,
                    occurred_at=occurred_at,
                    subject=record.get("Subject"),
                    sender=record.get("Sender"),
                    threat_name=threat,
                    raw=record,
                ))
        except Exception as e:
            log.error(f"Mimecast SIEM log pull error: {e}")

        log.info(f"Mimecast adapter pulled {len(events)} events since {since.isoformat()}")
        return events
