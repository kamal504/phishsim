"""
Proofpoint Email Security Gateway Adapter
==========================================
Uses the Proofpoint SIEM API (v2) to pull per-recipient threat events.
Covers: clicks to malicious URLs, messages blocked as phish/malware/BEC.

Docs: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API

Credentials: Principal + Secret from Proofpoint TAP dashboard.
"""

import json
import logging
from base64 import b64encode
from datetime import datetime, timedelta
from typing import Optional

from .base import BaseGatewayAdapter, GatewayEvent

log = logging.getLogger(__name__)

_BASE = "https://tap-api-v2.proofpoint.com/v2/siem"


class ProofpointAdapter(BaseGatewayAdapter):
    name = "proofpoint"

    def _headers(self) -> dict:
        creds = b64encode(
            f"{self.config.pp_principal}:{self.config.pp_secret}".encode()
        ).decode()
        return {"Authorization": f"Basic {creds}", "Accept": "application/json"}

    def test_connection(self) -> tuple[bool, str]:
        try:
            import urllib.request
            url = f"{_BASE}/all?format=json&sinceSeconds=300&clusterID={self.config.pp_cluster_id}"
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    return True, "Proofpoint connection successful."
                return False, f"Proofpoint returned HTTP {resp.status}."
        except Exception as e:
            return False, f"Proofpoint connection failed: {e}"

    def pull(self, since: Optional[datetime] = None) -> list[GatewayEvent]:
        import urllib.request

        if since is None:
            since = datetime.utcnow() - timedelta(hours=1)

        # Proofpoint API max window = 1 hour, max history = 7 days
        delta_secs = int((datetime.utcnow() - since).total_seconds())
        delta_secs = min(delta_secs, 3600)  # cap at 1 hour per call

        events: list[GatewayEvent] = []

        # ── Clicks to malicious URLs (per-recipient) ─────────────────────────
        try:
            url = (
                f"{_BASE}/clicks/blocked?format=json"
                f"&sinceSeconds={delta_secs}"
                f"&clusterID={self.config.pp_cluster_id}"
            )
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            for click in data.get("clicksBlocked", []):
                recipient = (click.get("recipient") or "").lower()
                if not recipient:
                    continue
                try:
                    occurred_at = datetime.strptime(click["clickTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    occurred_at = datetime.utcnow()

                events.append(GatewayEvent(
                    email=recipient,
                    event_type="real_click",
                    gateway=self.name,
                    occurred_at=occurred_at,
                    url=click.get("url"),
                    threat_name=click.get("threatStatus"),
                    raw=click,
                ))
        except Exception as e:
            log.error(f"Proofpoint clicks/blocked error: {e}")

        # ── Messages blocked as phish / malware / BEC ────────────────────────
        try:
            url = (
                f"{_BASE}/messages/blocked?format=json"
                f"&sinceSeconds={delta_secs}"
                f"&clusterID={self.config.pp_cluster_id}"
            )
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            for msg in data.get("messagesBlocked", []):
                for recipient in msg.get("toAddresses", []):
                    email = recipient.lower()
                    classification = (msg.get("messageSmimeClassification") or
                                      msg.get("spamScore") or "").lower()

                    event_type = None
                    threats = [t.get("classification", "").lower() for t in msg.get("threatsInfoMap", [])]
                    if any("phish" in t for t in threats):
                        event_type = "phish"
                    elif any("malware" in t for t in threats):
                        event_type = "malware"
                    elif any("impostor" in t or "bec" in t for t in threats):
                        event_type = "bec"
                    else:
                        continue

                    try:
                        occurred_at = datetime.strptime(msg["messageTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
                    except Exception:
                        occurred_at = datetime.utcnow()

                    events.append(GatewayEvent(
                        email=email,
                        event_type=event_type,
                        gateway=self.name,
                        occurred_at=occurred_at,
                        subject=msg.get("subject"),
                        sender=msg.get("fromAddress", [""])[0],
                        raw=msg,
                    ))
        except Exception as e:
            log.error(f"Proofpoint messages/blocked error: {e}")

        log.info(f"Proofpoint adapter pulled {len(events)} events")
        return events
