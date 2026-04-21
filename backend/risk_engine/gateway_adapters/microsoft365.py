"""
Microsoft 365 / Defender for Office 365 Gateway Adapter
=========================================================
Uses Microsoft Graph API + Defender Threat Explorer API to pull
per-user email threat telemetry.

Required app registration permissions (Application, not Delegated):
  - ThreatAssessment.Read.All
  - Mail.Read
  - SecurityEvents.Read.All
  - ThreatIndicators.Read.All

Setup in Azure AD:
  1. App registrations → New registration
  2. API permissions → Add → Microsoft Graph → Application permissions → above list
  3. Grant admin consent
  4. Certificates & secrets → New client secret → copy value
  5. Note: Tenant ID, Client ID, Client Secret
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from .base import BaseGatewayAdapter, GatewayEvent

log = logging.getLogger(__name__)

# Microsoft OAuth and Graph endpoints
_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_SECURITY_BASE = "https://graph.microsoft.com/v1.0/security"


class Microsoft365Adapter(BaseGatewayAdapter):
    name = "microsoft365"

    def _get_token(self) -> Optional[str]:
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode({
                "grant_type":    "client_credentials",
                "client_id":     self.config.m365_client_id,
                "client_secret": self.config.m365_client_secret,
                "scope":         "https://graph.microsoft.com/.default",
            }).encode()
            url = _TOKEN_URL.format(tenant=self.config.m365_tenant_id)
            req = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                import json
                body = json.loads(resp.read())
                return body.get("access_token")
        except Exception as e:
            log.error(f"M365 token error: {e}")
            return None

    def test_connection(self) -> tuple[bool, str]:
        token = self._get_token()
        if not token:
            return False, "Failed to obtain access token. Check Tenant ID, Client ID, and Client Secret."
        return True, "Microsoft 365 connection successful."

    def pull(self, since: Optional[datetime] = None) -> list[GatewayEvent]:
        """
        Pull email threat events from Microsoft Defender for Office 365.
        Uses the Threat Explorer query endpoint to get per-recipient threat data.
        """
        token = self._get_token()
        if not token:
            log.error("M365 pull: could not obtain token")
            return []

        if since is None:
            since = datetime.utcnow() - timedelta(hours=24)

        events: list[GatewayEvent] = []

        try:
            import urllib.request, json
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type":  "application/json",
            }

            # Query email threat detections via Security API alerts
            # Covers: phishing detected, malware detected, high confidence spam
            start_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            url = (
                f"{_SECURITY_BASE}/alerts_v2"
                f"?$filter=createdDateTime ge {start_iso}"
                f" and serviceSource eq 'microsoftDefenderForOffice365'"
                f"&$top=999"
                f"&$select=id,createdDateTime,category,description,evidence"
            )
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            for alert in data.get("value", []):
                category = (alert.get("category") or "").lower()
                event_type = None
                if "phish" in category:
                    event_type = "phish"
                elif "malware" in category:
                    event_type = "malware"
                elif "bec" in category or "business email" in category:
                    event_type = "bec"
                else:
                    continue

                # Extract recipient from evidence
                for evidence in alert.get("evidence", []):
                    recipient = (
                        evidence.get("userPrincipalName") or
                        evidence.get("recipientEmailAddress") or ""
                    ).lower()
                    if not recipient:
                        continue

                    occurred_str = alert.get("createdDateTime", since.isoformat())
                    try:
                        occurred_at = datetime.fromisoformat(occurred_str.replace("Z", "+00:00")).replace(tzinfo=None)
                    except Exception:
                        occurred_at = datetime.utcnow()

                    events.append(GatewayEvent(
                        email=recipient,
                        event_type=event_type,
                        gateway=self.name,
                        occurred_at=occurred_at,
                        threat_name=category,
                        raw=alert,
                    ))

        except Exception as e:
            log.error(f"M365 pull error: {e}")

        log.info(f"M365 adapter pulled {len(events)} events since {since.isoformat()}")
        return events
