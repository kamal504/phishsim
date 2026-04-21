"""
Google Workspace Gateway Adapter
==================================
Uses the Google Admin SDK Reports API to pull per-user email security events.
Also uses the Alert Center API for high-confidence threat alerts.

Required service account scopes:
  - https://www.googleapis.com/auth/admin.reports.audit.readonly
  - https://www.googleapis.com/auth/apps.alerts

Setup:
  1. Google Cloud Console → Create project → Enable Admin SDK API + Alert Center API
  2. IAM & Admin → Service Accounts → Create → Download JSON key
  3. Google Admin Console → Security → API Controls → Domain-wide delegation
     → Add client ID with above scopes
  4. Paste the service account JSON into PhishSim gateway config
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from .base import BaseGatewayAdapter, GatewayEvent

log = logging.getLogger(__name__)


class GoogleWorkspaceAdapter(BaseGatewayAdapter):
    name = "google_workspace"

    def _build_service(self, api_name: str, api_version: str):
        """Build an authenticated Google API service object."""
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            sa_info = json.loads(self.config.gws_service_account_json)
            scopes = [
                "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                "https://www.googleapis.com/auth/apps.alerts",
            ]
            creds = service_account.Credentials.from_service_account_info(
                sa_info, scopes=scopes
            ).with_subject(self.config.gws_admin_email)

            return build(api_name, api_version, credentials=creds, cache_discovery=False)
        except Exception as e:
            log.error(f"Google Workspace service build error: {e}")
            return None

    def test_connection(self) -> tuple[bool, str]:
        svc = self._build_service("admin", "reports_v1")
        if svc is None:
            return False, "Failed to build Google Admin SDK service. Check service account JSON."
        try:
            svc.activities().list(userKey="all", applicationName="token", maxResults=1).execute()
            return True, "Google Workspace connection successful."
        except Exception as e:
            return False, f"Connection test failed: {e}"

    def pull(self, since: Optional[datetime] = None) -> list[GatewayEvent]:
        events: list[GatewayEvent] = []

        if since is None:
            since = datetime.utcnow() - timedelta(hours=24)

        start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        # ── Gmail security events via Reports API ────────────────────────────
        try:
            svc = self._build_service("admin", "reports_v1")
            if svc:
                page_token = None
                while True:
                    result = svc.activities().list(
                        userKey="all",
                        applicationName="gmail",
                        startTime=start_time,
                        maxResults=500,
                        pageToken=page_token,
                        eventName="email_phishing",  # also: email_malware, suspicious_login
                    ).execute()

                    for activity in result.get("items", []):
                        actor_email = (activity.get("actor", {}).get("email") or "").lower()
                        if not actor_email:
                            continue

                        for event in activity.get("events", []):
                            name = (event.get("name") or "").lower()
                            event_type = None
                            if "phish" in name:
                                event_type = "phish"
                            elif "malware" in name or "virus" in name:
                                event_type = "malware"
                            else:
                                continue

                            time_str = activity.get("id", {}).get("time", "")
                            try:
                                occurred_at = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
                            except Exception:
                                occurred_at = datetime.utcnow()

                            events.append(GatewayEvent(
                                email=actor_email,
                                event_type=event_type,
                                gateway=self.name,
                                occurred_at=occurred_at,
                                raw=activity,
                            ))

                    page_token = result.get("nextPageToken")
                    if not page_token:
                        break
        except Exception as e:
            log.error(f"Google Workspace Reports API error: {e}")

        # ── Alert Center API — high confidence threats ───────────────────────
        try:
            alert_svc = self._build_service("alertcenter", "v1beta1")
            if alert_svc:
                filter_str = f'createTime >= "{since.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
                result = alert_svc.alerts().list(filter=filter_str, pageSize=100).execute()

                for alert in result.get("alerts", []):
                    alert_type = (alert.get("type") or "").lower()
                    event_type = None
                    if "phish" in alert_type:
                        event_type = "phish"
                    elif "malware" in alert_type:
                        event_type = "malware"
                    else:
                        continue

                    data = alert.get("data", {})
                    recipients = data.get("messages", [{}])
                    for msg in recipients:
                        recipient = (msg.get("recipient") or "").lower()
                        if not recipient:
                            continue
                        time_str = alert.get("createTime", "")
                        try:
                            occurred_at = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        except Exception:
                            occurred_at = datetime.utcnow()

                        events.append(GatewayEvent(
                            email=recipient,
                            event_type=event_type,
                            gateway=self.name,
                            occurred_at=occurred_at,
                            raw=alert,
                        ))
        except Exception as e:
            log.error(f"Google Workspace Alert Center error: {e}")

        log.info(f"Google Workspace adapter pulled {len(events)} events since {since.isoformat()}")
        return events
