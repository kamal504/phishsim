"""
Microsoft Graph API Adapter — polls a shared mailbox (Exchange Online / M365)
via the Microsoft Graph API using client credentials flow (app-only auth).

Required Azure AD App permissions (application, not delegated):
  Mail.Read, Mail.ReadWrite (for the shared mailbox)

Usage:
    from mailbox.graph_adapter import poll_graph_mailbox, test_graph_connection
    result = poll_graph_mailbox(config, db)
"""
import logging
import re
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session
import models
from mailbox.matcher import match_reported_email, fire_reported_event
import encryption

log = logging.getLogger(__name__)

# Microsoft identity platform endpoints
_TOKEN_URL_TEMPLATE  = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_BASE          = "https://graph.microsoft.com/v1.0"

_EMAIL_RE = re.compile(r'[\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}')


def _get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """
    Obtain an OAuth2 access token via client credentials flow.
    Raises RuntimeError if the token cannot be obtained.
    """
    try:
        import urllib.request
        import urllib.parse
        import json as _json

        data = urllib.parse.urlencode({
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }).encode()

        url = _TOKEN_URL_TEMPLATE.format(tenant_id=tenant_id)
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        with urllib.request.urlopen(req, timeout=15) as resp:
            body = _json.loads(resp.read())

        if "access_token" not in body:
            raise RuntimeError(f"Token response missing access_token: {body.get('error_description', body)}")
        return body["access_token"]

    except Exception as e:
        raise RuntimeError(f"Failed to obtain Graph API token: {e}") from e


def _graph_get(url: str, token: str) -> dict:
    """Make an authenticated GET request to the Graph API."""
    import urllib.request
    import json as _json

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return _json.loads(resp.read())


def _graph_patch(url: str, token: str, body: dict) -> None:
    """Make an authenticated PATCH request to the Graph API."""
    import urllib.request
    import json as _json

    data = _json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, method="PATCH")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20):
        pass


def _graph_delete(url: str, token: str) -> None:
    """Make an authenticated DELETE request to the Graph API."""
    import urllib.request
    req = urllib.request.Request(url, method="DELETE")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=20):
        pass


def _extract_body(payload: dict) -> str:
    """Extract plain-text or HTML body from a Graph message payload."""
    body_obj = payload.get("body", {})
    content  = body_obj.get("content", "")
    ctype    = body_obj.get("contentType", "text")
    if ctype == "html":
        return re.sub(r'<[^>]+>', ' ', content)
    return content


def _extract_from(payload: dict) -> str:
    """Extract the sender email from a Graph message payload."""
    try:
        return payload["from"]["emailAddress"]["address"].lower()
    except (KeyError, TypeError):
        return ""


def poll_graph_mailbox(cfg: models.MailboxConfig, db: Session) -> dict:
    """
    Connect to the configured M365 shared mailbox via Microsoft Graph API,
    fetch unread emails from the Inbox, attempt to match each to a campaign
    target, and fire reported events.

    Returns a dict with: emails_checked, emails_matched, emails_skipped, errors
    """
    stats = {
        "emails_checked": 0,
        "emails_matched": 0,
        "emails_skipped": 0,
        "errors": [],
    }

    # Decrypt credentials
    try:
        client_secret = encryption.decrypt(cfg.graph_client_secret) if cfg.graph_client_secret else ""
    except Exception:
        client_secret = cfg.graph_client_secret or ""

    if not all([cfg.graph_tenant_id, cfg.graph_client_id, client_secret, cfg.graph_mailbox_email]):
        stats["errors"].append("Microsoft Graph configuration is incomplete.")
        return stats

    try:
        token = _get_access_token(cfg.graph_tenant_id, cfg.graph_client_id, client_secret)
    except RuntimeError as e:
        stats["errors"].append(str(e))
        return stats

    mailbox = cfg.graph_mailbox_email
    # Fetch unread messages from inbox (up to 50 per poll cycle)
    url = (
        f"{_GRAPH_BASE}/users/{mailbox}/mailFolders/Inbox/messages"
        f"?$filter=isRead eq false"
        f"&$select=id,subject,from,body,internetMessageHeaders"
        f"&$top=50"
    )

    try:
        resp = _graph_get(url, token)
        messages = resp.get("value", [])
        log.info(f"Graph: found {len(messages)} unread message(s) in {mailbox}/Inbox")
    except Exception as e:
        stats["errors"].append(f"Failed to fetch messages: {e}")
        return stats

    for msg in messages:
        stats["emails_checked"] += 1
        try:
            msg_id   = msg["id"]
            subject  = msg.get("subject", "")
            from_addr = _extract_from(msg)
            body     = _extract_body(msg)

            # Extract custom headers
            internet_headers = {
                h["name"].lower(): h["value"]
                for h in msg.get("internetMessageHeaders", [])
            }
            headers = {
                "x-phishsim-token": internet_headers.get("x-phishsim-token", ""),
            }

            target, campaign = match_reported_email(
                db, subject, body, from_addr, headers
            )

            if target and campaign:
                fired = fire_reported_event(db, target, campaign)
                if fired:
                    stats["emails_matched"] += 1
                    log.info(f"Graph: reported event fired for target {target.id} from {from_addr}")
                else:
                    stats["emails_skipped"] += 1
            else:
                stats["emails_skipped"] += 1

            # Mark as read
            if cfg.mark_read_after_process:
                try:
                    _graph_patch(
                        f"{_GRAPH_BASE}/users/{mailbox}/messages/{msg_id}",
                        token, {"isRead": True}
                    )
                except Exception as patch_err:
                    log.warning(f"Graph: could not mark message {msg_id} as read: {patch_err}")

            # Delete
            if cfg.delete_after_process:
                try:
                    _graph_delete(f"{_GRAPH_BASE}/users/{mailbox}/messages/{msg_id}", token)
                except Exception as del_err:
                    log.warning(f"Graph: could not delete message {msg_id}: {del_err}")

        except Exception as e:
            log.warning(f"Graph: error processing message {msg.get('id', '?')}: {e}")
            stats["errors"].append(str(e))

    return stats


def test_graph_connection(cfg: models.MailboxConfig) -> dict:
    """
    Test Microsoft Graph connectivity without processing any emails.
    Returns {"ok": bool, "message": str, "unread_count": int}
    """
    try:
        client_secret = encryption.decrypt(cfg.graph_client_secret) if cfg.graph_client_secret else ""
    except Exception:
        client_secret = cfg.graph_client_secret or ""

    try:
        token = _get_access_token(cfg.graph_tenant_id, cfg.graph_client_id, client_secret)
        mailbox = cfg.graph_mailbox_email
        url  = (f"{_GRAPH_BASE}/users/{mailbox}/mailFolders/Inbox/messages"
                f"?$filter=isRead eq false&$count=true&$top=1&$select=id")
        resp = _graph_get(url, token)
        count = resp.get("@odata.count", len(resp.get("value", [])))
        return {"ok": True, "message": f"Connected to {mailbox} successfully. ~{count} unread message(s).", "unread_count": count}
    except Exception as e:
        return {"ok": False, "message": str(e), "unread_count": 0}
