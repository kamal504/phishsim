"""
IMAP Adapter — polls a dedicated report-phishing mailbox via IMAP4_SSL.

Compatible with: Gmail, Outlook/Exchange, any IMAP-compliant server.

Usage:
    from mailbox.imap_adapter import poll_imap_mailbox
    result = poll_imap_mailbox(config, db)
"""
import email
import email.header
import imaplib
import logging
import re
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session
import models
from mailbox.matcher import match_reported_email, fire_reported_event
import encryption

log = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r'[\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}')


def _decode_header(value: str) -> str:
    """Decode RFC2047 encoded header value to plain text."""
    if not value:
        return ""
    parts = email.header.decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except Exception:
                decoded.append(part.decode("utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded).strip()


def _get_body(msg: email.message.Message) -> str:
    """Extract plain text body from a MIME email."""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype    = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            if ctype == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="replace"))
            elif ctype == "text/html" and not body_parts:
                # Fallback to HTML if no plain text
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html = payload.decode(charset, errors="replace")
                    # Strip tags for body matching
                    body_parts.append(re.sub(r'<[^>]+>', ' ', html))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            body_parts.append(payload.decode(charset, errors="replace"))
    return "\n".join(body_parts)


def _extract_from_address(msg: email.message.Message) -> str:
    """Extract the sender email address from a message."""
    from_header = _decode_header(msg.get("From", ""))
    matches = _EMAIL_RE.findall(from_header)
    return matches[0].lower() if matches else ""


def poll_imap_mailbox(cfg: models.MailboxConfig, db: Session) -> dict:
    """
    Connect to the configured IMAP mailbox, fetch unread/unseen emails,
    attempt to match each to a campaign target, and fire reported events.

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
        password = encryption.decrypt(cfg.imap_password) if cfg.imap_password else ""
    except Exception:
        password = cfg.imap_password or ""

    try:
        # Connect
        if cfg.imap_use_ssl:
            M = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
        else:
            M = imaplib.IMAP4(cfg.imap_host, cfg.imap_port)
            M.starttls()

        M.login(cfg.imap_username, password)
        M.select(cfg.imap_folder or "INBOX")

        # Search for unseen emails
        status, data = M.search(None, "UNSEEN")
        if status != "OK":
            M.logout()
            stats["errors"].append(f"IMAP SEARCH failed: {status}")
            return stats

        msg_ids = data[0].split() if data and data[0] else []
        log.info(f"IMAP: found {len(msg_ids)} unseen message(s) in {cfg.imap_folder}")

        for uid in msg_ids:
            stats["emails_checked"] += 1
            try:
                # Fetch full message
                status, msg_data = M.fetch(uid, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    stats["errors"].append(f"Failed to fetch message {uid}")
                    continue

                raw_email = msg_data[0][1]
                msg       = email.message_from_bytes(raw_email)

                subject  = _decode_header(msg.get("Subject", ""))
                from_addr = _extract_from_address(msg)
                body     = _get_body(msg)

                # Extract custom headers
                headers = {
                    "x-phishsim-token": msg.get("X-PhishSim-Token", ""),
                }

                target, campaign = match_reported_email(
                    db, subject, body, from_addr, headers
                )

                if target and campaign:
                    fired = fire_reported_event(db, target, campaign)
                    if fired:
                        stats["emails_matched"] += 1
                        log.info(f"IMAP: reported event fired for target {target.id} from {from_addr}")
                    else:
                        stats["emails_skipped"] += 1  # already reported
                else:
                    stats["emails_skipped"] += 1

                # Mark as read / delete per config
                if cfg.mark_read_after_process:
                    M.store(uid, "+FLAGS", "\\Seen")
                if cfg.delete_after_process:
                    M.store(uid, "+FLAGS", "\\Deleted")

            except Exception as e:
                log.warning(f"IMAP: error processing message {uid}: {e}")
                stats["errors"].append(str(e))

        if cfg.delete_after_process:
            M.expunge()
        M.logout()

    except imaplib.IMAP4.error as e:
        msg = f"IMAP connection error: {e}"
        log.error(msg)
        stats["errors"].append(msg)
    except Exception as e:
        msg = f"Unexpected IMAP error: {e}"
        log.error(msg)
        stats["errors"].append(msg)

    return stats


def test_imap_connection(cfg: models.MailboxConfig) -> dict:
    """
    Test IMAP connectivity without processing any emails.
    Returns {"ok": bool, "message": str, "mailbox_count": int}
    """
    try:
        password = encryption.decrypt(cfg.imap_password) if cfg.imap_password else ""
    except Exception:
        password = cfg.imap_password or ""

    try:
        if cfg.imap_use_ssl:
            M = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
        else:
            M = imaplib.IMAP4(cfg.imap_host, cfg.imap_port)

        M.login(cfg.imap_username, password)
        status, data = M.select(cfg.imap_folder or "INBOX")
        count = int(data[0]) if data and data[0] else 0
        M.logout()
        return {"ok": True, "message": f"Connected successfully. {count} message(s) in {cfg.imap_folder or 'INBOX'}.", "mailbox_count": count}
    except Exception as e:
        return {"ok": False, "message": str(e), "mailbox_count": 0}
