"""
Mailbox Poller — main entry point called by APScheduler.

Reads the MailboxConfig, routes to the correct adapter (IMAP or Graph),
writes a MailboxPollLog record, and updates last_poll_at on the config.
"""
import logging
from datetime import datetime

from sqlalchemy.orm import Session
import models

log = logging.getLogger(__name__)


def run_mailbox_poll(db: Session) -> dict:
    """
    Poll the configured report-phishing mailbox.
    Returns a summary dict with poll statistics.
    """
    cfg = db.query(models.MailboxConfig).first()
    if not cfg or not cfg.enabled:
        return {"skipped": True, "reason": "Mailbox integration not enabled"}

    adapter = cfg.adapter_type or "imap"
    log.info(f"Mailbox poll starting (adapter={adapter})")

    stats = {"emails_checked": 0, "emails_matched": 0, "emails_skipped": 0, "errors": []}

    try:
        if adapter == "imap":
            from mailbox.imap_adapter import poll_imap_mailbox
            stats = poll_imap_mailbox(cfg, db)
        elif adapter == "graph":
            from mailbox.graph_adapter import poll_graph_mailbox
            stats = poll_graph_mailbox(cfg, db)
        else:
            stats["errors"].append(f"Unknown adapter type: {adapter}")

        status = "error" if stats["errors"] else "ok"
    except Exception as e:
        log.error(f"Mailbox poll failed: {e}")
        stats["errors"].append(str(e))
        status = "error"

    # Update config state
    cfg.last_poll_at     = datetime.utcnow()
    cfg.last_poll_status = status
    cfg.last_error       = "; ".join(stats["errors"])[:500] if stats["errors"] else ""
    db.commit()

    # Write poll log
    poll_log = models.MailboxPollLog(
        polled_at      = datetime.utcnow(),
        adapter_type   = adapter,
        emails_checked = stats["emails_checked"],
        emails_matched = stats["emails_matched"],
        emails_skipped = stats["emails_skipped"],
        status         = status,
        error_message  = cfg.last_error,
    )
    db.add(poll_log)
    db.commit()

    log.info(f"Mailbox poll complete: checked={stats['emails_checked']}, "
             f"matched={stats['emails_matched']}, skipped={stats['emails_skipped']}")
    return stats
