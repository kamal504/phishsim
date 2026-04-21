"""
Reporting Mailbox Router
=========================
Endpoints for configuring and managing the report-phishing mailbox integration.

GET  /api/mailbox/config          — get current config (admin)
POST /api/mailbox/config          — save config (admin)
POST /api/mailbox/test            — test connection (admin)
POST /api/mailbox/poll            — trigger manual poll (admin)
GET  /api/mailbox/logs            — poll history (admin)
GET  /api/mailbox/stats           — aggregate stats (admin)
"""
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

import models
from database import get_db
from routers.auth import require_admin
import encryption

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/mailbox", tags=["mailbox"])


# ── Config helpers ────────────────────────────────────────────────────────────

def _cfg_to_dict(cfg: models.MailboxConfig) -> dict:
    return {
        "id":                      cfg.id,
        "enabled":                 cfg.enabled,
        "adapter_type":            cfg.adapter_type,
        "display_name":            cfg.display_name,
        # IMAP
        "imap_host":               cfg.imap_host,
        "imap_port":               cfg.imap_port,
        "imap_username":           cfg.imap_username,
        "imap_password":           "••••••••" if cfg.imap_password else "",
        "imap_use_ssl":            cfg.imap_use_ssl,
        "imap_folder":             cfg.imap_folder,
        # Graph
        "graph_tenant_id":         cfg.graph_tenant_id,
        "graph_client_id":         cfg.graph_client_id,
        "graph_client_secret":     "••••••••" if cfg.graph_client_secret else "",
        "graph_mailbox_email":     cfg.graph_mailbox_email,
        # Polling
        "poll_interval_minutes":   cfg.poll_interval_minutes,
        "delete_after_process":    cfg.delete_after_process,
        "mark_read_after_process": cfg.mark_read_after_process,
        # State
        "last_poll_at":            cfg.last_poll_at.isoformat() if cfg.last_poll_at else None,
        "last_poll_status":        cfg.last_poll_status,
        "last_error":              cfg.last_error,
        "updated_at":              cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/config")
def get_mailbox_config(_: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = db.query(models.MailboxConfig).first()
    if not cfg:
        cfg = models.MailboxConfig()
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return _cfg_to_dict(cfg)


@router.post("/config")
def save_mailbox_config(
    payload: dict,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.MailboxConfig).first()
    if not cfg:
        cfg = models.MailboxConfig()
        db.add(cfg)

    cfg.enabled          = payload.get("enabled", cfg.enabled)
    cfg.adapter_type     = payload.get("adapter_type", cfg.adapter_type)
    cfg.display_name     = payload.get("display_name", cfg.display_name)

    # IMAP
    if "imap_host"     in payload: cfg.imap_host     = payload["imap_host"]
    if "imap_port"     in payload: cfg.imap_port     = int(payload["imap_port"])
    if "imap_username" in payload: cfg.imap_username = payload["imap_username"]
    if "imap_folder"   in payload: cfg.imap_folder   = payload["imap_folder"]
    if "imap_use_ssl"  in payload: cfg.imap_use_ssl  = bool(payload["imap_use_ssl"])
    if "imap_password" in payload and payload["imap_password"] not in ("", "••••••••"):
        cfg.imap_password = encryption.encrypt(payload["imap_password"])

    # Graph
    if "graph_tenant_id"     in payload: cfg.graph_tenant_id     = payload["graph_tenant_id"]
    if "graph_client_id"     in payload: cfg.graph_client_id     = payload["graph_client_id"]
    if "graph_mailbox_email" in payload: cfg.graph_mailbox_email = payload["graph_mailbox_email"]
    if "graph_client_secret" in payload and payload["graph_client_secret"] not in ("", "••••••••"):
        cfg.graph_client_secret = encryption.encrypt(payload["graph_client_secret"])

    # Polling
    if "poll_interval_minutes"   in payload: cfg.poll_interval_minutes   = int(payload["poll_interval_minutes"])
    if "delete_after_process"    in payload: cfg.delete_after_process    = bool(payload["delete_after_process"])
    if "mark_read_after_process" in payload: cfg.mark_read_after_process = bool(payload["mark_read_after_process"])

    cfg.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(cfg)
    return _cfg_to_dict(cfg)


@router.post("/test")
def test_mailbox_connection(
    payload: dict,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Test the mailbox connection using the current (saved) config."""
    cfg = db.query(models.MailboxConfig).first()
    if not cfg:
        raise HTTPException(status_code=400, detail="No mailbox configuration found. Save config first.")

    adapter = payload.get("adapter_type", cfg.adapter_type) or "imap"
    try:
        if adapter == "imap":
            from mailbox.imap_adapter import test_imap_connection
            return test_imap_connection(cfg)
        elif adapter == "graph":
            from mailbox.graph_adapter import test_graph_connection
            return test_graph_connection(cfg)
        else:
            return {"ok": False, "message": f"Unknown adapter: {adapter}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@router.post("/poll")
def trigger_manual_poll(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Manually trigger a mailbox poll cycle."""
    from mailbox.poller import run_mailbox_poll
    try:
        result = run_mailbox_poll(db)
        return {"status": "ok", "result": result}
    except Exception as e:
        log.error(f"Manual mailbox poll error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs")
def get_poll_logs(
    limit: int = 50,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Return recent mailbox poll log entries."""
    logs = db.query(models.MailboxPollLog)\
              .order_by(models.MailboxPollLog.polled_at.desc())\
              .limit(limit).all()
    return [{
        "id":             l.id,
        "polled_at":      l.polled_at.isoformat(),
        "adapter_type":   l.adapter_type,
        "emails_checked": l.emails_checked,
        "emails_matched": l.emails_matched,
        "emails_skipped": l.emails_skipped,
        "status":         l.status,
        "error_message":  l.error_message,
    } for l in logs]


@router.get("/stats")
def get_mailbox_stats(
    days: int = 30,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Aggregate mailbox poll statistics for the last N days."""
    since = datetime.utcnow() - timedelta(days=days)
    logs  = db.query(models.MailboxPollLog)\
               .filter(models.MailboxPollLog.polled_at >= since).all()

    total_polls   = len(logs)
    total_checked = sum(l.emails_checked for l in logs)
    total_matched = sum(l.emails_matched for l in logs)
    total_skipped = sum(l.emails_skipped for l in logs)
    error_polls   = sum(1 for l in logs if l.status == "error")
    match_rate    = round(total_matched / total_checked * 100, 1) if total_checked else 0

    return {
        "days":           days,
        "total_polls":    total_polls,
        "error_polls":    error_polls,
        "emails_checked": total_checked,
        "emails_matched": total_matched,
        "emails_skipped": total_skipped,
        "match_rate_pct": match_rate,
    }
