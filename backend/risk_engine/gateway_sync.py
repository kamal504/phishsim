"""
Gateway Sync Orchestrator
==========================
Selects the correct adapter based on GatewayConfig.gateway_type,
pulls events, converts them to RiskSignals, and persists everything.

Called by APScheduler on the configured interval (default: hourly).
"""

import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

import models
from risk_engine import core as risk_core
from risk_engine.gateway_adapters.base import GatewayEvent

log = logging.getLogger(__name__)

# Volume threshold: if an employee receives more than this many phish/month
# we fire a gateway_phish_volume signal to reflect targeted exposure.
PHISH_VOLUME_THRESHOLD = 10


def _get_adapter(cfg: models.GatewayConfig):
    """Return the right adapter instance for this config, or None."""
    t = (cfg.gateway_type or "none").lower()
    if t == "microsoft365":
        from risk_engine.gateway_adapters.microsoft365 import Microsoft365Adapter
        return Microsoft365Adapter(cfg)
    elif t == "google_workspace":
        from risk_engine.gateway_adapters.google_workspace import GoogleWorkspaceAdapter
        return GoogleWorkspaceAdapter(cfg)
    elif t == "proofpoint":
        from risk_engine.gateway_adapters.proofpoint import ProofpointAdapter
        return ProofpointAdapter(cfg)
    elif t == "mimecast":
        from risk_engine.gateway_adapters.mimecast import MimecastAdapter
        return MimecastAdapter(cfg)
    elif t == "syslog":
        from risk_engine.gateway_adapters.syslog_listener import SyslogAdapter
        return SyslogAdapter(cfg)
    return None


def _event_to_signal_type(event: GatewayEvent) -> Optional[str]:
    mapping = {
        "phish":       "gateway_phish_volume",
        "malware":     "gateway_malware",
        "bec":         "gateway_bec",
        "real_click":  "gateway_real_click",
        "real_report": "gateway_real_report",
    }
    return mapping.get(event.event_type)


def run_gateway_sync(db: Session) -> dict:
    """
    Pull events from the configured email gateway and record risk signals.
    Returns a summary dict.
    """
    cfg = db.query(models.GatewayConfig).first()
    if not cfg or not cfg.enabled or cfg.gateway_type == "none":
        return {"skipped": True, "reason": "Gateway integration is disabled or not configured"}

    adapter = _get_adapter(cfg)
    if adapter is None:
        return {"skipped": True, "reason": f"Unknown gateway type: {cfg.gateway_type}"}

    since = cfg.last_sync_at
    events_processed = 0
    signals_fired    = 0

    try:
        events = adapter.pull(since=since)

        # Track per-user phish volume this pull to detect high-volume targeting
        phish_counts: dict[str, int] = {}

        for event in events:
            signal_type = _event_to_signal_type(event)
            if not signal_type:
                continue

            # For volume-based signals, count them first before deciding to fire
            if signal_type == "gateway_phish_volume":
                phish_counts[event.email] = phish_counts.get(event.email, 0) + 1
                events_processed += 1
                continue

            # Fire individual gateway signals (malware, bec, real_click, real_report)
            risk_core.record_signal(
                email=event.email,
                signal_type=signal_type,
                source=cfg.gateway_type,
                db=db,
                metadata={
                    "event_type":   event.event_type,
                    "gateway":      event.gateway,
                    "occurred_at":  event.occurred_at.isoformat(),
                    "subject":      event.subject,
                    "sender":       event.sender,
                    "threat_name":  event.threat_name,
                },
            )
            events_processed += 1
            signals_fired    += 1

        # Fire phish volume signals only if threshold exceeded
        for email, count in phish_counts.items():
            if count >= PHISH_VOLUME_THRESHOLD:
                risk_core.record_signal(
                    email=email,
                    signal_type="gateway_phish_volume",
                    source=cfg.gateway_type,
                    db=db,
                    metadata={"phish_count": count, "period": "sync_window"},
                )
                signals_fired += 1

        cfg.last_sync_at     = datetime.utcnow()
        cfg.last_sync_status = "ok"
        cfg.last_error       = ""
        db.commit()

    except Exception as e:
        log.error(f"Gateway sync error: {e}")
        cfg.last_sync_status = "error"
        cfg.last_error       = str(e)
        db.commit()
        return {"error": str(e)}

    result = {
        "gateway":          cfg.gateway_type,
        "events_processed": events_processed,
        "signals_fired":    signals_fired,
        "synced_at":        datetime.utcnow().isoformat(),
    }
    log.info(f"Gateway sync complete: {result}")
    return result


def test_gateway_connection(db: Session) -> tuple[bool, str]:
    cfg = db.query(models.GatewayConfig).first()
    if not cfg or cfg.gateway_type == "none":
        return False, "No gateway configured"
    adapter = _get_adapter(cfg)
    if not adapter:
        return False, f"Unknown gateway type: {cfg.gateway_type}"
    return adapter.test_connection()
