"""
Tamper-Proof Audit Log
=======================
Hash-chain implementation: each record stores
  SHA-256( prev_hash + timestamp + action + actor + details )

Any modification to a historical record invalidates all subsequent hashes,
making tampering immediately detectable by the verify_chain() function.

The audit log is APPEND-ONLY. There are no update or delete operations.
All reads go through the API with require_auth/require_admin protection.

Usage:
    from audit import write, verify_chain

    write(db, "campaign.launched", actor="admin",
          target_type="campaign", target_id="42",
          details={"campaign_name": "Q1 Finance Test"},
          ip_address=request.client.host)
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

import models

log = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64   # Starting hash for the first record


def _compute_hash(prev_hash: str, occurred_at: datetime, action: str,
                  actor: str, details: str) -> str:
    """Compute the chain hash for a new record."""
    payload = f"{prev_hash}|{occurred_at.isoformat()}|{action}|{actor}|{details}"
    return hashlib.sha256(payload.encode()).hexdigest()


def write(
    db: Session,
    action: str,
    actor: str = "system",
    target_type: str = "",
    target_id: str = "",
    details: dict | None = None,
    ip_address: str = "",
) -> models.AuditLog:
    """
    Append a new record to the audit log.
    Automatically links to the previous record's hash.

    BUG-04 fix: calls db.flush() after adding the entry so that the new
    record is assigned a database ID and becomes visible to subsequent
    hash-chain queries within the same transaction.  The caller is still
    responsible for the final db.commit() (which persists the entry
    together with any related model changes in the same transaction).
    """
    now = datetime.utcnow()
    details_str = json.dumps(details or {}, default=str)

    # Get hash of the last committed record (flush makes any pending entry visible)
    last = db.query(models.AuditLog).order_by(
        models.AuditLog.id.desc()
    ).first()
    prev_hash = last.record_hash if last else _GENESIS_HASH

    record_hash = _compute_hash(prev_hash, now, action, actor, details_str)

    entry = models.AuditLog(
        action      = action,
        actor       = actor,
        target_type = target_type,
        target_id   = str(target_id),
        details     = details_str,
        ip_address  = ip_address,
        occurred_at = now,
        record_hash = record_hash,
        prev_hash   = prev_hash,
    )
    db.add(entry)
    db.flush()   # BUG-04 fix: assign DB ID and make visible within this session
    return entry


def verify_chain(db: Session) -> dict:
    """
    Walk the entire audit log and verify the hash chain is intact.
    Returns a dict with:
      valid       : bool — True if chain is unbroken
      total       : int  — number of records checked
      first_broken: int | None — ID of first record with invalid hash (if any)
      message     : str
    """
    records = db.query(models.AuditLog).order_by(models.AuditLog.id).all()

    if not records:
        return {"valid": True, "total": 0, "first_broken": None,
                "message": "Audit log is empty — nothing to verify."}

    prev_hash = _GENESIS_HASH

    for rec in records:
        expected = _compute_hash(
            prev_hash,
            rec.occurred_at,
            rec.action,
            rec.actor,
            rec.details,
        )
        if expected != rec.record_hash:
            log.warning(f"Audit chain broken at record ID {rec.id}")
            return {
                "valid":        False,
                "total":        len(records),
                "first_broken": rec.id,
                "message":      f"Chain integrity violation detected at record #{rec.id} "
                                f"({rec.action} by {rec.actor} at {rec.occurred_at.isoformat()}). "
                                f"Records may have been tampered with.",
            }
        prev_hash = rec.record_hash

    return {
        "valid":        True,
        "total":        len(records),
        "first_broken": None,
        "message":      f"Chain verified — all {len(records)} records are intact.",
    }
