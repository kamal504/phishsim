"""
Breach Intelligence Monitor — HaveIBeenPwned (HIBP) Integration
================================================================
Checks employee emails against HIBP breach data and scores them.

Two APIs used:
  1. /breachedaccount/{email}  — requires HIBP API key (~$3.50/month)
     Returns all breaches where that email appeared.

  2. /range/{prefix}           — Pwned Passwords, completely FREE, k-anonymity
     Checks whether a known password hash prefix has been seen in breaches.
     We use this to check the employee's DOMAIN password policy — specifically
     we check common weak passwords to assess organisational hygiene.

Breach recency scoring:
  < 6 months  → breach_recent  +35
  6–12 months → breach_medium  +20
  1–2 years   → breach_old     +10
  > 2 years   → breach_ancient +5

If "Passwords" appears in data_classes → also add breach_password +25

HIBP respects per-email rate limiting. We add a 1.5s delay between calls.
"""

import hashlib
import json
import logging
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

import models
from risk_engine import core as risk_core

log = logging.getLogger(__name__)

_HIBP_BASE     = "https://haveibeenpwned.com/api/v3"
_PWNED_PW_BASE = "https://api.pwnedpasswords.com"
_USER_AGENT    = "PhishSim-BreachMonitor/1.0"


# ── Breach recency helpers ────────────────────────────────────────────────────

def _breach_severity(breach_date_str: Optional[str]) -> Optional[str]:
    """Convert HIBP BreachDate string ('2023-01-15') to severity label."""
    if not breach_date_str:
        return "breach_ancient"
    try:
        breach_date = datetime.strptime(breach_date_str, "%Y-%m-%d")
    except ValueError:
        return "breach_ancient"

    age_days = (datetime.utcnow() - breach_date).days
    if age_days < 180:
        return "breach_recent"
    elif age_days < 365:
        return "breach_medium"
    elif age_days < 730:
        return "breach_old"
    else:
        return "breach_ancient"


# ── HIBP API calls ────────────────────────────────────────────────────────────

def _hibp_get(path: str, api_key: str) -> Optional[list]:
    """
    Make an authenticated HIBP API call.
    Returns parsed JSON list or None on error.
    """
    url = f"{_HIBP_BASE}{path}"
    req = urllib.request.Request(url, headers={
        "hibp-api-key": api_key,
        "User-Agent":   _USER_AGENT,
        "Accept":       "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []    # No breaches found for this email
        if e.code == 429:
            log.warning("HIBP rate limit hit — sleeping 60s")
            time.sleep(60)
            return None
        log.error(f"HIBP HTTP error {e.code} for {path}")
        return None
    except Exception as e:
        log.error(f"HIBP request error: {e}")
        return None


def check_password_pwned(password: str) -> int:
    """
    k-Anonymity Pwned Passwords check (completely free, no API key).
    Returns count of times this password appeared in breach datasets.
    0 = not found, >0 = found (number of occurrences).
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        url = f"{_PWNED_PW_BASE}/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode()
        for line in content.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                return int(parts[1])
    except Exception as e:
        log.error(f"Pwned Passwords check error: {e}")
    return 0


# ── Main check function ───────────────────────────────────────────────────────

def check_email(email: str, api_key: str, db: Session) -> dict:
    """
    Check a single employee email against HIBP.
    Persists BreachRecords and fires RiskSignals for new breaches.
    Returns a summary dict.
    """
    email = email.strip().lower()
    breaches = _hibp_get(f"/breachedaccount/{urllib.request.quote(email)}?truncateResponse=false", api_key)

    if breaches is None:
        return {"email": email, "error": "HIBP API error"}

    now = datetime.utcnow()
    new_breaches = 0
    total_points = 0.0

    for breach in breaches:
        breach_name = breach.get("Name", "Unknown")
        breach_date = breach.get("BreachDate")         # "YYYY-MM-DD"
        data_classes = breach.get("DataClasses", [])   # ["Email addresses","Passwords",...]
        password_exposed = "Passwords" in data_classes

        # Check if already recorded
        existing = db.query(models.BreachRecord).filter_by(
            email=email, breach_name=breach_name
        ).first()

        if existing:
            continue   # Already scored — skip

        severity = _breach_severity(breach_date)

        # Persist breach record
        record = models.BreachRecord(
            email=email,
            breach_name=breach_name,
            breach_date=breach_date,
            data_classes=json.dumps(data_classes),
            password_exposed=password_exposed,
            severity=severity,
        )
        db.add(record)

        # Fire primary breach signal
        meta = {
            "breach_name":    breach_name,
            "breach_date":    breach_date,
            "data_classes":   data_classes,
            "severity":       severity,
        }
        risk_core.record_signal(
            email=email,
            signal_type=severity,
            source="hibp",
            db=db,
            metadata=meta,
        )
        total_points += risk_core.SIGNAL_WEIGHTS.get(severity, 5.0)
        new_breaches += 1

        # Additional password-exposed signal
        if password_exposed:
            risk_core.record_signal(
                email=email,
                signal_type="breach_password",
                source="hibp",
                db=db,
                metadata=meta,
            )
            total_points += risk_core.SIGNAL_WEIGHTS["breach_password"]

        time.sleep(1.5)   # HIBP rate limit: 1 request per 1.5s

    db.commit()

    return {
        "email":        email,
        "total_breaches": len(breaches),
        "new_breaches": new_breaches,
        "points_added": round(total_points, 1),
    }


# ── Bulk scan (scheduled job) ─────────────────────────────────────────────────

def run_full_scan(db: Session) -> dict:
    """
    Scan all employees in the risk scoring table + all campaign targets.
    Called by APScheduler on the configured frequency (default: weekly).
    Returns a summary dict.
    """
    cfg = db.query(models.BreachConfig).first()
    if not cfg or not cfg.enabled:
        return {"skipped": True, "reason": "Breach monitoring is disabled"}

    if not cfg.hibp_api_key:
        return {"skipped": True, "reason": "No HIBP API key configured"}

    # Collect unique employee emails from targets + existing risk scores
    emails = set()

    targets = db.query(models.PhishTarget.email).distinct().all()
    for (email,) in targets:
        if email:
            emails.add(email.strip().lower())

    existing = db.query(models.EmployeeRiskScore.email).all()
    for (email,) in existing:
        emails.add(email.strip().lower())

    results = {"scanned": 0, "total_new_breaches": 0, "errors": 0}

    for email in emails:
        try:
            summary = check_email(email, cfg.hibp_api_key, db)
            if "error" not in summary:
                results["scanned"]            += 1
                results["total_new_breaches"] += summary.get("new_breaches", 0)
            else:
                results["errors"] += 1
        except Exception as e:
            log.error(f"Breach scan error for {email}: {e}")
            results["errors"] += 1

        time.sleep(1.5)   # Be respectful of HIBP rate limits

    cfg.last_full_check_at = datetime.utcnow()
    cfg.last_check_status  = "ok"
    cfg.last_error         = ""
    db.commit()

    log.info(f"Breach scan complete: {results}")
    return results
