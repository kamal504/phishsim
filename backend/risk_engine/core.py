"""
Risk Engine — Core Scoring Module
==================================
Implements the three-signal employee risk model:
  Signal 1: Simulation behaviour  (PhishSim internal events)
  Signal 2: Email gateway telemetry (Microsoft 365, Google Workspace, Proofpoint, Mimecast, Syslog)
  Signal 3: Breach intelligence    (HaveIBeenPwned, BreachDirectory)

Score is normalised to 0–100. Bands:
  0–20    → low      (green)
  21–50   → medium   (amber)
  51–80   → high     (orange)
  81–100  → critical (red)

Design principles:
  - All signals are additive with per-type weights
  - Breach and gateway signals are optional — engine works on simulation signals alone
  - Score decays -5 pts per 30 clean days automatically
  - Each signal records an expiry so expired signals are excluded from recalculation
  - Transparency: every score includes a breakdown of contributing factors
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

import models

log = logging.getLogger(__name__)

# ── Signal weights ────────────────────────────────────────────────────────────
SIGNAL_WEIGHTS: dict[str, float] = {
    # Simulation
    "simulation_click":       20.0,
    "simulation_submit":      40.0,
    "simulation_report":     -15.0,
    "training_complete":     -10.0,
    # Gateway
    "gateway_phish_volume":    5.0,
    "gateway_malware":         5.0,
    "gateway_bec":            10.0,
    "gateway_real_click":     30.0,
    "gateway_real_report":   -10.0,
    # Breach
    "breach_recent":          35.0,   # < 6 months
    "breach_medium":          20.0,   # 6–12 months
    "breach_old":             10.0,   # 1–2 years
    "breach_ancient":          5.0,   # > 2 years
    "breach_password":        25.0,   # password also found in breach
}

# Default signal expiry (signals older than this no longer affect score)
SIGNAL_EXPIRY: dict[str, Optional[timedelta]] = {
    "simulation_click":   timedelta(days=180),
    "simulation_submit":  timedelta(days=365),
    "simulation_report":  timedelta(days=90),
    "training_complete":  timedelta(days=180),
    "gateway_phish_volume": timedelta(days=60),
    "gateway_malware":    timedelta(days=90),
    "gateway_bec":        timedelta(days=180),
    "gateway_real_click": timedelta(days=365),
    "gateway_real_report": timedelta(days=90),
    "breach_recent":      None,   # breach signals don't auto-expire (recency is embedded in signal type)
    "breach_medium":      None,
    "breach_old":         None,
    "breach_ancient":     None,
    "breach_password":    None,
}

# Decay: -5 pts per 30 clean days (applied by scheduler)
DECAY_POINTS_PER_PERIOD = 5.0
DECAY_PERIOD_DAYS       = 30

# Band thresholds
BANDS = [
    (81.0, "critical"),
    (51.0, "high"),
    (21.0, "medium"),
    (0.0,  "low"),
]


def score_to_band(score: float) -> str:
    for threshold, band in BANDS:
        if score >= threshold:
            return band
    return "low"


# ── Core recalculation ────────────────────────────────────────────────────────

def recalculate(email: str, db: Session) -> models.EmployeeRiskScore:
    """
    Recompute the risk score for an employee from all active (non-expired) signals.
    Creates an EmployeeRiskScore record if one does not exist.
    Returns the updated record (not yet committed — caller must db.commit()).
    """
    now = datetime.utcnow()

    record = db.query(models.EmployeeRiskScore).filter_by(email=email).first()
    if not record:
        record = models.EmployeeRiskScore(email=email)
        db.add(record)

    # Fetch all non-expired signals for this employee
    signals = (
        db.query(models.RiskSignal)
        .filter(
            models.RiskSignal.email == email,
            (models.RiskSignal.expires_at == None) | (models.RiskSignal.expires_at > now)  # noqa: E711
        )
        .all()
    )

    sim_pts = gateway_pts = breach_pts = 0.0

    for sig in signals:
        pts = sig.points
        if sig.signal_type.startswith("simulation_") or sig.signal_type == "training_complete":
            sim_pts += pts
        elif sig.signal_type.startswith("gateway_"):
            gateway_pts += pts
        elif sig.signal_type.startswith("breach_"):
            breach_pts += pts

    raw = sim_pts + gateway_pts + breach_pts
    score = max(0.0, min(100.0, raw))

    record.simulation_points  = round(sim_pts, 2)
    record.gateway_points     = round(gateway_pts, 2)
    record.breach_points      = round(breach_pts, 2)
    record.score              = round(score, 2)
    record.band               = score_to_band(score)
    record.last_calculated_at = now

    return record


def record_signal(
    email: str,
    signal_type: str,
    source: str,
    db: Session,
    metadata: dict | None = None,
    custom_points: float | None = None,
    name: str = "",
    department: str = "",
) -> models.RiskSignal:
    """
    Persist a new risk signal and immediately recalculate the employee's score.
    Returns the RiskSignal record. Caller must db.commit().
    """
    if signal_type not in SIGNAL_WEIGHTS:
        raise ValueError(f"Unknown signal_type '{signal_type}'")

    points = custom_points if custom_points is not None else SIGNAL_WEIGHTS[signal_type]
    expiry_delta = SIGNAL_EXPIRY.get(signal_type)
    expires_at = (datetime.utcnow() + expiry_delta) if expiry_delta else None

    signal = models.RiskSignal(
        email=email,
        signal_type=signal_type,
        source=source,
        points=points,
        metadata_json=json.dumps(metadata or {}),
        expires_at=expires_at,
    )
    db.add(signal)

    # Ensure employee risk record exists and is up to date
    rec = recalculate(email, db)
    if name and not rec.name:
        rec.name = name
    if department and not rec.department:
        rec.department = department

    return signal


# ── Decay job (run by APScheduler daily) ─────────────────────────────────────

def apply_decay(db: Session) -> int:
    """
    Apply score decay to all employees who have had no new positive signals
    in the last DECAY_PERIOD_DAYS days. Returns the number of employees affected.
    """
    now     = datetime.utcnow()
    cutoff  = now - timedelta(days=DECAY_PERIOD_DAYS)
    affected = 0

    employees = db.query(models.EmployeeRiskScore).filter(
        models.EmployeeRiskScore.score > 0,
        models.EmployeeRiskScore.last_decayed_at <= cutoff,
    ).all()

    for emp in employees:
        # Check if any positive signal was recorded in the last decay period
        recent_positive = db.query(models.RiskSignal).filter(
            models.RiskSignal.email == emp.email,
            models.RiskSignal.points > 0,
            models.RiskSignal.recorded_at > cutoff,
        ).first()

        if not recent_positive:
            # No new risk events — apply decay
            emp.score = max(0.0, round(emp.score - DECAY_POINTS_PER_PERIOD, 2))
            emp.band  = score_to_band(emp.score)
            emp.last_decayed_at = now
            affected += 1

    if affected:
        db.commit()
        log.info(f"Risk decay applied to {affected} employees.")

    return affected


# ── Threshold action checks ───────────────────────────────────────────────────

def check_threshold_actions(
    email: str,
    old_band: str,
    new_band: str,
    new_score: float,
    db: Session,
) -> list[str]:
    """
    After a score change, determine what automated actions to trigger.
    Records the action in RiskAction table. Returns list of action types triggered.
    """
    BAND_ORDER = ["low", "medium", "high", "critical"]
    triggered = []

    old_idx = BAND_ORDER.index(old_band) if old_band in BAND_ORDER else 0
    new_idx = BAND_ORDER.index(new_band) if new_band in BAND_ORDER else 0

    if new_idx <= old_idx:
        return triggered   # Score went down or stayed same — no escalation needed

    if new_band in ("medium", "high", "critical"):
        triggered.append("training_enrolled")
        db.add(models.RiskAction(
            email=email,
            action_type="training_enrolled",
            trigger_band=new_band,
            trigger_score=new_score,
            details_json=json.dumps({"reason": f"Score crossed into {new_band} band"}),
        ))

    if new_band in ("high", "critical"):
        triggered.append("escalation_sent")
        db.add(models.RiskAction(
            email=email,
            action_type="escalation_sent",
            trigger_band=new_band,
            trigger_score=new_score,
            details_json=json.dumps({"reason": f"Employee risk elevated to {new_band}"}),
        ))

    return triggered


# ── Summary helpers ───────────────────────────────────────────────────────────

def get_risk_factors(email: str, db: Session) -> list[dict]:
    """
    Return a human-readable list of active signals driving this employee's score.
    Used by the API and the frontend risk detail view.
    """
    now = datetime.utcnow()
    signals = (
        db.query(models.RiskSignal)
        .filter(
            models.RiskSignal.email == email,
            (models.RiskSignal.expires_at == None) | (models.RiskSignal.expires_at > now)  # noqa: E711
        )
        .order_by(models.RiskSignal.recorded_at.desc())
        .all()
    )

    LABELS = {
        "simulation_click":     "Clicked phishing link (simulation)",
        "simulation_submit":    "Submitted credentials (simulation)",
        "simulation_report":    "Reported simulated phish (good)",
        "training_complete":    "Completed training module (good)",
        "gateway_phish_volume": "High phishing email volume received",
        "gateway_malware":      "Malware email received",
        "gateway_bec":          "BEC / impersonation attack targeted",
        "gateway_real_click":   "Clicked real malicious URL (gateway detected)",
        "gateway_real_report":  "Reported real phishing (good)",
        "breach_recent":        "Email found in recent data breach (< 6 months)",
        "breach_medium":        "Email found in data breach (6–12 months ago)",
        "breach_old":           "Email found in older data breach (1–2 years ago)",
        "breach_ancient":       "Email found in historical breach (> 2 years)",
        "breach_password":      "Password exposed in data breach",
    }

    factors = []
    for sig in signals:
        factors.append({
            "signal_type":  sig.signal_type,
            "label":        LABELS.get(sig.signal_type, sig.signal_type),
            "points":       sig.points,
            "source":       sig.source,
            "recorded_at":  sig.recorded_at.isoformat(),
            "expires_at":   sig.expires_at.isoformat() if sig.expires_at else None,
            "metadata":     json.loads(sig.metadata_json or "{}"),
        })
    return factors


def department_risk_summary(db: Session) -> list[dict]:
    """
    Aggregate risk scores by department for the dashboard heat-map.
    """
    employees = db.query(models.EmployeeRiskScore).all()
    dept_map: dict[str, dict] = {}

    for emp in employees:
        dept = emp.department or "Unknown"
        if dept not in dept_map:
            dept_map[dept] = {"department": dept, "count": 0, "total_score": 0.0,
                              "low": 0, "medium": 0, "high": 0, "critical": 0}
        dept_map[dept]["count"]       += 1
        dept_map[dept]["total_score"] += emp.score
        dept_map[dept][emp.band]      += 1

    result = []
    for d in dept_map.values():
        d["avg_score"] = round(d["total_score"] / d["count"], 1) if d["count"] else 0
        result.append(d)

    return sorted(result, key=lambda x: x["avg_score"], reverse=True)
