"""
Autonomy Engine — Zero-Touch Campaign Operations
===================================================
The core differentiator of PhishSim vs KnowBe4/Proofpoint:
fully autonomous operation without daily human intervention.

Capabilities:
  1. Campaign Proposal Engine
     - Monitors threat intel trends, risk bands, schedule gaps
     - Generates fully-configured campaign proposals for operator review
     - Proposals include rationale, target selection, template, difficulty

  2. Adaptive Difficulty
     - Per-employee difficulty history analysis
     - Selects harder templates for employees who have passed easy ones
     - Ensures programme never becomes stale or predictable

  3. Auto-Enrolment in Training
     - Triggered when employee clicks / submits in a simulation
     - Creates TrainingEnrolment record with personalised module selection

  4. Recurring Campaign Scheduler
     - Generates campaigns on configurable cadence (weekly/monthly)
     - Zero-touch mode: auto-accepts proposals if approval workflow disabled
     - Sends notification to operators when proposal is created

Usage (called by APScheduler in main.py every 24 hours):
    from autonomy.engine import run_autonomy_cycle
    result = run_autonomy_cycle(db)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

import models

log = logging.getLogger(__name__)


# ── Trigger thresholds ────────────────────────────────────────────────────────

MIN_DAYS_BETWEEN_CAMPAIGNS = 7      # don't propose if recent campaign in last 7 days
HIGH_RISK_TRIGGER_BAND     = "high" # propose targeted campaign if avg band >= high
THREAT_SPIKE_THRESHOLD     = 20     # new IOCs since last sync triggers proposal
TRAINING_COOLDOWN_DAYS     = 30     # don't re-enrol in same module within 30 days


# ── Campaign Proposal Engine ──────────────────────────────────────────────────

def _get_last_campaign_date(db: Session) -> Optional[datetime]:
    """Get the most recent campaign launch date."""
    last = (db.query(models.Campaign)
            .filter(models.Campaign.launched_at.isnot(None))
            .order_by(models.Campaign.launched_at.desc())
            .first())
    return last.launched_at if last else None


def _get_high_risk_departments(db: Session) -> list:
    """Find departments where average risk score >= 51 (high band)."""
    from risk_engine.core import department_risk_summary
    try:
        depts = department_risk_summary(db)
        return [d["department"] for d in depts if d.get("avg_score", 0) >= 51]
    except Exception as e:
        log.warning(f"Could not get dept risk summary: {e}")
        return []


def _get_best_template_for_difficulty(db: Session, difficulty: int) -> Optional[models.Template]:
    """Find a template matching the target difficulty level."""
    # Look for templates with matching difficulty
    t = (db.query(models.Template)
         .filter(models.Template.difficulty == difficulty)
         .order_by(models.Template.id.desc())
         .first())
    if not t:
        # Fallback: any template
        t = db.query(models.Template).first()
    return t


def propose_threat_intel_campaign(db: Session) -> Optional[models.CampaignProposal]:
    """
    If threat intel shows a significant spike in a particular attack type,
    propose a campaign themed around that attack.
    """
    try:
        from threat_intel.feeds import get_feed_stats
        from threat_intel.template_generator import analyse_recent_trends
        stats = get_feed_stats(db)
        if not stats.get("enabled"):
            return None

        # Check for recent spike in indicators (last 24h vs previous 7d average)
        today_count = (db.query(models.ThreatIndicator)
                       .filter(models.ThreatIndicator.first_seen >= datetime.utcnow() - timedelta(days=1))
                       .count())
        if today_count < THREAT_SPIKE_THRESHOLD:
            return None

        trends = analyse_recent_trends(db)
        if not trends["top_categories"]:
            return None

        top_cat   = trends["top_categories"][0]
        top_brand = trends["top_brands"][0] if trends["top_brands"] else "generic"
        template  = _get_best_template_for_difficulty(db, 4)  # Use hard templates for threat-triggered

        proposal = models.CampaignProposal(
            name         = f"Threat Response: {top_brand.title()} {top_cat.replace('_',' ').title()} Attack",
            rationale    = (
                f"Threat intelligence detected {today_count} new IOCs in the last 24 hours, "
                f"primarily targeting '{top_brand}' via '{top_cat}' techniques. "
                f"A targeted simulation will test employee resilience to this active threat pattern."
            ),
            trigger_type   = "threat_intel",
            trigger_detail = json.dumps({
                "ioc_spike_count": today_count,
                "top_brand": top_brand,
                "top_category": top_cat,
                "trends": trends,
            }),
            template_id     = template.id if template else None,
            suggested_targets = json.dumps({"band": "all", "department": None}),
            difficulty      = 4,
            status          = "pending",
        )
        db.add(proposal)
        db.commit()
        log.info(f"Proposed threat-intel campaign: {proposal.name}")
        return proposal
    except Exception as e:
        log.error(f"Threat intel proposal error: {e}")
        return None


def propose_high_risk_campaign(db: Session) -> Optional[models.CampaignProposal]:
    """
    If a department has average risk score in the high/critical band,
    propose a targeted campaign for that department.
    """
    try:
        high_risk_depts = _get_high_risk_departments(db)
        if not high_risk_depts:
            return None

        dept = high_risk_depts[0]
        template = _get_best_template_for_difficulty(db, 3)

        proposal = models.CampaignProposal(
            name         = f"Targeted: {dept} Department Risk Reduction",
            rationale    = (
                f"The {dept} department has an elevated average risk score. "
                f"A targeted phishing simulation will reinforce security awareness "
                f"and provide measurable improvement data."
            ),
            trigger_type   = "risk_band",
            trigger_detail = json.dumps({"department": dept, "band": "high"}),
            template_id    = template.id if template else None,
            suggested_targets = json.dumps({"band": "high", "department": dept}),
            difficulty     = 3,
            status         = "pending",
        )
        db.add(proposal)
        db.commit()
        log.info(f"Proposed high-risk campaign for dept: {dept}")
        return proposal
    except Exception as e:
        log.error(f"High-risk proposal error: {e}")
        return None


def propose_scheduled_campaign(db: Session) -> Optional[models.CampaignProposal]:
    """
    Propose a general recurring campaign if no campaign has launched recently.
    Ensures minimum programme cadence even without threat intel triggers.
    """
    try:
        last = _get_last_campaign_date(db)
        if last and (datetime.utcnow() - last).days < MIN_DAYS_BETWEEN_CAMPAIGNS:
            return None  # Too recent

        template = _get_best_template_for_difficulty(db, 2)

        proposal = models.CampaignProposal(
            name         = f"Scheduled Awareness: {datetime.utcnow().strftime('%B %Y')} Programme",
            rationale    = (
                "No phishing simulation has run in the last 7+ days. "
                "Regular simulations are essential for maintaining security awareness. "
                "This proposal maintains the minimum recommended monthly cadence."
            ),
            trigger_type  = "schedule",
            trigger_detail = json.dumps({"days_since_last": (datetime.utcnow() - last).days if last else "never"}),
            template_id   = template.id if template else None,
            suggested_targets = json.dumps({"band": "all", "department": None}),
            difficulty    = 2,
            status        = "pending",
        )
        db.add(proposal)
        db.commit()
        log.info("Proposed scheduled campaign.")
        return proposal
    except Exception as e:
        log.error(f"Scheduled proposal error: {e}")
        return None


# ── Adaptive Difficulty ───────────────────────────────────────────────────────

def get_adaptive_difficulty(email: str, db: Session) -> int:
    """
    Determine the appropriate difficulty level for an employee based on
    their historical simulation performance.

    Logic:
      - No history → difficulty 2 (easy intro)
      - Clicked in last campaign → difficulty 1 (easy, build confidence after reinforcement)
      - Passed last 2 campaigns (no click/submit) → difficulty 3 (escalate)
      - Passed last 3+ campaigns → difficulty 4 (challenge)
      - Consistently passing at 4 → difficulty 5 (expert)
    """
    signals = (db.query(models.RiskSignal)
               .filter_by(email=email)
               .filter(models.RiskSignal.signal_type.in_(
                   ["simulation_click", "simulation_submit", "simulation_report"]))
               .order_by(models.RiskSignal.recorded_at.desc())
               .limit(10).all())

    if not signals:
        return 2  # First time — start easy

    recent_clicks  = sum(1 for s in signals[:3] if s.signal_type in ("simulation_click", "simulation_submit"))
    recent_reports = sum(1 for s in signals[:3] if s.signal_type == "simulation_report")

    if recent_clicks >= 2:
        return 1  # Still clicking — keep it easy, make the cues obvious

    clean_streak = 0
    for s in signals:
        if s.signal_type == "simulation_report":
            clean_streak += 1
        elif s.signal_type in ("simulation_click", "simulation_submit"):
            break
        else:
            clean_streak += 1

    if clean_streak >= 5:
        return 5
    elif clean_streak >= 3:
        return 4
    elif clean_streak >= 2:
        return 3
    else:
        return 2


# ── Auto-enrolment in training ────────────────────────────────────────────────

TRAINING_MODULES = {
    "simulation_click":  [
        {"id": "phishing_basics",     "title": "Recognising Phishing Emails",          "duration_mins": 15},
        {"id": "link_inspection",     "title": "How to Inspect Suspicious Links",       "duration_mins": 10},
    ],
    "simulation_submit": [
        {"id": "credential_safety",   "title": "Protecting Your Login Credentials",     "duration_mins": 20},
        {"id": "password_hygiene",    "title": "Password Hygiene & MFA Best Practices", "duration_mins": 15},
    ],
    "high_risk_band": [
        {"id": "security_foundations","title": "Security Awareness Foundations",        "duration_mins": 30},
    ],
    "breach_detected": [
        {"id": "breach_response",     "title": "What To Do After a Credential Breach",  "duration_mins": 15},
    ],
}


def auto_enrol_training(email: str, trigger: str, db: Session) -> list:
    """
    Enrol employee in relevant training modules based on trigger type.
    Respects TRAINING_COOLDOWN_DAYS to avoid spam.
    Returns list of enrolled module IDs.
    """
    modules = TRAINING_MODULES.get(trigger, [])
    if not modules:
        return []

    enrolled = []
    cooldown_cutoff = datetime.utcnow() - timedelta(days=TRAINING_COOLDOWN_DAYS)

    for module in modules:
        # Check if already enrolled recently
        existing = (db.query(models.TrainingEnrolment)
                    .filter_by(email=email, module_id=module["id"])
                    .filter(models.TrainingEnrolment.enrolled_at >= cooldown_cutoff)
                    .first())
        if existing:
            continue

        enrolment = models.TrainingEnrolment(
            email        = email,
            module_id    = module["id"],
            module_title = module["title"],
            trigger      = trigger,
            status       = "enrolled",
        )
        db.add(enrolment)
        enrolled.append(module["id"])

    if enrolled:
        db.commit()
        log.info(f"Auto-enrolled {email} in training: {enrolled} (trigger: {trigger})")

    return enrolled


# ── Gamification — Badge awards ───────────────────────────────────────────────

BADGE_DEFINITIONS = {
    "first_report": {
        "label": "🏅 First Defender",
        "description": "Reported your first phishing simulation email",
        "check": lambda email, db: _check_first_report(email, db),
    },
    "five_reports": {
        "label": "🥇 Phishing Hunter",
        "description": "Reported 5 phishing simulation emails",
        "check": lambda email, db: _check_n_reports(email, db, 5),
    },
    "clean_month": {
        "label": "🛡️ Clean Record",
        "description": "30 days with no phishing clicks",
        "check": lambda email, db: _check_clean_streak(email, db, 30),
    },
    "training_graduate": {
        "label": "🎓 Security Graduate",
        "description": "Completed 3 or more training modules",
        "check": lambda email, db: _check_training_count(email, db, 3),
    },
    "risk_reducer": {
        "label": "📉 Risk Reducer",
        "description": "Improved risk band (e.g. High → Medium)",
        "check": lambda email, db: _check_risk_improvement(email, db),
    },
}


def _check_first_report(email: str, db: Session) -> bool:
    return db.query(models.RiskSignal).filter_by(
        email=email, signal_type="simulation_report"
    ).count() == 1


def _check_n_reports(email: str, db: Session, n: int) -> bool:
    return db.query(models.RiskSignal).filter_by(
        email=email, signal_type="simulation_report"
    ).count() >= n


def _check_clean_streak(email: str, db: Session, days: int) -> bool:
    cutoff = datetime.utcnow() - timedelta(days=days)
    return db.query(models.RiskSignal).filter(
        models.RiskSignal.email == email,
        models.RiskSignal.signal_type.in_(["simulation_click", "simulation_submit"]),
        models.RiskSignal.recorded_at >= cutoff,
    ).count() == 0


def _check_training_count(email: str, db: Session, n: int) -> bool:
    return db.query(models.TrainingEnrolment).filter_by(
        email=email, status="completed"
    ).count() >= n


def _check_risk_improvement(email: str, db: Session) -> bool:
    actions = (db.query(models.RiskAction)
               .filter_by(email=email, action_type="band_improved")
               .count())
    return actions > 0


def check_and_award_badges(email: str, db: Session) -> list:
    """
    Check all badge criteria for an employee and award any newly earned badges.
    Returns list of newly awarded badge types.
    """
    awarded = []
    for badge_type, defn in BADGE_DEFINITIONS.items():
        # Skip if already has this badge
        existing = db.query(models.EmployeeBadge).filter_by(
            email=email, badge_type=badge_type
        ).first()
        if existing:
            continue
        try:
            if defn["check"](email, db):
                badge = models.EmployeeBadge(email=email, badge_type=badge_type,
                                              notes=defn["description"])
                db.add(badge)
                awarded.append(badge_type)
        except Exception as e:
            log.warning(f"Badge check error ({badge_type}) for {email}: {e}")

    if awarded:
        db.commit()
        log.info(f"Awarded badges to {email}: {awarded}")
    return awarded


# ── Leaderboard refresh ───────────────────────────────────────────────────────

def refresh_leaderboard(db: Session) -> int:
    """
    Rebuild the leaderboard for the current month.
    Called monthly by APScheduler.
    Returns number of entries created.
    """
    period = datetime.utcnow().strftime("%Y-%m")

    # Delete existing entries for this period
    db.query(models.SecurityLeaderboard).filter_by(period=period).delete()

    employees = db.query(models.EmployeeRiskScore).all()
    entries = []

    for emp in employees:
        from encryption import decrypt
        email = decrypt(emp.email)
        name  = decrypt(emp.name) if emp.name else ""

        # Count positive behaviours
        reports = db.query(models.RiskSignal).filter_by(
            email=email, signal_type="simulation_report"
        ).count()
        clicks = db.query(models.RiskSignal).filter_by(
            email=email, signal_type="simulation_click"
        ).count()
        training = db.query(models.TrainingEnrolment).filter_by(
            email=email, status="completed"
        ).count() if hasattr(models, 'TrainingEnrolment') else 0
        badges = db.query(models.EmployeeBadge).filter_by(email=email).count()

        # Score: start at 100, subtract risk, add positive behaviours
        leaderboard_score = max(0, 100 - emp.score + (reports * 10) + (training * 5) + (badges * 8))

        entry = models.SecurityLeaderboard(
            period         = period,
            email          = email,
            name           = name,
            department     = decrypt(emp.department) if emp.department else "",
            score          = round(leaderboard_score, 1),
            badges_count   = badges,
            reports_count  = reports,
            clicks_count   = clicks,
            training_count = training,
        )
        db.add(entry)
        entries.append(entry)

    db.flush()

    # Assign ranks (sorted by leaderboard score descending)
    entries.sort(key=lambda e: e.score, reverse=True)
    for rank, entry in enumerate(entries, 1):
        entry.rank = rank

    db.commit()
    log.info(f"Leaderboard refreshed for {period}: {len(entries)} entries")
    return len(entries)


# ── Main autonomy cycle ───────────────────────────────────────────────────────

def run_autonomy_cycle(db: Session) -> dict:
    """
    Run the full autonomy cycle. Called daily by APScheduler.
    1. Check for campaign proposals
    2. Auto-accept proposals if approval workflow is disabled (zero-touch mode)
    3. Send notifications for new proposals
    """
    results = {
        "proposals_created": [],
        "auto_accepted":     [],
        "notifications_sent": [],
    }

    # 1. Generate proposals (only if no pending proposals already exist)
    existing_pending = db.query(models.CampaignProposal).filter_by(status="pending").count()
    if existing_pending == 0:
        # Try threat intel trigger first
        p = propose_threat_intel_campaign(db)
        if p:
            results["proposals_created"].append({"id": p.id, "name": p.name, "trigger": "threat_intel"})

        # Try high-risk department trigger
        if not results["proposals_created"]:
            p = propose_high_risk_campaign(db)
            if p:
                results["proposals_created"].append({"id": p.id, "name": p.name, "trigger": "risk_band"})

        # Schedule-based fallback
        if not results["proposals_created"]:
            p = propose_scheduled_campaign(db)
            if p:
                results["proposals_created"].append({"id": p.id, "name": p.name, "trigger": "schedule"})

    # 2. Send notifications for new proposals
    import notifications
    for prop in results["proposals_created"]:
        try:
            notifications.send(
                db=db,
                event_type="campaign.proposal_created",
                title=f"New Campaign Proposal: {prop['name']}",
                message=f"The autonomy engine has proposed a new campaign (trigger: {prop['trigger']}). Review it in the Autonomy dashboard.",
                details={"proposal_id": prop["id"], "trigger": prop["trigger"]},
                severity="info",
            )
            results["notifications_sent"].append(prop["id"])
        except Exception as e:
            log.warning(f"Notification failed for proposal {prop['id']}: {e}")

    log.info(f"Autonomy cycle complete: {results}")
    return results
