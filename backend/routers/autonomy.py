"""
Autonomy Engine Router
========================
API endpoints for managing the autonomous campaign operations.

Endpoints:
  GET  /autonomy/proposals              — list campaign proposals (operator)
  POST /autonomy/proposals/{id}/accept  — accept proposal → create campaign (operator)
  POST /autonomy/proposals/{id}/reject  — reject proposal (operator)
  POST /autonomy/run-cycle              — manually trigger autonomy cycle (admin)
  GET  /autonomy/leaderboard            — security leaderboard (auth)
  POST /autonomy/leaderboard/refresh    — refresh leaderboard for current month (admin)
  GET  /autonomy/badges/{email}         — employee badges (operator)
  POST /autonomy/badges/check/{email}   — manually check + award badges (admin)
  GET  /autonomy/training               — training enrolments (operator)
"""

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

import models
from database import get_db
from routers.auth import require_auth, require_admin, require_operator

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/autonomy", tags=["autonomy"])


# ── Proposals ─────────────────────────────────────────────────────────────────

@router.get("/proposals")
def list_proposals(
    status: Optional[str] = Query(None),
    limit:  int = Query(50, ge=1, le=200),
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    q = db.query(models.CampaignProposal)
    if status:
        q = q.filter_by(status=status)
    proposals = q.order_by(models.CampaignProposal.created_at.desc()).limit(limit).all()
    return [{
        "id":           p.id,
        "name":         p.name,
        "rationale":    p.rationale,
        "trigger_type": p.trigger_type,
        "difficulty":   p.difficulty,
        "status":       p.status,
        "created_at":   p.created_at.isoformat(),
        "reviewed_at":  p.reviewed_at.isoformat() if p.reviewed_at else None,
        "reviewed_by":  p.reviewed_by,
        "campaign_id":  p.campaign_id,
        "trigger_detail": json.loads(p.trigger_detail or "{}"),
        "suggested_targets": json.loads(p.suggested_targets or "{}"),
    } for p in proposals]


@router.post("/proposals/{proposal_id}/accept")
def accept_proposal(
    proposal_id: int,
    payload: dict = None,
    user: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """
    Accept a campaign proposal.
    Creates a campaign draft from the proposal's template + suggested targets.
    """
    proposal = db.query(models.CampaignProposal).filter_by(id=proposal_id).first()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.status != "pending":
        raise HTTPException(status_code=400, detail=f"Proposal is already {proposal.status}")

    template = None
    if proposal.template_id:
        template = db.query(models.Template).filter_by(id=proposal.template_id).first()

    # Build campaign from proposal
    campaign = models.Campaign(
        name        = proposal.name,
        description = f"Auto-proposed by Autonomy Engine. Rationale: {proposal.rationale[:200]}",
        subject     = template.subject if template else "Important Security Notice",
        body        = template.body if template else "This is a phishing simulation. {{phishing_link}} {{tracking_pixel}}",
        from_email  = "security@company.com",
        from_name   = "Security Team",
        phishing_url = "http://localhost:8000",
        status      = "draft",
        tags        = f"autonomy,{proposal.trigger_type}",
    )
    db.add(campaign)
    db.flush()

    proposal.status      = "accepted"
    proposal.reviewed_at = datetime.utcnow()
    proposal.reviewed_by = user.username
    proposal.campaign_id = campaign.id

    import audit as audit_module
    audit_module.write(db, "autonomy.proposal_accepted", actor=user.username,
                       target_type="campaign", target_id=str(campaign.id),
                       details={"proposal_id": proposal_id, "campaign_name": campaign.name})
    db.commit()
    return {"ok": True, "campaign_id": campaign.id, "campaign_name": campaign.name}


@router.post("/proposals/{proposal_id}/reject")
def reject_proposal(
    proposal_id: int,
    payload: dict = None,
    user: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    proposal = db.query(models.CampaignProposal).filter_by(id=proposal_id).first()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.status != "pending":
        raise HTTPException(status_code=400, detail=f"Proposal is already {proposal.status}")

    proposal.status      = "rejected"
    proposal.reviewed_at = datetime.utcnow()
    proposal.reviewed_by = user.username

    import audit as audit_module
    audit_module.write(db, "autonomy.proposal_rejected", actor=user.username,
                       details={"proposal_id": proposal_id, "name": proposal.name})
    db.commit()
    return {"ok": True}


@router.post("/run-cycle")
def run_cycle(
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Manually trigger the autonomy cycle (normally runs daily via APScheduler)."""
    try:
        from autonomy.engine import run_autonomy_cycle
        result = run_autonomy_cycle(db)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Leaderboard ───────────────────────────────────────────────────────────────

@router.get("/leaderboard")
def get_leaderboard(
    period: Optional[str] = Query(None),  # YYYY-MM format
    limit:  int = Query(50, ge=1, le=200),
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    if not period:
        period = datetime.utcnow().strftime("%Y-%m")
    entries = (db.query(models.SecurityLeaderboard)
               .filter_by(period=period)
               .order_by(models.SecurityLeaderboard.rank)
               .limit(limit).all())
    return [{
        "rank":           e.rank,
        "name":           e.name or e.email.split("@")[0],
        "department":     e.department,
        "score":          e.score,
        "badges_count":   e.badges_count,
        "reports_count":  e.reports_count,
        "clicks_count":   e.clicks_count,
        "training_count": e.training_count,
    } for e in entries]


@router.post("/leaderboard/refresh")
def refresh_leaderboard(
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        from autonomy.engine import refresh_leaderboard as _refresh
        count = _refresh(db)
        return {"ok": True, "entries": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Badges ────────────────────────────────────────────────────────────────────

BADGE_LABELS = {
    "first_report":       "🏅 First Defender",
    "five_reports":       "🥇 Phishing Hunter",
    "clean_month":        "🛡️ Clean Record",
    "training_graduate":  "🎓 Security Graduate",
    "risk_reducer":       "📉 Risk Reducer",
    "early_detector":     "⚡ Early Detector",
    "perfect_quarter":    "🌟 Perfect Quarter",
}


@router.get("/badges/{email:path}")
def get_badges(
    email: str,
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    badges = db.query(models.EmployeeBadge).filter_by(email=email).all()
    return [{
        "badge_type": b.badge_type,
        "label":      BADGE_LABELS.get(b.badge_type, b.badge_type),
        "awarded_at": b.awarded_at.isoformat(),
        "notes":      b.notes,
    } for b in badges]


@router.post("/badges/check/{email:path}")
def check_badges(
    email: str,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        from autonomy.engine import check_and_award_badges
        awarded = check_and_award_badges(email, db)
        return {"ok": True, "awarded": awarded}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Training enrolments ───────────────────────────────────────────────────────

@router.get("/training")
def list_training(
    email:  Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit:  int = Query(100, ge=1, le=500),
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    q = db.query(models.TrainingEnrolment)
    if email:
        q = q.filter_by(email=email)
    if status:
        q = q.filter_by(status=status)
    enrolments = q.order_by(models.TrainingEnrolment.enrolled_at.desc()).limit(limit).all()
    return [{
        "id":           e.id,
        "email":        e.email,
        "module_id":    e.module_id,
        "module_title": e.module_title,
        "trigger":      e.trigger,
        "status":       e.status,
        "enrolled_at":  e.enrolled_at.isoformat(),
        "completed_at": e.completed_at.isoformat() if e.completed_at else None,
    } for e in enrolments]


@router.post("/training/{enrolment_id}/complete")
def complete_training(
    enrolment_id: int,
    user: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """Mark a training enrolment as completed."""
    e = db.query(models.TrainingEnrolment).filter_by(id=enrolment_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Enrolment not found")
    e.status       = "completed"
    e.completed_at = datetime.utcnow()

    # Fire a training_complete risk signal
    try:
        from risk_engine.core import record_signal, recalculate
        record_signal(e.email, "training_complete", "training_portal", db)
        recalculate(e.email, db)
    except Exception as ex:
        log.warning(f"Training signal error: {ex}")

    # Check for new badges
    try:
        from autonomy.engine import check_and_award_badges
        check_and_award_badges(e.email, db)
    except Exception as ex:
        log.warning(f"Badge check error: {ex}")

    db.commit()
    return {"ok": True}
