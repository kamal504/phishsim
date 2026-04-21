"""
Threat Intelligence Router
============================
API endpoints for managing threat intelligence feeds, viewing indicators,
and generating AI-powered phishing templates from current threat trends.

Endpoints:
  GET  /threat-intel/status              — feed status + stats
  GET  /threat-intel/config              — get config (admin)
  POST /threat-intel/config              — save config (admin)
  POST /threat-intel/sync                — trigger manual sync (admin)
  GET  /threat-intel/indicators          — browse IOC database (operator)
  GET  /threat-intel/trends              — current threat trends (operator)
  POST /threat-intel/generate-template   — generate template from trends (admin)
  GET  /threat-intel/generated-templates — list AI-generated templates (operator)
  POST /threat-intel/promote/{id}        — promote generated → template library (admin)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

import models
from database import get_db
from routers.auth import require_auth, require_admin, require_operator

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


# ── Status & Config ───────────────────────────────────────────────────────────

@router.get("/status")
def get_status(
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    try:
        from threat_intel.feeds import get_feed_stats
        return get_feed_stats(db)
    except Exception as e:
        return {"error": str(e), "enabled": False, "total": 0, "active": 0}


@router.get("/config")
def get_config(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.ThreatIntelConfig).first()
    if not cfg:
        return {
            "enabled": False, "sync_interval_hours": 6,
            "otx_api_key": "", "phishtank_api_key": "", "openai_api_key": "",
            "feed_openphish": True, "feed_urlhaus": True,
            "feed_otx": False, "feed_phishtank": False,
            "last_synced_at": None,
        }
    return {
        "enabled":             cfg.enabled,
        "sync_interval_hours": cfg.sync_interval_hours,
        "otx_api_key":         "••••" if cfg.otx_api_key else "",
        "phishtank_api_key":   "••••" if cfg.phishtank_api_key else "",
        "openai_api_key":      "••••" if cfg.openai_api_key else "",
        "feed_openphish":      cfg.feed_openphish,
        "feed_urlhaus":        cfg.feed_urlhaus,
        "feed_otx":            cfg.feed_otx,
        "feed_phishtank":      cfg.feed_phishtank,
        "last_synced_at":      cfg.last_synced_at.isoformat() if cfg.last_synced_at else None,
    }


@router.post("/config")
def save_config(
    payload: dict,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.ThreatIntelConfig).first()
    if not cfg:
        cfg = models.ThreatIntelConfig()
        db.add(cfg)
    MASK = "••••"
    cfg.enabled             = payload.get("enabled", cfg.enabled)
    cfg.sync_interval_hours = payload.get("sync_interval_hours", cfg.sync_interval_hours)
    cfg.feed_openphish      = payload.get("feed_openphish", cfg.feed_openphish)
    cfg.feed_urlhaus        = payload.get("feed_urlhaus", cfg.feed_urlhaus)
    cfg.feed_otx            = payload.get("feed_otx", cfg.feed_otx)
    cfg.feed_phishtank      = payload.get("feed_phishtank", cfg.feed_phishtank)
    # Only update keys if a real value (not mask) was submitted
    if payload.get("otx_api_key") and payload["otx_api_key"] != MASK:
        cfg.otx_api_key = payload["otx_api_key"]
    if payload.get("phishtank_api_key") and payload["phishtank_api_key"] != MASK:
        cfg.phishtank_api_key = payload["phishtank_api_key"]
    if payload.get("openai_api_key") and payload["openai_api_key"] != MASK:
        cfg.openai_api_key = payload["openai_api_key"]
    cfg.updated_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


@router.post("/sync")
def manual_sync(
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Trigger an immediate threat intel feed sync (runs in-process, may take ~30s)."""
    try:
        from threat_intel.feeds import run_feed_sync
        result = run_feed_sync(db)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Indicators ────────────────────────────────────────────────────────────────

@router.get("/indicators")
def list_indicators(
    ioc_type:   Optional[str] = Query(None),
    feed:       Optional[str] = Query(None),
    search:     Optional[str] = Query(None),
    days:       int = Query(7, ge=1, le=90),
    limit:      int = Query(100, ge=1, le=500),
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(days=days)
    q = db.query(models.ThreatIndicator).filter(
        models.ThreatIndicator.active == True,
        models.ThreatIndicator.last_seen >= since,
    )
    if ioc_type:
        q = q.filter(models.ThreatIndicator.ioc_type == ioc_type)
    if feed:
        q = q.filter(models.ThreatIndicator.feed == feed)
    if search:
        q = q.filter(models.ThreatIndicator.value.ilike(f"%{search}%"))
    indicators = q.order_by(models.ThreatIndicator.last_seen.desc()).limit(limit).all()
    return [{
        "id":          i.id,
        "ioc_type":    i.ioc_type,
        "value":       i.value,
        "feed":        i.feed,
        "threat_type": i.threat_type,
        "tags":        json.loads(i.tags or "[]"),
        "first_seen":  i.first_seen.isoformat(),
        "last_seen":   i.last_seen.isoformat(),
        "hit_count":   i.hit_count,
    } for i in indicators]


@router.get("/trends")
def get_trends(
    days: int = Query(7, ge=1, le=30),
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    try:
        from threat_intel.template_generator import analyse_recent_trends
        return analyse_recent_trends(db, days=days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Template generation ───────────────────────────────────────────────────────

@router.post("/generate-template")
def generate_template(
    payload: dict,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Generate a new phishing template based on current threat intelligence trends.
    Optionally saves it to the generated_templates table.
    """
    try:
        from threat_intel.template_generator import generate_from_intel, analyse_recent_trends
        category  = payload.get("category")
        brand     = payload.get("brand")
        use_ai    = payload.get("use_ai", True)
        result    = generate_from_intel(db, category_hint=category,
                                         brand_hint=brand, use_ai=use_ai)
        if not result:
            raise HTTPException(status_code=500, detail="Template generation failed")

        # Save to generated_templates
        trends = analyse_recent_trends(db)
        gen = models.GeneratedTemplate(
            name         = result["name"],
            category     = result.get("category", "credential_harvest"),
            subject      = result["subject"],
            body         = result["body"],
            difficulty   = result.get("difficulty", 3),
            tags         = result.get("tags", "[]"),
            generated_by = result.get("generated_by", "blueprint"),
            intel_trends = json.dumps(trends),
        )
        db.add(gen)
        db.commit()
        db.refresh(gen)

        return {
            "id":           gen.id,
            "name":         gen.name,
            "category":     gen.category,
            "subject":      gen.subject,
            "body":         gen.body,
            "difficulty":   gen.difficulty,
            "generated_by": gen.generated_by,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/generated-templates")
def list_generated_templates(
    limit: int = Query(50, ge=1, le=200),
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    templates = (db.query(models.GeneratedTemplate)
                 .order_by(models.GeneratedTemplate.created_at.desc())
                 .limit(limit).all())
    return [{
        "id":           t.id,
        "name":         t.name,
        "category":     t.category,
        "subject":      t.subject,
        "difficulty":   t.difficulty,
        "generated_by": t.generated_by,
        "promoted":     t.promoted,
        "created_at":   t.created_at.isoformat(),
    } for t in templates]


@router.post("/promote/{template_id}")
def promote_template(
    template_id: int,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Promote a generated template to the main Template library so it
    can be used in campaigns.
    """
    gen = db.query(models.GeneratedTemplate).filter_by(id=template_id).first()
    if not gen:
        raise HTTPException(status_code=404, detail="Generated template not found")
    if gen.promoted:
        raise HTTPException(status_code=400, detail="Already promoted")

    # Create a Template record
    template = models.Template(
        name        = gen.name,
        category    = gen.category,
        subject     = gen.subject,
        body        = gen.body,
        description = f"AI-generated from threat intel ({gen.generated_by}). Difficulty: {gen.difficulty}/5",
        is_builtin  = False,
        difficulty  = gen.difficulty,
    )
    db.add(template)
    gen.promoted = True

    import audit as audit_module
    audit_module.write(db, "threat_intel.template_promoted", actor=user.username,
                       details={"template_name": gen.name, "difficulty": gen.difficulty})
    db.commit()
    db.refresh(template)
    return {"ok": True, "template_id": template.id, "name": template.name}
