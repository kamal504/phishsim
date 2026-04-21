"""
Risk Engine API Router
=======================
Exposes all risk scoring endpoints:

  GET  /risk/employees               — paginated list of all employee risk scores
  GET  /risk/employees/{email}       — single employee score + factors + breach records
  GET  /risk/summary                 — org-wide stats (band distribution, avg score)
  GET  /risk/department-heatmap      — dept-level avg scores for heatmap
  GET  /risk/top-risk                — top N highest-risk employees
  GET  /risk/actions                 — recent automated actions log

  POST /risk/signal                  — manually record a risk signal (admin only)
  POST /risk/recalculate/{email}     — force recalculate one employee
  POST /risk/recalculate-all         — force recalculate every employee (admin)
  POST /risk/decay                   — manually trigger decay job (admin)

  GET  /risk/gateway/config          — get current gateway config
  POST /risk/gateway/config          — save gateway config (admin)
  POST /risk/gateway/test            — test gateway connection (admin)
  POST /risk/gateway/sync            — manually trigger a gateway pull (admin)

  GET  /risk/breach/config           — get breach monitor config
  POST /risk/breach/config           — save breach config (admin)
  POST /risk/breach/scan/{email}     — scan one employee for breaches (admin)
  POST /risk/breach/scan-all         — run full org breach scan (admin)
"""

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from database import get_db
from routers.auth import require_auth, require_admin, require_operator
from risk_engine import core as risk_core
from risk_engine import breach_monitor, gateway_sync

log = logging.getLogger(__name__)
router = APIRouter(prefix="/risk", tags=["risk"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SignalPayload(BaseModel):
    email:        str
    signal_type:  str
    source:       str = "manual"
    points:       Optional[float] = None
    metadata:     Optional[dict] = None
    name:         Optional[str]  = ""
    department:   Optional[str]  = ""


class GatewayConfigPayload(BaseModel):
    gateway_type:          str   = "none"
    enabled:               bool  = False
    m365_tenant_id:        str   = ""
    m365_client_id:        str   = ""
    m365_client_secret:    str   = ""
    gws_service_account_json: str = ""
    gws_admin_email:       str   = ""
    pp_principal:          str   = ""
    pp_secret:             str   = ""
    pp_cluster_id:         str   = "s1"
    mc_base_url:           str   = ""
    mc_client_id:          str   = ""
    mc_client_secret:      str   = ""
    syslog_port:           int   = 5140
    syslog_format:         str   = "cef"
    pull_interval_minutes: int   = 60


class BreachConfigPayload(BaseModel):
    enabled:              bool  = False
    hibp_api_key:         str   = ""
    check_frequency_days: int   = 7
    check_passwords:      bool  = True
    alert_on_new_breach:  bool  = True


# ── Employee risk endpoints ───────────────────────────────────────────────────

@router.get("/employees")
def list_employees(
    page:       int   = Query(1, ge=1),
    limit:      int   = Query(50, ge=1, le=200),
    band:       Optional[str] = Query(None),
    department: Optional[str] = Query(None),
    sort_by:    str   = Query("score"),
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    q = db.query(models.EmployeeRiskScore)
    if band:
        q = q.filter(models.EmployeeRiskScore.band == band)
    if department:
        q = q.filter(models.EmployeeRiskScore.department.ilike(f"%{department}%"))

    if sort_by == "score":
        q = q.order_by(models.EmployeeRiskScore.score.desc())
    elif sort_by == "name":
        q = q.order_by(models.EmployeeRiskScore.name)
    elif sort_by == "department":
        q = q.order_by(models.EmployeeRiskScore.department)

    total = q.count()
    employees = q.offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page":  page,
        "limit": limit,
        "employees": [_employee_dict(e) for e in employees]
    }


@router.get("/employees/{email:path}")
def get_employee(
    email: str,
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    record = db.query(models.EmployeeRiskScore).filter_by(email=email).first()
    if not record:
        raise HTTPException(status_code=404, detail="No risk profile found for this email")

    factors = risk_core.get_risk_factors(email, db)
    breaches = db.query(models.BreachRecord).filter_by(email=email).order_by(
        models.BreachRecord.recorded_at.desc()
    ).all()
    actions = db.query(models.RiskAction).filter_by(email=email).order_by(
        models.RiskAction.performed_at.desc()
    ).limit(20).all()

    return {
        **_employee_dict(record),
        "factors":  factors,
        "breaches": [_breach_dict(b) for b in breaches],
        "actions":  [_action_dict(a) for a in actions],
    }


@router.get("/summary")
def risk_summary(
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    all_scores = db.query(models.EmployeeRiskScore).all()
    total = len(all_scores)
    if total == 0:
        return {"total": 0, "avg_score": 0, "bands": {}}

    band_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    total_score = 0.0
    for emp in all_scores:
        band_counts[emp.band] = band_counts.get(emp.band, 0) + 1
        total_score += emp.score

    return {
        "total":          total,
        "avg_score":      round(total_score / total, 1),
        "bands":          band_counts,
        "critical_count": band_counts["critical"],
        "high_count":     band_counts["high"],
    }


@router.get("/department-heatmap")
def department_heatmap(
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    return risk_core.department_risk_summary(db)


@router.get("/top-risk")
def top_risk(
    limit: int = Query(20, ge=1, le=100),
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    employees = (
        db.query(models.EmployeeRiskScore)
        .order_by(models.EmployeeRiskScore.score.desc())
        .limit(limit)
        .all()
    )
    return [_employee_dict(e) for e in employees]


@router.get("/actions")
def list_actions(
    limit: int = Query(50, ge=1, le=200),
    _: models.User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    actions = (
        db.query(models.RiskAction)
        .order_by(models.RiskAction.performed_at.desc())
        .limit(limit)
        .all()
    )
    return [_action_dict(a) for a in actions]


# ── Manual signal + recalculate ───────────────────────────────────────────────

@router.post("/signal")
def record_signal_manual(
    payload: SignalPayload,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        sig = risk_core.record_signal(
            email=payload.email.strip().lower(),
            signal_type=payload.signal_type,
            source=payload.source,
            db=db,
            metadata=payload.metadata,
            custom_points=payload.points,
            name=payload.name or "",
            department=payload.department or "",
        )
        db.commit()
        return {"ok": True, "signal_id": sig.id}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.post("/recalculate/{email:path}")
def recalculate_one(
    email: str,
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    rec = risk_core.recalculate(email, db)
    db.commit()
    return _employee_dict(rec)


@router.post("/recalculate-all")
def recalculate_all(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    employees = db.query(models.EmployeeRiskScore).all()
    count = 0
    for emp in employees:
        risk_core.recalculate(emp.email, db)
        count += 1
    db.commit()
    return {"recalculated": count}


@router.post("/decay")
def trigger_decay(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    affected = risk_core.apply_decay(db)
    return {"employees_decayed": affected}


# ── Gateway config ────────────────────────────────────────────────────────────

@router.get("/gateway/config")
def get_gateway_config(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.GatewayConfig).first()
    if not cfg:
        return {}
    return _gateway_config_dict(cfg)


@router.post("/gateway/config")
def save_gateway_config(
    payload: GatewayConfigPayload,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.GatewayConfig).first()
    if not cfg:
        cfg = models.GatewayConfig()
        db.add(cfg)

    for field, value in payload.model_dump().items():
        setattr(cfg, field, value)
    cfg.updated_at = datetime.utcnow()
    db.commit()

    # Start syslog listener if needed
    if cfg.gateway_type == "syslog" and cfg.enabled:
        from risk_engine.gateway_adapters.syslog_listener import start_listener
        start_listener(cfg.syslog_port or 5140)

    return {"ok": True}


@router.post("/gateway/test")
def test_gateway(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    ok, msg = gateway_sync.test_gateway_connection(db)
    return {"success": ok, "message": msg}


@router.post("/gateway/sync")
def manual_gateway_sync(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    result = gateway_sync.run_gateway_sync(db)
    return result


# ── Breach config ─────────────────────────────────────────────────────────────

@router.get("/breach/config")
def get_breach_config(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.BreachConfig).first()
    if not cfg:
        return {}
    return {
        "enabled":              cfg.enabled,
        "hibp_api_key":         "••••••" if cfg.hibp_api_key else "",
        "check_frequency_days": cfg.check_frequency_days,
        "check_passwords":      cfg.check_passwords,
        "alert_on_new_breach":  cfg.alert_on_new_breach,
        "last_full_check_at":   cfg.last_full_check_at.isoformat() if cfg.last_full_check_at else None,
        "last_check_status":    cfg.last_check_status,
        "last_error":           cfg.last_error,
    }


@router.post("/breach/config")
def save_breach_config(
    payload: BreachConfigPayload,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.BreachConfig).first()
    if not cfg:
        cfg = models.BreachConfig()
        db.add(cfg)

    cfg.enabled              = payload.enabled
    cfg.check_frequency_days = payload.check_frequency_days
    cfg.check_passwords      = payload.check_passwords
    cfg.alert_on_new_breach  = payload.alert_on_new_breach
    cfg.updated_at           = datetime.utcnow()

    # Only update the API key if a new one was provided (not the masked version)
    if payload.hibp_api_key and not payload.hibp_api_key.startswith("•"):
        cfg.hibp_api_key = payload.hibp_api_key

    db.commit()
    return {"ok": True}


@router.post("/breach/scan/{email:path}")
def scan_one_email(
    email: str,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.BreachConfig).first()
    if not cfg or not cfg.enabled or not cfg.hibp_api_key:
        raise HTTPException(status_code=400, detail="Breach monitoring is not configured or enabled")
    result = breach_monitor.check_email(email.strip().lower(), cfg.hibp_api_key, db)
    return result


@router.post("/breach/scan-all")
def scan_all_emails(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    result = breach_monitor.run_full_scan(db)
    return result


# ── Serialisers ───────────────────────────────────────────────────────────────

def _employee_dict(e: models.EmployeeRiskScore) -> dict:
    return {
        "email":              e.email,
        "name":               e.name,
        "department":         e.department,
        "score":              e.score,
        "band":               e.band,
        "simulation_points":  e.simulation_points,
        "gateway_points":     e.gateway_points,
        "breach_points":      e.breach_points,
        "last_calculated_at": e.last_calculated_at.isoformat() if e.last_calculated_at else None,
        "last_breach_check":  e.last_breach_check.isoformat() if e.last_breach_check else None,
    }


def _breach_dict(b: models.BreachRecord) -> dict:
    return {
        "breach_name":      b.breach_name,
        "breach_date":      b.breach_date,
        "data_classes":     json.loads(b.data_classes or "[]"),
        "password_exposed": b.password_exposed,
        "severity":         b.severity,
        "recorded_at":      b.recorded_at.isoformat(),
    }


def _action_dict(a: models.RiskAction) -> dict:
    return {
        "email":         a.email,
        "action_type":   a.action_type,
        "trigger_band":  a.trigger_band,
        "trigger_score": a.trigger_score,
        "details":       json.loads(a.details_json or "{}"),
        "performed_at":  a.performed_at.isoformat(),
        "performed_by":  a.performed_by,
    }


def _gateway_config_dict(cfg: models.GatewayConfig) -> dict:
    return {
        "gateway_type":          cfg.gateway_type,
        "enabled":               cfg.enabled,
        "m365_tenant_id":        cfg.m365_tenant_id,
        "m365_client_id":        cfg.m365_client_id,
        "m365_client_secret":    "••••••" if cfg.m365_client_secret else "",
        "gws_admin_email":       cfg.gws_admin_email,
        "gws_service_account_json": "••••••" if cfg.gws_service_account_json else "",
        "pp_principal":          cfg.pp_principal,
        "pp_secret":             "••••••" if cfg.pp_secret else "",
        "pp_cluster_id":         cfg.pp_cluster_id,
        "mc_base_url":           cfg.mc_base_url,
        "mc_client_id":          cfg.mc_client_id,
        "mc_client_secret":      "••••••" if cfg.mc_client_secret else "",
        "syslog_port":           cfg.syslog_port,
        "syslog_format":         cfg.syslog_format,
        "pull_interval_minutes": cfg.pull_interval_minutes,
        "last_sync_at":          cfg.last_sync_at.isoformat() if cfg.last_sync_at else None,
        "last_sync_status":      cfg.last_sync_status,
        "last_error":            cfg.last_error,
    }
