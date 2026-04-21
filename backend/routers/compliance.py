"""
Compliance Reports Router
===========================
Endpoints:
  GET  /compliance/reports              — list generated reports (admin)
  POST /compliance/reports/generate     — generate new report (admin)
  GET  /compliance/reports/{id}         — get report summary (admin)
  GET  /compliance/reports/{id}/pdf     — download PDF (admin)
  GET  /compliance/frameworks           — list supported frameworks (auth)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

import models
from database import get_db
from routers.auth import require_auth, require_admin

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/compliance", tags=["compliance"])


FRAMEWORKS = {
    "iso27001": "ISO/IEC 27001:2022 — A.6.3 Awareness Training",
    "nist_csf": "NIST CSF 2.0 — PR.AT Awareness and Training",
    "soc2":     "SOC 2 Type II — CC1.4 Commitment to Competence",
    "gdpr":     "GDPR — Article 39 / Recital 78 DPO Awareness",
}


@router.get("/frameworks")
def list_frameworks(_: models.User = Depends(require_auth)):
    return [{"id": k, "name": v} for k, v in FRAMEWORKS.items()]


@router.get("/reports")
def list_reports(
    framework: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(models.ComplianceReport)
    if framework:
        q = q.filter_by(framework=framework)
    reports = q.order_by(models.ComplianceReport.generated_at.desc()).limit(limit).all()
    return [{
        "id":           r.id,
        "framework":    r.framework,
        "period_start": r.period_start.isoformat(),
        "period_end":   r.period_end.isoformat(),
        "generated_at": r.generated_at.isoformat(),
        "generated_by": r.generated_by,
        "status":       r.status,
    } for r in reports]


@router.post("/reports/generate")
def generate_report(
    payload: dict,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Generate a compliance report for a given framework and period.
    period_start and period_end are ISO datetime strings (or use preset periods).
    """
    framework = payload.get("framework", "iso27001")
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail=f"Unknown framework. Valid: {list(FRAMEWORKS.keys())}")

    # Parse period
    preset = payload.get("preset")  # last_quarter | last_month | last_year | custom
    if preset == "last_month":
        now = datetime.utcnow()
        period_end   = now.replace(day=1) - timedelta(days=1)
        period_start = period_end.replace(day=1)
    elif preset == "last_quarter":
        now = datetime.utcnow()
        quarter_start_month = ((now.month - 1) // 3) * 3 + 1
        period_start = now.replace(month=quarter_start_month, day=1) - timedelta(days=90)
        period_end   = now.replace(month=quarter_start_month, day=1) - timedelta(days=1)
    elif preset == "last_year":
        now = datetime.utcnow()
        period_start = datetime(now.year - 1, 1, 1)
        period_end   = datetime(now.year - 1, 12, 31, 23, 59, 59)
    else:
        # Custom dates
        try:
            period_start = datetime.fromisoformat(payload["period_start"])
            period_end   = datetime.fromisoformat(payload["period_end"])
        except Exception:
            raise HTTPException(status_code=400,
                                detail="Provide period_start and period_end as ISO datetime strings, or use preset=last_month|last_quarter|last_year")

    try:
        from compliance.reports import generate_report as _generate
        report = _generate(db, framework, period_start, period_end, generated_by=user.username)
        return {
            "id":       report.id,
            "status":   report.status,
            "framework": report.framework,
            "summary":  json.loads(report.summary),
        }
    except Exception as e:
        log.error(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{report_id}")
def get_report(
    report_id: int,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    report = db.query(models.ComplianceReport).filter_by(id=report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id":           report.id,
        "framework":    report.framework,
        "period_start": report.period_start.isoformat(),
        "period_end":   report.period_end.isoformat(),
        "generated_at": report.generated_at.isoformat(),
        "generated_by": report.generated_by,
        "status":       report.status,
        "summary":      json.loads(report.summary or "{}"),
    }
