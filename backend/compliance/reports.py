"""
Compliance Report Generator
==============================
Generates structured security awareness compliance reports mapped to
major security frameworks:

  - ISO 27001 (A.7.2.2 — Information security awareness, education and training)
  - NIST CSF (PR.AT — Awareness and Training)
  - SOC 2 Type II (CC1.4 — Training and Awareness)
  - GDPR Article 39 (Data protection awareness)

Reports include:
  - Programme metrics (campaigns run, employees tested, click/report rates)
  - Risk score distribution and trend over the period
  - Training completion statistics
  - Breach intelligence summary
  - Remediation actions taken
  - Framework-specific control mapping

Output: JSON summary stored in ComplianceReport table.
        PDF generation is triggered via the PDF skill from the API layer.

Usage:
    from compliance.reports import generate_report
    report = generate_report(db, "iso27001",
                              period_start=datetime(2026,1,1),
                              period_end=datetime(2026,3,31))
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

import models

log = logging.getLogger(__name__)


# ── Framework control mappings ────────────────────────────────────────────────

FRAMEWORK_CONTROLS = {
    "iso27001": {
        "title":       "ISO/IEC 27001:2022",
        "clause":      "A.6.3 — Information security awareness, education and training",
        "requirement": (
            "All personnel and, where relevant, contractors shall receive appropriate "
            "awareness education and training and regular updates in organizational "
            "policies and procedures, as relevant for their job function."
        ),
        "evidence_items": [
            "Phishing simulation campaigns conducted",
            "Employee click-through and reporting rates",
            "Risk score distribution before/after training",
            "Training module completion records",
            "Incident response to credential exposure",
        ],
    },
    "nist_csf": {
        "title":       "NIST Cybersecurity Framework 2.0",
        "clause":      "PR.AT — Awareness and Training",
        "requirement": (
            "PR.AT-01: All users are informed and trained. "
            "PR.AT-02: Individuals with privileged access to systems and data receive role-based awareness. "
            "PR.AT-03: Third-party stakeholders are aware of their cybersecurity responsibilities. "
            "PR.AT-04: Senior executives understand cybersecurity roles, responsibilities, and risk."
        ),
        "evidence_items": [
            "Regular phishing simulation programme",
            "Role-based training for privileged users",
            "Measurable awareness metrics (click rates, report rates)",
            "Automated risk scoring and threshold alerting",
            "Breach intelligence integration for real-world relevance",
        ],
    },
    "soc2": {
        "title":       "SOC 2 Type II",
        "clause":      "CC1.4 — Commitment to Competence",
        "requirement": (
            "The entity demonstrates a commitment to attract, develop, and retain competent "
            "individuals in alignment with objectives. Security awareness training demonstrates "
            "management's commitment to maintaining appropriate security competencies."
        ),
        "evidence_items": [
            "Documented phishing simulation programme with measurable outcomes",
            "Employee training records with completion tracking",
            "Risk-based targeting of highest-risk employees",
            "Automated alerting for high-risk behaviour patterns",
        ],
    },
    "gdpr": {
        "title":       "GDPR — Article 39 / Recital 78",
        "clause":      "Article 39(1)(b) — DPO Training and Awareness Tasks",
        "requirement": (
            "The data protection officer shall, with due regard for risk associated with processing "
            "operations, promote a data protection culture within the organisation, including "
            "through training and awareness of staff involved in processing operations."
        ),
        "evidence_items": [
            "Regular simulation of social engineering attacks targeting personal data",
            "Training focused on data protection obligations",
            "Risk scoring of employees with access to personal data",
            "Breach detection and rapid awareness response",
        ],
    },
}


# ── Metric calculators ────────────────────────────────────────────────────────

def _get_campaign_metrics(db: Session, since: datetime, until: datetime) -> dict:
    campaigns = db.query(models.Campaign).filter(
        models.Campaign.launched_at >= since,
        models.Campaign.launched_at <= until,
    ).all()

    total_campaigns = len(campaigns)
    total_targets = 0
    total_clicks  = 0
    total_submits = 0
    total_reports = 0
    total_opens   = 0

    for c in campaigns:
        targets = db.query(models.Target).filter_by(campaign_id=c.id).count()
        total_targets += targets
        events = db.query(models.TrackingEvent).filter_by(campaign_id=c.id).all()
        event_types = [e.event_type for e in events]
        total_opens   += event_types.count("opened")
        total_clicks  += event_types.count("clicked")
        total_submits += event_types.count("submitted")
        total_reports += event_types.count("reported")

    click_rate  = round((total_clicks / total_targets * 100), 1) if total_targets else 0
    submit_rate = round((total_submits / total_targets * 100), 1) if total_targets else 0
    report_rate = round((total_reports / total_targets * 100), 1) if total_targets else 0

    return {
        "campaigns_run":     total_campaigns,
        "employees_tested":  total_targets,
        "phishing_emails_sent": total_targets,
        "opens":             total_opens,
        "clicks":            total_clicks,
        "credential_submissions": total_submits,
        "phishing_reports":  total_reports,
        "click_rate_pct":    click_rate,
        "submit_rate_pct":   submit_rate,
        "report_rate_pct":   report_rate,
        "open_rate_pct":     round((total_opens / total_targets * 100), 1) if total_targets else 0,
    }


def _get_risk_metrics(db: Session) -> dict:
    employees = db.query(models.EmployeeRiskScore).all()
    if not employees:
        return {"total_employees_scored": 0, "band_distribution": {}, "avg_score": 0}

    band_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_score = 0
    for e in employees:
        band_dist[e.band] = band_dist.get(e.band, 0) + 1
        total_score += e.score

    return {
        "total_employees_scored": len(employees),
        "band_distribution":      band_dist,
        "avg_score":              round(total_score / len(employees), 1),
        "high_critical_count":    band_dist["critical"] + band_dist["high"],
        "high_critical_pct":      round((band_dist["critical"] + band_dist["high"]) / len(employees) * 100, 1),
    }


def _get_training_metrics(db: Session, since: datetime, until: datetime) -> dict:
    if not hasattr(models, "TrainingEnrolment"):
        return {"enrolled": 0, "completed": 0, "completion_rate_pct": 0}

    enrolled  = db.query(models.TrainingEnrolment).filter(
        models.TrainingEnrolment.enrolled_at >= since,
        models.TrainingEnrolment.enrolled_at <= until,
    ).count()
    completed = db.query(models.TrainingEnrolment).filter(
        models.TrainingEnrolment.enrolled_at >= since,
        models.TrainingEnrolment.enrolled_at <= until,
        models.TrainingEnrolment.status == "completed",
    ).count()
    return {
        "enrolled":              enrolled,
        "completed":             completed,
        "completion_rate_pct":   round((completed / enrolled * 100), 1) if enrolled else 0,
    }


def _get_breach_metrics(db: Session, since: datetime, until: datetime) -> dict:
    if not hasattr(models, "BreachRecord"):
        return {"breaches_detected": 0, "employees_affected": 0}
    breaches = db.query(models.BreachRecord).filter(
        models.BreachRecord.id > 0  # all records — BreachRecord has no timestamp
    ).count()
    affected = db.query(func.count(func.distinct(models.BreachRecord.email))).scalar() or 0
    return {
        "breaches_detected": breaches,
        "employees_with_breached_credentials": affected,
    }


# ── Report generator ──────────────────────────────────────────────────────────

def generate_report(
    db: Session,
    framework: str,
    period_start: datetime,
    period_end:   datetime,
    generated_by: str = "system",
) -> models.ComplianceReport:
    """
    Generate a compliance report for the given framework and period.
    Stores the report in the ComplianceReport table and returns it.
    """
    if framework not in FRAMEWORK_CONTROLS:
        raise ValueError(f"Unknown framework: {framework}. Valid: {list(FRAMEWORK_CONTROLS.keys())}")

    ctrl     = FRAMEWORK_CONTROLS[framework]
    campaign = _get_campaign_metrics(db, period_start, period_end)
    risk     = _get_risk_metrics(db)
    training = _get_training_metrics(db, period_start, period_end)
    breach   = _get_breach_metrics(db, period_start, period_end)

    # Compliance assessment
    awareness_score = _calculate_awareness_score(campaign, risk, training)
    compliance_status = (
        "Compliant"        if awareness_score >= 75 else
        "Partially Compliant" if awareness_score >= 50 else
        "Non-Compliant"
    )

    summary = {
        "framework":           framework,
        "framework_title":     ctrl["title"],
        "clause":              ctrl["clause"],
        "requirement":         ctrl["requirement"],
        "evidence_items":      ctrl["evidence_items"],
        "period": {
            "start": period_start.isoformat(),
            "end":   period_end.isoformat(),
        },
        "programme_metrics":   campaign,
        "risk_metrics":        risk,
        "training_metrics":    training,
        "breach_metrics":      breach,
        "awareness_score":     awareness_score,
        "compliance_status":   compliance_status,
        "generated_at":        datetime.utcnow().isoformat(),
        "generated_by":        generated_by,
    }

    report = models.ComplianceReport(
        framework     = framework,
        period_start  = period_start,
        period_end    = period_end,
        generated_by  = generated_by,
        summary       = json.dumps(summary, default=str),
        status        = "ready",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    log.info(f"Compliance report generated: {framework} ({period_start.date()} – {period_end.date()})")
    return report


def _calculate_awareness_score(campaign: dict, risk: dict, training: dict) -> int:
    """
    Calculate an overall programme awareness score 0–100.
    Used for compliance status assessment.
    """
    score = 0

    # Campaigns run (max 30 pts)
    if campaign["campaigns_run"] >= 4:   score += 30
    elif campaign["campaigns_run"] >= 2: score += 20
    elif campaign["campaigns_run"] >= 1: score += 10

    # Click rate improvement (max 30 pts)
    click_rate = campaign.get("click_rate_pct", 100)
    if click_rate <= 5:    score += 30
    elif click_rate <= 15: score += 20
    elif click_rate <= 30: score += 10

    # Report rate (max 20 pts)
    report_rate = campaign.get("report_rate_pct", 0)
    if report_rate >= 20:  score += 20
    elif report_rate >= 10: score += 15
    elif report_rate >= 5:  score += 8

    # Training completion (max 20 pts)
    # ARC-04 fix: only award training points when there is actual evidence of
    # training being delivered (i.e., at least one employee was enrolled).
    # If no enrolment records exist for the period, this component scores 0
    # rather than inflating the awareness score with phantom data.
    enrolled   = training.get("enrolled", 0)
    completion = training.get("completion_rate_pct", 0) if enrolled > 0 else 0
    if completion >= 80:   score += 20
    elif completion >= 50: score += 12
    elif completion >= 20: score += 6

    return min(100, score)
