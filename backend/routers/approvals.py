"""
Campaign Approval Workflow Router
===================================
Handles the full approval lifecycle for campaigns.

Flow:
  1. Operator creates/configures a campaign
  2. Operator clicks "Submit for Approval"  → POST /approvals/submit/{campaign_id}
  3. System emails all configured approvers with one-click Approve/Reject links
  4. Approver clicks link → GET /approvals/decide/{token}?action=approve|reject
     (This endpoint is PUBLIC — no login required, token is the auth)
  5. System updates campaign status, notifies submitter, writes audit log

Endpoints:
  POST /approvals/submit/{campaign_id}   — submit a campaign for approval
  GET  /approvals/decide/{token}         — approver decision page (public)
  POST /approvals/decide/{token}         — process decision (public, token-auth)
  GET  /approvals/                       — list all approvals (admin/operator)
  GET  /approvals/config                 — get approval config (admin)
  POST /approvals/config                 — save approval config (admin)
  POST /approvals/verify-chain           — verify audit log chain (admin)
  GET  /audit-log                        — paginated audit log (admin)
  GET  /audit-log/export                 — export full log as JSON (admin)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import audit as audit_module
import models
import notifications
from database import get_db
from routers.auth import require_auth, require_admin, require_operator

log = logging.getLogger(__name__)
router = APIRouter(tags=["approvals"])


# ── Pydantic ──────────────────────────────────────────────────────────────────

class ApprovalConfigPayload(BaseModel):
    enabled:              bool = False
    approver_emails:      str  = ""   # comma-separated
    require_approval_for: str  = "all"
    auto_expire_hours:    int  = 72
    notify_on_decision:   bool = True


class DecisionPayload(BaseModel):
    action:   str  # approve | reject
    comments: str = ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_base_url(db: Session) -> str:
    cfg = db.query(models.SMTPConfig).first()
    if cfg and getattr(cfg, "base_url", ""):
        return cfg.base_url.rstrip("/")
    return "http://localhost:8000"


def _send_approval_emails(campaign: models.Campaign, approvals: list[models.CampaignApproval],
                           submitter: str, db: Session, base_url: str):
    """Send approval request emails to all configured approvers."""
    smtp_cfg = db.query(models.SMTPConfig).first()
    if not smtp_cfg or not smtp_cfg.host:
        log.warning("No SMTP configured — approval emails not sent.")
        return

    import smtplib, ssl
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    for approval in approvals:
        approve_url = f"{base_url}/approvals/decide/{approval.token}?action=approve"
        reject_url  = f"{base_url}/approvals/decide/{approval.token}?action=reject"

        html = f"""
        <div style="font-family:-apple-system,sans-serif;max-width:620px;margin:20px auto">
          <div style="background:#1F4E79;color:white;padding:24px 28px;border-radius:10px 10px 0 0">
            <h2 style="margin:0;font-size:20px">📋 Campaign Approval Required</h2>
            <p style="margin:6px 0 0;opacity:.8;font-size:14px">PhishSim Security Awareness Platform</p>
          </div>
          <div style="background:#f9fafb;padding:24px 28px;border:1px solid #e5e7eb;border-top:0">
            <p style="color:#374151">Hi {approval.approver_name or 'Approver'},</p>
            <p style="color:#374151"><strong>{submitter}</strong> has submitted a phishing simulation
               campaign for your review and approval.</p>
            <table style="width:100%;border-collapse:collapse;background:white;border:1px solid #e5e7eb;
                          border-radius:8px;margin:16px 0">
              <tr style="background:#f3f4f6"><td colspan="2" style="padding:10px 14px;font-weight:700;
                   font-size:13px;color:#374151">Campaign Details</td></tr>
              <tr><td style="padding:8px 14px;color:#6b7280;font-size:13px;width:140px">Name</td>
                  <td style="padding:8px 14px;font-size:13px;font-weight:600">{campaign.name}</td></tr>
              <tr style="background:#f9fafb">
                  <td style="padding:8px 14px;color:#6b7280;font-size:13px">Submitted by</td>
                  <td style="padding:8px 14px;font-size:13px">{submitter}</td></tr>
              <tr><td style="padding:8px 14px;color:#6b7280;font-size:13px">Submitted at</td>
                  <td style="padding:8px 14px;font-size:13px">{approval.submitted_at.strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
              <tr style="background:#f9fafb">
                  <td style="padding:8px 14px;color:#6b7280;font-size:13px">Expires</td>
                  <td style="padding:8px 14px;font-size:13px">{approval.expires_at.strftime('%Y-%m-%d %H:%M UTC') if approval.expires_at else 'Never'}</td></tr>
            </table>
            <p style="color:#374151;font-size:14px">Please review and take action:</p>
            <div style="display:flex;gap:12px;margin:20px 0">
              <a href="{approve_url}" style="background:#16a34a;color:white;text-decoration:none;
                 padding:12px 28px;border-radius:8px;font-weight:700;font-size:14px;
                 display:inline-block">✓ Approve Campaign</a>
              <a href="{reject_url}" style="background:#dc2626;color:white;text-decoration:none;
                 padding:12px 28px;border-radius:8px;font-weight:700;font-size:14px;
                 display:inline-block;margin-left:12px">✗ Reject Campaign</a>
            </div>
            <p style="font-size:12px;color:#9ca3af">This approval link expires in
               {db.query(models.ApprovalConfig).first().auto_expire_hours or 72} hours.
               If you have questions, contact the submitter directly.</p>
          </div>
        </div>"""

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[PhishSim] Approval Required: {campaign.name}"
            msg["From"]    = f"{smtp_cfg.from_name} <{smtp_cfg.from_email}>"
            msg["To"]      = approval.approver_email
            msg.attach(MIMEText(html, "html"))

            ctx = ssl.create_default_context() if smtp_cfg.use_tls else None
            with smtplib.SMTP(smtp_cfg.host, smtp_cfg.port, timeout=10) as s:
                if smtp_cfg.use_tls:
                    s.starttls(context=ctx)
                if smtp_cfg.username:
                    s.login(smtp_cfg.username, smtp_cfg.password)
                s.sendmail(smtp_cfg.from_email, [approval.approver_email], msg.as_string())

            log.info(f"Approval email sent to {approval.approver_email} for campaign {campaign.id}")
        except Exception as e:
            log.error(f"Failed to send approval email to {approval.approver_email}: {e}")


def _notify_submitter(campaign: models.Campaign, approval: models.CampaignApproval,
                      action: str, db: Session):
    """Email the campaign submitter when a decision is made."""
    if not approval.submitted_by:
        return
    submitter_user = db.query(models.User).filter_by(username=approval.submitted_by).first()
    if not submitter_user or not submitter_user.email:
        return

    action_word = "Approved ✓" if action == "approve" else "Rejected ✗"
    color       = "#16a34a" if action == "approve" else "#dc2626"
    msg_body    = (f"Your campaign has been approved and is ready to launch."
                   if action == "approve"
                   else f"Your campaign was rejected. Comments: {approval.comments or 'None provided.'}")

    notifications.send(
        db=db,
        event_type=f"approval.{action}d",
        title=f"Campaign {action_word}: {campaign.name}",
        message=msg_body,
        details={"campaign": campaign.name, "decided_by": approval.approver_email,
                 "comments": approval.comments or ""},
        severity="info" if action == "approve" else "warning",
        email_subject=f"[PhishSim] Campaign {action_word}: {campaign.name}",
        to_emails=[submitter_user.email],
    )


# ── Config endpoints ──────────────────────────────────────────────────────────

@router.get("/approvals/config")
def get_approval_config(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.ApprovalConfig).first()
    if not cfg:
        return {"enabled": False, "approver_emails": "", "require_approval_for": "all",
                "auto_expire_hours": 72, "notify_on_decision": True}
    return {
        "enabled":              cfg.enabled,
        "approver_emails":      cfg.approver_emails,
        "require_approval_for": cfg.require_approval_for,
        "auto_expire_hours":    cfg.auto_expire_hours,
        "notify_on_decision":   cfg.notify_on_decision,
    }


@router.post("/approvals/config")
def save_approval_config(
    payload: ApprovalConfigPayload,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.ApprovalConfig).first()
    if not cfg:
        cfg = models.ApprovalConfig()
        db.add(cfg)
    cfg.enabled              = payload.enabled
    cfg.approver_emails      = payload.approver_emails
    cfg.require_approval_for = payload.require_approval_for
    cfg.auto_expire_hours    = payload.auto_expire_hours
    cfg.notify_on_decision   = payload.notify_on_decision
    cfg.updated_at           = datetime.utcnow()
    audit_module.write(db, "settings.approval_config_updated", actor=user.username,
                       details={"enabled": payload.enabled})
    db.commit()
    return {"ok": True}


# ── Submit for approval ───────────────────────────────────────────────────────

@router.post("/approvals/submit/{campaign_id}")
def submit_for_approval(
    campaign_id: int,
    request: Request,
    user: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    campaign = db.query(models.Campaign).filter_by(id=campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status not in ("draft", "pending_approval"):
        raise HTTPException(status_code=400,
                            detail=f"Campaign is '{campaign.status}' — only drafts can be submitted for approval")

    cfg = db.query(models.ApprovalConfig).first()
    if not cfg or not cfg.enabled:
        raise HTTPException(status_code=400, detail="Approval workflow is not enabled. Configure it in Settings → Approvals.")

    approver_emails = [e.strip() for e in (cfg.approver_emails or "").split(",") if e.strip()]
    if not approver_emails:
        raise HTTPException(status_code=400, detail="No approvers configured. Add approver emails in Settings → Approvals.")

    # Expire any previous pending approvals for this campaign
    db.query(models.CampaignApproval).filter_by(
        campaign_id=campaign_id, status="pending"
    ).update({"status": "expired"})

    expire_dt = datetime.utcnow() + timedelta(hours=cfg.auto_expire_hours)
    approvals = []
    for email in approver_emails:
        approval = models.CampaignApproval(
            campaign_id    = campaign_id,
            approver_email = email,
            token          = models.CampaignApproval.generate_token(),
            status         = "pending",
            submitted_by   = user.username,
            expires_at     = expire_dt,
        )
        db.add(approval)
        approvals.append(approval)

    campaign.status = "pending_approval"
    audit_module.write(db, "campaign.submitted_for_approval", actor=user.username,
                       target_type="campaign", target_id=str(campaign_id),
                       details={"campaign_name": campaign.name,
                                "approvers": approver_emails},
                       ip_address=request.client.host if request.client else "")
    db.commit()

    base_url = _get_base_url(db)
    _send_approval_emails(campaign, approvals, user.username, db, base_url)

    notifications.send(
        db=db, event_type="campaign.approval_requested",
        title=f"Approval Required: {campaign.name}",
        message=f"{user.username} submitted campaign '{campaign.name}' for approval.",
        details={"campaign": campaign.name, "submitted_by": user.username},
        severity="info",
    )

    return {"ok": True, "approvers_notified": len(approvals), "expires_at": expire_dt.isoformat()}


# ── Decision page (PUBLIC — token auth only) ──────────────────────────────────

@router.get("/approvals/decide/{token}", response_class=HTMLResponse, include_in_schema=False)
def approval_decision_page(
    token: str,
    action: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Renders the decision confirmation page for the approver.
    If ?action=approve|reject is in the URL (from the email link), auto-submits.
    """
    approval = db.query(models.CampaignApproval).filter_by(token=token).first()
    campaign = None
    if approval:
        campaign = db.query(models.Campaign).filter_by(id=approval.campaign_id).first()

    # Auto-process if action is in query string (direct email link click)
    if action in ("approve", "reject") and approval and approval.status == "pending":
        result = _process_decision(approval, campaign, action, "", db)
        return HTMLResponse(_decision_result_page(
            campaign.name if campaign else "Unknown",
            action, approval.approver_email, result.get("message", "")
        ))

    if not approval:
        return HTMLResponse(_decision_error_page("Invalid or expired approval link."))
    if approval.status != "pending":
        return HTMLResponse(_decision_error_page(
            f"This approval request has already been {approval.status}."
        ))
    if approval.expires_at and datetime.utcnow() > approval.expires_at:
        approval.status = "expired"
        db.commit()
        return HTMLResponse(_decision_error_page("This approval link has expired."))

    return HTMLResponse(_decision_form_page(token, campaign))


@router.post("/approvals/decide/{token}", include_in_schema=False)
def process_decision(
    token: str,
    payload: DecisionPayload,
    db: Session = Depends(get_db),
):
    approval = db.query(models.CampaignApproval).filter_by(token=token).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Invalid approval token")
    if approval.status != "pending":
        raise HTTPException(status_code=400, detail=f"Already {approval.status}")
    if approval.expires_at and datetime.utcnow() > approval.expires_at:
        approval.status = "expired"
        db.commit()
        raise HTTPException(status_code=410, detail="Approval link has expired")

    campaign = db.query(models.Campaign).filter_by(id=approval.campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    return _process_decision(approval, campaign, payload.action, payload.comments, db)


def _process_decision(approval, campaign, action: str, comments: str, db: Session) -> dict:
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=422, detail="action must be 'approve' or 'reject'")

    approval.status     = "approved" if action == "approve" else "rejected"
    approval.decided_at = datetime.utcnow()
    approval.comments   = comments

    if campaign:
        if action == "approve":
            campaign.status = "draft"   # Ready to launch — operator can now click Launch
        else:
            campaign.status = "draft"   # Back to draft for revision

    audit_module.write(
        db, f"approval.{approval.status}", actor=approval.approver_email,
        target_type="campaign", target_id=str(approval.campaign_id),
        details={"campaign_name": campaign.name if campaign else "", "comments": comments},
    )
    db.commit()

    # Notify submitter
    if campaign:
        _notify_submitter(campaign, approval, action, db)

    return {
        "ok":      True,
        "status":  approval.status,
        "message": f"Campaign '{campaign.name if campaign else ''}' has been {approval.status}.",
    }


# ── List approvals ────────────────────────────────────────────────────────────

@router.get("/approvals/")
def list_approvals(
    status: Optional[str] = Query(None),
    limit:  int = Query(50, ge=1, le=200),
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    q = db.query(models.CampaignApproval)
    if status:
        q = q.filter_by(status=status)
    approvals = q.order_by(models.CampaignApproval.submitted_at.desc()).limit(limit).all()

    result = []
    for a in approvals:
        c = db.query(models.Campaign).filter_by(id=a.campaign_id).first()
        result.append({
            "id":             a.id,
            "campaign_id":    a.campaign_id,
            "campaign_name":  c.name if c else "—",
            "approver_email": a.approver_email,
            "status":         a.status,
            "submitted_by":   a.submitted_by,
            "submitted_at":   a.submitted_at.isoformat(),
            "decided_at":     a.decided_at.isoformat() if a.decided_at else None,
            "comments":       a.comments,
            "expires_at":     a.expires_at.isoformat() if a.expires_at else None,
        })
    return result


# ── Audit log endpoints ───────────────────────────────────────────────────────

@router.get("/audit-log")
def get_audit_log(
    page:   int = Query(1, ge=1),
    limit:  int = Query(100, ge=1, le=500),
    action: Optional[str] = Query(None),
    actor:  Optional[str] = Query(None),
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(models.AuditLog)
    if action:
        q = q.filter(models.AuditLog.action.ilike(f"%{action}%"))
    if actor:
        q = q.filter(models.AuditLog.actor.ilike(f"%{actor}%"))

    total = q.count()
    records = q.order_by(models.AuditLog.id.desc()).offset((page-1)*limit).limit(limit).all()

    return {
        "total": total,
        "page":  page,
        "limit": limit,
        "records": [{
            "id":          r.id,
            "action":      r.action,
            "actor":       r.actor,
            "target_type": r.target_type,
            "target_id":   r.target_id,
            "details":     json.loads(r.details or "{}"),
            "ip_address":  r.ip_address,
            "occurred_at": r.occurred_at.isoformat(),
            "record_hash": r.record_hash[:16] + "...",  # Truncated for display
        } for r in records]
    }


@router.post("/audit-log/verify")
def verify_audit_chain(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return audit_module.verify_chain(db)


@router.get("/audit-log/export")
def export_audit_log(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from fastapi.responses import JSONResponse
    records = db.query(models.AuditLog).order_by(models.AuditLog.id).all()
    return JSONResponse(content={
        "exported_at": datetime.utcnow().isoformat(),
        "total":       len(records),
        "records": [{
            "id":          r.id,
            "action":      r.action,
            "actor":       r.actor,
            "target_type": r.target_type,
            "target_id":   r.target_id,
            "details":     json.loads(r.details or "{}"),
            "ip_address":  r.ip_address,
            "occurred_at": r.occurred_at.isoformat(),
            "record_hash": r.record_hash,
            "prev_hash":   r.prev_hash,
        } for r in records]
    })


# ── Notification config endpoints ─────────────────────────────────────────────

@router.get("/notifications/config")
def get_notification_config(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.NotificationConfig).first()
    if not cfg:
        return {}
    return {
        "webhook_enabled":          cfg.webhook_enabled,
        "webhook_url":              cfg.webhook_url,
        "slack_enabled":            cfg.slack_enabled,
        "slack_webhook_url":        cfg.slack_webhook_url,
        "slack_channel":            cfg.slack_channel,
        "teams_enabled":            cfg.teams_enabled,
        "teams_webhook_url":        cfg.teams_webhook_url,
        "email_alerts_enabled":     cfg.email_alerts_enabled,
        "alert_emails":             cfg.alert_emails,
        "notify_campaign_launch":   cfg.notify_campaign_launch,
        "notify_campaign_complete": cfg.notify_campaign_complete,
        "notify_high_risk_employee":cfg.notify_high_risk_employee,
        "notify_breach_detected":   cfg.notify_breach_detected,
        "notify_approval_request":  cfg.notify_approval_request,
    }


@router.post("/notifications/config")
def save_notification_config(
    payload: dict,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = db.query(models.NotificationConfig).first()
    if not cfg:
        cfg = models.NotificationConfig()
        db.add(cfg)
    for k, v in payload.items():
        if hasattr(cfg, k):
            setattr(cfg, k, v)
    cfg.updated_at = datetime.utcnow()
    audit_module.write(db, "settings.notifications_updated", actor=user.username)
    db.commit()
    return {"ok": True}


@router.post("/notifications/test")
def test_notification(
    payload: dict,
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    result = notifications.send(
        db=db,
        event_type="system.test",
        title="PhishSim Test Notification",
        message="This is a test notification from PhishSim. Your notification channel is working correctly.",
        details={"source": "Manual test from Settings"},
        severity="info",
    )
    return result


# ── Page builders ─────────────────────────────────────────────────────────────

def _decision_form_page(token: str, campaign) -> str:
    name = campaign.name if campaign else "Campaign"
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Campaign Approval — PhishSim</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,sans-serif;background:#0f1117;color:#e2e8f0;
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.card{{background:#141720;border:1px solid #1e2232;border-radius:16px;padding:40px;max-width:520px;width:100%}}
h1{{font-size:22px;font-weight:800;margin-bottom:8px;color:#e2e8f0}}
.sub{{color:#64748b;font-size:14px;margin-bottom:24px;line-height:1.5}}
.campaign-name{{background:#1e2232;border-radius:8px;padding:14px 18px;font-weight:700;
               font-size:16px;color:#93c5fd;margin-bottom:24px}}
textarea{{width:100%;padding:12px;background:#0f1117;border:1px solid #1e2232;border-radius:8px;
          color:#e2e8f0;font-size:13px;font-family:inherit;resize:vertical;margin-bottom:16px}}
.actions{{display:flex;gap:12px}}
.btn{{padding:12px 28px;border:none;border-radius:8px;font-weight:700;font-size:14px;
      cursor:pointer;font-family:inherit;flex:1}}
.approve{{background:#16a34a;color:#fff}}
.reject{{background:#dc2626;color:#fff}}
</style></head><body>
<div class="card">
  <div style="font-size:40px;margin-bottom:16px">📋</div>
  <h1>Campaign Approval Request</h1>
  <p class="sub">You have been asked to review and approve or reject the following phishing simulation campaign before it launches.</p>
  <div class="campaign-name">📧 {name}</div>
  <textarea id="comments" rows="3" placeholder="Comments (required for rejection, optional for approval)"></textarea>
  <div class="actions">
    <button class="btn approve" onclick="decide('approve')">✓ Approve</button>
    <button class="btn reject"  onclick="decide('reject')">✗ Reject</button>
  </div>
</div>
<script>
async function decide(action) {{
  const comments = document.getElementById('comments').value;
  if (action === 'reject' && !comments.trim()) {{
    alert('Please provide a reason for rejection.');
    return;
  }}
  const r = await fetch('/approvals/decide/{token}', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{action,comments}})
  }});
  const d = await r.json();
  document.querySelector('.card').innerHTML = '<div style="text-align:center;padding:20px">'
    + (action==='approve'?'<div style="font-size:56px">✅</div><h2 style="color:#4ade80;margin:16px 0">Approved!</h2>':'<div style="font-size:56px">❌</div><h2 style="color:#f87171;margin:16px 0">Rejected</h2>')
    + '<p style="color:#94a3b8">' + (d.message||'Decision recorded.') + '</p></div>';
}}
</script></body></html>"""


def _decision_result_page(campaign_name: str, action: str,
                           approver: str, message: str) -> str:
    icon  = "✅" if action == "approve" else "❌"
    color = "#4ade80" if action == "approve" else "#f87171"
    word  = "Approved" if action == "approve" else "Rejected"
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>body{{font-family:-apple-system,sans-serif;background:#0f1117;color:#e2e8f0;
min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#141720;border:1px solid #1e2232;border-radius:16px;padding:48px;
max-width:480px;width:100%;text-align:center}}</style></head>
<body><div class="card">
<div style="font-size:64px;margin-bottom:20px">{icon}</div>
<h1 style="color:{color};font-size:24px;margin-bottom:8px">Campaign {word}</h1>
<p style="color:#94a3b8;font-size:14px;line-height:1.6">{message or ''}</p>
<p style="color:#475569;font-size:12px;margin-top:20px">Decision by {approver}</p>
</div></body></html>"""


def _decision_error_page(message: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>body{{font-family:-apple-system,sans-serif;background:#0f1117;color:#e2e8f0;
min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#141720;border:1px solid #dc2626;border-radius:16px;padding:48px;
max-width:480px;width:100%;text-align:center}}</style></head>
<body><div class="card">
<div style="font-size:56px;margin-bottom:16px">⚠️</div>
<h1 style="color:#f87171;font-size:20px;margin-bottom:8px">Approval Link Invalid</h1>
<p style="color:#94a3b8;font-size:14px">{message}</p>
</div></body></html>"""
