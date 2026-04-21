"""
Notification Layer — Slack / Teams / Webhook / Email Alerts
============================================================
Sends structured notifications on key platform events.
All channels are optional and independently configurable.

Supported channels:
  - Slack (Incoming Webhook)
  - Microsoft Teams (Incoming Webhook / Power Automate)
  - Generic Webhook (HMAC-SHA256 signed JSON payload)
  - Email (via configured SMTP)

Event types:
  campaign.launched       campaign.completed      campaign.approval_requested
  approval.approved       approval.rejected
  risk.high_employee      risk.critical_employee  breach.detected
  system.error
"""

import hashlib
import hmac
import json
import logging
import smtplib
import ssl
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from sqlalchemy.orm import Session

import models

log = logging.getLogger(__name__)


# ── Payload builder ───────────────────────────────────────────────────────────

def _build_payload(event_type: str, title: str, message: str,
                   details: dict | None = None, severity: str = "info") -> dict:
    return {
        "source":     "PhishSim",
        "event_type": event_type,
        "severity":   severity,        # info | warning | critical
        "title":      title,
        "message":    message,
        "details":    details or {},
        "timestamp":  datetime.utcnow().isoformat() + "Z",
    }


# ── Slack ─────────────────────────────────────────────────────────────────────

def _send_slack(webhook_url: str, payload: dict) -> bool:
    COLORS = {"info": "#2E75B6", "warning": "#f59e0b", "critical": "#dc2626"}
    color = COLORS.get(payload["severity"], "#2E75B6")
    body = {
        "attachments": [{
            "color":  color,
            "title":  payload["title"],
            "text":   payload["message"],
            "footer": "PhishSim",
            "ts":     int(datetime.utcnow().timestamp()),
            "fields": [
                {"title": k, "value": str(v), "short": True}
                for k, v in (payload.get("details") or {}).items()
            ],
        }]
    }
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status < 300
    except Exception as e:
        log.error(f"Slack notification error: {e}")
        return False


# ── Microsoft Teams ───────────────────────────────────────────────────────────

def _send_teams(webhook_url: str, payload: dict) -> bool:
    THEME = {"info": "0078D4", "warning": "F59E0B", "critical": "DC2626"}
    color = THEME.get(payload["severity"], "0078D4")
    facts = [{"name": k, "value": str(v)} for k, v in (payload.get("details") or {}).items()]
    body = {
        "@type":      "MessageCard",
        "@context":   "https://schema.org/extensions",
        "themeColor": color,
        "summary":    payload["title"],
        "sections":   [{
            "activityTitle":    f"**{payload['title']}**",
            "activitySubtitle": payload["message"],
            "facts":            facts,
        }],
    }
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status < 300
    except Exception as e:
        log.error(f"Teams notification error: {e}")
        return False


# ── Generic Webhook (HMAC signed) ─────────────────────────────────────────────

def _send_webhook(url: str, secret: str, payload: dict) -> bool:
    data = json.dumps(payload, default=str).encode()
    sig = ""
    if secret:
        sig = hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(
            url, data=data,
            headers={
                "Content-Type":       "application/json",
                "X-PhishSim-Event":   payload["event_type"],
                "X-PhishSim-Sig256":  sig,
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status < 300
    except Exception as e:
        log.error(f"Webhook notification error: {e}")
        return False


# ── Email alert ───────────────────────────────────────────────────────────────

def _send_email_alert(db: Session, to_emails: list[str],
                      subject: str, html_body: str) -> bool:
    smtp_cfg = db.query(models.SMTPConfig).first()
    if not smtp_cfg or not smtp_cfg.host:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{smtp_cfg.from_name} <{smtp_cfg.from_email}>"
        msg["To"]      = ", ".join(to_emails)
        msg.attach(MIMEText(html_body, "html"))

        ctx = ssl.create_default_context() if smtp_cfg.use_tls else None
        with smtplib.SMTP(smtp_cfg.host, smtp_cfg.port, timeout=10) as s:
            if smtp_cfg.use_tls:
                s.starttls(context=ctx)
            if smtp_cfg.username:
                s.login(smtp_cfg.username, smtp_cfg.password)
            s.sendmail(smtp_cfg.from_email, to_emails, msg.as_string())
        return True
    except Exception as e:
        log.error(f"Email alert error: {e}")
        return False


# ── Main dispatch function ────────────────────────────────────────────────────

def send(
    db: Session,
    event_type: str,
    title: str,
    message: str,
    details: dict | None = None,
    severity: str = "info",
    email_subject: Optional[str] = None,
    email_html: Optional[str] = None,
    to_emails: Optional[list[str]] = None,
) -> dict:
    """
    Dispatch a notification to all configured and subscribed channels.
    Returns a dict summarising which channels were notified.
    """
    cfg = db.query(models.NotificationConfig).first()
    if not cfg:
        return {"sent": []}

    # Check if this event type is subscribed
    subscription_map = {
        "campaign.launched":          cfg.notify_campaign_launch,
        "campaign.completed":         cfg.notify_campaign_complete,
        "campaign.approval_requested":cfg.notify_approval_request,
        "approval.approved":          cfg.notify_approval_request,
        "approval.rejected":          cfg.notify_approval_request,
        "risk.high_employee":         cfg.notify_high_risk_employee,
        "risk.critical_employee":     cfg.notify_high_risk_employee,
        "breach.detected":            cfg.notify_breach_detected,
    }

    if event_type in subscription_map and not subscription_map[event_type]:
        return {"sent": [], "skipped": "event not subscribed"}

    payload = _build_payload(event_type, title, message, details, severity)
    sent = []

    if cfg.slack_enabled and cfg.slack_webhook_url:
        if _send_slack(cfg.slack_webhook_url, payload):
            sent.append("slack")

    if cfg.teams_enabled and cfg.teams_webhook_url:
        if _send_teams(cfg.teams_webhook_url, payload):
            sent.append("teams")

    if cfg.webhook_enabled and cfg.webhook_url:
        if _send_webhook(cfg.webhook_url, cfg.webhook_secret or "", payload):
            sent.append("webhook")

    if cfg.email_alerts_enabled:
        recipients = to_emails or [e.strip() for e in (cfg.alert_emails or "").split(",") if e.strip()]
        if recipients:
            subj  = email_subject or f"[PhishSim] {title}"
            body  = email_html    or _default_email_html(title, message, details, severity)
            if _send_email_alert(db, recipients, subj, body):
                sent.append("email")

    return {"sent": sent}


def _default_email_html(title: str, message: str,
                         details: dict | None, severity: str) -> str:
    COLORS = {"info": "#2E75B6", "warning": "#f59e0b", "critical": "#dc2626"}
    color = COLORS.get(severity, "#2E75B6")
    rows = "".join(
        f"<tr><td style='padding:4px 8px;color:#555;font-size:13px'>{k}</td>"
        f"<td style='padding:4px 8px;font-size:13px'>{v}</td></tr>"
        for k, v in (details or {}).items()
    )
    return f"""
    <div style="font-family:-apple-system,sans-serif;max-width:600px;margin:20px auto">
      <div style="background:{color};color:white;padding:20px 28px;border-radius:10px 10px 0 0">
        <h2 style="margin:0;font-size:18px">{title}</h2>
      </div>
      <div style="background:#f9fafb;padding:24px 28px;border:1px solid #e5e7eb;border-top:0;border-radius:0 0 10px 10px">
        <p style="margin:0 0 16px;color:#374151">{message}</p>
        {f'<table style="width:100%;border-collapse:collapse;background:white;border-radius:6px;border:1px solid #e5e7eb"><tbody>{rows}</tbody></table>' if rows else ''}
        <p style="margin:16px 0 0;font-size:11px;color:#9ca3af">Sent by PhishSim · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
      </div>
    </div>"""
