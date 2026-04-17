"""
Settings router — SMTP gateway + infrastructure configuration.

  GET  /api/settings/smtp                -> current config (password masked)
  PUT  /api/settings/smtp                -> save / update config (incl. base_url)
  POST /api/settings/smtp/test           -> verify SMTP connection
  POST /api/settings/smtp/send/{id}      -> send phishing emails for a campaign
  GET  /api/settings/smtp/preview/{id}   -> rendered HTML preview of email
  GET  /api/settings/infra               -> infrastructure info (base_url, scheduler)
"""
import smtplib
import ssl
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from database import get_db
from routers.auth import require_auth, require_operator, require_admin
import models
import schemas

router = APIRouter(prefix="/api/settings", tags=["settings"])

MASK = "••••••••"

# Injected by main.py after import
SCHEDULER_AVAILABLE: bool = False


# ── Helpers ───────────────────────────────────────────────────

def _get_config(db: Session) -> models.SMTPConfig:
    cfg = db.query(models.SMTPConfig).first()
    if not cfg:
        cfg = models.SMTPConfig()
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _effective_base_url(cfg: models.SMTPConfig) -> str:
    """Return the configured public base URL, falling back to localhost."""
    return (cfg.base_url or "http://localhost:8000").rstrip("/")


_PRIVATE_IP_RE = __import__("re").compile(
    r"^(localhost|127\.|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|"
    r"169\.254\.|::1|fc00:|fd[0-9a-f]{2}:)",
    __import__("re").IGNORECASE,
)

def _check_ssrf(host: str):
    """Block SMTP hosts that point to internal/private networks (CVE-6 SSRF fix)."""
    import socket
    h = host.strip().lower()
    if _PRIVATE_IP_RE.match(h):
        raise HTTPException(status_code=400,
            detail=f"SMTP host '{host}' resolves to a private/internal address. Use a public SMTP server.")
    # Resolve and check the actual IP
    try:
        ip = socket.gethostbyname(h)
        if _PRIVATE_IP_RE.match(ip):
            raise HTTPException(status_code=400,
                detail=f"SMTP host '{host}' resolves to internal IP {ip}. Use a public SMTP server.")
    except HTTPException:
        raise
    except Exception:
        pass  # DNS resolution failure is handled during actual connection


def _smtp_connect(cfg: models.SMTPConfig):
    """Open an authenticated SMTP connection. Caller must close it."""
    _check_ssrf(cfg.host)
    context = ssl.create_default_context()
    server = smtplib.SMTP(cfg.host, cfg.port, timeout=15)
    server.ehlo()
    if cfg.use_tls:
        server.starttls(context=context)
        server.ehlo()
    server.login(cfg.username, cfg.password)
    return server


def _build_email_html(campaign: models.Campaign, target: models.Target, base_url: str) -> str:
    """
    Convert a campaign body (plain text with {{placeholders}}) into a
    styled HTML email, injecting per-target tracking URLs built from
    the global base_url.

    Supported placeholders:
      {{name}}                      — target's display name
      {{phishing_link}}             — CTA button with default text
      {{phishing_link|Custom Text}} — CTA button with custom anchor text
      {{tracking_pixel}}            — invisible 1×1 open-tracking pixel

    Security: body text is HTML-escaped before rendering (CVE-2 / XSS fix).
    Placeholders are replaced AFTER escaping to preserve their HTML output.
    """
    import re
    import html as _html

    base = base_url.rstrip("/")
    click_url = f"{base}/track/click/{target.tracking_token}"
    pixel_url = f"{base}/track/pixel/{target.tracking_token}"

    # ── Step 1: extract placeholders, replace with safe sentinels ────────────
    # This lets us HTML-escape the body text without mangling our placeholder HTML
    LINK_SENTINEL  = "\x00PHISHLINK\x00"
    PIXEL_SENTINEL = "\x00PIXEL\x00"
    NAME_SENTINEL  = "\x00NAME\x00"

    body = campaign.body
    body = body.replace("{{name}}", NAME_SENTINEL)
    body = re.sub(r'\{\{phishing_link(?:\|([^}]+))?\}\}',
                  lambda m: f"\x00PHISHLINK:{m.group(1) or ''}\x00", body)
    body = body.replace("{{tracking_pixel}}", PIXEL_SENTINEL)

    # ── Step 2: HTML-escape all remaining text (CVE-2 fix) ───────────────────
    body = _html.escape(body)

    # ── Step 3: restore placeholder HTML ────────────────────────────────────
    body = body.replace(_html.escape(NAME_SENTINEL), _html.escape(target.name))

    def _restore_link(match):
        raw_text = match.group(1) or ""
        anchor_text = _html.escape(raw_text.strip()) if raw_text.strip() else "Click here to verify your account"
        return (
            f'<a href="{click_url}" '
            f'style="display:inline-block;background:#0067b8;color:#ffffff !important;'
            f'padding:11px 24px;border-radius:4px;text-decoration:none;'
            f'font-weight:600;font-size:14px;letter-spacing:0.01em;'
            f'border:1px solid #005a9e;mso-padding-alt:11px 24px">'
            f'{anchor_text}</a>'
        )

    body = re.sub(r'\x00PHISHLINK:(.*?)\x00', _restore_link, body)
    body = body.replace(
        PIXEL_SENTINEL,
        f'<img src="{pixel_url}" width="1" height="1" style="display:none" alt="">',
    )

    body_html = body.replace("\r\n", "\n").replace("\n", "<br>")
    safe_from_name = _html.escape(campaign.from_name)
    safe_email     = _html.escape(target.email)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
             font-size:14px;color:#1f2937;background:#f9fafb;margin:0;padding:0">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f9fafb;padding:32px 0">
    <tr><td align="center">
      <table width="580" cellpadding="0" cellspacing="0"
             style="background:#ffffff;border-radius:8px;
                    box-shadow:0 1px 8px rgba(0,0,0,.1);overflow:hidden">
        <tr>
          <td style="background:#1e293b;padding:16px 32px">
            <span style="color:#f1f5f9;font-size:14px;font-weight:600">{safe_from_name}</span>
          </td>
        </tr>
        <tr>
          <td style="padding:32px;line-height:1.7;color:#374151">{body_html}</td>
        </tr>
        <tr>
          <td style="padding:16px 32px;background:#f8fafc;border-top:1px solid #e2e8f0;
                     font-size:11px;color:#9ca3af;text-align:center">
            This email was sent to {safe_email}.
            If you believe this is an error, contact IT Support.
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────

@router.get("/smtp", response_model=schemas.SMTPConfigResponse)
def get_smtp_config(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """Return current SMTP + infrastructure settings. Password is always masked."""
    cfg = _get_config(db)
    return schemas.SMTPConfigResponse(
        host=cfg.host,
        port=cfg.port,
        username=cfg.username,
        password=MASK if cfg.password else "",
        use_tls=cfg.use_tls,
        from_name=cfg.from_name,
        from_email=cfg.from_email,
        is_configured=cfg.is_configured,
        base_url=cfg.base_url or "http://localhost:8000",
    )


@router.put("/smtp")
def save_smtp_config(data: schemas.SMTPConfigUpdate, _: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    """Persist SMTP + infrastructure settings."""
    cfg = _get_config(db)
    cfg.host       = data.host.strip()
    cfg.port       = data.port
    cfg.username   = data.username.strip()
    cfg.use_tls    = data.use_tls
    cfg.from_name  = data.from_name.strip()
    cfg.from_email = data.from_email.strip()
    cfg.base_url   = (data.base_url or "http://localhost:8000").rstrip("/")
    cfg.updated_at = datetime.utcnow()

    # Only overwrite password if a real new value was submitted
    if data.password and data.password != MASK:
        cfg.password = data.password

    cfg.is_configured = bool(
        cfg.host and cfg.username and cfg.password and cfg.from_email
    )
    db.commit()
    return {
        "status": "saved",
        "is_configured": cfg.is_configured,
        "base_url": cfg.base_url,
    }


@router.get("/infra")
def get_infra(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """Return infrastructure-only info (base_url, scheduler status) for the UI."""
    cfg = _get_config(db)
    base = cfg.base_url or "http://localhost:8000"
    return {
        "base_url": base,
        "scheduler_available": SCHEDULER_AVAILABLE,
        "is_localhost": ("localhost" in base or "127.0.0.1" in base),
    }


@router.post("/smtp/test")
def test_smtp_connection(_: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    """Open a real SMTP connection to verify stored credentials work."""
    cfg = _get_config(db)
    if not cfg.is_configured:
        raise HTTPException(
            status_code=400,
            detail="SMTP is not fully configured. Save host, username, password, and from email first.",
        )
    try:
        server = _smtp_connect(cfg)
        server.quit()
        return {
            "status": "success",
            "message": f"Connected to {cfg.host}:{cfg.port} — authenticated as {cfg.username} ✅",
        }
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(
            status_code=400,
            detail=f"Authentication failed — check your username and password for {cfg.host}.",
        )
    except smtplib.SMTPConnectError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Could not connect to {cfg.host}:{cfg.port}. Check host and port. ({e})",
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Connection error: {str(e)}")


@router.post("/smtp/send/{campaign_id}")
def send_campaign_emails(
    campaign_id: int,
    retry_failed: bool = False,
    _: models.User = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """
    Send phishing emails to targets using stored SMTP config.

    Idempotency rules (enforced by default, cannot be overridden):
      - Targets with email_sent_at already set are ALWAYS skipped — one email per target, ever.
      - retry_failed=True additionally re-attempts targets where send_failed=True.

    Tracking URLs are built from the global base_url in infrastructure settings.
    """
    cfg = _get_config(db)
    if not cfg.is_configured:
        raise HTTPException(
            status_code=400,
            detail="SMTP gateway is not configured. Go to Settings first.",
        )

    campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    if campaign.status != "active":
        raise HTTPException(
            status_code=400,
            detail="Campaign must be Active before sending emails.",
        )

    all_targets = db.query(models.Target).filter(models.Target.campaign_id == campaign_id).all()
    if not all_targets:
        raise HTTPException(status_code=400, detail="No targets found for this campaign.")

    # ── Idempotency: never send twice to the same target ────────
    # Always skip targets that already have email_sent_at populated.
    # Optionally include targets that previously failed (retry_failed=True).
    targets = [
        t for t in all_targets
        if t.email_sent_at is None and (not t.send_failed or retry_failed)
    ]
    already_sent_count = sum(1 for t in all_targets if t.email_sent_at is not None)

    if not targets:
        return {
            "status": "skipped",
            "sent_count": 0,
            "failed_count": 0,
            "skipped_count": already_sent_count,
            "sent": [],
            "failed": [],
            "base_url_used": _effective_base_url(cfg),
            "message": (
                f"All {already_sent_count} target(s) already received this email. "
                "No duplicates sent. Use retry_failed=true to retry failures."
            ),
        }

    # Always use the global base_url for tracking links
    base_url = _effective_base_url(cfg)

    sent, failed = [], []

    try:
        server = _smtp_connect(cfg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not open SMTP connection: {str(e)}")

    # Throttling config (CVE-6 fix — prevents SMTP account suspension)
    import time as _time
    send_delay  = float(getattr(cfg, "send_delay_seconds", 1.5))   # seconds between sends
    max_per_min = int(getattr(cfg, "max_per_minute", 30))          # hard cap per minute
    sent_this_minute = 0
    minute_start = _time.time()

    try:
        for target in targets:
            # Per-minute rate cap
            now_t = _time.time()
            if now_t - minute_start >= 60:
                sent_this_minute = 0
                minute_start = now_t
            if sent_this_minute >= max_per_min:
                sleep_for = 60 - (now_t - minute_start)
                if sleep_for > 0:
                    _time.sleep(sleep_for)
                sent_this_minute = 0
                minute_start = _time.time()

            try:
                from email.mime.multipart import MIMEMultipart
                from email.mime.text import MIMEText

                msg = MIMEMultipart("alternative")
                msg["Subject"]  = campaign.subject
                msg["From"]     = f"{campaign.from_name} <{campaign.from_email}>"
                msg["To"]       = target.email
                msg["X-Mailer"] = "PhishSim/2.1"

                html_body = _build_email_html(campaign, target, base_url)
                msg.attach(MIMEText(html_body, "html"))

                server.sendmail(cfg.from_email, target.email, msg.as_string())
                sent.append(target.email)
                sent_this_minute += 1

                now = datetime.utcnow()
                target.email_sent_at = now
                target.send_failed   = False
                target.send_error    = ""

                for et in ("sent", "delivered"):
                    existing = db.query(models.TrackingEvent).filter(
                        models.TrackingEvent.target_id == target.id,
                        models.TrackingEvent.event_type == et,
                    ).first()
                    if not existing:
                        db.add(models.TrackingEvent(
                            target_id=target.id,
                            campaign_id=campaign_id,
                            event_type=et,
                            timestamp=now,
                        ))
                db.commit()

                # Throttle delay between sends
                if send_delay > 0:
                    _time.sleep(send_delay)

            except Exception as e:
                err_msg = str(e)[:250]
                failed.append({"email": target.email, "error": err_msg})
                target.send_failed = True
                target.send_error  = err_msg
                db.commit()
    finally:
        try:
            server.quit()
        except Exception:
            pass

    return {
        "status": "done",
        "sent_count":    len(sent),
        "failed_count":  len(failed),
        "skipped_count": already_sent_count,
        "sent":   sent,
        "failed": failed,
        "base_url_used": base_url,
        "message": (
            f"Sent to {len(sent)} target(s) using {base_url}."
            + (f" {already_sent_count} already-sent target(s) skipped." if already_sent_count else "")
            + (f" {len(failed)} failed — check the errors list." if failed else "")
        ),
    }


@router.post("/smtp/test-email/{campaign_id}")
def send_test_email(campaign_id: int, _: models.User = Depends(require_operator), db: Session = Depends(get_db)):
    """
    Send a single test email to the configured SMTP from_email address
    so the sender can verify rendering and delivery before launching.
    """
    cfg = _get_config(db)
    if not cfg.is_configured:
        raise HTTPException(status_code=400, detail="SMTP gateway is not configured.")

    campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found.")

    base_url = _effective_base_url(cfg)

    # Create a synthetic target for preview purposes
    preview_target = models.Target(
        id=0,
        campaign_id=campaign_id,
        email=cfg.from_email,
        name="[Test Recipient]",
        department="IT",
        tracking_token="test-preview-000",
    )

    try:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        server = _smtp_connect(cfg)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[TEST] {campaign.subject}"
        msg["From"]    = f"{campaign.from_name} <{campaign.from_email}>"
        msg["To"]      = cfg.from_email
        msg["X-Mailer"] = "PhishSim/2.0-TestMode"

        html_body = _build_email_html(campaign, preview_target, base_url)
        # Add a visible test banner at the top
        test_banner = (
            '<div style="background:#fef3c7;border:2px solid #f59e0b;border-radius:6px;'
            'padding:10px 16px;margin-bottom:16px;font-size:13px;color:#92400e">'
            '🧪 <strong>TEST EMAIL</strong> — This is a preview sent to yourself. '
            'Tracking links point to real URLs but are labelled [TEST].</div>'
        )
        html_body = html_body.replace("<body", "<body").replace(
            '<td style="padding:32px',
            f'<td style="padding:32px'
        )
        # Inject banner after body opening
        html_body = html_body.replace(
            '<td style="padding:32px;line-height:1.7;color:#374151">',
            f'<td style="padding:32px;line-height:1.7;color:#374151">{test_banner}'
        )

        msg.attach(MIMEText(html_body, "html"))
        server.sendmail(cfg.from_email, cfg.from_email, msg.as_string())
        server.quit()

        return {
            "status": "success",
            "message": f"Test email sent to {cfg.from_email} — check your inbox.",
            "sent_to": cfg.from_email,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send test email: {str(e)}")


@router.get("/smtp/preview/{campaign_id}", response_class=HTMLResponse)
def preview_campaign_email(campaign_id: int, _: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """Rendered HTML preview of the phishing email (uses global base_url)."""
    campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    cfg = _get_config(db)
    base_url = _effective_base_url(cfg)

    target = db.query(models.Target).filter(models.Target.campaign_id == campaign_id).first()
    if not target:
        target = models.Target(
            id=0,
            campaign_id=campaign_id,
            email="recipient@example.com",
            name="John Doe",
            department="IT",
            tracking_token="preview-token-000",
        )

    html = _build_email_html(campaign, target, base_url)
    return HTMLResponse(content=html)
