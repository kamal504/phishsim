"""
Email matcher — maps an inbound "report phishing" email to a campaign target.

Strategy (in order):
  1. Look for a tracking token embedded in the forwarded email's headers
     (X-PhishSim-Token) or in the email body as a hidden link anchor.
  2. Match on the From/Reply-To address of the ORIGINAL phishing email
     (extracted from the forwarded body) against active campaign targets.
  3. Match on Subject similarity if no direct address match.

Returns (target, campaign) or (None, None) if no match found.
"""
import logging
import re
from typing import Optional, Tuple

from sqlalchemy.orm import Session
import models
import encryption

log = logging.getLogger(__name__)

# Pattern to find embedded tracking token in forwarded body
_TOKEN_PATTERN = re.compile(r'[?&]token=([a-f0-9\-]{32,36})', re.IGNORECASE)

# Pattern to find email addresses in forwarded text
_EMAIL_PATTERN = re.compile(r'[\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}')


def match_reported_email(
    db: Session,
    raw_subject: str,
    raw_body: str,
    reporter_email: str,
    headers: dict = None,
) -> Tuple[Optional[models.Target], Optional[models.Campaign]]:
    """
    Attempt to match an inbound report-phishing email to a campaign target.

    Parameters
    ----------
    db             : DB session
    raw_subject    : Subject line of the reported email (forwarded email subject)
    raw_body       : Plain-text or HTML body of the reported email
    reporter_email : Email address of the person who forwarded the report
    headers        : Optional dict of email headers from the forwarded message

    Returns
    -------
    (target, campaign) if matched, (None, None) otherwise
    """
    headers = headers or {}

    # ── Strategy 1: Tracking token in headers ────────────────────────────────
    token = headers.get("x-phishsim-token") or headers.get("X-PhishSim-Token")
    if token:
        target = db.query(models.Target).filter(models.Target.tracking_token == token).first()
        if target:
            campaign = db.query(models.Campaign).filter(models.Campaign.id == target.campaign_id).first()
            log.info(f"Mailbox: matched via header token {token[:8]}... → target {target.id}")
            return target, campaign

    # ── Strategy 2: Tracking token in body ───────────────────────────────────
    body_text = raw_body or ""
    token_matches = _TOKEN_PATTERN.findall(body_text)
    for tm in token_matches:
        target = db.query(models.Target).filter(models.Target.tracking_token == tm).first()
        if target:
            campaign = db.query(models.Campaign).filter(models.Campaign.id == target.campaign_id).first()
            log.info(f"Mailbox: matched via body token {tm[:8]}... → target {target.id}")
            return target, campaign

    # ── Strategy 3: Match reporter email to active campaign targets ───────────
    # The person who reports IS the target — find them in active campaigns
    if reporter_email:
        reporter_enc = None
        # Search targets by comparing decrypted emails against reporter_email
        active_campaign_ids = [
            c.id for c in db.query(models.Campaign).filter(
                models.Campaign.status.in_(["active", "paused"])
            ).all()
        ]
        if active_campaign_ids:
            candidates = db.query(models.Target).filter(
                models.Target.campaign_id.in_(active_campaign_ids)
            ).all()
            reporter_lower = reporter_email.strip().lower()
            for t in candidates:
                try:
                    decrypted = encryption.decrypt(t.email).lower()
                except Exception:
                    decrypted = t.email.lower()
                if decrypted == reporter_lower:
                    campaign = db.query(models.Campaign).filter(models.Campaign.id == t.campaign_id).first()
                    log.info(f"Mailbox: matched via reporter email {reporter_email} → target {t.id}")
                    return t, campaign

    # ── Strategy 4: Extract original sender from forwarded body and match ─────
    # Forwarded emails often contain "From: phish@company.com" in the body
    emails_in_body = _EMAIL_PATTERN.findall(body_text)
    if emails_in_body:
        # Skip the reporter's own email
        candidate_emails = [e.lower() for e in emails_in_body if e.lower() != reporter_email.lower()]
        active_campaign_ids = [
            c.id for c in db.query(models.Campaign).filter(
                models.Campaign.status.in_(["active", "paused"])
            ).all()
        ]
        if active_campaign_ids:
            for candidate in candidate_emails:
                targets = db.query(models.Target).filter(
                    models.Target.campaign_id.in_(active_campaign_ids)
                ).all()
                for t in targets:
                    try:
                        decrypted = encryption.decrypt(t.email).lower()
                    except Exception:
                        decrypted = t.email.lower()
                    if decrypted == candidate:
                        campaign = db.query(models.Campaign).filter(models.Campaign.id == t.campaign_id).first()
                        log.info(f"Mailbox: matched via body email {candidate} → target {t.id}")
                        return t, campaign

    log.debug(f"Mailbox: no match for reporter={reporter_email}, subject={raw_subject[:60]}")
    return None, None


def fire_reported_event(db: Session, target: models.Target, campaign: models.Campaign) -> bool:
    """
    Fire a 'reported' TrackingEvent for the target if one doesn't already exist.
    Also updates the employee risk score via simulation_report signal.
    Returns True if a new event was created, False if already reported.
    """
    existing = db.query(models.TrackingEvent).filter(
        models.TrackingEvent.target_id == target.id,
        models.TrackingEvent.event_type == "reported",
    ).first()
    if existing:
        return False

    db.add(models.TrackingEvent(
        target_id=target.id,
        campaign_id=campaign.id,
        event_type="reported",
    ))
    db.flush()

    # Fire risk signal
    try:
        from risk_engine.core import record_signal
        try:
            email = encryption.decrypt(target.email)
        except Exception:
            email = target.email
        record_signal(db, email, "simulation_report", weight=-5.0,
                      context={"campaign_id": campaign.id, "source": "mailbox"})
    except Exception as e:
        log.warning(f"Mailbox: could not record risk signal: {e}")

    db.commit()
    log.info(f"Mailbox: reported event fired for target {target.id} in campaign {campaign.id}")
    return True
