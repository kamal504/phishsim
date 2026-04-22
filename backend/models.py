import uuid
import secrets
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean, Float
from sqlalchemy.orm import relationship
from database import Base


def generate_token():
    return str(uuid.uuid4())


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    subject = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    from_email = Column(String, nullable=False)
    from_name = Column(String, nullable=False)
    phishing_url = Column(String, default="http://localhost:8000")
    landing_page_theme = Column(String, default="corporate_sso")  # microsoft_365 | hr_portal | finance_portal | executive_portal | delivery_portal | corporate_sso
    status = Column(String, default="draft")  # draft | active | paused | completed | scheduled
    tags   = Column(String, default="")       # comma-separated tags e.g. "Q1-2026,Finance"
    created_at = Column(DateTime, default=datetime.utcnow)
    launched_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    scheduled_at = Column(DateTime, nullable=True)      # when to auto-launch
    auto_complete_at = Column(DateTime, nullable=True)  # when to auto-complete

    targets = relationship("Target", back_populates="campaign", cascade="all, delete-orphan")
    events = relationship("TrackingEvent", back_populates="campaign", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    email = Column(String, nullable=False)
    name = Column(String, nullable=False)
    department = Column(String, default="Unknown")
    tracking_token = Column(String, unique=True, index=True, default=generate_token)
    created_at = Column(DateTime, default=datetime.utcnow)
    email_sent_at = Column(DateTime, nullable=True)   # when email was actually sent via SMTP
    send_failed   = Column(Boolean,  default=False)   # True if SMTP delivery failed
    send_error    = Column(String,   default="")      # error message from failed send

    campaign = relationship("Campaign", back_populates="targets")
    events = relationship("TrackingEvent", back_populates="target", cascade="all, delete-orphan")


class TrackingEvent(Base):
    __tablename__ = "tracking_events"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    event_type = Column(String, nullable=False)  # sent|delivered|opened|clicked|submitted|reported
    event_category = Column(String, default="behavioral")  # diagnostic | behavioral
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, default="")
    user_agent = Column(String, default="")
    extra_data = Column(Text, default="{}")

    target = relationship("Target", back_populates="events")
    campaign = relationship("Campaign", back_populates="events")


class SMTPConfig(Base):
    """Single-row table — stores SMTP gateway + infrastructure settings."""
    __tablename__ = "smtp_config"

    id         = Column(Integer, primary_key=True)
    host       = Column(String,  default="")
    port       = Column(Integer, default=587)
    username   = Column(String,  default="")
    password   = Column(String,  default="")   # stored plain-text (local app only)
    use_tls    = Column(Boolean, default=True)
    from_name  = Column(String,  default="IT Security Team")
    from_email = Column(String,  default="")
    is_configured = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow)
    # ── Infrastructure ────────────────────────────────────────
    base_url   = Column(String,  default="http://localhost:8000")  # public-facing server URL (ngrok/VPS)


class LLMConfig(Base):
    """Single-row table — stores the AI/LLM engine settings."""
    __tablename__ = "llm_config"

    id          = Column(Integer, primary_key=True)
    provider    = Column(String,  default="ollama")  # anthropic | openai | ollama
    api_key     = Column(String,  default="")        # plain-text, local app only
    model       = Column(String,  default="llama3.2")
    ollama_url  = Column(String,  default="http://localhost:11434")
    is_configured = Column(Boolean, default=False)
    updated_at  = Column(DateTime, default=datetime.utcnow)


class EmailTemplate(Base):
    __tablename__ = "email_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    category = Column(String, default="General")  # IT Security | HR | Finance | Executive | Delivery | General
    subject = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    from_name = Column(String, nullable=False)
    from_email = Column(String, nullable=False)
    description = Column(Text, default="")
    is_builtin  = Column(Boolean, default=False)
    difficulty  = Column(Integer, default=2)   # 1–5 difficulty score for adaptive selection
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow)


# Alias used by autonomy/threat_intel code — EmailTemplate is the canonical model
Template = EmailTemplate


# ── Auth ─────────────────────────────────────────────────────────────────────

class User(Base):
    """Application user with role-based access control."""
    __tablename__ = "users"

    id             = Column(Integer, primary_key=True, index=True)
    username       = Column(String, unique=True, nullable=False, index=True)
    email          = Column(String, default="")
    password_hash  = Column(String, nullable=False)
    role           = Column(String, default="viewer")  # admin | operator | viewer
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    last_login_at  = Column(DateTime, nullable=True)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """Session token issued on successful login. Expires after 8 hours."""
    __tablename__ = "user_sessions"

    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    token      = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")

    @staticmethod
    def generate():
        return secrets.token_hex(32)


# ═════════════════════════════════════════════════════════════════════════════
# RISK SCORING ENGINE
# Three-signal model: Simulation + Gateway Telemetry + Breach Intelligence
# ═════════════════════════════════════════════════════════════════════════════

class EmployeeRiskScore(Base):
    """
    Current aggregated risk score for each employee (keyed by email).
    Updated every time a new signal is recorded or the decay job runs.
    """
    __tablename__ = "employee_risk_scores"

    id                  = Column(Integer, primary_key=True)
    email               = Column(String, unique=True, nullable=False, index=True)
    name                = Column(String, default="")
    department          = Column(String, default="")
    score               = Column(Float, default=0.0)      # 0–100 normalised
    band                = Column(String, default="low")   # low | medium | high | critical
    # Component contributions (for transparency / audit)
    simulation_points   = Column(Float, default=0.0)
    gateway_points      = Column(Float, default=0.0)
    breach_points       = Column(Float, default=0.0)
    # Metadata
    last_calculated_at  = Column(DateTime, default=datetime.utcnow)
    last_decayed_at     = Column(DateTime, default=datetime.utcnow)
    last_breach_check   = Column(DateTime, nullable=True)
    created_at          = Column(DateTime, default=datetime.utcnow)

    signals = relationship("RiskSignal", back_populates="employee",
                           foreign_keys="RiskSignal.email",
                           primaryjoin="EmployeeRiskScore.email == RiskSignal.email",
                           cascade="all, delete-orphan")


class RiskSignal(Base):
    """
    Individual risk event that contributes to an employee's score.
    Each signal carries a weight, a source, and an optional expiry (for decay).

    Signal types:
    -- Simulation --
      simulation_click          +20   Employee clicked a phishing link in simulation
      simulation_submit         +40   Employee submitted credentials in simulation
      simulation_report         -15   Employee reported simulated phish
      training_complete         -10   Employee completed a training module

    -- Gateway --
      gateway_phish_volume      +5    High volume phishing received (>10/month)
      gateway_malware           +5    Malware email received (per incident)
      gateway_bec               +10   BEC/impersonation attack targeted at user
      gateway_real_click        +30   Clicked real malicious URL (gateway confirmed)
      gateway_real_report       -10   Reported real phishing to security team

    -- Breach --
      breach_recent             +35   Email in breach < 6 months old
      breach_medium             +20   Email in breach 6–12 months old
      breach_old                +10   Email in breach 1–2 years old
      breach_ancient            +5    Email in breach > 2 years old
      breach_password           +25   Password also found in breach data
    """
    __tablename__ = "risk_signals"

    id            = Column(Integer, primary_key=True)
    email         = Column(String, nullable=False, index=True)
    signal_type   = Column(String, nullable=False)   # see docstring above
    source        = Column(String, nullable=False)   # phishsim | microsoft365 | google | proofpoint | mimecast | syslog | hibp
    points        = Column(Float, nullable=False)    # positive = risk up, negative = risk down
    metadata_json = Column(Text, default="{}")       # JSON: campaign_id, breach_name, gateway_event_id, etc.
    recorded_at   = Column(DateTime, default=datetime.utcnow)
    expires_at    = Column(DateTime, nullable=True)  # NULL = never expires (breach records), else decays

    employee = relationship("EmployeeRiskScore",
                            foreign_keys=[email],
                            primaryjoin="RiskSignal.email == EmployeeRiskScore.email",
                            back_populates="signals")


class GatewayConfig(Base):
    """
    Optional email gateway integration configuration.
    Only one active gateway is expected per deployment (the organisation's email platform).
    All credential fields are stored encrypted (Fernet) when encryption is enabled.
    """
    __tablename__ = "gateway_config"

    id            = Column(Integer, primary_key=True)
    # Gateway type: microsoft365 | google_workspace | proofpoint | mimecast | syslog | none
    gateway_type  = Column(String, default="none")
    enabled       = Column(Boolean, default=False)
    # Microsoft 365 / Defender
    m365_tenant_id     = Column(String, default="")
    m365_client_id     = Column(String, default="")
    m365_client_secret = Column(String, default="")   # stored encrypted
    # Google Workspace
    gws_service_account_json = Column(Text, default="")  # stored encrypted
    gws_admin_email          = Column(String, default="")
    # Proofpoint
    pp_principal  = Column(String, default="")
    pp_secret     = Column(String, default="")         # stored encrypted
    pp_cluster_id = Column(String, default="s1")
    # Mimecast
    mc_base_url   = Column(String, default="")
    mc_client_id  = Column(String, default="")
    mc_client_secret = Column(String, default="")      # stored encrypted
    # Generic Syslog listener
    syslog_port   = Column(Integer, default=5140)
    syslog_format = Column(String, default="cef")      # cef | leef | json
    # Sync state
    pull_interval_minutes = Column(Integer, default=60)
    last_sync_at  = Column(DateTime, nullable=True)
    last_sync_status = Column(String, default="never")  # never | ok | error
    last_error    = Column(String, default="")
    updated_at    = Column(DateTime, default=datetime.utcnow)


class BreachConfig(Base):
    """
    Configuration for breach intelligence feed integration.
    Currently supports HaveIBeenPwned (HIBP) domain monitoring + Pwned Passwords.
    """
    __tablename__ = "breach_config"

    id                    = Column(Integer, primary_key=True)
    enabled               = Column(Boolean, default=False)
    hibp_api_key          = Column(String, default="")   # stored encrypted
    check_frequency_days  = Column(Integer, default=7)   # how often to re-check all employees
    check_passwords       = Column(Boolean, default=True)  # also check Pwned Passwords (k-anonymity, free)
    alert_on_new_breach   = Column(Boolean, default=True)
    last_full_check_at    = Column(DateTime, nullable=True)
    last_check_status     = Column(String, default="never")
    last_error            = Column(String, default="")
    updated_at            = Column(DateTime, default=datetime.utcnow)


class BreachRecord(Base):
    """
    Individual breach event associated with an employee email.
    Persisted to avoid re-scoring the same breach repeatedly.
    """
    __tablename__ = "breach_records"

    id               = Column(Integer, primary_key=True)
    email            = Column(String, nullable=False, index=True)
    breach_name      = Column(String, nullable=False)         # e.g. "LinkedIn", "Adobe2013"
    breach_date      = Column(String, nullable=True)          # ISO date string from HIBP
    data_classes     = Column(Text, default="[]")             # JSON: ["Email addresses","Passwords",...]
    password_exposed = Column(Boolean, default=False)         # True if Passwords in data_classes
    severity         = Column(String, default="medium")       # recent | medium | old | ancient
    recorded_at      = Column(DateTime, default=datetime.utcnow)


class RiskAction(Base):
    """
    Automated or manual actions triggered by risk threshold crossings.
    Records what was done and its outcome — part of the audit trail.
    """
    __tablename__ = "risk_actions"

    id           = Column(Integer, primary_key=True)
    email        = Column(String, nullable=False, index=True)
    action_type  = Column(String, nullable=False)
    # action_type values:
    #   training_enrolled   — auto-enrolled in training module
    #   escalation_sent     — email sent to security team / CISO
    #   breach_alert_sent   — breach notification sent to admin
    #   score_reviewed      — manual review by security team
    trigger_band = Column(String, nullable=False)   # the band that triggered this action
    trigger_score= Column(Float, nullable=False)
    details_json = Column(Text, default="{}")
    performed_at = Column(DateTime, default=datetime.utcnow)
    performed_by = Column(String, default="system")  # system | username


# ═════════════════════════════════════════════════════════════════════════════
# CAMPAIGN APPROVAL WORKFLOW
# ═════════════════════════════════════════════════════════════════════════════

class CampaignApproval(Base):
    """
    Approval request for a campaign before it is allowed to launch.
    Supports multi-approver: one record per approver per campaign submission.

    Lifecycle:
      pending → approved  (approver clicks approve link)
      pending → rejected  (approver clicks reject link)
      pending → expired   (no decision after 72 hours)
    """
    __tablename__ = "campaign_approvals"

    id              = Column(Integer, primary_key=True)
    campaign_id     = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    approver_email  = Column(String, nullable=False)
    approver_name   = Column(String, default="")
    token           = Column(String, unique=True, nullable=False, index=True)  # one-time decision token
    status          = Column(String, default="pending")  # pending | approved | rejected | expired
    submitted_by    = Column(String, default="")          # username who submitted
    submitted_at    = Column(DateTime, default=datetime.utcnow)
    decided_at      = Column(DateTime, nullable=True)
    comments        = Column(Text, default="")            # approver's comments on reject
    expires_at      = Column(DateTime, nullable=True)

    @staticmethod
    def generate_token():
        return secrets.token_urlsafe(32)


class ApprovalConfig(Base):
    """
    Global approval workflow configuration.
    Stores who receives approval requests and policy settings.
    """
    __tablename__ = "approval_config"

    id                      = Column(Integer, primary_key=True)
    enabled                 = Column(Boolean, default=False)
    approver_emails         = Column(Text, default="")  # comma-separated emails
    require_approval_for    = Column(String, default="all")  # all | ai_generated | manual
    auto_expire_hours       = Column(Integer, default=72)
    notify_on_decision      = Column(Boolean, default=True)  # notify submitter on approve/reject
    updated_at              = Column(DateTime, default=datetime.utcnow)


# ═════════════════════════════════════════════════════════════════════════════
# TAMPER-PROOF AUDIT LOG
# Hash-chain: each record stores SHA-256(prev_hash + timestamp + action + details)
# Any modification to a past record breaks the chain — detectable immediately.
# ═════════════════════════════════════════════════════════════════════════════

class AuditLog(Base):
    """
    Append-only cryptographic audit log.
    Every security-relevant action is recorded here with a hash linking
    it to all previous records.

    Action types:
      auth.login              auth.logout             auth.login_failed
      auth.password_changed   auth.user_created       auth.user_deactivated
      campaign.created        campaign.launched       campaign.paused
      campaign.resumed        campaign.completed      campaign.deleted
      campaign.submitted_for_approval
      approval.approved       approval.rejected       approval.expired
      target.imported         target.deleted
      settings.smtp_updated   settings.smtp_tested
      risk.signal_recorded    risk.escalation_sent
      breach.detected         breach.scan_run
      gateway.synced
      system.startup          system.config_changed
    """
    __tablename__ = "audit_log"

    id          = Column(Integer, primary_key=True)
    action      = Column(String, nullable=False, index=True)
    actor       = Column(String, nullable=False)          # username or "system"
    target_type = Column(String, default="")              # campaign | user | target | system
    target_id   = Column(String, default="")              # ID of affected record
    details     = Column(Text, default="{}")              # JSON with relevant context
    ip_address  = Column(String, default="")
    occurred_at = Column(DateTime, default=datetime.utcnow, index=True)
    record_hash = Column(String, nullable=False)          # SHA-256 of chain
    prev_hash   = Column(String, default="0" * 64)        # hash of previous record


# ═════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CONFIG
# ═════════════════════════════════════════════════════════════════════════════

class NotificationConfig(Base):
    """
    Webhook / Slack / Teams notification configuration.
    """
    __tablename__ = "notification_config"

    id                  = Column(Integer, primary_key=True)
    # Webhook
    webhook_enabled     = Column(Boolean, default=False)
    webhook_url         = Column(String, default="")
    webhook_secret      = Column(String, default="")   # HMAC secret for payload signing
    # Slack
    slack_enabled       = Column(Boolean, default=False)
    slack_webhook_url   = Column(String, default="")   # Slack Incoming Webhook URL
    slack_channel       = Column(String, default="")
    # Microsoft Teams
    teams_enabled       = Column(Boolean, default=False)
    teams_webhook_url   = Column(String, default="")
    # Email alerts
    email_alerts_enabled = Column(Boolean, default=False)
    alert_emails        = Column(Text, default="")     # comma-separated
    # Event subscriptions (which events trigger notifications)
    notify_campaign_launch    = Column(Boolean, default=True)
    notify_campaign_complete  = Column(Boolean, default=True)
    notify_high_risk_employee = Column(Boolean, default=True)
    notify_breach_detected    = Column(Boolean, default=True)
    notify_approval_request   = Column(Boolean, default=True)
    updated_at          = Column(DateTime, default=datetime.utcnow)



# ═════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═════════════════════════════════════════════════════════════════════════════

class ThreatIntelConfig(Base):
    """Global threat intelligence feed configuration."""
    __tablename__ = "threat_intel_config"

    id                  = Column(Integer, primary_key=True)
    enabled             = Column(Boolean, default=False)
    # Feed credentials
    otx_api_key         = Column(String, default="")    # AlienVault OTX
    phishtank_api_key   = Column(String, default="")    # PhishTank (optional)
    openai_api_key      = Column(String, default="")    # GPT-4o template generation
    # Sync settings
    sync_interval_hours = Column(Integer, default=6)
    last_synced_at      = Column(DateTime, nullable=True)
    # Feed toggles
    feed_openphish      = Column(Boolean, default=True)
    feed_urlhaus        = Column(Boolean, default=True)
    feed_otx            = Column(Boolean, default=False)
    feed_phishtank      = Column(Boolean, default=False)
    updated_at          = Column(DateTime, default=datetime.utcnow)


class ThreatIndicator(Base):
    """
    A single threat intelligence indicator (IOC) from a feed.
    Types: url | domain | ip | hash | email | other
    """
    __tablename__ = "threat_indicators"

    id            = Column(Integer, primary_key=True)
    ioc_type      = Column(String, nullable=False, index=True)   # url | domain | ip | hash
    value         = Column(String, nullable=False)               # the actual IOC value
    feed          = Column(String, nullable=False, index=True)   # openphish | urlhaus | otx | phishtank
    threat_type   = Column(String, default="phishing")           # phishing | malware | ransomware | bec
    tags          = Column(Text, default="[]")                   # JSON list of tags
    metadata_json = Column(Text, default="{}")                   # arbitrary feed-specific metadata
    ioc_hash      = Column(String, unique=True, index=True)      # SHA-256(type:value) deduplicate key
    first_seen    = Column(DateTime, default=datetime.utcnow)
    last_seen     = Column(DateTime, default=datetime.utcnow, index=True)
    hit_count     = Column(Integer, default=1)
    active        = Column(Boolean, default=True, index=True)


class GeneratedTemplate(Base):
    """
    AI/blueprint generated phishing template based on threat intel trends.
    Separate from the Template table so curated templates are not mixed.
    """
    __tablename__ = "generated_templates"

    id            = Column(Integer, primary_key=True)
    name          = Column(String, nullable=False)
    category      = Column(String, default="credential_harvest")
    subject       = Column(String, nullable=False)
    body          = Column(Text, nullable=False)
    difficulty    = Column(Integer, default=3)   # 1–5
    tags          = Column(Text, default="[]")
    generated_by  = Column(String, default="blueprint")   # blueprint | gpt-4o-mini
    created_at    = Column(DateTime, default=datetime.utcnow)
    promoted      = Column(Boolean, default=False)  # True = promoted to Template library
    intel_trends  = Column(Text, default="{}")       # snapshot of trends at generation time


# ═════════════════════════════════════════════════════════════════════════════
# GAMIFICATION
# ═════════════════════════════════════════════════════════════════════════════

class EmployeeBadge(Base):
    """
    Achievement badges awarded to employees based on their security behaviour.
    Badges are awarded by the autonomy engine when thresholds are met.
    """
    __tablename__ = "employee_badges"

    id          = Column(Integer, primary_key=True)
    email       = Column(String, nullable=False, index=True)
    badge_type  = Column(String, nullable=False)  # see BADGE_TYPES below
    awarded_at  = Column(DateTime, default=datetime.utcnow)
    campaign_id = Column(Integer, nullable=True)   # which campaign triggered the badge
    notes       = Column(String, default="")


# Badge type catalogue:
# "first_report"        — reported first phishing email
# "five_reports"        — reported 5 phishing emails
# "clean_month"         — no clicks for 30 days
# "training_graduate"   — completed all training modules
# "perfect_quarter"     — 0 clicks + 2+ reports in 90 days
# "risk_reducer"        — reduced risk band (e.g. high → medium)
# "early_detector"      — reported within 5 minutes of delivery


class SecurityLeaderboard(Base):
    """
    Monthly security awareness leaderboard snapshot.
    Refreshed by the autonomy engine at the start of each month.
    """
    __tablename__ = "security_leaderboard"

    id              = Column(Integer, primary_key=True)
    period          = Column(String, nullable=False, index=True)  # "2026-04" (YYYY-MM)
    email           = Column(String, nullable=False)
    name            = Column(String, default="")
    department      = Column(String, default="")
    score           = Column(Float, default=0.0)   # lower risk = higher leaderboard score
    badges_count    = Column(Integer, default=0)
    reports_count   = Column(Integer, default=0)
    clicks_count    = Column(Integer, default=0)
    training_count  = Column(Integer, default=0)
    rank            = Column(Integer, default=0)
    created_at      = Column(DateTime, default=datetime.utcnow)


# ═════════════════════════════════════════════════════════════════════════════
# AUTONOMY ENGINE — CAMPAIGN PROPOSALS
# ═════════════════════════════════════════════════════════════════════════════

class CampaignProposal(Base):
    """
    Autonomously generated campaign proposal created by the autonomy engine.
    A proposal is a fully-configured draft campaign waiting for operator review.
    """
    __tablename__ = "campaign_proposals"

    id              = Column(Integer, primary_key=True)
    name            = Column(String, nullable=False)
    rationale       = Column(Text, default="")       # why this campaign was proposed
    trigger_type    = Column(String, default="")     # threat_intel | risk_band | schedule | breach
    trigger_detail  = Column(Text, default="{}")     # JSON with trigger context
    template_id     = Column(Integer, nullable=True)
    suggested_targets = Column(Text, default="{}")   # JSON: {department: str, band: str}
    difficulty      = Column(Integer, default=3)
    status          = Column(String, default="pending")  # pending | accepted | rejected | launched
    created_at      = Column(DateTime, default=datetime.utcnow)
    reviewed_at     = Column(DateTime, nullable=True)
    reviewed_by     = Column(String, default="")
    campaign_id     = Column(Integer, nullable=True)  # set when accepted + campaign created


# ═════════════════════════════════════════════════════════════════════════════
# TRAINING ENROLMENTS
# Tracks which employees have been enrolled in which training modules,
# either by the autonomy engine (auto-enrol) or manually by an operator.
# ═════════════════════════════════════════════════════════════════════════════

class TrainingEnrolment(Base):
    """Employee training module enrolment record."""
    __tablename__ = "training_enrolments"

    id           = Column(Integer, primary_key=True)
    email        = Column(String, nullable=False, index=True)
    module_id    = Column(String, nullable=False)    # e.g. "phishing_basics"
    module_title = Column(String, default="")
    trigger      = Column(String, default="")         # simulation_click | manual | risk_band
    status       = Column(String, default="enrolled") # enrolled | in_progress | completed | skipped
    enrolled_at  = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


# ═════════════════════════════════════════════════════════════════════════════
# REPORT-PHISHING MAILBOX INTEGRATION
# Polls a dedicated "report phishing" mailbox to automatically capture
# employee reporting events without requiring manual button-clicks.
# Supports IMAP (standard) and Microsoft Graph API (M365/Exchange Online).
# ═════════════════════════════════════════════════════════════════════════════

class MailboxConfig(Base):
    """
    Configuration for the dedicated report-phishing mailbox integration.
    Supports two adapter types: IMAP (standard) and Microsoft Graph API (M365).
    Only one configuration row is expected per deployment.
    """
    __tablename__ = "mailbox_config"

    id              = Column(Integer, primary_key=True)
    enabled         = Column(Boolean, default=False)
    adapter_type    = Column(String, default="imap")    # imap | graph
    display_name    = Column(String, default="Report Phishing Mailbox")
    # IMAP settings
    imap_host       = Column(String, default="")
    imap_port       = Column(Integer, default=993)
    imap_username   = Column(String, default="")
    imap_password   = Column(String, default="")        # stored encrypted
    imap_use_ssl    = Column(Boolean, default=True)
    imap_folder     = Column(String, default="INBOX")
    # Microsoft Graph API settings
    graph_tenant_id     = Column(String, default="")
    graph_client_id     = Column(String, default="")
    graph_client_secret = Column(String, default="")    # stored encrypted
    graph_mailbox_email = Column(String, default="")    # shared mailbox email address
    # Polling settings
    poll_interval_minutes  = Column(Integer, default=5)
    delete_after_process   = Column(Boolean, default=False)
    mark_read_after_process = Column(Boolean, default=True)
    # State tracking
    last_poll_at     = Column(DateTime, nullable=True)
    last_poll_status = Column(String, default="never")  # never | ok | error
    last_error       = Column(String, default="")
    updated_at       = Column(DateTime, default=datetime.utcnow)


class MailboxPollLog(Base):
    """
    Log entry for each mailbox poll run — tracks how many emails were
    processed, matched to campaign targets, and skipped as unrelated.
    """
    __tablename__ = "mailbox_poll_log"

    id              = Column(Integer, primary_key=True)
    polled_at       = Column(DateTime, default=datetime.utcnow, index=True)
    adapter_type    = Column(String, default="imap")
    emails_checked  = Column(Integer, default=0)
    emails_matched  = Column(Integer, default=0)     # matched to a campaign target → reported event fired
    emails_skipped  = Column(Integer, default=0)     # could not match to any active campaign
    status          = Column(String, default="ok")   # ok | error | partial
    error_message   = Column(String, default="")
