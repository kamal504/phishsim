import uuid
import secrets
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
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
    is_builtin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


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
