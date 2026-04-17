from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# ── Target ───────────────────────────────────────────────────
class TargetCreate(BaseModel):
    email: str
    name: str
    department: str = "Unknown"

class TargetResponse(BaseModel):
    id: int
    email: str
    name: str
    department: str
    tracking_token: str
    created_at: datetime
    email_sent_at: Optional[datetime] = None
    send_failed:   bool = False
    send_error:    str  = ""
    model_config = {"from_attributes": True}


# ── Campaign ─────────────────────────────────────────────────
class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    subject: str
    body: str
    from_email: str
    from_name: str
    phishing_url: str = "http://localhost:8000"
    landing_page_theme: str = "corporate_sso"
    scheduled_at: Optional[datetime] = None
    auto_complete_hours: Optional[float] = None   # hours until auto-complete (after launch)

class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    from_email: Optional[str] = None
    from_name: Optional[str] = None
    phishing_url: Optional[str] = None
    landing_page_theme: Optional[str] = None
    status: Optional[str] = None
    scheduled_at: Optional[datetime] = None
    auto_complete_hours: Optional[float] = None

class CampaignResponse(BaseModel):
    id: int
    name: str
    description: str
    subject: str
    body: str
    from_email: str
    from_name: str
    phishing_url: str
    landing_page_theme: str
    status: str
    created_at: datetime
    launched_at: Optional[datetime]
    completed_at: Optional[datetime]
    scheduled_at: Optional[datetime] = None
    auto_complete_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class CampaignWithTargets(CampaignResponse):
    targets: List[TargetResponse] = []
    model_config = {"from_attributes": True}


# ── Tracking Event ────────────────────────────────────────────
class TrackingEventResponse(BaseModel):
    id: int
    target_id: int
    campaign_id: int
    event_type: str
    timestamp: datetime
    ip_address: str
    user_agent: str
    model_config = {"from_attributes": True}


# ── Analytics ────────────────────────────────────────────────
class FunnelStage(BaseModel):
    stage: str
    count: int
    percentage: float

class FunnelData(BaseModel):
    campaign_id: int
    campaign_name: str
    total_targets: int
    stages: List[FunnelStage]

class RiskyUser(BaseModel):
    email: str
    name: str
    department: str
    risk_score: int
    opens: int
    clicks: int
    submissions: int

class DepartmentStat(BaseModel):
    department: str
    sent: int
    opened: int
    clicked: int
    submitted: int
    click_rate: float
    submission_rate: float

class CampaignTrend(BaseModel):
    campaign_id: int
    campaign_name: str
    launched_at: Optional[datetime]
    total_targets: int
    open_rate: float
    click_rate: float
    submission_rate: float

class OverviewStats(BaseModel):
    total_campaigns: int
    active_campaigns: int
    total_targets: int
    total_events: int
    overall_open_rate: float
    overall_click_rate: float
    overall_submission_rate: float


# ── SMTP Config ───────────────────────────────────────────────
class SMTPConfigUpdate(BaseModel):
    host:       str  = ""
    port:       int  = 587
    username:   str  = ""
    password:   str  = ""   # empty string = keep existing password
    use_tls:    bool = True
    from_name:  str  = "IT Security Team"
    from_email: str  = ""
    base_url:   str  = "http://localhost:8000"  # public phishsim server URL

class SMTPConfigResponse(BaseModel):
    host:         str
    port:         int
    username:     str
    password:     str   # always returned masked
    use_tls:      bool
    from_name:    str
    from_email:   str
    is_configured: bool
    base_url:     str = "http://localhost:8000"
    model_config = {"from_attributes": True}


# ── LLM / AI Config ──────────────────────────────────────────
class LLMConfigUpdate(BaseModel):
    provider:   str = "ollama"               # anthropic | openai | ollama
    api_key:    str = ""                     # empty = keep existing
    model:      str = "llama3.2"
    ollama_url: str = "http://localhost:11434"

class LLMConfigResponse(BaseModel):
    provider:   str
    api_key:    str                          # always masked in response
    model:      str
    ollama_url: str
    is_configured: bool
    model_config = {"from_attributes": True}

class TemplateGenerateRequest(BaseModel):
    prompt:   str
    category: Optional[str] = None          # hint to steer the LLM
    # optional per-request overrides (use stored config if omitted)
    provider:   Optional[str] = None
    api_key:    Optional[str] = None
    model:      Optional[str] = None
    ollama_url: Optional[str] = None

class TemplateImportRequest(BaseModel):
    raw_text: str
    filename: Optional[str] = None          # hint for file type detection


# ── Campaign Schedule ─────────────────────────────────────────
class CampaignSchedule(BaseModel):
    scheduled_at: datetime
    auto_complete_hours: Optional[float] = None  # hours after launch to auto-complete


# ── Email Template ────────────────────────────────────────────
class TemplateCreate(BaseModel):
    name: str
    category: str = "General"
    subject: str
    body: str
    from_name: str
    from_email: str
    description: str = ""

class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    from_name: Optional[str] = None
    from_email: Optional[str] = None
    description: Optional[str] = None

class TemplateResponse(BaseModel):
    id: int
    name: str
    category: str
    subject: str
    body: str
    from_name: str
    from_email: str
    description: str
    is_builtin: bool
    created_at: datetime
    model_config = {"from_attributes": True}
