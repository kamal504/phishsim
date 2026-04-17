"""
AI router — LLM-powered template generation and email import/parsing.

Supported providers:
  • Anthropic Claude  (cloud, API key required)
  • OpenAI GPT        (cloud, API key required)
  • Ollama            (local, free, no API key)

  GET  /api/ai/config           → current LLM config (key masked)
  PUT  /api/ai/config           → save LLM config
  POST /api/ai/test             → test LLM connection
  GET  /api/ai/ollama-models    → list models installed in local Ollama
  POST /api/ai/generate         → generate template from plain-text prompt
  POST /api/ai/import-text      → parse pasted email text → template fields
  POST /api/ai/import-file      → parse uploaded file     → template fields
"""
import json
import re
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from database import get_db
from routers.auth import require_auth, require_operator, require_admin
import models
import schemas

router = APIRouter(prefix="/api/ai", tags=["ai"])

MASK = "••••••••"

# ── Provider model catalogues ─────────────────────────────────
PROVIDER_MODELS = {
    "anthropic": [
        "claude-opus-4-6",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
    ],
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-3.5-turbo",
    ],
    "ollama": [],  # populated dynamically from local Ollama
}

# System prompt shared by all providers
_SYSTEM_PROMPT = """You are a cybersecurity expert who designs realistic phishing simulation email templates for security awareness training programmes.

Given a brief description, generate ONE phishing simulation email template. Return ONLY a valid JSON object with these exact fields — no markdown fences, no extra commentary, just the raw JSON:

{
  "name": "Short descriptive template name (e.g. IT: Password Expiry Alert)",
  "category": "Exactly one of: IT Security, HR, Finance, Executive, Delivery, General",
  "subject": "The email subject line (realistic, creates urgency or authority)",
  "from_name": "Sender display name (looks official but slightly off)",
  "from_email": "sender@realistic-but-fake-domain.com",
  "description": "One sentence describing the social-engineering tactic used",
  "body": "Full email body text"
}

Rules for the body field:
- Must include {{name}} where the recipient name appears
- Must include {{phishing_link}} as the clickable call-to-action link
- Must include {{tracking_pixel}} as the very last token
- Create a sense of urgency, authority, or fear to encourage clicking
- Make it realistic but include at least one subtle red flag a trained employee would notice
- Include a professional greeting and a plausible signature block
- Plain text only — no HTML tags"""


# ── Helpers ───────────────────────────────────────────────────

def _get_llm_config(db: Session) -> models.LLMConfig:
    cfg = db.query(models.LLMConfig).first()
    if not cfg:
        cfg = models.LLMConfig()
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _http_post(url: str, payload: dict, headers: dict, timeout: int = 60) -> dict:
    """Synchronous HTTP POST using only stdlib — no extra dependencies."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=e.code, detail=f"LLM API error {e.code}: {body[:400]}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach LLM endpoint: {e.reason}")


def _http_get(url: str, headers: dict = None, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach endpoint: {e.reason}")


def _call_llm(provider: str, api_key: str, model: str, ollama_url: str,
              user_prompt: str) -> str:
    """Call the chosen LLM and return the raw text response."""

    if provider == "anthropic":
        if not api_key:
            raise HTTPException(status_code=400, detail="Anthropic API key not configured.")
        payload = {
            "model": model or "claude-sonnet-4-6",
            "max_tokens": 1024,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        resp = _http_post("https://api.anthropic.com/v1/messages", payload, headers, timeout=60)
        return resp["content"][0]["text"]

    elif provider == "openai":
        if not api_key:
            raise HTTPException(status_code=400, detail="OpenAI API key not configured.")
        payload = {
            "model": model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 1024,
            "temperature": 0.7,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        }
        resp = _http_post("https://api.openai.com/v1/chat/completions", payload, headers, timeout=60)
        return resp["choices"][0]["message"]["content"]

    elif provider == "ollama":
        base = (ollama_url or "http://localhost:11434").rstrip("/")
        payload = {
            "model": model or "llama3.2",
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.7},
        }
        headers = {"content-type": "application/json"}
        resp = _http_post(f"{base}/api/chat", payload, headers, timeout=120)
        return resp["message"]["content"]

    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")


def _extract_json(text: str) -> dict:
    """Extract and parse the first JSON object found in the LLM response text."""
    # Strip markdown code fences if present
    text = re.sub(r"```(?:json)?\s*", "", text).replace("```", "").strip()
    # Find first { ... } block
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        raise HTTPException(status_code=502,
            detail="LLM did not return a valid JSON object. Try rephrasing your prompt.")
    try:
        return json.loads(match.group())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=502,
            detail=f"LLM returned malformed JSON: {e}. Try again or rephrase your prompt.")


def _parse_email_text(raw: str, filename: str = "") -> dict:
    """
    Parse raw email text (plain text, .eml, or HTML) into template field dict.
    Adds {{name}}, {{phishing_link}}, {{tracking_pixel}} placeholders automatically.
    """
    lines = raw.replace("\r\n", "\n").strip().split("\n")
    headers: dict = {}
    body_start = 0

    # Detect and parse email headers (first block before blank line)
    for i, line in enumerate(lines):
        if not line.strip():
            body_start = i + 1
            break
        if ":" in line and i < 30:
            key, _, val = line.partition(":")
            k = key.strip().lower()
            if k in ("from", "subject", "to", "reply-to", "date", "sender"):
                # Handle multi-line header folding
                headers[k] = val.strip()

    body = "\n".join(lines[body_start:]).strip()

    # If no headers detected, treat entire text as the body
    if not headers:
        body = raw.strip()

    # --- Strip HTML tags if this looks like HTML ---
    if filename.endswith(".html") or body.strip().startswith("<"):
        body = re.sub(r"<style[^>]*>[\s\S]*?</style>", "", body, flags=re.IGNORECASE)
        body = re.sub(r"<script[^>]*>[\s\S]*?</script>", "", body, flags=re.IGNORECASE)
        body = re.sub(r"<[^>]+>", "", body)
        body = re.sub(r"&nbsp;", " ", body)
        body = re.sub(r"&lt;", "<", body)
        body = re.sub(r"&gt;", ">", body)
        body = re.sub(r"&amp;", "&", body)
        body = re.sub(r" {2,}", " ", body)
        body = "\n".join(l.strip() for l in body.split("\n") if l.strip())

    # --- Parse From header ---
    from_raw = headers.get("from", "")
    from_name, from_email = "", ""
    m = re.match(r'^"?([^"<]*?)"?\s*<([^>]+)>', from_raw)
    if m:
        from_name  = m.group(1).strip()
        from_email = m.group(2).strip()
    elif "@" in from_raw:
        from_email = re.search(r"[\w.+-]+@[\w.-]+", from_raw).group()
        from_name  = from_email.split("@")[0].replace(".", " ").replace("_", " ").title()

    subject = headers.get("subject", "")

    # --- Auto-detect category by keyword scan ---
    scan = (subject + " " + body).lower()
    if any(w in scan for w in ["password", "microsoft", "office 365", "it security",
                                "account", "login", "verify your", "mfa", "2fa"]):
        category = "IT Security"
    elif any(w in scan for w in ["invoice", "payment", "bank", "wire", "finance",
                                  "accounts payable", "purchase order"]):
        category = "Finance"
    elif any(w in scan for w in ["hr", "human resources", "performance review",
                                  "docusign", "employee", "payroll"]):
        category = "HR"
    elif any(w in scan for w in ["ceo", "executive", "president", "urgent request",
                                  "confidential", "chairman"]):
        category = "Executive"
    elif any(w in scan for w in ["delivery", "package", "parcel", "shipment",
                                  "fedex", "ups", "dhl", "tracking number"]):
        category = "Delivery"
    else:
        category = "General"

    # --- Inject placeholders ---
    # {{name}}
    if "{{name}}" not in body:
        body = re.sub(r"\b(Dear|Hi|Hello)\s+[\w\s,]+,",
                      lambda m: m.group().split()[0] + " {{name}},",
                      body, count=1, flags=re.IGNORECASE)
        if "{{name}}" not in body:
            body = "Dear {{name}},\n\n" + body

    # {{phishing_link}}
    if "{{phishing_link}}" not in body:
        replaced = re.sub(r"https?://[^\s<>\"']+", "{{phishing_link}}", body, count=1)
        if replaced != body:
            body = replaced
        else:
            body = body.rstrip() + "\n\nClick here to proceed: {{phishing_link}}"

    # {{tracking_pixel}}
    if "{{tracking_pixel}}" not in body:
        body = body.rstrip() + "\n\n{{tracking_pixel}}"

    name = f"{category}: " + (subject[:45] if subject else "Imported Template")

    return {
        "name": name,
        "category": category,
        "subject": subject or "Important Notice",
        "body": body,
        "from_name": from_name or "IT Security Team",
        "from_email": from_email or "security@corp-support.com",
        "description": f"Imported {category} phishing simulation template.",
    }


# ── Routes ────────────────────────────────────────────────────

@router.get("/config", response_model=schemas.LLMConfigResponse)
def get_llm_config(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    cfg = _get_llm_config(db)
    return schemas.LLMConfigResponse(
        provider=cfg.provider,
        api_key=MASK if cfg.api_key else "",
        model=cfg.model,
        ollama_url=cfg.ollama_url or "http://localhost:11434",
        is_configured=cfg.is_configured,
    )


@router.put("/config")
def save_llm_config(data: schemas.LLMConfigUpdate, _: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _get_llm_config(db)
    cfg.provider   = data.provider.strip().lower()
    cfg.model      = data.model.strip()
    cfg.ollama_url = (data.ollama_url or "http://localhost:11434").rstrip("/")
    cfg.updated_at = datetime.utcnow()

    # Only overwrite API key if a real value submitted
    if data.api_key and data.api_key != MASK:
        cfg.api_key = data.api_key

    # Ollama needs no API key; cloud providers do
    if cfg.provider == "ollama":
        cfg.is_configured = bool(cfg.model and cfg.ollama_url)
    else:
        cfg.is_configured = bool(cfg.model and cfg.api_key)

    db.commit()
    return {"status": "saved", "is_configured": cfg.is_configured, "provider": cfg.provider}


@router.post("/test")
def test_llm_connection(_: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    """Quick connectivity test — sends a tiny prompt and checks for any valid response."""
    cfg = _get_llm_config(db)
    if not cfg.is_configured:
        raise HTTPException(status_code=400,
            detail="AI engine not configured. Save your settings first.")

    try:
        result = _call_llm(
            provider=cfg.provider,
            api_key=cfg.api_key,
            model=cfg.model,
            ollama_url=cfg.ollama_url,
            user_prompt='Reply with only the word "READY" and nothing else.',
        )
        short = result.strip()[:80]
        return {
            "status": "success",
            "message": f"✅ {cfg.provider.title()} ({cfg.model}) is responding — got: '{short}'",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LLM test failed: {str(e)}")


@router.get("/ollama-models")
def list_ollama_models(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """Return the list of models currently installed in local Ollama."""
    cfg = _get_llm_config(db)
    base = (cfg.ollama_url or "http://localhost:11434").rstrip("/")
    try:
        data = _http_get(f"{base}/api/tags", timeout=8)
        models_list = [m["name"] for m in data.get("models", [])]
        return {"models": models_list, "ollama_url": base}
    except HTTPException:
        return {"models": [], "ollama_url": base,
                "error": "Ollama not reachable — is it running?"}


@router.post("/generate")
def generate_template(payload: schemas.TemplateGenerateRequest,
                      current_user: models.User = Depends(require_operator), db: Session = Depends(get_db)):
    """
    Generate a phishing email template from a plain-language prompt using the
    configured LLM. Returns the structured template fields ready to save.
    """
    cfg = _get_llm_config(db)

    # Per-request overrides take precedence over stored config
    provider   = payload.provider   or cfg.provider
    api_key    = (payload.api_key   or cfg.api_key  or "")
    model      = payload.model      or cfg.model
    ollama_url = payload.ollama_url or cfg.ollama_url

    if not provider:
        raise HTTPException(status_code=400, detail="No LLM provider configured.")

    # Build the user prompt
    category_hint = f" Make the category '{payload.category}'." if payload.category else ""
    user_prompt = (
        f"Create a phishing simulation email template for security awareness training.\n"
        f"Description: {payload.prompt.strip()}{category_hint}\n"
        f"Return ONLY the JSON object as specified."
    )

    raw_text = _call_llm(
        provider=provider,
        api_key=api_key,
        model=model,
        ollama_url=ollama_url,
        user_prompt=user_prompt,
    )

    template_data = _extract_json(raw_text)

    # Validate required fields exist; fill defaults if LLM omitted any
    defaults = {
        "name": "AI Generated Template",
        "category": payload.category or "General",
        "subject": "Important Notice",
        "body": "Dear {{name}},\n\nPlease click here: {{phishing_link}}\n\n{{tracking_pixel}}",
        "from_name": "IT Security Team",
        "from_email": "security@corp-support.com",
        "description": "AI-generated phishing simulation template.",
    }
    for k, v in defaults.items():
        if k not in template_data or not template_data[k]:
            template_data[k] = v

    # Ensure placeholders are present in the body
    body = template_data.get("body", "")
    if "{{name}}"           not in body: body = "Dear {{name}},\n\n" + body
    if "{{phishing_link}}"  not in body: body = body + "\n\nClick here: {{phishing_link}}"
    if "{{tracking_pixel}}" not in body: body = body + "\n\n{{tracking_pixel}}"
    template_data["body"] = body

    return {"status": "ok", "template": template_data, "provider_used": provider, "model_used": model}


@router.post("/import-text")
def import_from_text(payload: schemas.TemplateImportRequest, _: models.User = Depends(require_operator)):
    """
    Parse pasted email text (plain-text, .eml headers, or HTML) into template fields.
    No LLM required — pure regex-based parsing.
    """
    if not payload.raw_text.strip():
        raise HTTPException(status_code=400, detail="No text provided.")
    result = _parse_email_text(payload.raw_text, payload.filename or "")
    return {"status": "ok", "template": result}


@router.post("/import-file")
async def import_from_file(file: UploadFile = File(...), _: models.User = Depends(require_operator)):
    """
    Upload a .txt, .html, or .eml file and parse it into template fields.
    Max file size: 512 KB.
    """
    MAX_BYTES = 512 * 1024
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=400,
            detail="File too large. Maximum size is 512 KB.")

    filename = file.filename or ""
    try:
        raw_text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400,
            detail="Could not decode file. Only UTF-8 text files are supported.")

    result = _parse_email_text(raw_text, filename)
    return {"status": "ok", "template": result, "filename": filename}


@router.get("/provider-models")
def get_provider_models(_: models.User = Depends(require_auth)):
    """Return the static model catalogue for each cloud provider."""
    return PROVIDER_MODELS
