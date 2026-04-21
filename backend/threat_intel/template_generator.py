"""
AI-Powered Template Generator
================================
Analyses threat intelligence feed data and generates realistic phishing
email templates that mirror current, real-world attack patterns.

Key capabilities:
  1. Trend analysis — identifies dominant phishing themes from recent IOCs
  2. Template synthesis — LLM (OpenAI/local) generates contextualised email
  3. Difficulty scoring — heuristic 1–5 score (harder = more convincing)
  4. Safe detonation — all links replaced with PhishSim tracking URLs
  5. Template categorisation — maps to existing template categories

Usage:
    from threat_intel.template_generator import generate_from_intel, score_template
    template = generate_from_intel(db, category_hint="credential_harvest")
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

import models

log = logging.getLogger(__name__)


# ── Trend analyser ────────────────────────────────────────────────────────────

# Common phishing brand targets extracted from indicator metadata/tags
BRAND_PATTERNS = {
    "microsoft":  ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "teams", "azure"],
    "google":     ["google", "gmail", "drive", "workspace", "accounts.google"],
    "amazon":     ["amazon", "aws", "prime", "amazonaws"],
    "docusign":   ["docusign", "esign", "e-signature"],
    "paypal":     ["paypal", "payment"],
    "linkedin":   ["linkedin", "connection"],
    "dropbox":    ["dropbox", "shared"],
    "zoom":       ["zoom", "meeting", "webinar"],
    "fedex":      ["fedex", "delivery", "shipment", "tracking"],
    "irs":        ["irs", "tax", "refund", "revenue"],
    "bank":       ["bank", "chase", "wellsfargo", "bofa", "hsbc", "barclays"],
}

CATEGORY_KEYWORDS = {
    "credential_harvest": ["login", "signin", "account", "password", "verify", "secure", "authenticate"],
    "urgent_action":      ["urgent", "immediate", "24 hours", "expire", "suspended", "locked"],
    "financial":          ["invoice", "payment", "transfer", "wire", "refund", "billing"],
    "document":           ["document", "shared", "sign", "review", "pdf", "docx"],
    "package":            ["delivery", "package", "tracking", "shipment", "courier"],
    "hr":                 ["payroll", "benefit", "hr", "vacation", "policy", "compliance"],
    "it_helpdesk":        ["it", "helpdesk", "password reset", "vpn", "mfa", "security"],
}


def analyse_recent_trends(db: Session, days: int = 7) -> dict:
    """
    Scan recent threat indicators to identify dominant phishing themes.
    Returns a dict of { category: relevance_score, brand: relevance_score }.
    """
    since = datetime.utcnow() - timedelta(days=days)
    indicators = db.query(models.ThreatIndicator).filter(
        models.ThreatIndicator.active == True,
        models.ThreatIndicator.last_seen >= since,
        models.ThreatIndicator.ioc_type == "url",
    ).limit(500).all()

    brand_scores = {b: 0 for b in BRAND_PATTERNS}
    category_scores = {c: 0 for c in CATEGORY_KEYWORDS}

    for ind in indicators:
        val_lower = ind.value.lower()
        tags = json.loads(ind.tags or "[]")
        meta_str = (ind.metadata_json or "").lower()
        combined = val_lower + " " + " ".join(tags) + " " + meta_str

        for brand, keywords in BRAND_PATTERNS.items():
            if any(k in combined for k in keywords):
                brand_scores[brand] += 1

        for cat, keywords in CATEGORY_KEYWORDS.items():
            if any(k in combined for k in keywords):
                category_scores[cat] += 1

    # Sort by frequency
    top_brands = sorted(brand_scores.items(), key=lambda x: x[1], reverse=True)[:3]
    top_cats   = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)[:3]
    total_urls = len(indicators)

    return {
        "total_indicators_analysed": total_urls,
        "top_brands":    [b for b, s in top_brands if s > 0],
        "top_categories": [c for c, s in top_cats if s > 0],
        "brand_scores":  {b: s for b, s in top_brands},
        "category_scores": {c: s for c, s in top_cats},
    }


# ── Difficulty scorer ─────────────────────────────────────────────────────────

def score_template_difficulty(subject: str, body: str) -> int:
    """
    Heuristic difficulty score 1–5 for a phishing email template.

    1 = Obvious (poor grammar, generic, easy to spot)
    3 = Moderate (plausible brand, some urgency, minor tells)
    5 = Very hard (perfect impersonation, personalised, strong social engineering)

    Used to match employee risk levels: high-risk employees get harder templates.
    """
    score = 1
    text = (subject + " " + body).lower()

    # Urgency indicators (+1)
    urgency_words = ["urgent", "immediate", "within 24", "action required",
                     "account suspended", "expires", "verify now", "last chance"]
    if any(w in text for w in urgency_words):
        score += 1

    # Brand impersonation — known brands (+1)
    all_brand_kw = [kw for kws in BRAND_PATTERNS.values() for kw in kws]
    if any(kw in text for kw in all_brand_kw):
        score += 1

    # Personalisation placeholders (+0.5 rounded up)
    if "{{name}}" in body or "{{first_name}}" in body or "{{department}}" in body:
        score = min(5, score + 1)

    # Professional HTML formatting — no raw plaintext (+0.5)
    if "<table" in body.lower() or "border-radius" in body.lower() or "font-family" in body.lower():
        score = min(5, score + 1)

    # Capped at 5
    return min(5, max(1, score))


# ── Template pre-built library based on trends ────────────────────────────────

TEMPLATE_BLUEPRINTS = {
    "microsoft_mfa": {
        "name":     "Microsoft MFA Verification Required",
        "category": "credential_harvest",
        "brand":    "microsoft",
        "subject":  "Action Required: Verify your Microsoft Authenticator — Account at Risk",
        "body": """Hi {{name}},

We detected a sign-in attempt to your Microsoft 365 account from an unrecognised device.

**For your security, your account has been temporarily restricted.**

To restore full access, you must verify your identity using Microsoft Authenticator within the next 4 hours.

{{phishing_link|Verify My Account Now}}

If you did not attempt to sign in, please disregard this email — your account will remain secure.

Microsoft Security Team
Microsoft Corporation

{{tracking_pixel}}""",
        "difficulty": 4,
    },
    "docusign_signature": {
        "name":     "DocuSign: Document Awaiting Your Signature",
        "category": "document",
        "brand":    "docusign",
        "subject":  "{{name}}, a document has been shared with you for review and signing",
        "body": """Hello {{name}},

A document has been sent to you for review and signature.

**Document:** Confidential — Annual Policy Acknowledgement 2024
**Sender:** HR Compliance Team
**Expires:** 48 hours from receipt

Please review and sign the document before it expires.

{{phishing_link|Review & Sign Document}}

This message was automatically generated by DocuSign Electronic Signature Service.

{{tracking_pixel}}""",
        "difficulty": 4,
    },
    "it_password_reset": {
        "name":     "IT Helpdesk: Mandatory Password Reset",
        "category": "it_helpdesk",
        "brand":    "microsoft",
        "subject":  "⚠️ Your password expires in 24 hours — Reset required",
        "body": """Hi {{name}},

This is an automated notification from the IT Security team.

Your network password will **expire in 24 hours**. To avoid losing access to company systems, email, and VPN, you must reset your password immediately.

{{phishing_link|Reset My Password Now}}

Passwords that are not reset will be locked automatically. Contact the IT Helpdesk if you experience any issues.

IT Security Operations
{{tracking_pixel}}""",
        "difficulty": 3,
    },
    "payroll_update": {
        "name":     "Payroll: Update Your Direct Deposit Information",
        "category": "financial",
        "brand":    "bank",
        "subject":  "Action Required: Update your payroll direct deposit information",
        "body": """Dear {{name}},

Our payroll system has detected that your direct deposit bank account information needs to be re-verified.

**This must be completed before the next pay cycle to avoid payment delays.**

Please log in to the employee portal to update your banking details securely:

{{phishing_link|Update Payroll Information}}

This is a time-sensitive request. Incomplete submissions will result in a cheque payment by default.

Payroll Department
Human Resources
{{tracking_pixel}}""",
        "difficulty": 4,
    },
    "sharepoint_file": {
        "name":     "SharePoint: File Shared With You",
        "category": "document",
        "brand":    "microsoft",
        "subject":  "{{name}} — someone shared a file with you on SharePoint",
        "body": """{{name}},

A colleague has shared a confidential file with you on SharePoint Online.

📄 **Q4 Financial Review — CONFIDENTIAL.xlsx**
👤 Shared by: Finance Team
🕐 Shared: Just now

{{phishing_link|Open in SharePoint}}

This link will expire in 7 days.

Microsoft SharePoint
{{tracking_pixel}}""",
        "difficulty": 3,
    },
    "zoom_invite": {
        "name":     "Zoom: Urgent Meeting Invitation",
        "category": "urgent_action",
        "brand":    "zoom",
        "subject":  "You have been invited to an urgent Zoom meeting — starting in 15 minutes",
        "body": """Hi {{name}},

You have been invited to join an urgent meeting.

📅 **Meeting:** Executive Leadership Update — CONFIDENTIAL
🕐 **Starts:** In 15 minutes
👤 **Host:** {{department}} Leadership Team

Click below to join immediately:

{{phishing_link|Join Meeting Now}}

If you are unable to join, please notify your manager immediately.

Zoom Communications Platform
{{tracking_pixel}}""",
        "difficulty": 3,
    },
}


# ── Template generator ────────────────────────────────────────────────────────

def generate_from_intel(db: Session, category_hint: str = None,
                         brand_hint: str = None, use_ai: bool = True) -> Optional[dict]:
    """
    Generate a new phishing template based on current threat intelligence trends.

    If AI (OpenAI API) is configured in ThreatIntelConfig.openai_api_key,
    uses GPT-4o to generate a novel, contextualised template.
    Otherwise, selects the best-matching blueprint from the pre-built library.

    Returns a dict ready to be used as a Template record, or None on failure.
    """
    cfg = db.query(models.ThreatIntelConfig).first()
    trends = analyse_recent_trends(db)

    # Determine best category + brand from trends or hints
    category = (category_hint or
                (trends["top_categories"][0] if trends["top_categories"] else "credential_harvest"))
    brand    = (brand_hint or
                (trends["top_brands"][0] if trends["top_brands"] else "microsoft"))

    # Try AI generation first
    if use_ai and cfg and cfg.openai_api_key:
        result = _generate_with_ai(cfg.openai_api_key, category, brand, trends)
        if result:
            return result

    # Fall back to blueprint library
    return _select_blueprint(category, brand)


def _select_blueprint(category: str, brand: str) -> dict:
    """Select the best matching pre-built template blueprint."""
    # Score each blueprint by category and brand match
    best = None
    best_score = -1
    for key, bp in TEMPLATE_BLUEPRINTS.items():
        score = 0
        if bp.get("category") == category:
            score += 2
        if bp.get("brand") == brand:
            score += 2
        if score > best_score:
            best_score = score
            best = bp

    if not best:
        best = list(TEMPLATE_BLUEPRINTS.values())[0]

    return {
        "name":       best["name"] + " [Intel-Generated]",
        "category":   best["category"],
        "subject":    best["subject"],
        "body":       best["body"],
        "difficulty": best["difficulty"],
        "tags":       json.dumps(["threat-intel", "auto-generated", best.get("brand", "generic")]),
        "generated_by": "blueprint",
    }


def _generate_with_ai(api_key: str, category: str, brand: str, trends: dict) -> Optional[dict]:
    """
    Use OpenAI GPT-4o to generate a novel phishing template based on threat trends.
    Returns template dict or None if API call fails.
    """
    prompt = f"""You are a cybersecurity professional creating a PHISHING SIMULATION template for
employee security awareness training. This is for INTERNAL TRAINING PURPOSES ONLY.

Current threat intelligence shows these dominant phishing patterns this week:
- Top targeted brands: {', '.join(trends.get('top_brands', ['Microsoft']))}
- Top attack categories: {', '.join(trends.get('top_categories', ['credential_harvest']))}

Create a realistic phishing simulation email with these parameters:
- Category: {category}
- Impersonated brand: {brand}
- Use these placeholders exactly: {{{{name}}}} for recipient name, {{{{phishing_link}}}} for the CTA link, {{{{tracking_pixel}}}} at the end
- Make it convincing but include at least one subtle tell (slightly off domain, unusual request)
- Use professional formatting with urgency but not panic
- Maximum 200 words in the body

Respond with ONLY a valid JSON object (no markdown, no explanation):
{{
  "subject": "...",
  "body": "...",
  "name": "...",
  "difficulty": 3
}}"""

    try:
        import urllib.request as ureq
        payload = json.dumps({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
            "max_tokens": 600,
        }).encode()
        req = ureq.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent":    "PhishSim-ThreatIntel/2.0",
            },
            method="POST",
        )
        with ureq.urlopen(req, timeout=20) as r:
            resp = json.loads(r.read())
        content = resp["choices"][0]["message"]["content"].strip()
        # Strip markdown code fences if present
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
        data = json.loads(content)
        return {
            "name":       data.get("name", f"AI: {brand.title()} {category.replace('_',' ').title()} [Intel]"),
            "category":   category,
            "subject":    data["subject"],
            "body":       data["body"],
            "difficulty": int(data.get("difficulty", 3)),
            "tags":       json.dumps(["threat-intel", "ai-generated", brand]),
            "generated_by": "gpt-4o-mini",
        }
    except Exception as e:
        log.warning(f"AI template generation failed: {e}")
        return None
