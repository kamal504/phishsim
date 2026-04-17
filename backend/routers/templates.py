"""
Email Template Library
Provides pre-built phishing simulation templates + full user CRUD.
"""
from typing import List
from routers.auth import require_auth, require_operator
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
import models, schemas

router = APIRouter(prefix="/api/templates", tags=["templates"])

# ── Built-in template library ─────────────────────────────────
BUILTIN_TEMPLATES = [
    {
        "name": "IT: Password Expiry Alert",
        "category": "IT Security",
        "subject": "[URGENT] Your corporate password expires in 24 hours",
        "from_name": "IT Help Desk",
        "from_email": "it-helpdesk@corp-support.com",
        "description": "Impersonates IT help desk with an urgent password reset. Consistently high click rate due to fear of losing access.",
        "body": """Dear {{name}},

Our system has detected that your corporate password will expire in 24 hours.

To avoid losing access to your email, files, and applications, please reset your password immediately by clicking the link below:

👉 Reset My Password Now: {{phishing_link}}

If you do not reset within 24 hours your account will be locked and you will need to contact IT Support directly to regain access.

Thank you for your prompt attention.

IT Help Desk
Corporate IT Security Team

{{tracking_pixel}}""",
        "is_builtin": True,
    },
    {
        "name": "IT: Microsoft 365 License Expiry",
        "category": "IT Security",
        "subject": "Action Required: Your Microsoft 365 license expires soon",
        "from_name": "Microsoft Account Team",
        "from_email": "account-noreply@microsoft365-renewal.com",
        "description": "Mimics an official Microsoft 365 license renewal notice. Targets any user who relies on Office applications daily.",
        "body": """Dear {{name}},

Your Microsoft 365 subscription is about to expire. To continue using Word, Excel, Outlook, Teams, and OneDrive without interruption, please verify your account immediately.

👉 Verify Account & Renew Subscription: {{phishing_link}}

Failure to act within 48 hours will result in read-only access to your Microsoft applications and you will be unable to send email.

Microsoft Account Team
Microsoft Corporation

{{tracking_pixel}}""",
        "is_builtin": True,
    },
    {
        "name": "HR: DocuSign Performance Review",
        "category": "HR",
        "subject": "DocuSign: Please review and sign your 2024 performance document",
        "from_name": "HR Department",
        "from_email": "hr-noreply@docusign-hr-portal.com",
        "description": "Impersonates HR DocuSign for annual performance review. Highly effective around Q4 review cycles.",
        "body": """Dear {{name}},

Your 2024 Annual Performance Review document is ready for your review and signature.

Please review and sign the document at your earliest convenience. Your signature is required for your compensation adjustment and promotion consideration to be processed by Finance.

👉 Review & Sign Document: {{phishing_link}}

This document will expire in 48 hours. Please complete your signature before the deadline to avoid delays in your review process.

Human Resources Department

{{tracking_pixel}}""",
        "is_builtin": True,
    },
    {
        "name": "Finance: Invoice Approval Required",
        "category": "Finance",
        "subject": "Invoice #INV-2024-8821 requires your approval — deadline today",
        "from_name": "Accounts Payable",
        "from_email": "ap-noreply@finance-approvals.com",
        "description": "Targets finance managers or approvers with an urgent vendor invoice. Creates pressure with a same-day deadline.",
        "body": """Dear {{name}},

A vendor invoice is pending your approval before end of business today:

  Invoice #:   INV-2024-8821
  Vendor:      Acme Software Solutions Ltd.
  Amount:      $14,750.00
  Due Date:    TODAY — End of Business

Please log in to the accounts payable portal to review and approve or reject this invoice:

👉 Review Invoice Now: {{phishing_link}}

Failure to act by end of day may result in late payment penalties and damage to our vendor relationship.

Accounts Payable Team
Finance Department

{{tracking_pixel}}""",
        "is_builtin": True,
    },
    {
        "name": "Executive: CEO Urgent Confidential Request",
        "category": "Executive",
        "subject": "Confidential — Need your help with something urgent",
        "from_name": "Office of the CEO",
        "from_email": "ceo-office@exec-corp-communications.com",
        "description": "Classic spear phishing using executive authority. Very effective due to authority bias — employees rarely question CEO requests.",
        "body": """Hi {{name}},

I need your urgent assistance with a sensitive matter. I'm currently in back-to-back meetings and cannot speak by phone right now.

I've shared a confidential document with you that requires your immediate review and acknowledgment. Please access it using the link below and confirm receipt as soon as possible.

👉 Access Confidential Document: {{phishing_link}}

Please treat this as priority and keep it confidential until further notice. Do not discuss with others.

Thank you,

{{tracking_pixel}}""",
        "is_builtin": True,
    },
    {
        "name": "Delivery: Failed Package Notification",
        "category": "Delivery",
        "subject": "Your package delivery attempt failed — schedule redelivery now",
        "from_name": "FedEx Delivery Services",
        "from_email": "delivery-status@fedex-redelivery-portal.com",
        "description": "Fake delivery failure from a courier. Works especially well with remote/hybrid workers expecting deliveries.",
        "body": """Dear {{name}},

We attempted to deliver your package today but were unable to complete the delivery as the recipient was unavailable.

  Tracking Number:    FX20248821{{name}}
  Delivery Attempt:   Today at 2:34 PM
  Status:             FAILED — Recipient not available
  Return deadline:    3 business days

To schedule a redelivery or arrange for collection at your nearest FedEx location, please verify your delivery address:

👉 Schedule Redelivery: {{phishing_link}}

If no action is taken within 3 business days, your package will be returned to the sender and a return fee may be charged.

FedEx Delivery Services

{{tracking_pixel}}""",
        "is_builtin": True,
    },
]


def seed_builtin_templates(db: Session):
    """Called on startup — inserts built-in templates if the table is empty."""
    existing = db.query(models.EmailTemplate).filter(
        models.EmailTemplate.is_builtin == True
    ).count()
    if existing == 0:
        for data in BUILTIN_TEMPLATES:
            db.add(models.EmailTemplate(**data))
        db.commit()


# ── CRUD endpoints ────────────────────────────────────────────

@router.get("", response_model=List[schemas.TemplateResponse])
def list_templates(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    return (
        db.query(models.EmailTemplate)
        .order_by(models.EmailTemplate.is_builtin.desc(), models.EmailTemplate.category, models.EmailTemplate.name)
        .all()
    )


@router.post("", response_model=schemas.TemplateResponse, status_code=201)
def create_template(payload: schemas.TemplateCreate, _: models.User = Depends(require_operator), db: Session = Depends(get_db)):
    template = models.EmailTemplate(**payload.model_dump(), is_builtin=False)
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


@router.get("/{template_id}", response_model=schemas.TemplateResponse)
def get_template(template_id: int, _: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    t = db.query(models.EmailTemplate).filter(models.EmailTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    return t


@router.put("/{template_id}", response_model=schemas.TemplateResponse)
def update_template(template_id: int, payload: schemas.TemplateUpdate, _: models.User = Depends(require_operator), db: Session = Depends(get_db)):
    t = db.query(models.EmailTemplate).filter(models.EmailTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(t, field, value)
    db.commit()
    db.refresh(t)
    return t


@router.delete("/{template_id}", status_code=204)
def delete_template(template_id: int, _: models.User = Depends(require_operator), db: Session = Depends(get_db)):
    t = db.query(models.EmailTemplate).filter(models.EmailTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    if t.is_builtin:
        raise HTTPException(status_code=400, detail="Built-in templates cannot be deleted. Duplicate it first.")
    db.delete(t)
    db.commit()


@router.post("/{template_id}/duplicate", response_model=schemas.TemplateResponse, status_code=201)
def duplicate_template(template_id: int, _: models.User = Depends(require_operator), db: Session = Depends(get_db)):
    """Create an editable copy of any template (especially useful for built-ins)."""
    t = db.query(models.EmailTemplate).filter(models.EmailTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    copy = models.EmailTemplate(
        name="Copy of " + t.name,
        category=t.category,
        subject=t.subject,
        body=t.body,
        from_name=t.from_name,
        from_email=t.from_email,
        description=t.description,
        is_builtin=False,
    )
    db.add(copy)
    db.commit()
    db.refresh(copy)
    return copy
