"""
Tracking endpoints — simulates what would be embedded in real phishing emails.

  Pixel:   GET  /track/pixel/{token}   → 1×1 GIF, logs "opened"
  Click:   GET  /track/click/{token}   → logs "clicked", shows themed fake login page
  Phish:   GET  /phish/{token}         → themed fake login landing page (direct)
  Submit:  POST /track/submit/{token}  → logs "submitted", shows security awareness page

Security: bot/scanner user-agents are detected and filtered (CVE-22 fix).
Known email security scanners (Defender, Proofpoint, Mimecast, etc.) pre-click
links before humans see them — filtering them prevents inflated click/open stats.
"""
import logging
import re
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response, HTMLResponse
from sqlalchemy.orm import Session
from database import get_db
import models

log = logging.getLogger(__name__)
router = APIRouter(tags=["tracking"])


def _fire_simulation_signal(target: models.Target, signal_type: str, db: Session):
    """
    Record a simulation risk signal after a tracking event.
    Silently skips if the risk engine fails — tracking must not be disrupted.
    """
    try:
        from risk_engine import core as risk_core
        risk_core.record_signal(
            email=target.email,
            signal_type=signal_type,
            source="phishsim",
            db=db,
            metadata={"target_id": target.id, "campaign_id": target.campaign_id},
            name=target.name or "",
            department=target.department or "",
        )
    except Exception as e:
        log.warning(f"Risk signal failed (non-critical): {e}")

# ── Bot/scanner user-agent filter (CVE-22 fix) ───────────────────────────────
_BOT_UA_RE = re.compile(
    r"(bot|crawler|spider|scraper|scanner|preview|prefetch|"
    r"microsoft.*safety|safelinks|proofpoint|mimecast|barracuda|"
    r"symantec|forcepoint|sophos|trend.*micro|cisco|fireeye|"
    r"headless|phantomjs|selenium|puppeteer|playwright|"
    r"python-requests|python-urllib|curl|wget|java\/|"
    r"go-http-client|okhttp|ruby|perl)",
    re.IGNORECASE,
)

def _is_bot(request: Request) -> bool:
    """Return True if the request looks like an automated scanner/bot."""
    ua = request.headers.get("user-agent", "")
    if not ua:
        return True  # No UA = likely a scanner
    if _BOT_UA_RE.search(ua):
        return True
    return False

# ── 1×1 transparent GIF ──────────────────────────────────────
PIXEL_GIF = bytes([
    0x47,0x49,0x46,0x38,0x39,0x61,0x01,0x00,0x01,0x00,0x80,0x00,0x00,
    0xFF,0xFF,0xFF,0x00,0x00,0x00,0x21,0xF9,0x04,0x00,0x00,0x00,0x00,
    0x00,0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x02,0x02,
    0x44,0x01,0x00,0x3B,
])

THEME_LABELS = {
    "microsoft_365":    "Microsoft 365 Sign-In",
    "hr_portal":        "HR Employee Portal",
    "finance_portal":   "Finance & Accounts Portal",
    "executive_portal": "Executive Secure Portal",
    "delivery_portal":  "Parcel Delivery Portal",
    "corporate_sso":    "Corporate Single Sign-On",
}


# ════════════════════════════════════════════════════════════════
#  THEMED FAKE LOGIN PAGES
# ════════════════════════════════════════════════════════════════

def _common_form_fields(token: str, btn_text: str, btn_color: str,
                         label_email: str = "Email address",
                         label_pass:  str = "Password") -> str:
    """Shared form HTML used by most themes."""
    return f"""
    <form method="POST" action="/track/submit/{token}" autocomplete="off">
      <div class="field">
        <label>{label_email}</label>
        <input type="email" name="email" placeholder="user@company.com" required autocomplete="username">
      </div>
      <div class="field">
        <label>{label_pass}</label>
        <input type="password" name="password" placeholder="••••••••••" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn" style="background:{btn_color}">{btn_text}</button>
    </form>"""


# ── Theme 1: Microsoft 365 ────────────────────────────────────
def _page_microsoft_365(token: str) -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to your account</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#f2f2f2;
       display:flex;flex-direction:column;min-height:100vh}
  .ms-logo{display:flex;gap:3px;margin-bottom:20px}
  .ms-logo span{display:block;width:10px;height:10px}
  .ms-logo .r1{background:#f25022}.ms-logo .r2{background:#7fba00}
  .ms-logo .r3{background:#00a4ef}.ms-logo .r4{background:#ffb900}
  .ms-text{font-size:18px;font-weight:300;color:#1b1b1b;margin-left:8px;align-self:center}
  .card{background:#fff;border-radius:2px;box-shadow:0 2px 6px rgba(0,0,0,.2);
        width:440px;padding:44px 44px 36px;margin:auto}
  h1{font-size:24px;font-weight:600;color:#1b1b1b;margin:24px 0 12px}
  .sub{font-size:13px;color:#605e5c;margin-bottom:24px}
  .field{margin-bottom:20px}
  label{display:block;font-size:13px;font-weight:600;color:#323130;margin-bottom:4px}
  input{width:100%;padding:7px 8px;border:none;border-bottom:1.5px solid #605e5c;
        font-size:14px;outline:none;background:transparent;font-family:inherit;color:#323130}
  input:focus{border-bottom:2px solid #0067b8}
  .btn{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;
       font-size:15px;font-weight:600;cursor:pointer;margin-top:20px;font-family:inherit}
  .btn:hover{background:#005a9e}
  .links{display:flex;justify-content:space-between;margin-top:12px;font-size:13px}
  .links a{color:#0067b8;text-decoration:none}
  .links a:hover{text-decoration:underline}
  .notice{font-size:11px;color:#605e5c;margin-top:20px;border-top:1px solid #edebe9;padding-top:12px}
  footer{text-align:center;font-size:11px;color:#605e5c;padding:14px;margin-top:auto}
  footer a{color:#0067b8;text-decoration:none;margin:0 8px}
</style>
</head>
<body>
<div class="card">
  <div style="display:flex;align-items:center">
    <div class="ms-logo">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:2px">
        <span class="r1"></span><span class="r2"></span>
        <span class="r3"></span><span class="r4"></span>
      </div>
    </div>
    <span class="ms-text">Microsoft</span>
  </div>
  <h1>Sign in</h1>
  <p class="sub">Use your Microsoft account to continue.</p>
  """ + _common_form_fields(token, "Sign in", "#0067b8") + """
  <div class="links">
    <a href="#">No account? Create one!</a>
    <a href="#">Forgot password?</a>
  </div>
  <p class="notice">
    Sign-in options · <a href="#" style="color:#0067b8;text-decoration:none">Windows Hello or security key</a>
  </p>
</div>
<footer>
  <a href="#">Terms of use</a><a href="#">Privacy & Cookies</a><a href="#">...</a>
  &copy; Microsoft 2024
</footer>
</body>
</html>"""


# ── Theme 2: HR Employee Portal ───────────────────────────────
def _page_hr_portal(token: str) -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Employee Self-Service Portal</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#f0faf5;min-height:100vh;display:flex;flex-direction:column}
  .top-bar{background:#006e4e;padding:12px 32px;display:flex;align-items:center;gap:12px}
  .top-bar .logo-box{width:36px;height:36px;background:#fff;border-radius:6px;
                      display:flex;align-items:center;justify-content:center;font-size:18px}
  .top-bar .brand{font-size:16px;font-weight:700;color:#fff}
  .top-bar .brand-sub{font-size:11px;color:rgba(255,255,255,.7)}
  .main{flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px}
  .card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,110,78,.14);
        width:440px;overflow:hidden}
  .card-header{background:#006e4e;padding:28px 32px;color:#fff}
  .card-header h1{font-size:20px;font-weight:700;margin-bottom:4px}
  .card-header p{font-size:13px;color:rgba(255,255,255,.8);line-height:1.5}
  .doc-notice{background:#e8f5f0;border-left:4px solid #006e4e;margin:20px 24px 0;
              padding:12px 14px;border-radius:0 8px 8px 0;font-size:13px;color:#005a40}
  .doc-notice strong{display:block;margin-bottom:4px}
  .card-body{padding:24px 32px 32px}
  .field{margin-bottom:18px}
  label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:5px;text-transform:uppercase;letter-spacing:.04em}
  input{width:100%;padding:10px 14px;border:1.5px solid #d1d5db;border-radius:8px;
        font-size:14px;outline:none;font-family:inherit;transition:border .2s}
  input:focus{border-color:#006e4e;box-shadow:0 0 0 3px rgba(0,110,78,.1)}
  .btn{width:100%;padding:12px;background:#006e4e;color:#fff;border:none;border-radius:8px;
       font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;margin-top:8px}
  .btn:hover{background:#005a40}
  .footer-links{display:flex;gap:16px;justify-content:center;margin-top:16px}
  .footer-links a{font-size:12px;color:#6b7280;text-decoration:none}
  .footer-links a:hover{color:#006e4e}
  footer{text-align:center;font-size:11px;color:#9ca3af;padding:16px}
</style>
</head>
<body>
<div class="top-bar">
  <div class="logo-box">👥</div>
  <div>
    <div class="brand">HRConnect</div>
    <div class="brand-sub">Employee Self-Service</div>
  </div>
</div>
<div class="main">
  <div class="card">
    <div class="card-header">
      <h1>Employee Portal Sign In</h1>
      <p>Access your performance reviews, payslips, and HR documents</p>
    </div>
    <div class="doc-notice">
      <strong>📄 1 document awaiting your signature</strong>
      Sign in to review and complete your annual performance evaluation.
    </div>
    <div class="card-body">
      """ + _common_form_fields(token, "Sign In to HR Portal", "#006e4e",
                                "Employee Email", "HR Portal Password") + """
      <div class="footer-links">
        <a href="#">Forgot password?</a>
        <a href="#">IT Support</a>
        <a href="#">Privacy Policy</a>
      </div>
    </div>
  </div>
</div>
<footer>© 2024 HRConnect · Employee Self-Service Platform · Secure Connection 🔒</footer>
</body>
</html>"""


# ── Theme 3: Finance & Accounts Portal ────────────────────────
def _page_finance_portal(token: str) -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Finance Management System — Sign In</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1e3d;
       min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
  .card{background:#fff;width:460px;border-radius:4px;overflow:hidden;
        box-shadow:0 8px 40px rgba(0,0,0,.5)}
  .card-header{background:linear-gradient(135deg,#0f1e3d,#1a3a6e);
               padding:32px;display:flex;align-items:center;gap:16px}
  .logo-ring{width:52px;height:52px;border-radius:50%;border:2px solid rgba(255,255,255,.3);
             display:flex;align-items:center;justify-content:center;font-size:22px}
  .header-text h1{font-size:18px;font-weight:700;color:#fff;margin-bottom:3px}
  .header-text p{font-size:12px;color:rgba(255,255,255,.6)}
  .alert-bar{background:#fff3cd;border-bottom:2px solid #f59e0b;
             padding:10px 24px;font-size:13px;color:#92400e;display:flex;align-items:center;gap:8px}
  .card-body{padding:28px 32px 32px}
  .invoice-info{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;
                padding:12px 14px;margin-bottom:22px;font-size:12px;color:#475569}
  .invoice-info .inv-row{display:flex;justify-content:space-between;margin-bottom:4px}
  .invoice-info .inv-row:last-child{margin:0}
  .invoice-info strong{color:#1e293b}
  label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:5px}
  input{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;
        font-size:14px;outline:none;font-family:inherit;transition:border .2s}
  input:focus{border-color:#1a3a6e;box-shadow:0 0 0 3px rgba(26,58,110,.1)}
  .field{margin-bottom:16px}
  .btn{width:100%;padding:11px;background:#1a3a6e;color:#fff;border:none;border-radius:6px;
       font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;margin-top:8px}
  .btn:hover{background:#0f2a56}
  .links{display:flex;justify-content:space-between;margin-top:12px;font-size:12px}
  .links a{color:#1a3a6e;text-decoration:none}
  footer{color:rgba(255,255,255,.35);font-size:11px;margin-top:20px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <div class="card-header">
    <div class="logo-ring">💼</div>
    <div class="header-text">
      <h1>Finance Management System</h1>
      <p>Accounts Payable &amp; Invoice Portal</p>
    </div>
  </div>
  <div class="alert-bar">⚠️ Invoice approval required — action needed before end of business today.</div>
  <div class="card-body">
    <div class="invoice-info">
      <div class="inv-row"><span>Invoice #:</span><span><strong>INV-2024-09471</strong></span></div>
      <div class="inv-row"><span>Amount:</span><span><strong>$24,350.00</strong></span></div>
      <div class="inv-row"><span>Vendor:</span><span><strong>TechSupplies Corp.</strong></span></div>
      <div class="inv-row"><span>Due:</span><span><strong style="color:#dc2626">Today, 5:00 PM</strong></span></div>
    </div>
    """ + _common_form_fields(token, "Authenticate & Approve", "#1a3a6e",
                              "Finance Account Email", "Password") + """
    <div class="links">
      <a href="#">Reset password</a>
      <a href="#">Contact Finance IT</a>
    </div>
  </div>
</div>
<footer>Finance Management System · Encrypted Connection · © 2024 Corp. Finance Division</footer>
</body>
</html>"""


# ── Theme 4: Executive Secure Portal ─────────────────────────
def _page_executive_portal(token: str) -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Executive Secure Access Portal</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#0a0e1a;min-height:100vh;display:flex;flex-direction:column;
       align-items:center;justify-content:center;padding:20px}
  .wrap{width:480px;display:flex;flex-direction:column;gap:16px}
  .badge{display:flex;align-items:center;justify-content:center;gap:10px;
         margin-bottom:4px}
  .badge-icon{font-size:28px}
  .badge-text{font-size:11px;font-weight:700;color:rgba(255,255,255,.4);
              letter-spacing:.12em;text-transform:uppercase}
  .card{background:linear-gradient(160deg,#13192e,#0d1220);
        border:1px solid rgba(255,255,255,.08);border-radius:14px;overflow:hidden}
  .card-top{padding:28px 32px 24px;border-bottom:1px solid rgba(255,255,255,.06)}
  .card-top h1{font-size:20px;font-weight:700;color:#f1f5f9;margin-bottom:6px}
  .card-top p{font-size:13px;color:rgba(255,255,255,.4);line-height:1.6}
  .confidential{display:inline-flex;align-items:center;gap:6px;font-size:10px;
                font-weight:700;letter-spacing:.08em;color:#dc2626;
                background:rgba(220,38,38,.1);border:1px solid rgba(220,38,38,.3);
                border-radius:4px;padding:3px 8px;margin-top:10px}
  .card-body{padding:24px 32px 32px}
  .secure-notice{background:rgba(255,255,255,.04);border-radius:8px;
                 padding:10px 14px;margin-bottom:20px;font-size:12px;
                 color:rgba(255,255,255,.4);display:flex;gap:8px;align-items:flex-start}
  label{display:block;font-size:11px;font-weight:600;color:rgba(255,255,255,.4);
        margin-bottom:6px;letter-spacing:.06em;text-transform:uppercase}
  input{width:100%;padding:11px 14px;background:rgba(255,255,255,.05);
        border:1px solid rgba(255,255,255,.1);border-radius:8px;font-size:14px;
        color:#f1f5f9;outline:none;font-family:inherit;transition:border .2s}
  input::placeholder{color:rgba(255,255,255,.2)}
  input:focus{border-color:rgba(255,215,0,.4);box-shadow:0 0 0 3px rgba(255,215,0,.06)}
  .field{margin-bottom:18px}
  .btn{width:100%;padding:12px;background:linear-gradient(135deg,#1e40af,#1d4ed8);
       color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:700;
       cursor:pointer;font-family:inherit;margin-top:6px;letter-spacing:.02em}
  .btn:hover{background:linear-gradient(135deg,#1d4ed8,#2563eb)}
  .footer-links{display:flex;justify-content:space-between;margin-top:14px;font-size:11px}
  .footer-links a{color:rgba(255,255,255,.3);text-decoration:none}
  .bottom{text-align:center;font-size:10px;color:rgba(255,255,255,.2);letter-spacing:.05em}
</style>
</head>
<body>
<div class="wrap">
  <div class="badge">
    <div class="badge-icon">🛡️</div>
    <div class="badge-text">Classified · Authorized Access Only</div>
  </div>
  <div class="card">
    <div class="card-top">
      <h1>Executive Secure Portal</h1>
      <p>This portal contains confidential board materials, executive communications,
         and restricted corporate documents.</p>
      <div class="confidential">🔴 CONFIDENTIAL — EYES ONLY</div>
    </div>
    <div class="card-body">
      <div class="secure-notice">
        🔐 You have been granted access to a time-sensitive executive briefing.
        Authenticate with your corporate credentials to proceed.
      </div>
      """ + _common_form_fields(token, "Authenticate — Secure Access", "#1d4ed8",
                                "Executive Email Address", "Corporate Password") + """
      <div class="footer-links">
        <a href="#">Access Issues?</a>
        <a href="#">Security Policy</a>
      </div>
    </div>
  </div>
  <div class="bottom">ENCRYPTED · TLS 1.3 · ZERO-TRUST ARCHITECTURE · SESSION AUDITED</div>
</div>
</body>
</html>"""


# ── Theme 5: Delivery / Parcel Portal ────────────────────────
def _page_delivery_portal(token: str) -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Schedule Your Parcel Delivery</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#f7f7f7;min-height:100vh;display:flex;flex-direction:column}
  .topbar{background:#4b0082;padding:0 32px;height:56px;display:flex;align-items:center;gap:12px}
  .tb-logo{display:flex;align-items:center;gap:8px}
  .tb-icon{width:34px;height:34px;background:#ffd700;border-radius:6px;
            display:flex;align-items:center;justify-content:center;font-size:16px}
  .tb-brand{font-size:18px;font-weight:800;color:#fff;letter-spacing:-.5px}
  .tb-brand span{color:#ffd700}
  .tb-right{margin-left:auto;font-size:12px;color:rgba(255,255,255,.6)}
  .hero{background:linear-gradient(135deg,#4b0082,#7c3aed);padding:32px;color:#fff;text-align:center}
  .hero h1{font-size:22px;font-weight:700;margin-bottom:8px}
  .hero p{font-size:14px;color:rgba(255,255,255,.75)}
  .pkg-card{background:#fff;border:2px solid #7c3aed;border-radius:10px;
            margin:0 auto;width:fit-content;padding:14px 24px;margin-top:16px;
            display:flex;gap:24px;font-size:13px}
  .pkg-item{text-align:center}
  .pkg-label{color:rgba(255,255,255,.6);font-size:10px;text-transform:uppercase;margin-bottom:2px}
  .pkg-val{font-weight:700;color:#fff}
  .main{flex:1;display:flex;align-items:flex-start;justify-content:center;padding:32px 20px}
  .card{background:#fff;border-radius:10px;box-shadow:0 2px 16px rgba(0,0,0,.1);
        width:440px;overflow:hidden}
  .card-header{background:#4b0082;padding:16px 24px;color:#fff}
  .card-header h2{font-size:15px;font-weight:700;margin-bottom:2px}
  .card-header p{font-size:12px;color:rgba(255,255,255,.7)}
  .card-body{padding:24px}
  .status-row{display:flex;align-items:center;gap:10px;background:#faf5ff;
              border:1px solid #e9d5ff;border-radius:8px;padding:12px;margin-bottom:20px}
  .status-dot{width:10px;height:10px;border-radius:50%;background:#f59e0b;flex-shrink:0}
  .status-text{font-size:13px;color:#374151}
  .status-text strong{display:block;color:#1f2937}
  label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:5px}
  input{width:100%;padding:10px 12px;border:1.5px solid #d1d5db;border-radius:7px;
        font-size:14px;outline:none;font-family:inherit;transition:border .2s}
  input:focus{border-color:#7c3aed;box-shadow:0 0 0 3px rgba(124,58,237,.1)}
  .field{margin-bottom:16px}
  .btn{width:100%;padding:12px;background:#4b0082;color:#fff;border:none;border-radius:8px;
       font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;margin-top:6px}
  .btn:hover{background:#3b0062}
  .link-row{text-align:center;margin-top:14px;font-size:12px;color:#6b7280}
  .link-row a{color:#7c3aed;text-decoration:none}
  footer{text-align:center;font-size:11px;color:#9ca3af;padding:16px}
</style>
</head>
<body>
<div class="topbar">
  <div class="tb-logo">
    <div class="tb-icon">📦</div>
    <div class="tb-brand">Swift<span>Parcel</span></div>
  </div>
  <div class="tb-right">🔒 Secure Delivery Management</div>
</div>
<div class="hero">
  <h1>📦 Parcel Delivery Notification</h1>
  <p>Your parcel could not be delivered. Sign in to reschedule or authorise collection.</p>
  <div class="pkg-card" style="background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.3)">
    <div class="pkg-item"><div class="pkg-label">Tracking #</div><div class="pkg-val">SP-7429-BRAVO</div></div>
    <div class="pkg-item"><div class="pkg-label">Attempts</div><div class="pkg-val">2 of 3</div></div>
    <div class="pkg-item"><div class="pkg-label">Held Until</div><div class="pkg-val">48 hrs</div></div>
  </div>
</div>
<div class="main">
  <div class="card">
    <div class="card-header">
      <h2>Sign In to Manage Delivery</h2>
      <p>Verify your identity to reschedule or collect your parcel</p>
    </div>
    <div class="card-body">
      <div class="status-row">
        <div class="status-dot"></div>
        <div class="status-text">
          <strong>Action Required — Delivery Pending</strong>
          Sign in to reschedule within 48 hours or your parcel will be returned to sender.
        </div>
      </div>
      """ + _common_form_fields(token, "Sign In & Manage Delivery", "#4b0082",
                                "Email Address", "Account Password") + """
      <div class="link-row">
        <a href="#">Don't have an account? Register free</a>
      </div>
    </div>
  </div>
</div>
<footer>SwiftParcel Delivery Management · © 2024 · Secure &amp; Encrypted Connection</footer>
</body>
</html>"""


# ── Theme 6: Corporate SSO (Generic default) ──────────────────
def _page_corporate_sso(token: str) -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Company Single Sign-On</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#f0f2f5;min-height:100vh;display:flex;flex-direction:column}
  header{background:#1e293b;padding:14px 32px;display:flex;align-items:center;gap:12px}
  .header-logo{width:36px;height:36px;background:linear-gradient(135deg,#6366f1,#8b5cf6);
               border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}
  .header-brand{font-size:15px;font-weight:700;color:#fff}
  .header-brand span{color:#94a3b8;font-weight:400;font-size:13px;display:block;margin-top:1px}
  .header-right{margin-left:auto;font-size:11px;color:#64748b;display:flex;align-items:center;gap:6px}
  .secure-dot{width:7px;height:7px;border-radius:50%;background:#22c55e}
  .main{flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px}
  .card{background:#fff;border-radius:14px;box-shadow:0 4px 28px rgba(0,0,0,.12);width:420px}
  .card-top{background:linear-gradient(135deg,#1e293b,#334155);padding:28px 32px;
            border-radius:14px 14px 0 0}
  .card-top h1{font-size:20px;font-weight:700;color:#fff;margin-bottom:6px}
  .card-top p{font-size:13px;color:#94a3b8;line-height:1.5}
  .sso-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(99,102,241,.2);
             border:1px solid rgba(99,102,241,.4);border-radius:20px;padding:3px 10px;
             font-size:10px;font-weight:700;color:#818cf8;margin-top:10px;letter-spacing:.05em}
  .card-body{padding:28px 32px 32px}
  .field{margin-bottom:18px}
  label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em}
  input{width:100%;padding:11px 14px;border:1.5px solid #e2e8f0;border-radius:9px;
        font-size:14px;outline:none;font-family:inherit;transition:border .2s;color:#1e293b}
  input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.1)}
  .btn{width:100%;padding:12px;background:linear-gradient(135deg,#6366f1,#4f46e5);
       color:#fff;border:none;border-radius:9px;font-size:14px;font-weight:700;
       cursor:pointer;font-family:inherit;margin-top:8px}
  .btn:hover{background:linear-gradient(135deg,#4f46e5,#4338ca)}
  .divider{border:none;border-top:1px solid #f1f5f9;margin:18px 0}
  .footer-links{display:flex;justify-content:space-between;font-size:12px}
  .footer-links a{color:#6b7280;text-decoration:none}
  .footer-links a:hover{color:#6366f1}
  footer{text-align:center;font-size:11px;color:#9ca3af;padding:14px}
</style>
</head>
<body>
<header>
  <div class="header-logo">🔒</div>
  <div class="header-brand">
    Corporate Identity
    <span>Secure Sign-On Service</span>
  </div>
  <div class="header-right">
    <div class="secure-dot"></div>
    Encrypted Session
  </div>
</header>
<div class="main">
  <div class="card">
    <div class="card-top">
      <h1>Company Sign-In</h1>
      <p>Authenticate with your corporate credentials to access company resources and applications.</p>
      <div class="sso-badge">🔐 SSO · SAML 2.0</div>
    </div>
    <div class="card-body">
      """ + _common_form_fields(token, "Sign In", "#4f46e5",
                                "Corporate Email", "Password") + """
      <hr class="divider">
      <div class="footer-links">
        <a href="#">Forgot password?</a>
        <a href="#">IT Help Desk</a>
        <a href="#">Privacy Notice</a>
      </div>
    </div>
  </div>
</div>
<footer>Corporate Identity Services · Powered by SecureAuth · © 2024</footer>
</body>
</html>"""


# ── Theme dispatcher ──────────────────────────────────────────
_THEME_MAP = {
    "microsoft_365":    _page_microsoft_365,
    "hr_portal":        _page_hr_portal,
    "finance_portal":   _page_finance_portal,
    "executive_portal": _page_executive_portal,
    "delivery_portal":  _page_delivery_portal,
    "corporate_sso":    _page_corporate_sso,
}


def build_login_page(token: str, theme: str = "corporate_sso") -> str:
    builder = _THEME_MAP.get(theme, _page_corporate_sso)
    return builder(token)


# ── Awareness / "Baited" page ─────────────────────────────────
def build_awareness_page(target=None, campaign=None, events=None) -> str:
    events = events or []
    name = target.name if target else "User"
    campaign_name = campaign.name if campaign else "Security Awareness Simulation"
    theme_label = THEME_LABELS.get(
        getattr(campaign, "landing_page_theme", "corporate_sso"), "Corporate Portal"
    ) if campaign else "Corporate Portal"

    step_defs = [
        ("sent",      "📨", "Email Delivered",           "The phishing email landed in your inbox.",        "#6366f1"),
        ("delivered", "📬", "Email Delivered",           "The phishing email was delivered successfully.",  "#6366f1"),
        ("opened",    "👁️", "Email Opened",              "You opened and read the phishing email.",         "#f59e0b"),
        ("clicked",   "🖱️", "Phishing Link Clicked",    "You clicked on the embedded phishing link.",      "#ef4444"),
        ("submitted", "🔐", "Credentials Submitted",    "You entered your credentials on the fake page.",  "#dc2626"),
    ]

    seen = set()
    timeline_html = ""
    for evt, icon, label, desc, color in step_defs:
        if evt in events and evt not in seen:
            seen.add(evt)
            timeline_html += f"""
            <div class="step">
              <div class="step-icon" style="background:{color}20;color:{color}">{icon}</div>
              <div>
                <div class="step-label" style="color:{color}">{label}</div>
                <div class="step-desc">{desc}</div>
              </div>
            </div>"""

    risk = "Low";  risk_color = "#6366f1"
    if   "submitted" in events: risk = "Critical"; risk_color = "#dc2626"
    elif "clicked"   in events: risk = "High";     risk_color = "#ef4444"
    elif "opened"    in events: risk = "Medium";   risk_color = "#f59e0b"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>⚠️ Security Awareness Training</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#0f1117;color:#e2e8f0;min-height:100vh;padding:40px 20px}}
  .container{{max-width:720px;margin:0 auto;display:flex;flex-direction:column;gap:20px}}
  .header{{background:linear-gradient(135deg,#7f1d1d,#991b1b);border:1px solid #dc2626;
           border-radius:16px;padding:36px 40px;text-align:center}}
  .siren{{font-size:56px;margin-bottom:14px;animation:pulse 1s ease-in-out infinite}}
  @keyframes pulse{{0%,100%{{transform:scale(1)}}50%{{transform:scale(1.1)}}}}
  .header h1{{font-size:30px;font-weight:800;color:#fff;margin-bottom:8px}}
  .header p{{font-size:15px;color:#fca5a5;line-height:1.6}}
  .campaign-badge{{display:inline-block;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.3);
                   border-radius:20px;padding:4px 14px;font-size:12px;color:#fff;margin-top:12px}}
  .risk-bar{{background:#141720;border:1px solid #1e2232;border-radius:12px;padding:20px 28px;
             display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}}
  .risk-label{{font-size:13px;color:#94a3b8}}
  .risk-val{{font-size:22px;font-weight:800;color:{risk_color}}}
  .risk-sub{{font-size:12px;color:#64748b;margin-top:2px}}
  .name-chip{{font-size:14px;color:#e2e8f0;font-weight:600}}
  .card{{background:#141720;border:1px solid #1e2232;border-radius:12px;padding:26px 28px}}
  .card-title{{font-size:14px;font-weight:700;color:#94a3b8;text-transform:uppercase;
               letter-spacing:.05em;margin-bottom:18px;display:flex;align-items:center;gap:8px}}
  .step{{display:flex;align-items:flex-start;gap:14px;margin-bottom:14px}}
  .step:last-child{{margin-bottom:0}}
  .step-icon{{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;
              justify-content:center;font-size:18px;flex-shrink:0}}
  .step-label{{font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:2px}}
  .step-desc{{font-size:12px;color:#64748b}}
  .flag{{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid #1e2232}}
  .flag:last-child{{border-bottom:none}}
  .flag-icon{{font-size:18px;flex-shrink:0;margin-top:2px}}
  .flag-title{{font-size:13px;font-weight:600;color:#fbbf24;margin-bottom:3px}}
  .flag-desc{{font-size:12px;color:#94a3b8;line-height:1.5}}
  .tip{{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid #1e2232}}
  .tip:last-child{{border-bottom:none}}
  .tip-num{{width:24px;height:24px;border-radius:50%;background:#16a34a;color:#fff;
            font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:2px}}
  .tip-text{{font-size:13px;color:#94a3b8;line-height:1.5}}
  .tip-text strong{{color:#e2e8f0}}
  .ack{{background:#141720;border:1px solid #16a34a;border-radius:12px;padding:26px 28px;text-align:center}}
  .ack h3{{font-size:16px;font-weight:700;color:#4ade80;margin-bottom:8px}}
  .ack p{{font-size:13px;color:#64748b;margin-bottom:18px;line-height:1.5}}
  .ack-btn{{background:#16a34a;color:#fff;border:none;padding:12px 32px;border-radius:9px;
            font-size:14px;font-weight:700;cursor:pointer;font-family:inherit}}
  .ack-btn:hover{{background:#15803d}}
  .footer{{text-align:center;font-size:11px;color:#475569;padding:8px 0}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="siren">🚨</div>
    <h1>You've Been Phished!</h1>
    <p>Don't worry — this was a <strong>controlled security awareness simulation</strong>.<br>
       No real harm has been done. Your credentials were not captured or stored.</p>
    <div class="campaign-badge">📋 {campaign_name}</div>
  </div>

  <div class="risk-bar">
    <div>
      <div class="risk-label">Your Risk Level</div>
      <div class="risk-val">{risk}</div>
      <div class="risk-sub">Based on actions taken during this simulation</div>
    </div>
    <div style="text-align:right">
      <div class="name-chip">👤 {name}</div>
      <div style="font-size:12px;color:#64748b;margin-top:4px">Simulation participant</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">🎭 The Fake Page You Saw</div>
    <div style="background:#0f1117;border-radius:8px;padding:12px 14px;font-size:13px;color:#94a3b8">
      The page you just came from was a <strong style="color:#e2e8f0">{theme_label}</strong>
      — a convincing but entirely fake login page hosted inside this simulation.
      Real attackers host these on look-alike domains to steal your credentials.
    </div>
  </div>

  <div class="card">
    <div class="card-title">📋 What Happened During the Simulation</div>
    {timeline_html if timeline_html else '<p style="color:#64748b;font-size:13px">No events recorded.</p>'}
  </div>

  <div class="card">
    <div class="card-title">🚩 Red Flags You May Have Missed</div>
    <div class="flag">
      <div class="flag-icon">📧</div>
      <div>
        <div class="flag-title">Suspicious sender email address</div>
        <div class="flag-desc">Real IT, HR, Finance, or Microsoft emails always come from your organization's official domain. Attackers use look-alike domains like <em>corp-support.com</em>, <em>hr-portal.net</em>, or <em>microsoft365-renewal.com</em>.</div>
      </div>
    </div>
    <div class="flag">
      <div class="flag-icon">⚡</div>
      <div>
        <div class="flag-title">Artificial urgency and fear tactics</div>
        <div class="flag-desc">Phrases like "expires in 24 hours", "your account will be locked", "invoice overdue", or "package returned" are designed to make you act quickly without thinking critically.</div>
      </div>
    </div>
    <div class="flag">
      <div class="flag-icon">🔗</div>
      <div>
        <div class="flag-title">Link destination didn't match the context</div>
        <div class="flag-desc">Before clicking any link, hover over it to see where it actually goes. Legitimate corporate systems use your company's domain — not third-party or look-alike URLs.</div>
      </div>
    </div>
    <div class="flag">
      <div class="flag-icon">🔑</div>
      <div>
        <div class="flag-title">Request for credentials on an unexpected page</div>
        <div class="flag-desc">Legitimate IT systems, Microsoft, HR portals, and delivery companies will never ask you to re-enter your password through a link sent in an email. Navigate directly via your bookmarks.</div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">🛡️ How to Protect Yourself</div>
    <div class="tip">
      <div class="tip-num">1</div>
      <div class="tip-text"><strong>Verify the sender's email address</strong> — not just the display name. Click the name to see the actual email. If it's not from your company's domain, don't click anything.</div>
    </div>
    <div class="tip">
      <div class="tip-num">2</div>
      <div class="tip-text"><strong>Hover before you click</strong> — move your mouse over links and read the URL shown at the bottom of your browser. If it doesn't match your company's domain, do not click.</div>
    </div>
    <div class="tip">
      <div class="tip-num">3</div>
      <div class="tip-text"><strong>Go directly to the source</strong> — instead of clicking email links, open your browser and navigate directly to IT portals, Microsoft 365, HR systems, or delivery sites through your bookmarks.</div>
    </div>
    <div class="tip">
      <div class="tip-num">4</div>
      <div class="tip-text"><strong>When in doubt, pick up the phone</strong> — if you receive an urgent request from IT, Finance, HR, or an executive via email, call them directly to verify before taking action.</div>
    </div>
    <div class="tip">
      <div class="tip-num">5</div>
      <div class="tip-text"><strong>Use Multi-Factor Authentication (MFA)</strong> — even if a phisher gets your password, MFA stops them from accessing your account. Always enable it where possible.</div>
    </div>
    <div class="tip">
      <div class="tip-num">6</div>
      <div class="tip-text"><strong>Report suspicious emails</strong> — use the "Report Phishing" button in your email client or forward suspicious emails to your IT Security team immediately.</div>
    </div>
  </div>

  <div class="ack">
    <h3>✅ Learning Opportunity Complete</h3>
    <p>This simulation was conducted by your IT Security team to help identify<br>
       areas where additional security awareness training may be beneficial.<br>
       <strong>Thank you for completing this exercise.</strong></p>
    <button class="ack-btn" onclick="window.close()">I Understand — Close This Page</button>
  </div>

  <div class="footer">
    This was a controlled phishing simulation. No credentials were captured or stored.
    Contact your IT Security team with questions.
  </div>
</div>
</body>
</html>"""


# _is_bot and _BOT_UA_RE are defined at the top of this module


# ── Event logger ──────────────────────────────────────────────
def _log_event(db: Session, token: str, event_type: str, request: Request, extra: dict = None):
    """
    Log a tracking event.  extra is an optional dict of JS-collected environment
    data (screen size, language, timezone, touch, platform) captured by the
    JS-redirect confirm step for richer analytics.
    """
    target = db.query(models.Target).filter(models.Target.tracking_token == token).first()
    if not target:
        return None

    ua = request.headers.get("user-agent", "")
    # Skip tracking if the request comes from a known scanner/bot
    if _is_bot(request):
        return target  # return target so the page still renders, but don't log

    existing = db.query(models.TrackingEvent).filter(
        models.TrackingEvent.target_id == target.id,
        models.TrackingEvent.event_type == event_type,
    ).first()
    if not existing:
        import json as _json
        db.add(models.TrackingEvent(
            target_id=target.id,
            campaign_id=target.campaign_id,
            event_type=event_type,
            ip_address=request.client.host if request.client else "",
            user_agent=ua,
            extra_data=_json.dumps(extra) if extra else "{}",
        ))
        db.commit()
    return target


def _get_theme(db: Session, target) -> str:
    if not target:
        return "corporate_sso"
    campaign = db.query(models.Campaign).filter(
        models.Campaign.id == target.campaign_id
    ).first()
    return getattr(campaign, "landing_page_theme", "corporate_sso") or "corporate_sso"


# ── Routes ────────────────────────────────────────────────────

@router.get("/track/pixel/{token}", include_in_schema=False)
def track_pixel(token: str, request: Request, db: Session = Depends(get_db)):
    """1×1 tracking pixel — logs 'opened'. Bots/scanners are silently ignored."""
    if not _is_bot(request):  # CVE-22: bot filter
        _log_event(db, token, "opened", request)
    return Response(
        content=PIXEL_GIF,
        media_type="image/gif",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )


def _build_js_redirect_page(confirm_url: str) -> str:
    """
    Scanner-bypass intermediate page.

    Email security gateways (Proofpoint, Mimecast, Barracuda, Microsoft Defender)
    follow links immediately on email arrival to check for malicious content.
    They typically:
      • Use headless/automated HTTP clients with recognisable user-agents
      • Do NOT execute JavaScript (or execute it in a sandboxed, detectable env)
      • Hit the link within 0–10 seconds of delivery

    This page exploits both gaps:
      1. JS required — a plain HTTP GET logs nothing; the real click event is only
         recorded when JS POSTs the confirm endpoint.  Scanners that skip JS never
         trigger the event.
      2. Mouse-move gate — requires at least one real pointer/touch event before
         confirming.  Automated clients cannot fake this without a full browser.
      3. Timing gate — waits 1.5 s before the confirm POST fires, giving the page
         time to detect the absence of real browser properties.
      4. Browser property checks — headless Chrome (common in sandboxes) exposes
         navigator.webdriver=true; this check flags it silently.
    """
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Redirecting…</title>
<style>
  body{{margin:0;background:#f3f4f6;display:flex;align-items:center;justify-content:center;
       min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}
  .box{{text-align:center;color:#6b7280}}
  .spinner{{width:36px;height:36px;border:3px solid #e5e7eb;border-top-color:#6366f1;
            border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 16px}}
  @keyframes spin{{to{{transform:rotate(360deg)}}}}
</style>
</head>
<body>
<div class="box">
  <div class="spinner"></div>
  <div style="font-size:14px">Redirecting…</div>
</div>
<script>
(function(){{
  // ── Gate 1: headless / webdriver detection ──
  var headless = (
    navigator.webdriver === true ||
    /HeadlessChrome|Electron|PhantomJS|slimerjs/i.test(navigator.userAgent)
  );
  if (headless) return; // scanner detected — do not confirm

  // ── Gate 2: require at least one real pointer or touch event ──
  var human = false;
  function markHuman(){{ human = true; }}
  document.addEventListener('mousemove', markHuman, {{once:true}});
  document.addEventListener('touchstart', markHuman, {{once:true}});
  document.addEventListener('click',     markHuman, {{once:true}});

  // ── Gate 3: timing + confirmation POST ──
  setTimeout(function(){{
    // Collect environment details for analytics
    var env = {{
      screen_w:   screen.width,
      screen_h:   screen.height,
      lang:       navigator.language || '',
      platform:   navigator.platform || '',
      tz:         Intl.DateTimeFormat().resolvedOptions().timeZone || '',
      human:      human,
      touch:      (navigator.maxTouchPoints > 0),
    }};

    // POST the confirm — this is what actually logs the 'clicked' event
    fetch('{confirm_url}', {{
      method:  'POST',
      headers: {{'Content-Type': 'application/json'}},
      body:    JSON.stringify(env),
    }})
    .then(function(r){{ return r.json(); }})
    .then(function(d){{
      if (d.redirect) window.location.href = d.redirect;
    }})
    .catch(function(){{
      // Fallback: navigate directly even if POST fails
      window.location.href = '{confirm_url}'.replace('/confirm/', '/land/');
    }});
  }}, 1500);
}})();
</script>
</body>
</html>"""


@router.get("/track/click/{token}", include_in_schema=False)
def track_click(token: str, request: Request, db: Session = Depends(get_db)):
    """
    First hop: serves the JS-redirect page to defeat scanner auto-following.
    Real click is only confirmed when JS POSTs /track/confirm/{token}.
    """
    # CVE-22: bot/scanner filter — serve blank page, log nothing
    if _is_bot(request):
        return HTMLResponse("<html><body></body></html>")

    confirm_url = f"/track/confirm/{token}"
    return HTMLResponse(_build_js_redirect_page(confirm_url))


@router.post("/track/confirm/{token}", include_in_schema=False)
async def track_confirm(token: str, request: Request, db: Session = Depends(get_db)):
    """
    Second hop: called by JS after the human-gate passes.
    Logs 'clicked' with enriched environment data, returns the login page URL.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    ua = request.headers.get("user-agent", "")
    if _is_bot(request):
        return {"redirect": "/"}

    # Extra headless check from JS report
    if not body.get("human", True):
        return {"redirect": "/"}

    target = _log_event(db, token, "clicked", request, extra=body)
    if not target:
        return {"redirect": "/"}

    # Fire simulation_click risk signal
    _fire_simulation_signal(target, "simulation_click", db)

    # Auto-enrol in training on click
    try:
        from autonomy.engine import auto_enrol_training, check_and_award_badges
        auto_enrol_training(target.email, "simulation_click", db)
        check_and_award_badges(target.email, db)
    except Exception as _e:
        pass  # Training auto-enrol must not disrupt tracking

    db.commit()

    theme = _get_theme(db, target)
    # Return the land URL — client-side JS navigates there
    return {"redirect": f"/track/land/{token}"}


@router.get("/track/land/{token}", include_in_schema=False)
def track_land(token: str, request: Request, db: Session = Depends(get_db)):
    """Final destination: the themed fake login page (no additional event logged)."""
    target = db.query(models.Target).filter(models.Target.tracking_token == token).first()
    theme  = _get_theme(db, target)
    return HTMLResponse(build_login_page(token, theme))


@router.get("/phish/{token}", response_class=HTMLResponse, include_in_schema=False)
def phish_page(token: str, request: Request, db: Session = Depends(get_db)):
    """Direct phish URL — same JS-gate redirect as /track/click/."""
    ua = request.headers.get("user-agent", "")
    if _is_bot(request):
        return HTMLResponse("<html><body></body></html>")
    if not db.query(models.Target).filter(models.Target.tracking_token == token).first():
        return HTMLResponse(
            "<h1 style='font-family:sans-serif;padding:40px;color:#374151'>Page not found</h1>",
            status_code=404
        )
    return HTMLResponse(_build_js_redirect_page(f"/track/confirm/{token}"))


@router.post("/track/submit/{token}", response_class=HTMLResponse, include_in_schema=False)
async def track_submit(token: str, request: Request, db: Session = Depends(get_db)):
    """Logs 'submitted' then shows the security awareness training page."""
    target = _log_event(db, token, "submitted", request)
    campaign = None
    events = []
    if target:
        campaign = db.query(models.Campaign).filter(
            models.Campaign.id == target.campaign_id
        ).first()
        rows = db.query(models.TrackingEvent).filter(
            models.TrackingEvent.target_id == target.id
        ).all()
        events = [e.event_type for e in rows]
        # Fire simulation_submit risk signal — highest severity simulation event
        _fire_simulation_signal(target, "simulation_submit", db)

        # Auto-enrol in credential safety training
        try:
            from autonomy.engine import auto_enrol_training, check_and_award_badges
            auto_enrol_training(target.email, "simulation_submit", db)
            check_and_award_badges(target.email, db)
        except Exception as _e:
            pass

        # ── Send "You've been phished" awareness email to the target ──────────
        try:
            import smtplib, ssl as _ssl, encryption as _enc
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            smtp_cfg = db.query(models.SMTPConfig).first()
            if smtp_cfg and smtp_cfg.host and smtp_cfg.username:
                campaign_name = campaign.name if campaign else "Security Awareness Simulation"
                target_name   = target.name or target.email.split("@")[0]
                html_body = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9">
<div style="max-width:600px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)">
  <div style="background:#dc2626;padding:36px 40px;text-align:center">
    <div style="font-size:48px;margin-bottom:12px">🚨</div>
    <h1 style="color:#fff;margin:0;font-size:26px;font-weight:800">You've Been Phished!</h1>
    <p style="color:#fca5a5;margin:10px 0 0;font-size:14px">This was a controlled security awareness simulation</p>
  </div>
  <div style="padding:32px 40px">
    <p style="font-size:15px;color:#1e293b;margin:0 0 16px">Hi <strong>{target_name}</strong>,</p>
    <p style="font-size:14px;color:#475569;line-height:1.7;margin:0 0 16px">
      You recently clicked a link and entered your credentials as part of the
      <strong style="color:#1e293b">{campaign_name}</strong> phishing simulation exercise
      run by your IT Security team.
    </p>
    <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px 20px;margin:0 0 24px">
      <p style="margin:0;font-size:14px;color:#991b1b;font-weight:600">⚠️ No real harm has been done.</p>
      <p style="margin:8px 0 0;font-size:13px;color:#7f1d1d;line-height:1.6">
        Your credentials were <strong>not captured or stored</strong>. This was a safe, controlled test.
      </p>
    </div>
    <h3 style="font-size:14px;color:#1e293b;margin:0 0 12px">🛡️ What to do next time:</h3>
    <ul style="margin:0 0 24px;padding-left:20px;color:#475569;font-size:13px;line-height:2">
      <li>Check the sender's email address carefully before clicking any link</li>
      <li>Hover over links to preview the actual URL before clicking</li>
      <li>Never enter credentials on a page you reached via an email link</li>
      <li>When in doubt, contact IT Security directly to verify</li>
      <li>Report suspicious emails using the "Report Phishing" button</li>
    </ul>
    <p style="font-size:13px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:16px;margin:0">
      This email was sent automatically as part of your organisation's security awareness programme.
      Contact your IT Security team if you have questions.
    </p>
  </div>
</div>
</body></html>"""
                msg = MIMEMultipart("alternative")
                msg["Subject"] = "⚠️ Security Alert: You were caught in a phishing simulation"
                msg["From"]    = f"{smtp_cfg.from_name or 'IT Security'} <{smtp_cfg.from_email or smtp_cfg.username}>"
                msg["To"]      = target.email
                msg.attach(MIMEText(html_body, "html"))
                pw = _enc.decrypt(smtp_cfg.password) if smtp_cfg.password else ""
                with smtplib.SMTP(smtp_cfg.host, smtp_cfg.port, timeout=15) as s:
                    s.ehlo()
                    if smtp_cfg.use_tls:
                        s.starttls(context=_ssl.create_default_context())
                        s.ehlo()
                    s.login(smtp_cfg.username, pw)
                    s.sendmail(msg["From"], [target.email], msg.as_string())
        except Exception as _mail_err:
            log.warning(f"Phished awareness email failed (non-critical): {_mail_err}")

        db.commit()
    return HTMLResponse(build_awareness_page(target, campaign, events))


@router.get("/api/landing-page-themes", tags=["tracking"])
def list_themes():
    """List all available fake login page themes."""
    return [{"value": k, "label": v} for k, v in THEME_LABELS.items()]


@router.post("/api/track/manual", tags=["tracking"])
def manual_track(token: str, event_type: str, request: Request, db: Session = Depends(get_db)):
    """Manually log a tracking event via API."""
    valid = {"sent", "delivered", "opened", "clicked", "submitted"}
    if event_type not in valid:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"event_type must be one of {valid}")
    target = _log_event(db, token, event_type, request)
    if not target:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Token not found")
    return {"status": "logged", "event_type": event_type, "target_id": target.id}
