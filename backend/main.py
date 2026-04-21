import logging
import logging.handlers
import os
from datetime import datetime, timedelta

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from database import engine, Base, SessionLocal
import models  # noqa: F401
from routers import campaigns, tracking, analytics, templates, settings, ai as ai_router, auth as auth_router
from routers import risk as risk_router
from routers import approvals as approvals_router
from routers import threat_intel as threat_intel_router
from routers import autonomy as autonomy_router
from routers import compliance as compliance_router

# ── Structured logging (CVE-16 fix) ──────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            os.path.join(LOG_DIR, "phishsim.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
        ),
    ],
)
log = logging.getLogger("phishsim")

# ── Create DB tables ──────────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# ── Enable WAL mode (CVE-15 fix — better concurrency, prevents corruption) ────
def _enable_wal():
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.execute(text("PRAGMA synchronous=NORMAL"))
            conn.execute(text("PRAGMA foreign_keys=ON"))
            conn.commit()
        log.info("SQLite WAL mode enabled.")
    except Exception as e:
        log.warning(f"Could not enable WAL mode: {e}")

_enable_wal()

# ── DB migrations ─────────────────────────────────────────────────────────────
def _migrate_db():
    from sqlalchemy import text
    migrations = [
        "ALTER TABLE campaigns ADD COLUMN landing_page_theme VARCHAR DEFAULT 'corporate_sso'",
        "ALTER TABLE campaigns ADD COLUMN scheduled_at DATETIME",
        "ALTER TABLE campaigns ADD COLUMN auto_complete_at DATETIME",
        "ALTER TABLE campaigns ADD COLUMN tags VARCHAR DEFAULT ''",
        "ALTER TABLE campaigns ADD COLUMN status_note VARCHAR DEFAULT ''",
        "ALTER TABLE targets ADD COLUMN email_sent_at DATETIME",
        "ALTER TABLE smtp_config ADD COLUMN base_url VARCHAR DEFAULT 'http://localhost:8000'",
        "ALTER TABLE smtp_config ADD COLUMN send_delay_seconds REAL DEFAULT 1.5",
        "ALTER TABLE smtp_config ADD COLUMN max_per_minute INTEGER DEFAULT 30",
        "ALTER TABLE targets ADD COLUMN send_failed BOOLEAN DEFAULT 0",
        "ALTER TABLE targets ADD COLUMN send_error VARCHAR DEFAULT ''",
        "ALTER TABLE tracking_events ADD COLUMN event_category VARCHAR DEFAULT 'behavioral'",
        # Risk engine tables are created by SQLAlchemy Base.metadata.create_all()
        # These are safety-net column additions for any manual DB edits
        "ALTER TABLE employee_risk_scores ADD COLUMN gateway_points REAL DEFAULT 0.0",
        "ALTER TABLE employee_risk_scores ADD COLUMN breach_points REAL DEFAULT 0.0",
        "ALTER TABLE employee_risk_scores ADD COLUMN last_breach_check DATETIME",
        # Approval workflow tables (created by SQLAlchemy, these are safety-net additions)
        "ALTER TABLE campaign_approvals ADD COLUMN approver_name VARCHAR DEFAULT ''",
        "ALTER TABLE approval_config ADD COLUMN updated_at DATETIME",
        # Audit log & notification tables
        "ALTER TABLE audit_log ADD COLUMN ip_address VARCHAR DEFAULT ''",
        "ALTER TABLE notification_config ADD COLUMN updated_at DATETIME",
        # Template difficulty (Phase 3)
        "ALTER TABLE email_templates ADD COLUMN difficulty INTEGER DEFAULT 2",
        # Phase 3-5 tables are created by SQLAlchemy Base.metadata.create_all()
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                pass

_migrate_db()

# ── Seed built-in templates ───────────────────────────────────────────────────
def startup_seed():
    db = SessionLocal()
    try:
        templates.seed_builtin_templates(db)
    finally:
        db.close()

startup_seed()

# ── Seed default admin (idempotent) ──────────────────────────────────────────
def seed_admin():
    from routers.auth import _store_hash
    db = SessionLocal()
    try:
        if not db.query(models.User).first():
            admin = models.User(
                username="admin",
                email="",
                password_hash=_store_hash("admin123"),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            # CVE-14: Never log credentials
            log.warning("Default admin created — change the password immediately after first login.")
    finally:
        db.close()

seed_admin()

# ── APScheduler ───────────────────────────────────────────────────────────────
_SCHEDULER_AVAILABLE = False
scheduler = None

def _launch_campaign_job(campaign_id: int):
    db = SessionLocal()
    try:
        campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
        if campaign and campaign.status == "scheduled":
            campaign.status = "active"
            campaign.launched_at = datetime.utcnow()
            db.commit()
            log.info(f"Campaign {campaign_id} auto-launched.")
            if campaign.auto_complete_at:
                _schedule_auto_complete(campaign_id, campaign.auto_complete_at)
    finally:
        db.close()

def _complete_campaign_job(campaign_id: int):
    db = SessionLocal()
    try:
        campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
        if campaign and campaign.status == "active":
            campaign.status = "completed"
            campaign.completed_at = datetime.utcnow()
            db.commit()
            log.info(f"Campaign {campaign_id} auto-completed.")
    finally:
        db.close()

def _schedule_auto_launch(campaign_id: int, run_at: datetime):
    if not scheduler:
        return
    scheduler.add_job(
        _launch_campaign_job, trigger="date", run_date=run_at,
        args=[campaign_id], id=f"launch_{campaign_id}", replace_existing=True,
    )

def _schedule_auto_complete(campaign_id: int, run_at: datetime):
    if not scheduler:
        return
    scheduler.add_job(
        _complete_campaign_job, trigger="date", run_date=run_at,
        args=[campaign_id], id=f"complete_{campaign_id}", replace_existing=True,
    )

def _session_cleanup_job():
    """Purge expired sessions hourly — CVE-10 fix."""
    db = SessionLocal()
    try:
        deleted = db.query(models.UserSession).filter(
            models.UserSession.expires_at < datetime.utcnow()
        ).delete()
        db.commit()
        if deleted:
            log.info(f"Session cleanup: removed {deleted} expired sessions.")
    except Exception as e:
        log.error(f"Session cleanup error: {e}")
    finally:
        db.close()

def restore_scheduled_jobs():
    if not scheduler:
        return
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        scheduled = db.query(models.Campaign).filter(models.Campaign.status == "scheduled").all()
        for c in scheduled:
            if c.scheduled_at and c.scheduled_at > now:
                _schedule_auto_launch(c.id, c.scheduled_at)
            elif c.scheduled_at and c.scheduled_at <= now:
                c.status = "active"
                c.launched_at = now
                db.commit()
                if c.auto_complete_at and c.auto_complete_at > now:
                    _schedule_auto_complete(c.id, c.auto_complete_at)
        active = db.query(models.Campaign).filter(
            models.Campaign.status == "active",
            models.Campaign.auto_complete_at != None  # noqa: E711
        ).all()
        for c in active:
            if c.auto_complete_at and c.auto_complete_at > now:
                _schedule_auto_complete(c.id, c.auto_complete_at)
            elif c.auto_complete_at and c.auto_complete_at <= now:
                c.status = "completed"
                c.completed_at = now
                db.commit()
    finally:
        db.close()

try:
    from apscheduler.schedulers.background import BackgroundScheduler as _BgSched
    scheduler = _BgSched(timezone="UTC")
    scheduler.start()
    _SCHEDULER_AVAILABLE = True
    restore_scheduled_jobs()
    scheduler.add_job(_session_cleanup_job, trigger="interval", hours=1, id="session_cleanup")

    # ── Risk Engine scheduled jobs ────────────────────────────────────────────
    def _risk_decay_job():
        db = SessionLocal()
        try:
            from risk_engine import core as risk_core
            affected = risk_core.apply_decay(db)
            log.info(f"Risk decay job: {affected} employees updated")
        except Exception as e:
            log.error(f"Risk decay job error: {e}")
        finally:
            db.close()

    def _gateway_sync_job():
        db = SessionLocal()
        try:
            from risk_engine import gateway_sync
            result = gateway_sync.run_gateway_sync(db)
            log.info(f"Gateway sync job: {result}")
        except Exception as e:
            log.error(f"Gateway sync job error: {e}")
        finally:
            db.close()

    def _breach_scan_job():
        db = SessionLocal()
        try:
            from risk_engine import breach_monitor
            result = breach_monitor.run_full_scan(db)
            log.info(f"Breach scan job: {result}")
        except Exception as e:
            log.error(f"Breach scan job error: {e}")
        finally:
            db.close()

    scheduler.add_job(_risk_decay_job,   trigger="interval", days=1,   id="risk_decay")
    scheduler.add_job(_gateway_sync_job, trigger="interval", hours=1,  id="gateway_sync")
    scheduler.add_job(_breach_scan_job,  trigger="interval", days=7,   id="breach_scan")

    # ── Threat Intel + Autonomy Engine jobs ───────────────────────────────────
    def _threat_intel_sync_job():
        db = SessionLocal()
        try:
            from threat_intel.feeds import run_feed_sync
            result = run_feed_sync(db)
            log.info(f"Threat intel sync job: {result}")
        except Exception as e:
            log.error(f"Threat intel sync job error: {e}")
        finally:
            db.close()

    def _autonomy_cycle_job():
        db = SessionLocal()
        try:
            from autonomy.engine import run_autonomy_cycle
            result = run_autonomy_cycle(db)
            log.info(f"Autonomy cycle job: {result}")
        except Exception as e:
            log.error(f"Autonomy cycle job error: {e}")
        finally:
            db.close()

    def _leaderboard_refresh_job():
        db = SessionLocal()
        try:
            from autonomy.engine import refresh_leaderboard
            count = refresh_leaderboard(db)
            log.info(f"Leaderboard refreshed: {count} entries")
        except Exception as e:
            log.error(f"Leaderboard refresh job error: {e}")
        finally:
            db.close()

    scheduler.add_job(_threat_intel_sync_job,  trigger="interval", hours=6,    id="threat_intel_sync")
    scheduler.add_job(_autonomy_cycle_job,     trigger="interval", hours=24,   id="autonomy_cycle")
    scheduler.add_job(_leaderboard_refresh_job,trigger="cron",     day=1, hour=3, id="leaderboard_refresh")

    # Start syslog listener if gateway is configured for syslog
    def _maybe_start_syslog():
        db = SessionLocal()
        try:
            cfg = db.query(models.GatewayConfig).first()
            if cfg and cfg.enabled and cfg.gateway_type == "syslog":
                from risk_engine.gateway_adapters.syslog_listener import start_listener
                start_listener(cfg.syslog_port or 5140)
        except Exception as e:
            log.warning(f"Syslog listener startup skipped: {e}")
        finally:
            db.close()
    _maybe_start_syslog()

    log.info("APScheduler started with risk engine jobs.")
except ImportError:
    log.warning("apscheduler not installed — scheduling disabled.")

campaigns.set_scheduler(scheduler, _schedule_auto_launch, _schedule_auto_complete)
settings.SCHEDULER_AVAILABLE = _SCHEDULER_AVAILABLE

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Phishing Simulator API",
    version="2.1.0",
    docs_url=None if os.getenv("PHISHSIM_DISABLE_DOCS") else "/docs",
    redoc_url=None if os.getenv("PHISHSIM_DISABLE_DOCS") else "/redoc",
)

# ── Request size limit middleware (CVE-13 fix) ────────────────────────────────
MAX_REQUEST_BODY = 10 * 1024 * 1024  # 10 MB

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_REQUEST_BODY:
        return JSONResponse(status_code=413, content={"detail": "Request body too large (max 10 MB)."})
    return await call_next(request)

# ── CORS (CVE-11 fix) — set PHISHSIM_ORIGIN=https://yourdomain.com in production
_allowed_origin = os.getenv("PHISHSIM_ORIGIN", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[_allowed_origin] if _allowed_origin != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router.router)
app.include_router(campaigns.router)
app.include_router(tracking.router)
app.include_router(analytics.router)
app.include_router(templates.router)
app.include_router(settings.router)
app.include_router(ai_router.router)
app.include_router(risk_router.router)
app.include_router(approvals_router.router)
app.include_router(threat_intel_router.router)
app.include_router(autonomy_router.router)
app.include_router(compliance_router.router)

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["health"])
def health():
    from sqlalchemy import text as _text
    db_ok = False
    db_type = "SQLite"
    try:
        with engine.connect() as conn:
            conn.execute(_text("SELECT 1"))
            db_ok = True
            url_str = str(engine.url)
            if "postgresql" in url_str: db_type = "PostgreSQL"
            elif "mysql" in url_str:    db_type = "MySQL"
    except Exception:
        pass
    import multiprocessing
    return {
        "status": "ok" if db_ok else "degraded",
        "version": "2.1.0",
        "scheduler": _SCHEDULER_AVAILABLE,
        "database": db_type,
        "database_ok": db_ok,
        "workers": multiprocessing.cpu_count(),
    }

# ── Serve frontend ────────────────────────────────────────────────────────────
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
INDEX_HTML  = os.path.join(STATIC_DIR, "index.html")

@app.get("/", include_in_schema=False)
def serve_root():
    return FileResponse(INDEX_HTML)
