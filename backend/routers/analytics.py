from routers.auth import require_auth
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy import func, distinct, extract
from sqlalchemy.orm import Session
from database import get_db
import models, schemas

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

EVENT_ORDER = ["sent", "delivered", "opened", "clicked", "submitted"]


def _event_counts(db: Session, campaign_id: int) -> dict:
    rows = (
        db.query(models.TrackingEvent.event_type, func.count(distinct(models.TrackingEvent.target_id)))
        .filter(models.TrackingEvent.campaign_id == campaign_id)
        .group_by(models.TrackingEvent.event_type)
        .all()
    )
    return {r[0]: r[1] for r in rows}


@router.get("/overview", response_model=schemas.OverviewStats)
def overview(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    total_campaigns = db.query(func.count(models.Campaign.id)).scalar() or 0
    active_campaigns = db.query(func.count(models.Campaign.id)).filter(
        models.Campaign.status == "active"
    ).scalar() or 0
    total_targets = db.query(func.count(models.Target.id)).scalar() or 0
    total_events = db.query(func.count(models.TrackingEvent.id)).scalar() or 0

    sent = db.query(func.count(distinct(models.TrackingEvent.target_id))).filter(
        models.TrackingEvent.event_type == "sent"
    ).scalar() or 0
    opened = db.query(func.count(distinct(models.TrackingEvent.target_id))).filter(
        models.TrackingEvent.event_type == "opened"
    ).scalar() or 0
    clicked = db.query(func.count(distinct(models.TrackingEvent.target_id))).filter(
        models.TrackingEvent.event_type == "clicked"
    ).scalar() or 0
    submitted = db.query(func.count(distinct(models.TrackingEvent.target_id))).filter(
        models.TrackingEvent.event_type == "submitted"
    ).scalar() or 0

    def rate(a, b): return round(a / b * 100, 1) if b else 0.0

    return schemas.OverviewStats(
        total_campaigns=total_campaigns,
        active_campaigns=active_campaigns,
        total_targets=total_targets,
        total_events=total_events,
        overall_open_rate=rate(opened, sent),
        overall_click_rate=rate(clicked, sent),
        overall_submission_rate=rate(submitted, sent),
    )


@router.get("/funnel/{campaign_id}", response_model=schemas.FunnelData)
def funnel(campaign_id: int, _: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
    if not campaign:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    total = db.query(func.count(models.Target.id)).filter(
        models.Target.campaign_id == campaign_id
    ).scalar() or 0

    counts = _event_counts(db, campaign_id)

    stages = []
    for stage in EVENT_ORDER:
        count = counts.get(stage, 0)
        pct = round(count / total * 100, 1) if total else 0.0
        stages.append(schemas.FunnelStage(stage=stage, count=count, percentage=pct))

    return schemas.FunnelData(
        campaign_id=campaign_id,
        campaign_name=campaign.name,
        total_targets=total,
        stages=stages,
    )


@router.get("/risky-users", response_model=List[schemas.RiskyUser])
def risky_users(limit: int = 20, _: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """
    Risk score = opens×1 + clicks×3 + submissions×5
    Returns the top `limit` riskiest users across all campaigns.
    """
    targets = db.query(models.Target).all()
    results = []

    for target in targets:
        events = db.query(models.TrackingEvent).filter(
            models.TrackingEvent.target_id == target.id
        ).all()
        event_types = [e.event_type for e in events]

        opens = event_types.count("opened")
        clicks = event_types.count("clicked")
        submissions = event_types.count("submitted")
        score = opens * 1 + clicks * 3 + submissions * 5

        if score > 0:
            results.append(schemas.RiskyUser(
                email=target.email,
                name=target.name,
                department=target.department,
                risk_score=score,
                opens=opens,
                clicks=clicks,
                submissions=submissions,
            ))

    results.sort(key=lambda x: x.risk_score, reverse=True)
    return results[:limit]


@router.get("/timeline/{campaign_id}")
def timeline(campaign_id: int, _: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """
    Return events grouped by hour-of-day (0-23) for time-of-day analysis.
    Also returns events in chronological order for the activity stream.
    """
    campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
    if not campaign:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    events = (
        db.query(models.TrackingEvent)
        .filter(models.TrackingEvent.campaign_id == campaign_id)
        .order_by(models.TrackingEvent.timestamp)
        .all()
    )

    # Hour-of-day buckets (0-23) per event type — pre-populate all 24 hours so chart x-axis is always complete
    hourly: dict = {h: {"opened": 0, "clicked": 0, "submitted": 0} for h in range(24)}
    for ev in events:
        if ev.timestamp and ev.event_type in ("opened", "clicked", "submitted"):
            hour = ev.timestamp.hour
            hourly[hour][ev.event_type] += 1

    # Build target lookup
    target_ids = list({ev.target_id for ev in events})
    targets = db.query(models.Target).filter(models.Target.id.in_(target_ids)).all()
    t_map = {t.id: t for t in targets}

    # Recent activity stream (last 50 events)
    activity = []
    for ev in reversed(events[-50:]):
        t = t_map.get(ev.target_id)
        activity.append({
            "timestamp":  str(ev.timestamp)[:19] if ev.timestamp else "",
            "event_type": ev.event_type,
            "name":       t.name  if t else "Unknown",
            "email":      t.email if t else "Unknown",
            "department": t.department if t else "Unknown",
            "ip_address": ev.ip_address or "",
        })

    return {
        "campaign_id":   campaign_id,
        "campaign_name": campaign.name,
        "hourly":        hourly,
        "activity":      activity,
    }


@router.get("/departments", response_model=List[schemas.DepartmentStat])
def departments(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """Aggregate phishing metrics grouped by department."""
    departments_query = db.query(distinct(models.Target.department)).all()
    dept_list = [d[0] for d in departments_query]

    stats = []
    for dept in dept_list:
        targets = db.query(models.Target).filter(models.Target.department == dept).all()
        target_ids = [t.id for t in targets]

        def count_event(evt):
            return db.query(func.count(distinct(models.TrackingEvent.target_id))).filter(
                models.TrackingEvent.target_id.in_(target_ids),
                models.TrackingEvent.event_type == evt
            ).scalar() or 0

        sent = count_event("sent")
        opened = count_event("opened")
        clicked = count_event("clicked")
        submitted = count_event("submitted")

        def rate(a, b): return round(a / b * 100, 1) if b else 0.0

        stats.append(schemas.DepartmentStat(
            department=dept,
            sent=sent,
            opened=opened,
            clicked=clicked,
            submitted=submitted,
            click_rate=rate(clicked, sent),
            submission_rate=rate(submitted, sent),
        ))

    stats.sort(key=lambda x: x.click_rate, reverse=True)
    return stats


@router.get("/trends", response_model=List[schemas.CampaignTrend])
def trends(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """Return per-campaign open/click/submit rates for trend visualisation."""
    campaigns = db.query(models.Campaign).filter(
        models.Campaign.status.in_(["active", "completed"])
    ).order_by(models.Campaign.launched_at).all()

    result = []
    for campaign in campaigns:
        total = db.query(func.count(models.Target.id)).filter(
            models.Target.campaign_id == campaign.id
        ).scalar() or 0
        counts = _event_counts(db, campaign.id)

        def rate(key): return round(counts.get(key, 0) / total * 100, 1) if total else 0.0

        result.append(schemas.CampaignTrend(
            campaign_id=campaign.id,
            campaign_name=campaign.name,
            launched_at=campaign.launched_at,
            total_targets=total,
            open_rate=rate("opened"),
            click_rate=rate("clicked"),
            submission_rate=rate("submitted"),
        ))

    return result


def _parse_ua(ua: str) -> dict:
    """
    Extract browser, OS, and device type from a User-Agent string.
    No external library needed — covers the browsers and OS that matter for awareness reports.
    """
    ua_l = ua.lower()

    # ── Browser ──────────────────────────────────────────────────
    if "edg/" in ua_l or "edge/" in ua_l:
        browser = "Edge"
    elif "opr/" in ua_l or "opera" in ua_l:
        browser = "Opera"
    elif "chrome/" in ua_l and "chromium" not in ua_l:
        browser = "Chrome"
    elif "firefox/" in ua_l:
        browser = "Firefox"
    elif "safari/" in ua_l and "chrome" not in ua_l:
        browser = "Safari"
    elif "msie" in ua_l or "trident/" in ua_l:
        browser = "Internet Explorer"
    elif not ua_l:
        browser = "Unknown"
    else:
        browser = "Other"

    # ── OS ───────────────────────────────────────────────────────
    if "windows nt" in ua_l:
        os_name = "Windows"
    elif "android" in ua_l:
        os_name = "Android"
    elif "iphone" in ua_l or "ipad" in ua_l:
        os_name = "iOS"
    elif "mac os x" in ua_l or "macos" in ua_l:
        os_name = "macOS"
    elif "linux" in ua_l:
        os_name = "Linux"
    elif "chromeos" in ua_l or "cros" in ua_l:
        os_name = "ChromeOS"
    elif not ua_l:
        os_name = "Unknown"
    else:
        os_name = "Other"

    # ── Device type ──────────────────────────────────────────────
    if "mobi" in ua_l or "iphone" in ua_l or "android" in ua_l and "mobile" in ua_l:
        device = "Mobile"
    elif "ipad" in ua_l or "tablet" in ua_l:
        device = "Tablet"
    elif ua_l:
        device = "Desktop"
    else:
        device = "Unknown"

    return {"browser": browser, "os": os_name, "device": device}


@router.get("/environment/{campaign_id}")
def environment(campaign_id: int, _: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """
    Return browser / OS / device breakdown for a campaign's click and submit events.
    Uses the User-Agent strings captured on tracking events.
    Also surfaces JS-collected extras (screen size, timezone, language) where available.
    """
    import json as _json

    events = (
        db.query(models.TrackingEvent)
        .filter(
            models.TrackingEvent.campaign_id == campaign_id,
            models.TrackingEvent.event_type.in_(["clicked", "submitted", "opened"]),
        )
        .all()
    )

    browsers: dict = {}
    os_counts: dict = {}
    devices: dict = {}
    timezones: dict = {}
    languages: dict = {}
    screens: list = []

    for ev in events:
        parsed = _parse_ua(ev.user_agent or "")
        browsers[parsed["browser"]] = browsers.get(parsed["browser"], 0) + 1
        os_counts[parsed["os"]]     = os_counts.get(parsed["os"], 0) + 1
        devices[parsed["device"]]   = devices.get(parsed["device"], 0) + 1

        # JS-collected extras (only present on confirmed clicks via JS-redirect page)
        try:
            extra = _json.loads(ev.extra_data or "{}")
        except Exception:
            extra = {}

        if extra.get("tz"):
            tz = extra["tz"]
            timezones[tz] = timezones.get(tz, 0) + 1
        if extra.get("lang"):
            lang = extra["lang"][:5]  # en-US → en-US
            languages[lang] = languages.get(lang, 0) + 1
        if extra.get("screen_w") and extra.get("screen_h"):
            screens.append(f"{extra['screen_w']}×{extra['screen_h']}")

    def top(d, n=8):
        return sorted(
            [{"label": k, "count": v} for k, v in d.items()],
            key=lambda x: -x["count"]
        )[:n]

    # Screen resolution frequency
    screen_freq: dict = {}
    for s in screens:
        screen_freq[s] = screen_freq.get(s, 0) + 1

    return {
        "campaign_id": campaign_id,
        "total_events": len(events),
        "browsers":   top(browsers),
        "os":         top(os_counts),
        "devices":    top(devices),
        "timezones":  top(timezones),
        "languages":  top(languages),
        "screens":    top(screen_freq),
    }


@router.get("/time-of-day/{campaign_id}")
def time_of_day(campaign_id: int, _: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """
    Return click/open event counts broken down by hour-of-day (0-23 UTC).
    Helps identify when targets are most susceptible.
    """
    events = db.query(models.TrackingEvent).filter(
        models.TrackingEvent.campaign_id == campaign_id,
        models.TrackingEvent.event_type.in_(["opened", "clicked", "submitted"]),
    ).all()

    hourly: dict = {h: {"opened": 0, "clicked": 0, "submitted": 0} for h in range(24)}
    for ev in events:
        if ev.timestamp:
            h = ev.timestamp.hour
            if ev.event_type in hourly[h]:
                hourly[h][ev.event_type] += 1

    return {
        "campaign_id": campaign_id,
        "hours": [
            {"hour": h, **hourly[h]} for h in range(24)
        ],
    }


@router.get("/time-of-day")
def time_of_day_all(_: models.User = Depends(require_auth), db: Session = Depends(get_db)):
    """Aggregate time-of-day click pattern across ALL campaigns."""
    events = db.query(models.TrackingEvent).filter(
        models.TrackingEvent.event_type.in_(["opened", "clicked", "submitted"]),
    ).all()

    hourly: dict = {h: {"opened": 0, "clicked": 0, "submitted": 0} for h in range(24)}
    for ev in events:
        if ev.timestamp:
            h = ev.timestamp.hour
            if ev.event_type in hourly[h]:
                hourly[h][ev.event_type] += 1

    peak_click_hour = max(range(24), key=lambda h: hourly[h]["clicked"])
    return {
        "hours": [{"hour": h, **hourly[h]} for h in range(24)],
        "peak_click_hour": peak_click_hour,
        "peak_click_label": f"{peak_click_hour:02d}:00 UTC",
    }
