"""
Threat Intelligence Feed Ingestion
====================================
Pulls real-world phishing/malware indicators from open-source threat intelligence
feeds and stores them in the ThreatIndicator table.

Supported feeds:
  - OpenPhish   (free, no key)   — active phishing URLs
  - PhishTank   (free, API key)  — community-verified phishing URLs
  - URLhaus     (free, no key)   — malware distribution URLs
  - AlienVault OTX (free, API key) — comprehensive threat indicators
  - MalwareBazaar (free, no key) — malware hashes & C2 domains

Feed update intervals are configurable via ThreatIntelConfig in the DB.

Usage (called by APScheduler job in main.py):
    from threat_intel.feeds import run_feed_sync
    result = run_feed_sync(db)
"""

import hashlib
import json
import logging
import time
import urllib.request
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

import models

log = logging.getLogger(__name__)

FEED_TIMEOUT = 15  # seconds per HTTP request
MAX_INDICATORS_PER_FEED = 2000


# ── Model helpers ─────────────────────────────────────────────────────────────

def _upsert_indicator(db: Session, ioc_type: str, value: str, feed: str,
                      threat_type: str, tags: list, metadata: dict) -> bool:
    """Insert or update a ThreatIndicator record. Returns True if new."""
    # Deduplicate by (type, value) hash
    key = hashlib.sha256(f"{ioc_type}:{value.lower()}".encode()).hexdigest()
    existing = db.query(models.ThreatIndicator).filter_by(ioc_hash=key).first()
    if existing:
        existing.last_seen = datetime.utcnow()
        existing.hit_count = (existing.hit_count or 0) + 1
        return False
    indicator = models.ThreatIndicator(
        ioc_type    = ioc_type,
        value       = value[:1000],
        feed        = feed,
        threat_type = threat_type,
        tags        = json.dumps(tags),
        metadata_json = json.dumps(metadata, default=str),
        ioc_hash    = key,
        first_seen  = datetime.utcnow(),
        last_seen   = datetime.utcnow(),
        hit_count   = 1,
        active      = True,
    )
    db.add(indicator)
    return True


def _fetch_url(url: str, headers: dict = None) -> Optional[bytes]:
    """Simple HTTP GET. Returns bytes or None on error."""
    try:
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "PhishSim-ThreatIntel/2.0 (security-awareness-platform)"
        })
        with urllib.request.urlopen(req, timeout=FEED_TIMEOUT) as r:
            return r.read()
    except Exception as e:
        log.warning(f"Feed fetch failed {url}: {e}")
        return None


# ── OpenPhish ─────────────────────────────────────────────────────────────────

def _sync_openphish(db: Session) -> int:
    """
    OpenPhish free feed — plain text, one URL per line.
    https://openphish.com/feed.txt
    """
    raw = _fetch_url("https://openphish.com/feed.txt")
    if not raw:
        return 0
    added = 0
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        url = line.strip()
        if url and url.startswith("http"):
            if _upsert_indicator(db, "url", url, "openphish", "phishing",
                                 ["phishing", "url"], {"source_feed": "openphish"}):
                added += 1
            if added >= MAX_INDICATORS_PER_FEED:
                break
    db.commit()
    log.info(f"OpenPhish: +{added} new indicators")
    return added


# ── URLhaus ───────────────────────────────────────────────────────────────────

def _sync_urlhaus(db: Session) -> int:
    """
    URLhaus CSV feed — recent malware distribution URLs.
    https://urlhaus.abuse.ch/downloads/csv_recent/
    """
    raw = _fetch_url("https://urlhaus.abuse.ch/downloads/csv_recent/",
                     headers={"User-Agent": "PhishSim-ThreatIntel/2.0"})
    if not raw:
        return 0
    added = 0
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 6:
            continue
        # Format: id, dateadded, url, url_status, threat, tags
        url        = parts[2] if len(parts) > 2 else ""
        threat     = parts[4] if len(parts) > 4 else "malware"
        url_status = parts[3] if len(parts) > 3 else ""
        if not url or not url.startswith("http"):
            continue
        tags = [t.strip() for t in (parts[5] if len(parts) > 5 else "").split(",") if t.strip()]
        if _upsert_indicator(db, "url", url, "urlhaus", threat or "malware",
                             tags + ["malware", "urlhaus"],
                             {"url_status": url_status, "source_feed": "urlhaus"}):
            added += 1
        if added >= MAX_INDICATORS_PER_FEED:
            break
    db.commit()
    log.info(f"URLhaus: +{added} new indicators")
    return added


# ── AlienVault OTX ────────────────────────────────────────────────────────────

def _sync_otx(db: Session, api_key: str) -> int:
    """
    AlienVault OTX — subscribed pulses with phishing/malware indicators.
    Free API key at: https://otx.alienvault.com/
    """
    if not api_key:
        return 0
    headers = {"X-OTX-API-KEY": api_key,
               "User-Agent": "PhishSim-ThreatIntel/2.0"}
    # Get pulses updated in the last 7 days
    since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}&limit=20"
    raw = _fetch_url(url, headers=headers)
    if not raw:
        return 0
    added = 0
    try:
        data = json.loads(raw)
        for pulse in data.get("results", []):
            threat_name = pulse.get("name", "unknown")
            tags = pulse.get("tags", [])
            for indicator in pulse.get("indicators", []):
                ioc_type = indicator.get("type", "").lower()
                value    = indicator.get("indicator", "")
                if not value:
                    continue
                # Map OTX types to our schema
                type_map = {
                    "url": "url", "domain": "domain", "hostname": "domain",
                    "ipv4": "ip", "ipv6": "ip", "filehash-md5": "hash",
                    "filehash-sha1": "hash", "filehash-sha256": "hash",
                    "email": "email",
                }
                our_type = type_map.get(ioc_type, "other")
                if _upsert_indicator(db, our_type, value, "otx",
                                     "threat", tags + ["otx"],
                                     {"pulse": threat_name, "otx_type": ioc_type}):
                    added += 1
                if added >= MAX_INDICATORS_PER_FEED:
                    break
    except json.JSONDecodeError as e:
        log.warning(f"OTX parse error: {e}")
    db.commit()
    log.info(f"AlienVault OTX: +{added} new indicators")
    return added


# ── PhishTank ─────────────────────────────────────────────────────────────────

def _sync_phishtank(db: Session, api_key: str = "") -> int:
    """
    PhishTank verified phishing URLs.
    Free API key at: https://www.phishtank.com/api_register.php
    JSON feed includes phishing_id, url, verified, online status.
    """
    url = "http://data.phishtank.com/data/"
    if api_key:
        url += f"{api_key}/"
    url += "online-valid.json.gz"
    try:
        import gzip
        raw_gz = _fetch_url(url)
        if not raw_gz:
            return 0
        raw = gzip.decompress(raw_gz)
        entries = json.loads(raw)
    except Exception as e:
        log.warning(f"PhishTank fetch/parse error: {e}")
        return 0

    added = 0
    for entry in entries:
        phish_url = entry.get("url", "")
        if not phish_url:
            continue
        target = entry.get("target", "")
        if _upsert_indicator(db, "url", phish_url, "phishtank", "phishing",
                             ["phishing", "verified", "phishtank"],
                             {"phishtank_id": entry.get("phish_id", ""),
                              "target": target, "verified": entry.get("verified", False)}):
            added += 1
        if added >= MAX_INDICATORS_PER_FEED:
            break
    db.commit()
    log.info(f"PhishTank: +{added} new indicators")
    return added


# ── Main sync dispatcher ──────────────────────────────────────────────────────

def run_feed_sync(db: Session) -> dict:
    """
    Run all enabled threat intelligence feed syncs.
    Called by APScheduler job every 6 hours.
    Returns summary dict.
    """
    cfg = db.query(models.ThreatIntelConfig).first()
    if not cfg or not cfg.enabled:
        return {"skipped": "threat intel disabled"}

    results = {}
    start = time.time()

    try:
        results["openphish"] = _sync_openphish(db)
    except Exception as e:
        log.error(f"OpenPhish sync error: {e}")
        results["openphish"] = {"error": str(e)}

    try:
        results["urlhaus"] = _sync_urlhaus(db)
    except Exception as e:
        log.error(f"URLhaus sync error: {e}")
        results["urlhaus"] = {"error": str(e)}

    if cfg.otx_api_key:
        try:
            results["otx"] = _sync_otx(db, cfg.otx_api_key)
        except Exception as e:
            log.error(f"OTX sync error: {e}")
            results["otx"] = {"error": str(e)}

    if cfg.phishtank_api_key:
        try:
            results["phishtank"] = _sync_phishtank(db, cfg.phishtank_api_key)
        except Exception as e:
            log.error(f"PhishTank sync error: {e}")
            results["phishtank"] = {"error": str(e)}

    # Mark last sync time
    cfg.last_synced_at = datetime.utcnow()
    db.commit()

    elapsed = round(time.time() - start, 1)
    log.info(f"Threat intel sync complete in {elapsed}s: {results}")
    return {"results": results, "elapsed_seconds": elapsed}


def get_recent_indicators(db: Session, ioc_type: str = None,
                           limit: int = 100, days: int = 7) -> list:
    """Fetch recently seen active indicators for the threat intel dashboard."""
    since = datetime.utcnow() - timedelta(days=days)
    q = db.query(models.ThreatIndicator).filter(
        models.ThreatIndicator.active == True,
        models.ThreatIndicator.last_seen >= since,
    )
    if ioc_type:
        q = q.filter(models.ThreatIndicator.ioc_type == ioc_type)
    return q.order_by(models.ThreatIndicator.last_seen.desc()).limit(limit).all()


def get_feed_stats(db: Session) -> dict:
    """Summary statistics for the threat intel dashboard."""
    from sqlalchemy import func
    total = db.query(func.count(models.ThreatIndicator.id)).scalar() or 0
    active = db.query(func.count(models.ThreatIndicator.id)).filter(
        models.ThreatIndicator.active == True
    ).scalar() or 0
    by_feed = {}
    rows = db.query(models.ThreatIndicator.feed,
                    func.count(models.ThreatIndicator.id)).group_by(
        models.ThreatIndicator.feed
    ).all()
    for feed, count in rows:
        by_feed[feed] = count
    by_type = {}
    rows = db.query(models.ThreatIndicator.ioc_type,
                    func.count(models.ThreatIndicator.id)).group_by(
        models.ThreatIndicator.ioc_type
    ).all()
    for t, count in rows:
        by_type[t] = count
    cfg = db.query(models.ThreatIntelConfig).first()
    return {
        "total":        total,
        "active":       active,
        "by_feed":      by_feed,
        "by_type":      by_type,
        "enabled":      cfg.enabled if cfg else False,
        "last_synced":  cfg.last_synced_at.isoformat() if cfg and cfg.last_synced_at else None,
    }
