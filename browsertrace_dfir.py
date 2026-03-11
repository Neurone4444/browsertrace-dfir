#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BrowserTrace DFIR
Single-file forensic browser artifact collector / triage tool

Features:
  - Discover Chromium and Firefox profiles
  - Optional offline analysis of a manually supplied profile path
  - Forensic-safe acquisition by copying artifacts
  - SHA256 hashing of acquired files
  - Parse:
    * Chromium history
    * Chromium downloads
    * Chromium bookmarks
    * Chromium extensions
    * Firefox history
    * Firefox bookmarks
    * Firefox downloads (best effort via places.sqlite visits)
    * Firefox extensions
  - AI-like heuristic analysis:
    * suspicious domains scoring
    * token-based keyword / brand analysis
    * reduced false positives on known legitimate domains
  - Visual outputs:
    * report.html
    * timeline.html
    * graph.html
  - JSON outputs:
    * manifest.json
    * report.json
    * ai_analysis.json
    * timeline.json
    * graph.json

Does NOT extract or decrypt:
  - passwords
  - cookies
  - credit cards
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

APP_NAME = "BrowserTrace DFIR"
APP_VERSION = "2.2.0"

# =============================================================================
# Utility
# =============================================================================

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def utc_from_timestamp(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def file_info(path: Path) -> Dict[str, Any]:
    st = path.stat()
    return {
        "path": str(path),
        "size": st.st_size,
        "mtime_utc": utc_from_timestamp(st.st_mtime),
        "sha256": sha256_file(path)
    }

def copy_forensic(src: Path, dst: Path) -> Optional[Dict[str, Any]]:
    try:
        ensure_dir(dst.parent)
        shutil.copy2(src, dst)
        return {
            "source_path": str(src),
            "acquired_path": str(dst),
            "size": dst.stat().st_size,
            "sha256": sha256_file(dst),
            "mtime_utc": utc_from_timestamp(dst.stat().st_mtime)
        }
    except Exception as e:
        return {
            "source_path": str(src),
            "acquired_path": str(dst),
            "error": str(e)
        }

def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)

def sqlite_connect_ro_copy(db_path: Path, work_dir: Path) -> Optional[Path]:
    """
    Copy DB to work_dir to avoid locking problems.
    """
    try:
        ensure_dir(work_dir)
        dst = work_dir / db_path.name
        shutil.copy2(db_path, dst)
        return dst
    except Exception:
        return None

def chromium_time_to_utc_str(value: Any) -> str:
    """
    Chromium timestamps are microseconds since 1601-01-01 UTC.
    """
    try:
        if not value:
            return ""
        base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        ts = base + dt.timedelta(microseconds=int(value))
        return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return ""

def firefox_time_to_utc_str(value: Any) -> str:
    """
    Firefox places.sqlite visit_date is microseconds since Unix epoch.
    """
    try:
        if not value:
            return ""
        ts = dt.datetime.fromtimestamp(int(value) / 1_000_000, dt.timezone.utc)
        return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return ""

def unix_ms_to_utc_str(value: Any) -> str:
    try:
        if not value:
            return ""
        ts = dt.datetime.fromtimestamp(int(value) / 1000.0, dt.timezone.utc)
        return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return ""

def hostname_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().strip()
    except Exception:
        return ""

def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))

def normalize_label(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())

def split_domain_tokens(host: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", host.lower()) if t]

def iso_to_dt(value: str) -> Optional[dt.datetime]:
    try:
        if not value:
            return None
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return dt.datetime.fromisoformat(value)
    except Exception:
        return None

# =============================================================================
# Browser discovery
# =============================================================================

def get_home() -> Path:
    return Path.home()

def discover_chromium_profiles() -> List[Dict[str, Any]]:
    profiles = []
    home = get_home()
    system = platform.system().lower()

    candidates: List[Tuple[str, Path]] = []

    if system == "windows":
        local = Path(os.environ.get("LOCALAPPDATA", home))
        roaming = Path(os.environ.get("APPDATA", home))
        candidates = [
            ("chrome", local / "Google/Chrome/User Data"),
            ("edge", local / "Microsoft/Edge/User Data"),
            ("brave", local / "BraveSoftware/Brave-Browser/User Data"),
            ("vivaldi", local / "Vivaldi/User Data"),
            ("opera", roaming / "Opera Software/Opera Stable"),
            ("opera-gx", roaming / "Opera Software/Opera GX Stable"),
            ("chromium", local / "Chromium/User Data"),
        ]
    elif system == "darwin":
        candidates = [
            ("chrome", home / "Library/Application Support/Google/Chrome"),
            ("edge", home / "Library/Application Support/Microsoft Edge"),
            ("brave", home / "Library/Application Support/BraveSoftware/Brave-Browser"),
            ("vivaldi", home / "Library/Application Support/Vivaldi"),
            ("opera", home / "Library/Application Support/com.operasoftware.Opera"),
            ("opera-gx", home / "Library/Application Support/com.operasoftware.OperaGX"),
            ("chromium", home / "Library/Application Support/Chromium"),
        ]
    else:
        candidates = [
            ("chrome", home / ".config/google-chrome"),
            ("edge", home / ".config/microsoft-edge"),
            ("brave", home / ".config/BraveSoftware/Brave-Browser"),
            ("vivaldi", home / ".config/vivaldi"),
            ("opera", home / ".config/opera"),
            ("chromium", home / ".config/chromium"),
        ]

    for browser_name, base in candidates:
        if not base.exists():
            continue

        profile_dirs = []
        if browser_name.startswith("opera"):
            profile_dirs = [base]
        else:
            for child in base.iterdir():
                if child.is_dir() and (
                    child.name == "Default"
                    or child.name.startswith("Profile ")
                    or child.name.startswith("Guest Profile")
                    or child.name.startswith("System Profile")
                ):
                    profile_dirs.append(child)

        for p in profile_dirs:
            profiles.append({
                "browser_family": "chromium",
                "browser": browser_name,
                "profile_name": p.name,
                "profile_path": str(p),
                "artifacts": {
                    "history": str(p / "History"),
                    "bookmarks": str(p / "Bookmarks"),
                    "extensions_dir": str(p / "Extensions"),
                }
            })

    return profiles

def discover_firefox_profiles() -> List[Dict[str, Any]]:
    profiles = []
    home = get_home()
    system = platform.system().lower()

    if system == "windows":
        base = Path(os.environ.get("APPDATA", home)) / "Mozilla/Firefox/Profiles"
    elif system == "darwin":
        base = home / "Library/Application Support/Firefox/Profiles"
    else:
        base = home / ".mozilla/firefox"

    if not base.exists():
        return profiles

    for child in base.iterdir():
        if child.is_dir():
            profiles.append({
                "browser_family": "firefox",
                "browser": "firefox",
                "profile_name": child.name,
                "profile_path": str(child),
                "artifacts": {
                    "places": str(child / "places.sqlite"),
                    "extensions_json": str(child / "extensions.json"),
                }
            })

    return profiles

def build_manual_profile(profile_path: Path, profile_type: str) -> Dict[str, Any]:
    """
    Build a synthetic profile descriptor from a manually supplied profile path.
    """
    profile_path = profile_path.resolve()
    profile_name = profile_path.name or "manual_profile"

    if profile_type == "chromium":
        return {
            "browser_family": "chromium",
            "browser": "manual-chromium",
            "profile_name": profile_name,
            "profile_path": str(profile_path),
            "artifacts": {
                "history": str(profile_path / "History"),
                "bookmarks": str(profile_path / "Bookmarks"),
                "extensions_dir": str(profile_path / "Extensions"),
            }
        }

    if profile_type == "firefox":
        return {
            "browser_family": "firefox",
            "browser": "manual-firefox",
            "profile_name": profile_name,
            "profile_path": str(profile_path),
            "artifacts": {
                "places": str(profile_path / "places.sqlite"),
                "extensions_json": str(profile_path / "extensions.json"),
            }
        }

    raise ValueError(f"Unsupported profile type: {profile_type}")

# =============================================================================
# Chromium parsers
# =============================================================================

def parse_chromium_history(history_db: Path) -> Dict[str, Any]:
    result = {"history": [], "downloads": [], "errors": []}
    temp_dir = Path(tempfile.mkdtemp(prefix="bt_hist_"))
    db_copy = sqlite_connect_ro_copy(history_db, temp_dir)

    if not db_copy or not db_copy.exists():
        result["errors"].append(f"Unable to copy/open History DB: {history_db}")
        return result

    try:
        con = sqlite3.connect(str(db_copy))
        cur = con.cursor()

        try:
            cur.execute("""
                SELECT url, title, visit_count, typed_count, last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 1000
            """)
            for row in cur.fetchall():
                result["history"].append({
                    "url": safe_str(row[0]),
                    "title": safe_str(row[1]),
                    "visit_count": row[2],
                    "typed_count": row[3],
                    "last_visit_utc": chromium_time_to_utc_str(row[4]),
                })
        except Exception as e:
            result["errors"].append(f"URLs parse error: {e}")

        try:
            cur.execute("""
                SELECT current_path, target_path, tab_url, tab_referrer_url, start_time, end_time,
                       received_bytes, total_bytes, mime_type
                FROM downloads
                ORDER BY start_time DESC
                LIMIT 1000
            """)
            for row in cur.fetchall():
                result["downloads"].append({
                    "current_path": safe_str(row[0]),
                    "target_path": safe_str(row[1]),
                    "source_url": safe_str(row[2]),
                    "referrer_url": safe_str(row[3]),
                    "start_utc": chromium_time_to_utc_str(row[4]),
                    "end_utc": chromium_time_to_utc_str(row[5]),
                    "received_bytes": row[6],
                    "total_bytes": row[7],
                    "mime_type": safe_str(row[8]),
                })
        except Exception as e:
            result["errors"].append(f"Downloads parse error: {e}")

        con.close()
    except Exception as e:
        result["errors"].append(f"Chromium history DB error: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return result

def walk_bookmarks(node: Dict[str, Any], out: List[Dict[str, Any]]) -> None:
    if not isinstance(node, dict):
        return
    node_type = node.get("type")
    if node_type == "url":
        out.append({
            "name": safe_str(node.get("name")),
            "url": safe_str(node.get("url")),
            "date_added": chromium_time_to_utc_str(node.get("date_added")),
        })
    for child in node.get("children", []) or []:
        if isinstance(child, dict):
            walk_bookmarks(child, out)

def parse_chromium_bookmarks(bookmarks_path: Path) -> Dict[str, Any]:
    result = {"bookmarks": [], "errors": []}
    try:
        data = read_json(bookmarks_path)
        roots = data.get("roots", {})
        for _, root_node in roots.items():
            if isinstance(root_node, dict):
                walk_bookmarks(root_node, result["bookmarks"])
    except Exception as e:
        result["errors"].append(f"Bookmarks parse error: {e}")
    return result

def parse_chromium_extensions(extensions_dir: Path) -> Dict[str, Any]:
    result = {"extensions": [], "errors": []}
    try:
        if not extensions_dir.exists():
            return result

        for ext_id_dir in extensions_dir.iterdir():
            if not ext_id_dir.is_dir():
                continue
            versions = [x for x in ext_id_dir.iterdir() if x.is_dir()]
            if not versions:
                result["extensions"].append({
                    "extension_id": ext_id_dir.name,
                    "name": "",
                    "version": "",
                    "description": "",
                    "manifest_path": ""
                })
                continue

            latest = sorted(versions, key=lambda p: p.name, reverse=True)[0]
            manifest = latest / "manifest.json"
            ext_data = {
                "extension_id": ext_id_dir.name,
                "name": "",
                "version": latest.name,
                "description": "",
                "manifest_path": str(manifest) if manifest.exists() else ""
            }

            if manifest.exists():
                try:
                    mj = read_json(manifest)
                    ext_data["name"] = safe_str(mj.get("name"))
                    ext_data["version"] = safe_str(mj.get("version", latest.name))
                    ext_data["description"] = safe_str(mj.get("description"))
                    ext_data["permissions"] = mj.get("permissions", [])
                    ext_data["host_permissions"] = mj.get("host_permissions", [])
                except Exception as e:
                    ext_data["error"] = str(e)

            result["extensions"].append(ext_data)

    except Exception as e:
        result["errors"].append(f"Extensions parse error: {e}")

    return result

# =============================================================================
# Firefox parsers
# =============================================================================

def parse_firefox_places(places_db: Path) -> Dict[str, Any]:
    result = {"history": [], "bookmarks": [], "downloads": [], "errors": []}
    temp_dir = Path(tempfile.mkdtemp(prefix="bt_ff_"))
    db_copy = sqlite_connect_ro_copy(places_db, temp_dir)

    if not db_copy or not db_copy.exists():
        result["errors"].append(f"Unable to copy/open places.sqlite: {places_db}")
        return result

    try:
        con = sqlite3.connect(str(db_copy))
        cur = con.cursor()

        try:
            cur.execute("""
                SELECT p.url, p.title, p.visit_count, h.visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                ORDER BY h.visit_date DESC
                LIMIT 1000
            """)
            for row in cur.fetchall():
                result["history"].append({
                    "url": safe_str(row[0]),
                    "title": safe_str(row[1]),
                    "visit_count": row[2],
                    "last_visit_utc": firefox_time_to_utc_str(row[3]),
                })
        except Exception as e:
            result["errors"].append(f"Firefox history parse error: {e}")

        try:
            cur.execute("""
                SELECT p.url, b.title, b.dateAdded
                FROM moz_bookmarks b
                JOIN moz_places p ON b.fk = p.id
                WHERE b.type = 1
                ORDER BY b.dateAdded DESC
                LIMIT 1000
            """)
            for row in cur.fetchall():
                result["bookmarks"].append({
                    "url": safe_str(row[0]),
                    "title": safe_str(row[1]),
                    "date_added_utc": firefox_time_to_utc_str(row[2]),
                })
        except Exception as e:
            result["errors"].append(f"Firefox bookmarks parse error: {e}")

        try:
            cur.execute("""
                SELECT p.url, p.title, h.visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                WHERE p.url LIKE 'file:%' OR p.url LIKE '%.zip%' OR p.url LIKE '%.exe%'
                   OR p.url LIKE '%.msi%' OR p.url LIKE '%.pdf%'
                ORDER BY h.visit_date DESC
                LIMIT 500
            """)
            for row in cur.fetchall():
                result["downloads"].append({
                    "url": safe_str(row[0]),
                    "title": safe_str(row[1]),
                    "timestamp_utc": firefox_time_to_utc_str(row[2]),
                })
        except Exception as e:
            result["errors"].append(f"Firefox downloads parse error: {e}")

        con.close()
    except Exception as e:
        result["errors"].append(f"Firefox places DB error: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return result

def parse_firefox_extensions(extensions_json: Path) -> Dict[str, Any]:
    result = {"extensions": [], "errors": []}
    try:
        data = read_json(extensions_json)
        addons = data.get("addons", [])
        for item in addons:
            result["extensions"].append({
                "id": safe_str(item.get("id")),
                "name": safe_str(item.get("defaultLocale", {}).get("name") if isinstance(item.get("defaultLocale"), dict) else ""),
                "version": safe_str(item.get("version")),
                "active": item.get("active"),
                "path": safe_str(item.get("path")),
                "source_uri": safe_str(item.get("sourceURI")),
            })
    except Exception as e:
        result["errors"].append(f"Firefox extensions parse error: {e}")

    return result

# =============================================================================
# AI / heuristic analysis
# =============================================================================

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account", "wallet",
    "support", "update", "auth", "password", "recovery", "sso", "mfa", "2fa",
    "bank", "invoice", "payment", "office", "mail", "webmail", "confirm", "service"
}

BRAND_KEYWORDS = {
    "google", "gmail", "microsoft", "outlook", "office", "apple", "icloud",
    "amazon", "facebook", "instagram", "linkedin", "paypal", "netflix",
    "telegram", "whatsapp", "github", "dropbox", "adobe", "dhl", "fedex",
    "ups", "poste", "posteitaliane", "banco", "unicredit", "intesa",
    "aruba", "spid", "cie", "chatgpt", "openai", "bing"
}

SUSPICIOUS_TLDS = {
    "ru", "su", "xyz", "top", "click", "shop", "rest", "gq", "cf", "ml", "ga", "tk", "work"
}

KNOWN_SAFE_SUFFIXES = [
    "google.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "office365.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "paypal.com",
    "netflix.com",
    "telegram.org",
    "github.com",
    "dropbox.com",
    "adobe.com",
    "mozilla.org",
    "opera.com",
    "brave.com",
    "poste.it",
    "posteitaliane.it",
    "bing.com",
    "chatgpt.com",
    "openai.com",
    "hf.space",
]

BRAND_SAFE_SUFFIXES: Dict[str, List[str]] = {
    "google": ["google.com"],
    "gmail": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "bing.com"],
    "office": ["office.com", "office365.com", "microsoft.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com", "facebook.com"],
    "linkedin": ["linkedin.com"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "telegram": ["telegram.org"],
    "github": ["github.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "poste": ["poste.it", "posteitaliane.it"],
    "posteitaliane": ["posteitaliane.it", "poste.it"],
    "intesa": [],
    "unicredit": [],
    "spid": [],
    "cie": [],
    "chatgpt": ["chatgpt.com", "openai.com"],
    "openai": ["openai.com", "chatgpt.com"],
    "bing": ["bing.com", "microsoft.com"],
}

def domain_matches_known_safe(domain: str) -> bool:
    domain = domain.lower().strip(".")
    return any(domain == x or domain.endswith("." + x) for x in KNOWN_SAFE_SUFFIXES)

def domain_matches_brand_safe(domain: str, brand: str) -> bool:
    suffixes = BRAND_SAFE_SUFFIXES.get(brand, [])
    if not suffixes:
        return False
    domain = domain.lower().strip(".")
    return any(domain == x or domain.endswith("." + x) for x in suffixes)

def classify_domain(score: int, domain: str) -> str:
    if domain_matches_known_safe(domain):
        return "safe"
    if score >= 60:
        return "suspicious"
    if score >= 30:
        return "review"
    return "unknown"

def score_domain(domain: str) -> Dict[str, Any]:
    reasons: List[str] = []
    score = 0
    host = domain.lower().strip()

    if not host:
        return {"domain": domain, "score": 0, "severity": "LOW", "classification": "unknown", "reasons": []}

    if domain_matches_known_safe(host):
        return {
            "domain": domain,
            "score": 0,
            "severity": "LOW",
            "classification": "safe",
            "reasons": ["known safe suffix match"]
        }

    if host.startswith("xn--"):
        score += 30
        reasons.append("punycode domain")

    if is_ip_host(host):
        score += 20
        reasons.append("direct IP host")

    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        score += 12
        reasons.append(f"suspicious TLD .{tld}")

    if len(host) > 35:
        score += 8
        reasons.append("long hostname")

    if host.count("-") >= 2:
        score += 10
        reasons.append("multiple hyphens")

    if sum(c.isdigit() for c in host) >= 3:
        score += 8
        reasons.append("many digits in hostname")

    tokens = split_domain_tokens(host)
    token_set = set(tokens)

    present_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in token_set]
    if present_keywords:
        score += min(18, 6 * len(present_keywords))
        reasons.append("suspicious keyword(s): " + ", ".join(sorted(present_keywords)[:5]))

    present_brands = [b for b in BRAND_KEYWORDS if b in token_set]
    if present_brands:
        score += min(14, 4 * len(present_brands))
        reasons.append("brand keyword(s): " + ", ".join(sorted(present_brands)[:5]))

    for brand in present_brands:
        if domain_matches_brand_safe(host, brand):
            continue

        risky_combo = any(k in token_set for k in {"login", "signin", "verify", "verification", "secure", "auth", "support", "account", "password", "webmail", "mail", "sso"})
        if risky_combo:
            score += 14
            reasons.append(f"possible brand impersonation: {brand}")
        else:
            score += 4
            reasons.append(f"brand mention outside trusted suffix: {brand}")
        break

    if any(tok in token_set for tok in ["free", "bonus", "gift", "promo", "claim"]):
        score += 8
        reasons.append("social engineering style token")

    if len(parts) >= 4:
        score += 6
        reasons.append("deep subdomain chain")

    score = min(score, 100)

    if score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    classification = classify_domain(score, host)

    return {
        "domain": domain,
        "score": score,
        "severity": severity,
        "classification": classification,
        "reasons": reasons
    }

def build_ai_analysis(profile_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    domain_map: Dict[str, Dict[str, Any]] = {}

    def touch_domain(profile_label: str, url: str, event_type: str, timestamp_utc: str) -> None:
        domain = hostname_from_url(url)
        if not domain:
            return

        if domain not in domain_map:
            domain_map[domain] = {
                "domain": domain,
                "occurrences": 0,
                "history_hits": 0,
                "download_hits": 0,
                "bookmark_hits": 0,
                "profiles": set(),
                "sample_urls": set(),
                "timestamps": [],
            }

        domain_map[domain]["occurrences"] += 1
        domain_map[domain]["profiles"].add(profile_label)
        domain_map[domain]["sample_urls"].add(url)

        if event_type == "history":
            domain_map[domain]["history_hits"] += 1
        elif event_type == "download":
            domain_map[domain]["download_hits"] += 1
        elif event_type == "bookmark":
            domain_map[domain]["bookmark_hits"] += 1

        if timestamp_utc:
            domain_map[domain]["timestamps"].append(timestamp_utc)

    for prof in profile_reports:
        profile_label = f"{prof.get('browser', '')}/{prof.get('profile_name', '')}"

        for item in prof.get("history", []):
            touch_domain(
                profile_label,
                item.get("url", ""),
                "history",
                item.get("last_visit_utc", "")
            )

        for item in prof.get("downloads", []):
            url = item.get("source_url") or item.get("url") or ""
            touch_domain(
                profile_label,
                url,
                "download",
                item.get("start_utc") or item.get("timestamp_utc") or item.get("end_utc") or ""
            )

        for item in prof.get("bookmarks", []):
            touch_domain(
                profile_label,
                item.get("url", ""),
                "bookmark",
                item.get("date_added") or item.get("date_added_utc") or ""
            )

    analyzed_domains: List[Dict[str, Any]] = []
    for domain, info in domain_map.items():
        scored = score_domain(domain)
        boost = 0
        if info["download_hits"] > 0:
            boost += min(12, info["download_hits"] * 3)
        if len(info["profiles"]) > 1:
            boost += 8

        final_score = min(100, scored["score"] + boost)

        if domain_matches_known_safe(domain):
            final_score = 0

        if final_score >= 60:
            severity = "HIGH"
        elif final_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        classification = classify_domain(final_score, domain)
        if domain_matches_known_safe(domain):
            severity = "LOW"
            classification = "safe"

        reasons = list(scored["reasons"])
        if info["download_hits"] > 0:
            reasons.append(f"seen in downloads: {info['download_hits']}")
        if len(info["profiles"]) > 1:
            reasons.append(f"seen across profiles: {len(info['profiles'])}")

        parsed_times = [iso_to_dt(x) for x in info["timestamps"]]
        parsed_times = [x for x in parsed_times if x is not None]
        first_seen = min(parsed_times).isoformat().replace("+00:00", "Z") if parsed_times else ""
        last_seen = max(parsed_times).isoformat().replace("+00:00", "Z") if parsed_times else ""

        analyzed_domains.append({
            "domain": domain,
            "score": final_score,
            "severity": severity,
            "classification": classification,
            "occurrences": info["occurrences"],
            "history_hits": info["history_hits"],
            "download_hits": info["download_hits"],
            "bookmark_hits": info["bookmark_hits"],
            "profiles": sorted(info["profiles"]),
            "profiles_count": len(info["profiles"]),
            "sample_urls": sorted(info["sample_urls"])[:10],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "reasons": reasons,
        })

    analyzed_domains.sort(key=lambda x: (x["score"], x["occurrences"]), reverse=True)

    return {
        "generated_utc": utc_now(),
        "domains_total": len(analyzed_domains),
        "high_risk_total": sum(1 for d in analyzed_domains if d["severity"] == "HIGH"),
        "medium_risk_total": sum(1 for d in analyzed_domains if d["severity"] == "MEDIUM"),
        "low_risk_total": sum(1 for d in analyzed_domains if d["severity"] == "LOW"),
        "classified_safe_total": sum(1 for d in analyzed_domains if d["classification"] == "safe"),
        "classified_review_total": sum(1 for d in analyzed_domains if d["classification"] == "review"),
        "classified_suspicious_total": sum(1 for d in analyzed_domains if d["classification"] == "suspicious"),
        "domains": analyzed_domains,
    }

# =============================================================================
# Timeline / graph generation
# =============================================================================

def build_timeline(profile_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    timeline: List[Dict[str, Any]] = []

    for prof in profile_reports:
        profile_label = f"{prof.get('browser', '')}/{prof.get('profile_name', '')}"

        for item in prof.get("history", []):
            ts = item.get("last_visit_utc") or ""
            if ts:
                timeline.append({
                    "timestamp_utc": ts,
                    "type": "history",
                    "profile": profile_label,
                    "url": item.get("url", ""),
                    "title": item.get("title", ""),
                    "details": {
                        "visit_count": item.get("visit_count"),
                        "typed_count": item.get("typed_count"),
                    }
                })

        for item in prof.get("downloads", []):
            ts = item.get("start_utc") or item.get("timestamp_utc") or item.get("end_utc") or ""
            if ts:
                timeline.append({
                    "timestamp_utc": ts,
                    "type": "download",
                    "profile": profile_label,
                    "url": item.get("source_url") or item.get("url") or "",
                    "title": item.get("title", "") or item.get("target_path", "") or item.get("current_path", ""),
                    "details": {
                        "target_path": item.get("target_path", ""),
                        "current_path": item.get("current_path", ""),
                        "mime_type": item.get("mime_type", ""),
                        "received_bytes": item.get("received_bytes"),
                        "total_bytes": item.get("total_bytes"),
                    }
                })

        for item in prof.get("bookmarks", []):
            ts = item.get("date_added") or item.get("date_added_utc") or ""
            if ts:
                timeline.append({
                    "timestamp_utc": ts,
                    "type": "bookmark",
                    "profile": profile_label,
                    "url": item.get("url", ""),
                    "title": item.get("name", "") or item.get("title", ""),
                    "details": {}
                })

    timeline.sort(key=lambda x: x.get("timestamp_utc", ""), reverse=True)
    return timeline

def build_graph(profile_reports: List[Dict[str, Any]], user_name: str, host_name: str) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    node_ids = set()

    def add_node(node_id: str, label: str, kind: str, meta: Optional[Dict[str, Any]] = None) -> None:
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({
            "id": node_id,
            "label": label,
            "kind": kind,
            "meta": meta or {}
        })

    def add_edge(src: str, dst: str, relation: str) -> None:
        edges.append({"source": src, "target": dst, "relation": relation})

    root_id = "user_root"
    add_node(root_id, f"{user_name or 'unknown-user'} @ {host_name or 'unknown-host'}", "user")

    for prof in profile_reports:
        browser_id = f"browser::{prof.get('browser', '')}"
        profile_id = f"profile::{prof.get('browser', '')}::{prof.get('profile_name', '')}"
        add_node(browser_id, prof.get("browser", ""), "browser")
        add_node(profile_id, f"{prof.get('browser', '')}/{prof.get('profile_name', '')}", "profile")
        add_edge(root_id, browser_id, "uses")
        add_edge(browser_id, profile_id, "contains")

        seen_domains = set()
        for item in prof.get("history", []):
            host = hostname_from_url(item.get("url", ""))
            if not host or host in seen_domains:
                continue
            seen_domains.add(host)
            domain_id = f"domain::{host}"
            add_node(domain_id, host, "domain")
            add_edge(profile_id, domain_id, "visited")

        seen_dl_domains = set()
        for item in prof.get("downloads", []):
            src = item.get("source_url") or item.get("url") or ""
            host = hostname_from_url(src)
            if host and host not in seen_dl_domains:
                seen_dl_domains.add(host)
                domain_id = f"domain::{host}"
                add_node(domain_id, host, "domain")
                add_edge(profile_id, domain_id, "download-source")

            name = item.get("target_path") or item.get("current_path") or item.get("title") or ""
            if name:
                dl_name = Path(name).name if any(sep in name for sep in ["\\", "/"]) else safe_str(name)
                dl_id = f"download::{profile_id}::{dl_name}"
                add_node(dl_id, dl_name[:60], "download")
                add_edge(profile_id, dl_id, "downloaded")

        for item in prof.get("extensions", []):
            ext_name = item.get("name") or item.get("extension_id") or item.get("id") or ""
            ext_id = item.get("extension_id") or item.get("id") or ext_name
            if ext_name:
                node_id = f"extension::{profile_id}::{ext_id}"
                add_node(node_id, ext_name[:60], "extension", {"version": item.get("version", "")})
                add_edge(profile_id, node_id, "has-extension")

    return {
        "generated_utc": utc_now(),
        "nodes_total": len(nodes),
        "edges_total": len(edges),
        "nodes": nodes,
        "edges": edges,
    }

# =============================================================================
# Reporting
# =============================================================================

def collect_domains_from_urls(url_items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in url_items:
        url = item.get("url") or item.get("source_url") or ""
        try:
            host = hostname_from_url(url)
            if host:
                counts[host] = counts.get(host, 0) + 1
        except Exception:
            pass
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:50])

def render_html_report(report: Dict[str, Any], ai_analysis: Dict[str, Any]) -> str:
    summary = report.get("summary", {})
    profiles = report.get("profiles", [])
    ai_domains = ai_analysis.get("domains", [])[:30]
    parts = []

    parts.append("<!DOCTYPE html>")
    parts.append("<html><head><meta charset='utf-8'>")
    parts.append("<title>BrowserTrace DFIR Report</title>")
    parts.append("""
    <style>
        body { font-family: Arial, Helvetica, sans-serif; margin: 24px; background: #f6f8fa; color: #222; }
        h1, h2, h3 { margin-top: 1.2em; }
        .card { background: #fff; border-radius: 10px; padding: 16px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; text-align: left; }
        th { background: #f0f3f7; }
        .small { color: #555; font-size: 12px; }
        .badge { display: inline-block; background: #e9eef7; border-radius: 999px; padding: 4px 10px; margin-right: 6px; margin-bottom: 6px; }
        .sev-high { color: #b00020; font-weight: bold; }
        .sev-medium { color: #a86400; font-weight: bold; }
        .sev-low { color: #156c2f; font-weight: bold; }
        .cls-safe { color: #156c2f; font-weight: bold; }
        .cls-review { color: #a86400; font-weight: bold; }
        .cls-suspicious { color: #b00020; font-weight: bold; }
        a { color: #0b57d0; text-decoration: none; }
        a:hover { text-decoration: underline; }
        ul { margin-top: 4px; }
    </style>
    </head><body>
    """)

    parts.append(f"<h1>{html.escape(APP_NAME)} Report</h1>")
    parts.append(f"<div class='card'><div><strong>Generated:</strong> {html.escape(report.get('generated_utc', ''))}</div>")
    parts.append(f"<div><strong>Host:</strong> {html.escape(report.get('host', ''))}</div>")
    parts.append(f"<div><strong>User:</strong> {html.escape(report.get('user', ''))}</div>")
    parts.append(f"<div><strong>Version:</strong> {html.escape(report.get('tool_version', ''))}</div>")
    parts.append("<div style='margin-top:10px'>")
    parts.append("<a href='timeline.html'>timeline.html</a> | ")
    parts.append("<a href='graph.html'>graph.html</a> | ")
    parts.append("<a href='ai_analysis.json'>ai_analysis.json</a> | ")
    parts.append("<a href='timeline.json'>timeline.json</a> | ")
    parts.append("<a href='graph.json'>graph.json</a>")
    parts.append("</div></div>")

    parts.append("<div class='card'><h2>Summary</h2>")
    for k, v in summary.items():
        parts.append(f"<span class='badge'>{html.escape(str(k))}: {html.escape(str(v))}</span>")
    parts.append("</div>")

    parts.append("<div class='card'><h2>AI Suspicious Domains</h2>")
    parts.append(
        f"<p><span class='badge'>domains_total: {ai_analysis.get('domains_total', 0)}</span>"
        f"<span class='badge'>high_risk_total: {ai_analysis.get('high_risk_total', 0)}</span>"
        f"<span class='badge'>medium_risk_total: {ai_analysis.get('medium_risk_total', 0)}</span>"
        f"<span class='badge'>low_risk_total: {ai_analysis.get('low_risk_total', 0)}</span>"
        f"<span class='badge'>safe: {ai_analysis.get('classified_safe_total', 0)}</span>"
        f"<span class='badge'>review: {ai_analysis.get('classified_review_total', 0)}</span>"
        f"<span class='badge'>suspicious: {ai_analysis.get('classified_suspicious_total', 0)}</span></p>"
    )
    if ai_domains:
        parts.append("<table><tr><th>Classification</th><th>Severity</th><th>Score</th><th>Domain</th><th>Occurrences</th><th>Profiles</th><th>First seen</th><th>Last seen</th><th>Reasons</th></tr>")
        for item in ai_domains:
            sev_cls = "sev-high" if item["severity"] == "HIGH" else ("sev-medium" if item["severity"] == "MEDIUM" else "sev-low")
            cls_cls = "cls-suspicious" if item["classification"] == "suspicious" else ("cls-review" if item["classification"] == "review" else "cls-safe")
            parts.append(
                f"<tr><td class='{cls_cls}'>{html.escape(item['classification'])}</td>"
                f"<td class='{sev_cls}'>{html.escape(item['severity'])}</td>"
                f"<td>{item['score']}</td>"
                f"<td>{html.escape(item['domain'])}</td>"
                f"<td>{item['occurrences']}</td>"
                f"<td>{item['profiles_count']}</td>"
                f"<td>{html.escape(item.get('first_seen', ''))}</td>"
                f"<td>{html.escape(item.get('last_seen', ''))}</td>"
                f"<td>{html.escape('; '.join(item.get('reasons', [])[:4]))}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>No domains analyzed.</p>")
    parts.append("</div>")

    for prof in profiles:
        parts.append("<div class='card'>")
        parts.append(f"<h2>{html.escape(prof.get('browser', ''))} / {html.escape(prof.get('profile_name', ''))}</h2>")
        parts.append(f"<div class='small'>Profile path: {html.escape(prof.get('profile_path', ''))}</div>")

        counts = prof.get("counts", {})
        parts.append("<p>")
        for k, v in counts.items():
            parts.append(f"<span class='badge'>{html.escape(str(k))}: {html.escape(str(v))}</span>")
        parts.append("</p>")

        top_domains = prof.get("top_domains", {})
        if top_domains:
            parts.append("<h3>Top domains</h3><table><tr><th>Domain</th><th>Count</th></tr>")
            for domain, cnt in top_domains.items():
                parts.append(f"<tr><td>{html.escape(domain)}</td><td>{cnt}</td></tr>")
            parts.append("</table>")

        history = prof.get("history", [])[:50]
        if history:
            parts.append("<h3>History (top 50)</h3><table><tr><th>Time</th><th>Title</th><th>URL</th></tr>")
            for item in history:
                parts.append(
                    f"<tr><td>{html.escape(item.get('last_visit_utc', ''))}</td>"
                    f"<td>{html.escape(item.get('title', ''))}</td>"
                    f"<td>{html.escape(item.get('url', ''))}</td></tr>"
                )
            parts.append("</table>")

        downloads = prof.get("downloads", [])[:50]
        if downloads:
            parts.append("<h3>Downloads (top 50)</h3><table><tr><th>Time</th><th>Source</th><th>Target</th></tr>")
            for item in downloads:
                time_val = item.get("start_utc") or item.get("timestamp_utc") or ""
                src = item.get("source_url") or item.get("url") or ""
                target = item.get("target_path") or item.get("current_path") or ""
                parts.append(
                    f"<tr><td>{html.escape(time_val)}</td>"
                    f"<td>{html.escape(src)}</td>"
                    f"<td>{html.escape(target)}</td></tr>"
                )
            parts.append("</table>")

        bookmarks = prof.get("bookmarks", [])[:50]
        if bookmarks:
            parts.append("<h3>Bookmarks (top 50)</h3><table><tr><th>Date</th><th>Name/Title</th><th>URL</th></tr>")
            for item in bookmarks:
                date_val = item.get("date_added") or item.get("date_added_utc") or ""
                name = item.get("name") or item.get("title") or ""
                url = item.get("url") or ""
                parts.append(
                    f"<tr><td>{html.escape(date_val)}</td>"
                    f"<td>{html.escape(name)}</td>"
                    f"<td>{html.escape(url)}</td></tr>"
                )
            parts.append("</table>")

        extensions = prof.get("extensions", [])[:50]
        if extensions:
            parts.append("<h3>Extensions (top 50)</h3><table><tr><th>ID</th><th>Name</th><th>Version</th><th>Path/Manifest</th></tr>")
            for item in extensions:
                ext_id = item.get("extension_id") or item.get("id") or ""
                name = item.get("name") or ""
                version = item.get("version") or ""
                path_ = item.get("manifest_path") or item.get("path") or ""
                parts.append(
                    f"<tr><td>{html.escape(ext_id)}</td>"
                    f"<td>{html.escape(name)}</td>"
                    f"<td>{html.escape(version)}</td>"
                    f"<td>{html.escape(path_)}</td></tr>"
                )
            parts.append("</table>")

        errors = prof.get("errors", [])
        if errors:
            parts.append("<h3>Errors</h3><ul>")
            for e in errors:
                parts.append(f"<li>{html.escape(str(e))}</li>")
            parts.append("</ul>")

        parts.append("</div>")

    parts.append("</body></html>")
    return "".join(parts)

def render_timeline_html(timeline: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>BrowserTrace Timeline</title>")
    parts.append("""
    <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 24px; background: #f6f8fa; color: #222; }
    .card { background: #fff; border-radius: 10px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f0f3f7; }
    .type-history { color: #0b57d0; font-weight: bold; }
    .type-download { color: #b00020; font-weight: bold; }
    .type-bookmark { color: #156c2f; font-weight: bold; }
    a { color: #0b57d0; }
    </style>
    </head><body>
    """)
    parts.append("<h1>BrowserTrace DFIR Timeline</h1>")
    parts.append("<div class='card'><a href='report.html'>report.html</a> | <a href='graph.html'>graph.html</a> | <a href='timeline.json'>timeline.json</a></div>")
    parts.append("<div class='card'>")
    parts.append("<table><tr><th>Timestamp UTC</th><th>Type</th><th>Profile</th><th>Title</th><th>URL</th></tr>")
    for item in timeline[:2000]:
        t = item.get("type", "")
        cls = "type-history" if t == "history" else ("type-download" if t == "download" else "type-bookmark")
        parts.append(
            f"<tr><td>{html.escape(item.get('timestamp_utc', ''))}</td>"
            f"<td class='{cls}'>{html.escape(t)}</td>"
            f"<td>{html.escape(item.get('profile', ''))}</td>"
            f"<td>{html.escape(item.get('title', ''))}</td>"
            f"<td>{html.escape(item.get('url', ''))}</td></tr>"
        )
    parts.append("</table></div></body></html>")
    return "".join(parts)

def render_graph_html(graph_data: Dict[str, Any]) -> str:
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    user_nodes = [n for n in nodes if n["kind"] == "user"]
    browser_nodes = [n for n in nodes if n["kind"] == "browser"]
    profile_nodes = [n for n in nodes if n["kind"] == "profile"]
    domain_nodes = [n for n in nodes if n["kind"] == "domain"][:80]
    extension_nodes = [n for n in nodes if n["kind"] == "extension"][:60]
    download_nodes = [n for n in nodes if n["kind"] == "download"][:60]

    columns = [
        ("User", user_nodes),
        ("Browsers", browser_nodes),
        ("Profiles", profile_nodes),
        ("Domains", domain_nodes),
        ("Extensions", extension_nodes),
        ("Downloads", download_nodes),
    ]

    width = 1800
    col_x = [90, 340, 650, 980, 1300, 1600]
    positions: Dict[str, Tuple[int, int]] = {}
    shapes: List[str] = []

    for idx, (_, col_nodes) in enumerate(columns):
        x = col_x[idx]
        spacing = 70
        start_y = 80
        for i, node in enumerate(col_nodes):
            y = start_y + i * spacing
            positions[node["id"]] = (x, y)

    def node_color(kind: str) -> str:
        return {
            "user": "#dbeafe",
            "browser": "#ede9fe",
            "profile": "#dcfce7",
            "domain": "#fee2e2",
            "extension": "#fef3c7",
            "download": "#e0f2fe",
        }.get(kind, "#f3f4f6")

    edge_lines: List[str] = []
    for edge in edges:
        src = positions.get(edge["source"])
        dst = positions.get(edge["target"])
        if not src or not dst:
            continue
        x1, y1 = src
        x2, y2 = dst
        edge_lines.append(
            f"<line x1='{x1 + 90}' y1='{y1 + 18}' x2='{x2 - 90}' y2='{y2 + 18}' stroke='#94a3b8' stroke-width='1.5' />"
        )

    for node in nodes:
        pos = positions.get(node["id"])
        if not pos:
            continue
        x, y = pos
        label = html.escape(node["label"][:32])
        fill = node_color(node["kind"])
        shapes.append(
            f"<rect x='{x - 85}' y='{y}' rx='10' ry='10' width='170' height='36' fill='{fill}' stroke='#475569' stroke-width='1' />"
            f"<text x='{x}' y='{y + 22}' font-size='12' text-anchor='middle' fill='#0f172a'>{label}</text>"
        )

    parts: List[str] = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>BrowserTrace Graph</title>")
    parts.append("""
    <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 24px; background: #f6f8fa; color: #222; }
    .card { background: #fff; border-radius: 10px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
    .legend span { display:inline-block; padding:6px 10px; border-radius:999px; margin-right:8px; margin-bottom:8px; font-size:13px; }
    a { color: #0b57d0; }
    .svgwrap { overflow-x: auto; border: 1px solid #ddd; background: white; }
    </style>
    </head><body>
    """)
    parts.append("<h1>BrowserTrace DFIR Evidence Graph</h1>")
    parts.append("<div class='card'><a href='report.html'>report.html</a> | <a href='timeline.html'>timeline.html</a> | <a href='graph.json'>graph.json</a></div>")
    parts.append("<div class='card legend'>")
    parts.append("<span style='background:#dbeafe'>User</span>")
    parts.append("<span style='background:#ede9fe'>Browser</span>")
    parts.append("<span style='background:#dcfce7'>Profile</span>")
    parts.append("<span style='background:#fee2e2'>Domain</span>")
    parts.append("<span style='background:#fef3c7'>Extension</span>")
    parts.append("<span style='background:#e0f2fe'>Download</span>")
    parts.append("</div>")
    parts.append("<div class='card svgwrap'>")
    svg_height = max(800, 120 + max((pos[1] for pos in positions.values()), default=0))
    parts.append(f"<svg width='{width}' height='{svg_height}' xmlns='http://www.w3.org/2000/svg'>")
    for idx, (title, _) in enumerate(columns):
        parts.append(f"<text x='{col_x[idx]}' y='35' font-size='16' text-anchor='middle' fill='#0f172a'>{html.escape(title)}</text>")
    parts.extend(edge_lines)
    parts.extend(shapes)
    parts.append("</svg></div></body></html>")
    return "".join(parts)

# =============================================================================
# Core workflow
# =============================================================================

def acquire_profile_artifacts(profile: Dict[str, Any], evidence_dir: Path) -> Dict[str, Any]:
    acquired = {"files": []}
    browser = profile["browser"]
    profile_name = profile["profile_name"]
    profile_root = evidence_dir / browser / profile_name
    ensure_dir(profile_root)

    if profile["browser_family"] == "chromium":
        for key in ("history", "bookmarks"):
            src = Path(profile["artifacts"].get(key, ""))
            if src.exists():
                info = copy_forensic(src, profile_root / src.name)
                acquired["files"].append({"artifact": key, **(info or {})})

        ext_dir = Path(profile["artifacts"].get("extensions_dir", ""))
        if ext_dir.exists() and ext_dir.is_dir():
            ext_out = profile_root / "ExtensionsManifests"
            ensure_dir(ext_out)
            for ext_id in ext_dir.iterdir():
                if not ext_id.is_dir():
                    continue
                versions = [x for x in ext_id.iterdir() if x.is_dir()]
                if not versions:
                    continue
                latest = sorted(versions, key=lambda p: p.name, reverse=True)[0]
                manifest = latest / "manifest.json"
                if manifest.exists():
                    dst = ext_out / f"{ext_id.name}_{latest.name}_manifest.json"
                    info = copy_forensic(manifest, dst)
                    acquired["files"].append({"artifact": "extension_manifest", **(info or {})})

    elif profile["browser_family"] == "firefox":
        for key in ("places", "extensions_json"):
            src = Path(profile["artifacts"].get(key, ""))
            if src.exists():
                info = copy_forensic(src, profile_root / src.name)
                acquired["files"].append({"artifact": key, **(info or {})})

    return acquired

def process_profile(profile: Dict[str, Any], evidence_dir: Path) -> Dict[str, Any]:
    out = {
        "browser_family": profile["browser_family"],
        "browser": profile["browser"],
        "profile_name": profile["profile_name"],
        "profile_path": profile["profile_path"],
        "acquisition": {},
        "history": [],
        "downloads": [],
        "bookmarks": [],
        "extensions": [],
        "top_domains": {},
        "counts": {},
        "errors": [],
    }

    out["acquisition"] = acquire_profile_artifacts(profile, evidence_dir)

    try:
        if profile["browser_family"] == "chromium":
            history_path = Path(profile["artifacts"]["history"])
            if history_path.exists():
                parsed = parse_chromium_history(history_path)
                out["history"] = parsed["history"]
                out["downloads"] = parsed["downloads"]
                out["errors"].extend(parsed["errors"])

            bookmarks_path = Path(profile["artifacts"]["bookmarks"])
            if bookmarks_path.exists():
                parsed = parse_chromium_bookmarks(bookmarks_path)
                out["bookmarks"] = parsed["bookmarks"]
                out["errors"].extend(parsed["errors"])

            ext_dir = Path(profile["artifacts"]["extensions_dir"])
            if ext_dir.exists():
                parsed = parse_chromium_extensions(ext_dir)
                out["extensions"] = parsed["extensions"]
                out["errors"].extend(parsed["errors"])

        elif profile["browser_family"] == "firefox":
            places_path = Path(profile["artifacts"]["places"])
            if places_path.exists():
                parsed = parse_firefox_places(places_path)
                out["history"] = parsed["history"]
                out["downloads"] = parsed["downloads"]
                out["bookmarks"] = parsed["bookmarks"]
                out["errors"].extend(parsed["errors"])

            ext_json = Path(profile["artifacts"]["extensions_json"])
            if ext_json.exists():
                parsed = parse_firefox_extensions(ext_json)
                out["extensions"] = parsed["extensions"]
                out["errors"].extend(parsed["errors"])

        domain_items = []
        domain_items.extend(out["history"])
        domain_items.extend(out["downloads"])
        out["top_domains"] = collect_domains_from_urls(domain_items)

        out["counts"] = {
            "history": len(out["history"]),
            "downloads": len(out["downloads"]),
            "bookmarks": len(out["bookmarks"]),
            "extensions": len(out["extensions"]),
            "errors": len(out["errors"]),
            "acquired_files": len(out["acquisition"].get("files", [])),
        }

    except Exception as e:
        out["errors"].append(str(e))

    return out

def build_summary(profile_reports: List[Dict[str, Any]], ai_analysis: Dict[str, Any], timeline: List[Dict[str, Any]], graph: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "profiles_total": len(profile_reports),
        "history_total": sum(len(p.get("history", [])) for p in profile_reports),
        "downloads_total": sum(len(p.get("downloads", [])) for p in profile_reports),
        "bookmarks_total": sum(len(p.get("bookmarks", [])) for p in profile_reports),
        "extensions_total": sum(len(p.get("extensions", [])) for p in profile_reports),
        "errors_total": sum(len(p.get("errors", [])) for p in profile_reports),
        "ai_high_risk_domains": ai_analysis.get("high_risk_total", 0),
        "ai_review_domains": ai_analysis.get("classified_review_total", 0),
        "timeline_events_total": len(timeline),
        "graph_nodes_total": graph.get("nodes_total", 0),
        "graph_edges_total": graph.get("edges_total", 0),
    }

# =============================================================================
# Main
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="BrowserTrace DFIR - forensic-safe browser artifact triage tool"
    )
    parser.add_argument("--output-dir", default="browsertrace_output", help="Output directory")
    parser.add_argument("--browser", default="all", choices=["all", "chromium", "firefox"],
                        help="Browser family to scan when using automatic discovery")
    parser.add_argument("--limit-profiles", type=int, default=0,
                        help="Optional limit on number of profiles processed")
    parser.add_argument("--profile-path", default="",
                        help="Optional path to a manually supplied browser profile directory")
    parser.add_argument("--profile-type", default="", choices=["", "chromium", "firefox"],
                        help="Required with --profile-path: profile family of the supplied profile")
    return parser.parse_args()

def main() -> int:
    args = parse_args()

    output_dir = Path(args.output_dir).resolve()
    evidence_dir = output_dir / "evidence"
    ensure_dir(output_dir)
    ensure_dir(evidence_dir)

    discovered: List[Dict[str, Any]] = []

    if args.profile_path:
        manual_profile_path = Path(args.profile_path)
        if not manual_profile_path.exists() or not manual_profile_path.is_dir():
            print(f"[!] Invalid --profile-path: {manual_profile_path}")
            return 1
        if not args.profile_type:
            print("[!] --profile-type is required when using --profile-path (chromium or firefox)")
            return 1

        discovered.append(build_manual_profile(manual_profile_path, args.profile_type))
    else:
        if args.browser in ("all", "chromium"):
            discovered.extend(discover_chromium_profiles())
        if args.browser in ("all", "firefox"):
            discovered.extend(discover_firefox_profiles())

        if args.limit_profiles and args.limit_profiles > 0:
            discovered = discovered[:args.limit_profiles]

    profile_reports: List[Dict[str, Any]] = []
    for profile in discovered:
        profile_reports.append(process_profile(profile, evidence_dir))

    ai_analysis = build_ai_analysis(profile_reports)
    timeline = build_timeline(profile_reports)
    graph_data = build_graph(
        profile_reports,
        os.environ.get("USERNAME") or os.environ.get("USER") or "",
        socket.gethostname()
    )

    manifest = {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "generated_utc": utc_now(),
        "host": socket.gethostname(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "profiles_discovered": len(discovered),
        "profiles": discovered,
        "mode": "manual-profile" if args.profile_path else "automatic-discovery",
        "extra_outputs": [
            "report.html",
            "report.json",
            "manifest.json",
            "ai_analysis.json",
            "timeline.json",
            "timeline.html",
            "graph.json",
            "graph.html",
        ]
    }

    report = {
        "app_name": APP_NAME,
        "tool_version": APP_VERSION,
        "generated_utc": utc_now(),
        "host": socket.gethostname(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "summary": build_summary(profile_reports, ai_analysis, timeline, graph_data),
        "profiles": profile_reports,
        "ai_analysis_overview": {
            "high_risk_total": ai_analysis.get("high_risk_total", 0),
            "medium_risk_total": ai_analysis.get("medium_risk_total", 0),
            "domains_total": ai_analysis.get("domains_total", 0),
            "safe_total": ai_analysis.get("classified_safe_total", 0),
            "review_total": ai_analysis.get("classified_review_total", 0),
            "suspicious_total": ai_analysis.get("classified_suspicious_total", 0),
        },
        "notice": (
            "This report is intended for authorized digital forensics / incident response / triage. "
            "It does not decrypt passwords, cookies, or payment data. "
            "AI findings are heuristic and should be treated as investigative leads, not proof."
        ),
    }

    manifest_path = output_dir / "manifest.json"
    report_path = output_dir / "report.json"
    html_path = output_dir / "report.html"
    ai_path = output_dir / "ai_analysis.json"
    timeline_json_path = output_dir / "timeline.json"
    timeline_html_path = output_dir / "timeline.html"
    graph_json_path = output_dir / "graph.json"
    graph_html_path = output_dir / "graph.html"

    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with ai_path.open("w", encoding="utf-8") as f:
        json.dump(ai_analysis, f, indent=2, ensure_ascii=False)

    with timeline_json_path.open("w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2, ensure_ascii=False)

    with graph_json_path.open("w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2, ensure_ascii=False)

    with html_path.open("w", encoding="utf-8") as f:
        f.write(render_html_report(report, ai_analysis))

    with timeline_html_path.open("w", encoding="utf-8") as f:
        f.write(render_timeline_html(timeline))

    with graph_html_path.open("w", encoding="utf-8") as f:
        f.write(render_graph_html(graph_data))

    print(f"[+] {APP_NAME} completed")
    print(f"[+] Output directory : {output_dir}")
    print(f"[+] Manifest : {manifest_path}")
    print(f"[+] JSON report : {report_path}")
    print(f"[+] HTML report : {html_path}")
    print(f"[+] AI analysis : {ai_path}")
    print(f"[+] Timeline JSON : {timeline_json_path}")
    print(f"[+] Timeline HTML : {timeline_html_path}")
    print(f"[+] Graph JSON : {graph_json_path}")
    print(f"[+] Graph HTML : {graph_html_path}")
    print(f"[+] Profiles scanned : {len(profile_reports)}")
    print(f"[+] Mode : {'manual-profile' if args.profile_path else 'automatic-discovery'}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
