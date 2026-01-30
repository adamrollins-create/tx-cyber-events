#!/usr/bin/env python3
"""
Texas Cyber Events Monitor (rewritten)
- Fetches a fixed list of event source URLs
- Extracts upcoming events in next 90 days
- Filters to Dallas / North Texas, Austin, Houston, San Antonio
- Includes virtual events only when clearly tied to a metro
- Deduplicates by (title + start_date + registration_url)
- Outputs: events.csv and events.ics
- Writes detailed run_log.json and saves debug HTML snapshots for troubleshooting

Important:
- This script does NOT invent events. If a source appears JS-rendered/bot-protected,
  it records needs_manual_review and stores the fetched HTML for inspection.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


# ----------------- Config -----------------
DAYS_AHEAD = 90

OUTPUT_CSV = "events.csv"
OUTPUT_ICS = "events.ics"
OUTPUT_LOG = "run_log.json"

DEBUG_DIR = Path("debug_html")
DEBUG_DIR.mkdir(exist_ok=True)

SLEEP_BETWEEN_SOURCES_SEC = 0.75
FETCH_TIMEOUT_SEC = 30
MAX_CANDIDATES_PER_SOURCE = 120

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0 Safari/537.36"
)

METROS: Dict[str, List[str]] = {
    "Dallas": ["dallas", "dfw", "fort worth", "north texas", "plano", "frisco", "irving", "arlington"],
    "Austin": ["austin", "atx", "round rock", "cedar park"],
    "Houston": ["houston", "the woodlands", "sugar land", "katy"],
    "San Antonio": ["san antonio", "satx"],
}

# Fixed sources: (org, group/chapter, source_url)
SOURCES: List[Tuple[str, str, str]] = [
    ("ONE-ISAC", "Event Calendar", "https://oneisac.org/event-calendar/"),
    ("ONE-ISAC", "Industry Events", "https://oneisac.org/industry-events/"),

    ("ISSA", "NTX Dallas", "https://www.ntxissa.org/about/calendar-of-events"),
    ("ISSA", "NTX Dallas", "https://www.ntxissa.org/upcoming"),
    ("ISSA", "Austin Chapter", "https://www.austinissa.org/events"),
    ("ISSA", "South Texas (Houston)", "https://southtexasissa.starchapter.com/meetinginfo.php"),
    ("ISSA", "Alamo (San Antonio)", "https://www.alamoissa.org/event-list"),

    ("ISACA", "North Texas Chapter", "https://engage.isaca.org/northtexaschapter/events/calendar"),
    ("ISACA", "Austin Chapter", "https://engage.isaca.org/austinchapter/events/calendar"),
    ("ISACA", "Greater Houston Chapter", "https://engage.isaca.org/greaterhoustonchapter/events/calendar"),
    ("ISACA", "San Antonio Chapter", "https://engage.isaca.org/sanantoniochapter/events/calendar"),

    ("(ISC)²", "DFW Chapter", "https://isc2chapter-dfw.org/events/future-events"),
    ("(ISC)²", "Houston Chapter", "https://www.isc2houstonchapter.org/events"),
    ("(ISC)²", "Alamo (San Antonio)", "https://alamoisc2.org/events"),

    ("Meetup", "Dallas Hackers Association", "https://www.meetup.com/dallas-hackers-association/"),
    ("Meetup", "OWASP Dallas", "https://www.meetup.com/dallas-the-open-web-application-security-project-meetup/"),
    ("Meetup", "dc512 ATX", "https://www.meetup.com/dc512atx/"),
    ("Meetup", "OWASP Austin", "https://www.meetup.com/owasp-austin-chapter/"),
    ("Meetup", "Austin Application Security", "https://www.meetup.com/austin-application-security-meetup-group/"),
    ("Meetup", "OWASP Houston", "https://www.meetup.com/owasp-houston/"),
    ("Meetup", "OWASP San Antonio", "https://www.meetup.com/owasp-sanantonio/"),
    ("Community", "DCGSA TX", "https://dcgsatx.com/"),

    ("Directory", "InfoSec-Conferences Texas", "https://infosec-conferences.com/us-state/texas"),
    ("Directory", "All Conference Alert TX", "https://www.allconferencealert.com/texas/information-security-conference.html"),
    ("Directory", "GovEvents", "https://govevents.com/"),
    ("Conference", "FutureCon Dallas", "https://futureconevents.com/events/dallas-tx-2026/"),
    ("Conference", "ISMG Dallas Summit", "https://ismg.events/summit/cybersecurity-summit-datasecurity-2025/"),
    ("Conference", "CS4CA USA", "https://usa.cs4ca.com/"),
    ("Conference", "Industrial Defender Events", "https://www.industrialdefender.com/events"),
    ("Conference", "API Cybersecurity Conf", "https://events.api.org/20th-annual-api-cybersecurity-conference-for-the-oil-and-natural-gas-industry/"),
    ("Conference", "Lone Star Cyber Summit", "https://lonestar.cyberseries.io/"),
    ("Conference", "UTINFOSEC", "https://www.utsystem.edu/offices/information-security/utinfosec"),
    ("Conference", "CybersecuritySummit.com", "https://cybersecuritysummit.com/"),
    ("Directory", "Eventbrite Austin Cybersecurity", "https://www.eventbrite.com/d/tx--austin/cyber-security/"),
    ("Directory", "Meetup San Antonio Cybersecurity Search", "https://www.meetup.com/find/us--tx--san-antonio/cybersecurity/"),
    ("Directory", "CyberRisk Alliance Events", "https://cyberriskalliance.com/events"),
]

# Sites that are frequently JS-rendered / bot-protected (heuristic only)
LIKELY_JS_OR_BLOCKED_HOST_KEYWORDS = [
    "meetup.com",
    "eventbrite.com",
]


# ----------------- Data model -----------------
@dataclass
class Event:
    org: str
    group: str
    city: str
    event_title: str
    start_date: str  # YYYY-MM-DD
    start_time: str  # HH:MM (24h) or ""
    end_date: str
    end_time: str
    venue: str
    registration_url: str
    source_url: str


# ----------------- Helpers -----------------
def utc_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def today_local() -> datetime:
    # Naive local time is fine for a rolling 90-day window.
    return datetime.now()

def clean_ws(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", (s or "").strip().lower()).strip("-")[:80]

def guess_metro(text: str) -> Optional[str]:
    t = (text or "").lower()
    for city, keys in METROS.items():
        if any(k in t for k in keys):
            return city
    return None

def is_virtual(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in ["virtual", "online", "zoom", "webinar", "teams", "remote"])

def is_likely_js_or_blocked(url: str) -> bool:
    u = (url or "").lower()
    return any(k in u for k in LIKELY_JS_OR_BLOCKED_HOST_KEYWORDS)

def within_window(dt: datetime, start: datetime, end: datetime) -> bool:
    return start <= dt <= end


# Date parsing
DATE_ISO = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")
DATE_MDY_SLASH = re.compile(r"\b(\d{1,2})/(\d{1,2})/(20\d{2})\b")  # 2/19/2026
DATE_MON_NAME = re.compile(
    r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Sept|Oct(?:ober)?|Nov(?:ember)?|"
    r"Dec(?:ember)?)\s+(\d{1,2})(?:st|nd|rd|th)?\,?\s+(20\d{2})\b",
    re.I,
)

MONTHS = {
    "jan": 1, "january": 1,
    "feb": 2, "february": 2,
    "mar": 3, "march": 3,
    "apr": 4, "april": 4,
    "may": 5,
    "jun": 6, "june": 6,
    "jul": 7, "july": 7,
    "aug": 8, "august": 8,
    "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10,
    "nov": 11, "november": 11,
    "dec": 12, "december": 12,
}

TIME_RE = re.compile(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b", re.I)

def parse_first_date(text: str) -> Optional[datetime]:
    t = text or ""
    m = DATE_ISO.search(t)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return datetime(y, mo, d)

    m = DATE_MDY_SLASH.search(t)
    if m:
        mo, d, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return datetime(y, mo, d)

    m = DATE_MON_NAME.search(t)
    if m:
        mon_raw = m.group(1).lower()
        mon_key = mon_raw if mon_raw in MONTHS else mon_raw[:3]
        mon = MONTHS.get(mon_key)
        if not mon:
            return None
        day = int(m.group(2))
        year = int(m.group(3))
        return datetime(year, mon, day)

    return None

def parse_first_time(text: str) -> str:
    # Heuristic: find something time-like with optional minutes, optional am/pm
    # Examples: "6 pm", "6:30pm", "18:30"
    t = (text or "").lower()
    m = TIME_RE.search(t)
    if not m:
        return ""
    hh = int(m.group(1))
    mm = int(m.group(2) or "00")
    ap = (m.group(3) or "").lower()

    # If no am/pm and hh > 23 treat as invalid
    if not ap and hh > 23:
        return ""

    if ap == "pm" and hh != 12:
        hh += 12
    if ap == "am" and hh == 12:
        hh = 0

    if hh > 23 or mm > 59:
        return ""
    return f"{hh:02d}:{mm:02d}"

def make_uid(ev: Event) -> str:
    raw = f"{ev.event_title}|{ev.start_date}|{ev.registration_url}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16] + "@txcyberevents"


def normalize_url(href: str, base: str) -> str:
    href = (href or "").strip()
    if not href:
        return ""
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return urljoin(base, href)


def event_key(ev: Event) -> Tuple[str, str, str]:
    return (ev.event_title.strip().lower(), ev.start_date, ev.registration_url.strip().lower())


def dedupe(events: List[Event]) -> List[Event]:
    seen = set()
    out: List[Event] = []
    for ev in events:
        k = event_key(ev)
        if k in seen:
            continue
        seen.add(k)
        out.append(ev)
    return out


def sort_events(events: List[Event]) -> List[Event]:
    def k(ev: Event):
        return (ev.start_date, ev.start_time or "00:00", ev.event_title.lower())
    return sorted(events, key=k)


# ----------------- Fetch with diagnostics -----------------
BLOCK_MARKERS = [
    "cloudflare",
    "access denied",
    "captcha",
    "enable javascript",
    "attention required",
    "incapsula",
    "ddos",
    "akamai",
]

def save_html_snapshot(source_key: str, url: str, html: str) -> str:
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    path = DEBUG_DIR / f"{slug(source_key)}_{h}.html"
    path.write_text(html or "", encoding="utf-8", errors="ignore")
    return str(path)

def fetch(session: requests.Session, url: str) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        r = session.get(url, timeout=FETCH_TIMEOUT_SEC, allow_redirects=True)
        if r.status_code >= 400:
            return r, f"HTTP {r.status_code}"
        return r, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


# ----------------- Parsing -----------------
def extract_candidate_blocks(soup: BeautifulSoup) -> List:
    """
    A wide net:
    - common event card containers
    - list items
    - table rows
    - articles/sections
    Then we later filter blocks that contain a parsable date.
    """
    selectors = [
        "article",
        "li",
        "tr",
        ".event",
        ".events",
        ".event-item",
        ".eventCard",
        ".tribe-events-calendar-list__event",
        ".tribe-events-calendar-list__event-row",
        ".views-row",
        ".ai1ec-event",
        ".calendar-event",
        ".post",
        ".type-tribe_events",
    ]
    blocks = []
    for sel in selectors:
        blocks.extend(soup.select(sel))

    # fallback: if nothing matched, scan likely containers
    if not blocks:
        blocks = soup.find_all(["article", "section", "div", "li", "tr"])

    # De-dupe by object id
    seen = set()
    uniq = []
    for b in blocks:
        i = id(b)
        if i in seen:
            continue
        seen.add(i)
        uniq.append(b)
    return uniq[: MAX_CANDIDATES_PER_SOURCE]

def find_best_title(block) -> str:
    for tag in ["h1", "h2", "h3", "h4"]:
        h = block.find(tag)
        if h:
            t = clean_ws(h.get_text(" "))
            if len(t) >= 4:
                return t
    # fallback: first anchor with meaningful text
    a = block.find("a")
    if a:
        t = clean_ws(a.get_text(" "))
        if len(t) >= 4:
            return t
    # fallback: first 10 words of block
    txt = clean_ws(block.get_text(" "))
    return " ".join(txt.split()[:10])

def find_best_link(block, source_url: str) -> str:
    # Prefer anchor that looks like registration/details, else first href
    anchors = block.find_all("a", href=True)
    if not anchors:
        return ""
    preferred = None
    for a in anchors:
        href = a.get("href", "")
        text = clean_ws(a.get_text(" ")).lower()
        if any(k in text for k in ["register", "registration", "rsvp", "details", "learn more", "tickets"]):
            preferred = href
            break
    href = preferred or anchors[0].get("href", "")
    return normalize_url(href, source_url)

def build_events_from_html(
    org: str,
    group: str,
    source_url: str,
    html: str,
    per_source_log: Dict,
) -> List[Event]:
    soup = BeautifulSoup(html, "html.parser")
    candidates = extract_candidate_blocks(soup)
    per_source_log["candidates_total"] = len(candidates)

    start = today_local().replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=DAYS_AHEAD)

    events: List[Event] = []
    drops: Dict[str, int] = {}
    def drop(reason: str):
        drops[reason] = drops.get(reason, 0) + 1

    dated_blocks = 0

    for b in candidates:
        txt = clean_ws(b.get_text(" "))
        if len(txt) < 30:
            drop("too_short")
            continue

        dt = parse_first_date(txt)
        if not dt:
            drop("no_date")
            continue
        dated_blocks += 1

        if not within_window(dt, start, end):
            drop("out_of_window")
            continue

        title = find_best_title(b)
        if not title or len(title) < 4:
            drop("no_title")
            continue

        reg_url = find_best_link(b, source_url)

        # Metro / virtual policy
        city = guess_metro(txt) or guess_metro(group) or ""
        virtual = is_virtual(txt)
        if virtual and not city:
            drop("virtual_without_metro")
            continue
        if city not in METROS:
            drop("not_target_metro")
            continue

        st_time = parse_first_time(txt)

        ev = Event(
            org=org,
            group=group,
            city=city,
            event_title=title,
            start_date=dt.strftime("%Y-%m-%d"),
            start_time=st_time,
            end_date=dt.strftime("%Y-%m-%d"),
            end_time="",
            venue="",
            registration_url=reg_url,
            source_url=source_url,
        )
        events.append(ev)

    per_source_log["dated_blocks"] = dated_blocks
    per_source_log["events_kept"] = len(events)
    per_source_log["drops"] = drops
    return events


# ----------------- Output writers -----------------
CSV_HEADERS = [
    "org",
    "group/chapter",
    "city",
    "event_title",
    "start_date",
    "start_time",
    "end_date",
    "end_time",
    "address/venue",
    "registration_url",
    "source_url",
]

def write_csv(events: List[Event], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADERS)
        for ev in events:
            w.writerow([
                ev.org,
                ev.group,
                ev.city,
                ev.event_title,
                ev.start_date,
                ev.start_time,
                ev.end_date,
                ev.end_time,
                ev.venue,
                ev.registration_url,
                ev.source_url,
            ])

def ics_escape(s: str) -> str:
    s = s or ""
    return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")

def write_ics(events: List[Event], path: str) -> None:
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "CALSCALE:GREGORIAN",
        "PRODID:-//Texas Cyber Events Monitor//EN",
    ]
    dtstamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    for ev in events:
        # Floating local time (no TZID) for simplicity.
        if ev.start_time:
            dtstart = ev.start_date.replace("-", "") + "T" + ev.start_time.replace(":", "") + "00"
        else:
            dtstart = ev.start_date.replace("-", "")  # all-day

        lines += [
            "BEGIN:VEVENT",
            f"UID:{make_uid(ev)}",
            f"DTSTAMP:{dtstamp}",
            f"SUMMARY:{ics_escape(ev.event_title)}",
        ]

        if ev.start_time:
            lines.append(f"DTSTART:{dtstart}")
        else:
            lines.append(f"DTSTART;VALUE=DATE:{dtstart}")

        desc_parts = [
            f"{ev.org} — {ev.group}",
            f"City: {ev.city}",
            f"Source: {ev.source_url}",
        ]
        if ev.registration_url:
            desc_parts.append(f"Registration: {ev.registration_url}")
        lines.append(f"DESCRIPTION:{ics_escape(' | '.join(desc_parts))}")

        if ev.venue:
            lines.append(f"LOCATION:{ics_escape(ev.venue)}")

        if ev.registration_url:
            lines.append(f"URL:{ics_escape(ev.registration_url)}")

        lines += ["END:VEVENT"]

    lines.append("END:VCALENDAR")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ----------------- Main -----------------
def main() -> int:
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    })

    log: Dict = {
        "run_started": utc_iso(),
        "days_ahead": DAYS_AHEAD,
        "sources_total": len(SOURCES),
        "events_extracted_raw": 0,
        "events_extracted_deduped": 0,
        "sources": {},  # per-source structured logs
        "sources_failed": [],
        "needs_manual_review": [],
    }

    all_events: List[Event] = []

    for org, group, url in SOURCES:
        source_key = f"{org} | {group}"
        per = {
            "org": org,
            "group": group,
            "source_url": url,
            "fetched_at": utc_iso(),
        }
        t0 = time.time()
        resp, err = fetch(session, url)
        per["fetch_seconds"] = round(time.time() - t0, 2)

        if resp is None:
            per["fetch_error"] = err
            log["sources_failed"].append({"source_url": url, "error": err})
            log["sources"][source_key] = per
            time.sleep(SLEEP_BETWEEN_SOURCES_SEC)
            continue

        per["status"] = resp.status_code
        per["final_url"] = str(resp.url)
        per["content_type"] = resp.headers.get("content-type", "")
        per["bytes"] = len(resp.content or b"")

        html = resp.text or ""
        head = (html[:800] or "").lower()
        per["blocked_markers"] = [m for m in BLOCK_MARKERS if m in head]
        per["blocked"] = bool(per["blocked_markers"])
        per["tiny_html"] = len(html) < 4000

        # Save snapshots when anything looks off
        if err or per["blocked"] or per["tiny_html"] or resp.status_code != 200:
            per["saved_html"] = save_html_snapshot(source_key, url, html)

        # If it looks JS-rendered/bot-protected, don’t pretend: record manual review
        if per["blocked"] or (per["tiny_html"] and is_likely_js_or_blocked(url)):
            log["needs_manual_review"].append({
                "source_key": source_key,
                "source_url": url,
                "reason": "Blocked or JS-rendered shell detected",
                "status": resp.status_code,
                "final_url": per["final_url"],
                "saved_html": per.get("saved_html", ""),
            })
            log["sources"][source_key] = per
            time.sleep(SLEEP_BETWEEN_SOURCES_SEC)
            continue

        # Parse HTML heuristically
        evs = build_events_from_html(org, group, url, html, per)
        all_events.extend(evs)

        # If we got nothing and this is likely JS-heavy, flag it
        if not evs and is_likely_js_or_blocked(url):
            log["needs_manual_review"].append({
                "source_key": source_key,
                "source_url": url,
                "reason": "No events parsed and source is likely JS-heavy (consider API/Playwright)",
                "status": resp.status_code,
                "final_url": per["final_url"],
                "saved_html": per.get("saved_html", ""),
            })

        log["sources"][source_key] = per
        time.sleep(SLEEP_BETWEEN_SOURCES_SEC)

    log["events_extracted_raw"] = len(all_events)
    all_events = dedupe(all_events)
    all_events = sort_events(all_events)
    log["events_extracted_deduped"] = len(all_events)

    write_csv(all_events, OUTPUT_CSV)
    write_ics(all_events, OUTPUT_ICS)

    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)

    print(f"Wrote {OUTPUT_CSV}, {OUTPUT_ICS}. Events: {len(all_events)}")
    if log["sources_failed"]:
        print(f"Sources failed: {len(log['sources_failed'])} (see {OUTPUT_LOG})", file=sys.stderr)
    if log["needs_manual_review"]:
        print(f"Needs manual review: {len(log['needs_manual_review'])} (see {OUTPUT_LOG})", file=sys.stderr)
    if DEBUG_DIR.exists():
        # Only mention if we actually wrote files
        wrote_any = any(DEBUG_DIR.glob("*.html"))
        if wrote_any:
            print(f"Saved debug HTML snapshots in {DEBUG_DIR}/", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
