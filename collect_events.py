#!/usr/bin/env python3
"""
Texas Cyber Events Monitor
- Fetches a fixed list of event source URLs
- Extracts upcoming events in next 90 days
- Filters to Dallas / North Texas, Austin, Houston, San Antonio
- Deduplicates by (title + start_date + registration_url)
- Outputs: events.csv and events.ics

Notes:
- Many sources are static HTML and can be parsed directly.
- Some (Meetup, certain chapter platforms) may be JS-heavy and/or block scraping.
  This script includes a graceful fallback: it records a "needs_manual_review"
  log entry instead of inventing events.
"""

from __future__ import annotations

import csv
import re
import sys
import json
import time
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ---------- Config ----------
DAYS_AHEAD = 90

OUTPUT_CSV = "events.csv"
OUTPUT_ICS = "events.ics"
OUTPUT_LOG = "run_log.json"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0 Safari/537.36"
)

TIMEZONE_NAME = "America/Chicago"  # Central Time (best-effort; ICS will use floating local time)

METROS = {
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

    # Conferences / directories (may need manual review depending on structure)
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

# ---------- Data model ----------
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


# ---------- Helpers ----------
def now_ct() -> datetime:
    # Best-effort: use naive local time in Actions runner; treat as CT for filtering windows.
    # (If you want perfect timezone handling, we can add zoneinfo and convert explicitly.)
    return datetime.now()

def clean_ws(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def guess_metro(text: str) -> Optional[str]:
    t = (text or "").lower()
    for city, keys in METROS.items():
        if any(k in t for k in keys):
            return city
    return None

def is_virtual(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in ["virtual", "online", "zoom", "webinar", "teams", "remote"])

def within_window(dt: datetime, start: datetime, end: datetime) -> bool:
    return start <= dt <= end

def safe_get(url: str, timeout: int = 30) -> Tuple[Optional[str], Optional[str]]:
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
        if r.status_code >= 400:
            return None, f"HTTP {r.status_code}"
        return r.text, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

DATE_PATTERNS = [
    # 2026-02-19
    re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b"),
    # Feb 19, 2026 / February 19, 2026
    re.compile(r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
               r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|"
               r"Dec(?:ember)?)\s+(\d{1,2})(?:st|nd|rd|th)?\,?\s+(20\d{2})\b", re.I),
]

MONTHS = {
    "jan": 1, "january": 1,
    "feb": 2, "february": 2,
    "mar": 3, "march": 3,
    "apr": 4, "april": 4,
    "may": 5,
    "jun": 6, "june": 6,
    "jul": 7, "july": 7,
    "aug": 8, "august": 8,
    "sep": 9, "september": 9,
    "oct": 10, "october": 10,
    "nov": 11, "november": 11,
    "dec": 12, "december": 12,
}

TIME_RE = re.compile(r"\b(\d{1,2}):(\d{2})\s*(am|pm)?\b", re.I)

def parse_first_date(text: str) -> Optional[datetime]:
    t = text or ""
    # ISO date
    m = DATE_PATTERNS[0].search(t)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return datetime(y, mo, d)
    # Month name date
    m = DATE_PATTERNS[1].search(t)
    if m:
        mon = MONTHS[m.group(1).lower()[:3] if len(m.group(1)) > 3 else m.group(1).lower()]
        day = int(m.group(2))
        year = int(m.group(3))
        return datetime(year, mon, day)
    return None

def parse_first_time(text: str) -> str:
    m = TIME_RE.search(text or "")
    if not m:
        return ""
    hh = int(m.group(1))
    mm = int(m.group(2))
    ap = (m.group(3) or "").lower()
    if ap == "pm" and hh != 12:
        hh += 12
    if ap == "am" and hh == 12:
        hh = 0
    return f"{hh:02d}:{mm:02d}"

def make_uid(ev: Event) -> str:
    raw = f"{ev.event_title}|{ev.start_date}|{ev.registration_url}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16] + "@txcyberevents"

def dedupe(events: List[Event]) -> List[Event]:
    seen = set()
    out = []
    for ev in events:
        k = (ev.event_title.strip().lower(), ev.start_date, ev.registration_url.strip().lower())
        if k in seen:
            continue
        seen.add(k)
        out.append(ev)
    return out

def sort_events(events: List[Event]) -> List[Event]:
    def key(ev: Event):
        return (ev.start_date, ev.start_time or "00:00", ev.event_title.lower())
    return sorted(events, key=key)

# ---------- Parsers (generic heuristic) ----------
def extract_candidate_blocks(soup: BeautifulSoup) -> List[BeautifulSoup]:
    # Heuristic: many event lists use article/li/div cards
    blocks = []
    for tag in soup.select("article, li, .event, .tribe-events-calendar-list__event, .event-item, .views-row"):
        text = clean_ws(tag.get_text(" "))
        if len(text) < 30:
            continue
        if parse_first_date(text):
            blocks.append(tag)
    # If nothing found, fall back to any element containing a date
    if not blocks:
        for tag in soup.find_all(["div", "section", "li", "article"]):
            text = clean_ws(tag.get_text(" "))
            if len(text) < 40:
                continue
            if parse_first_date(text):
                blocks.append(tag)
    return blocks[:80]

def extract_link(tag) -> str:
    a = tag.find("a", href=True)
    if not a:
        return ""
    return a["href"]

def build_events_from_html(org: str, group: str, source_url: str, html: str, log: Dict) -> List[Event]:
    soup = BeautifulSoup(html, "html.parser")
    blocks = extract_candidate_blocks(soup)

    events: List[Event] = []
    start = now_ct()
    end = start + timedelta(days=DAYS_AHEAD)

    for b in blocks:
        txt = clean_ws(b.get_text(" "))

        dt = parse_first_date(txt)
        if not dt:
            continue

        # Filter window
        if not within_window(dt, start.replace(hour=0, minute=0, second=0, microsecond=0), end):
            continue

        title = ""
        # Prefer headings
        h = b.find(["h1", "h2", "h3", "h4"])
        if h:
            title = clean_ws(h.get_text(" "))
        if not title:
            # fallback: first ~12 words
            title = " ".join(txt.split()[:12])

        href = extract_link(b)
        if href and not href.startswith("http"):
            href = urljoin(source_url, href)

        # Guess metro / virtual rules
        city = guess_metro(txt) or guess_metro(group) or ""
        virtual = is_virtual(txt)
        if virtual and not city:
            # only include if virtual AND tagged to a metro (we couldn't detect)
            continue
        if city not in METROS:
            # Only keep if clearly one of our metros
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
            registration_url=href or "",
            source_url=source_url,
        )
        events.append(ev)

    # Track if we got zero events from a likely JS-heavy source
    if not events and any(k in source_url.lower() for k in ["meetup.com", "eventbrite.com", "engage.isaca.org"]):
        log["needs_manual_review"].append({
            "source_url": source_url,
            "reason": "Likely JS-rendered or bot-protected; consider API/headless browser."
        })

    return events


# ---------- Output writers ----------
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
        # Floating local time (no TZID) for simplicity; Google Calendar will interpret in your calendar's TZ.
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

        # Description includes org/chapter + source + registration
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


def main() -> int:
    log = {
        "run_started": datetime.utcnow().isoformat() + "Z",
        "sources_total": len(SOURCES),
        "sources_ok": 0,
        "sources_failed": [],
        "needs_manual_review": [],
        "events_extracted": 0,
    }

    all_events: List[Event] = []

    for org, group, url in SOURCES:
        html, err = safe_get(url)
        if err:
            log["sources_failed"].append({"source_url": url, "error": err})
            continue
        log["sources_ok"] += 1
        evs = build_events_from_html(org, group, url, html, log)
        all_events.extend(evs)
        time.sleep(0.5)  # be polite

    all_events = dedupe(all_events)
    all_events = sort_events(all_events)
    log["events_extracted"] = len(all_events)

    write_csv(all_events, OUTPUT_CSV)
    write_ics(all_events, OUTPUT_ICS)
    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)

    print(f"Wrote {OUTPUT_CSV}, {OUTPUT_ICS}. Extracted events: {len(all_events)}")
    if log["sources_failed"]:
        print(f"Sources failed: {len(log['sources_failed'])} (see {OUTPUT_LOG})", file=sys.stderr)
    if log["needs_manual_review"]:
        print(f"Needs manual review: {len(log['needs_manual_review'])} (see {OUTPUT_LOG})", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
