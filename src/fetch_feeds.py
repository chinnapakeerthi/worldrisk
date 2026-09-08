"""
fetch_feeds.py

Pulls raw items from a broad set of public threat-intel sources across two tracks:
  - "traditional_appsec": CVEs, exploited vulnerabilities, breaches, OWASP Top 10
  - "ai_security": AI/LLM/agent security research, attacks, and OWASP GenAI updates

NOTE ON SOURCE VERIFICATION: every URL below is a real, publicly documented feed
or API as of this writing, but outlets occasionally rename or retire feeds.
Before relying on this in production, run `python src/fetch_feeds.py` once and
check the [warn] lines in stdout -- any source that 404s or times out should be
fixed or removed rather than silently trusted.

Output: a list of dicts with the raw fields the classifier will enrich further.
"""

from __future__ import annotations

import hashlib
import json

import re
import feedparser
import requests

USER_AGENT = "worldrisk-tracker/0.1 (+https://github.com/)"
TIMEOUT = 15

# --- RSS/Atom feeds -----------------------------------------------------

RSS_FEEDS = [
    # --- Traditional AppSec: general security news ---
    {"url": "https://thehackernews.com/feeds/posts/default", "source": "The Hacker News", "track": "traditional_appsec"},
    {"url": "https://www.bleepingcomputer.com/feed/", "source": "BleepingComputer", "track": "traditional_appsec"},
    {"url": "https://www.darkreading.com/rss.xml", "source": "Dark Reading", "track": "traditional_appsec"},
    {"url": "https://www.securityweek.com/feed/", "source": "SecurityWeek", "track": "traditional_appsec"},
    {"url": "https://krebsonsecurity.com/feed/", "source": "Krebs on Security", "track": "traditional_appsec"},
    {"url": "https://therecord.media/feed", "source": "The Record", "track": "traditional_appsec"},

    # FIXED URLS
    {"url": "https://owasp.org/feed.xml", "source": "OWASP News", "track": "traditional_appsec"},
    {"url": "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml", "source": "CISA Advisories", "track": "traditional_appsec"},
    {"url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", "source": "CISA ICS Advisories", "track": "traditional_appsec"},

    # NEW SOURCES — Traditional AppSec
    {"url": "https://isc.sans.edu/rssfeed.xml", "source": "SANS Internet Storm Center", "track": "traditional_appsec"},
    {"url": "https://feeds.feedburner.com/TheHackersNews", "source": "THN Feedburner", "track": "traditional_appsec"},
    {"url": "https://www.schneier.com/feed/atom/", "source": "Schneier on Security", "track": "traditional_appsec"},
    {"url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "source": "Google Project Zero", "track": "traditional_appsec"},
    {"url": "https://www.mandiant.com/resources/blog/rss.xml", "source": "Mandiant Blog", "track": "traditional_appsec"},
    {"url": "https://unit42.paloaltonetworks.com/feed/", "source": "Palo Alto Unit 42", "track": "traditional_appsec"},
    {"url": "https://blog.talosintelligence.com/feeds/posts/default", "source": "Cisco Talos", "track": "traditional_appsec"},
    {"url": "https://www.crowdstrike.com/blog/feed/", "source": "CrowdStrike Blog", "track": "traditional_appsec"},
    {"url": "https://research.checkpoint.com/feed/", "source": "Check Point Research", "track": "traditional_appsec"},
    {"url": "https://www.rapid7.com/blog/feed/", "source": "Rapid7 Blog", "track": "traditional_appsec"},
    {"url": "https://socprime.com/feed/", "source": "SOC Prime", "track": "traditional_appsec"},
    {"url": "https://dailycybersecurity.com/feed/", "source": "Daily CyberSecurity", "track": "traditional_appsec"},

    # --- AI / LLM security ---
    {"url": "https://simonwillison.net/atom/everything/", "source": "Simon Willison's Blog", "track": "ai_security"},
    {"url": "https://embracethered.com/blog/index.xml", "source": "Embrace The Red", "track": "ai_security"},
    {"url": "https://genai.owasp.org/feed.xml", "source": "OWASP GenAI Security Project", "track": "ai_security"},

    # FIXED URLS
    {"url": "https://www.lakera.ai/blog/rss", "source": "Lakera Blog", "track": "ai_security"},
    {"url": "https://hiddenlayer.com/research/feed/", "source": "HiddenLayer Research", "track": "ai_security"},

    # NEW SOURCES — AI / LLM Security
    {"url": "https://www.anthropic.com/research/feed.xml", "source": "Anthropic Research", "track": "ai_security"},
    {"url": "https://openai.com/research/index/rss.xml", "source": "OpenAI Research", "track": "ai_security"},
    {"url": "https://aivillage.org/feed.xml", "source": "AI Village", "track": "ai_security"},
    {"url": "https://www.alignmentforum.org/feed.xml", "source": "AI Alignment Forum", "track": "ai_security"},
]

# --- JSON/REST sources ----------------------------------------------------

# NVD 2.0 API: recent published CVEs, paged. pubStartDate/pubEndDate are filled
# in by fetch_nvd_recent() at call time to cover a rolling window.
NVD_CVE_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?resultsPerPage=100&pubStartDate={start}&pubEndDate={end}"
)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ARXIV_API_URL = (
    "http://export.arxiv.org/api/query?search_query=cat:cs.CR+AND+"
    "(abs:%22large+language+model%22+OR+abs:%22LLM+agent%22+OR+abs:%22prompt+injection%22)"
    "&sortBy=submittedDate&sortOrder=descending&max_results=25"
)
# abuse.ch URLhaus: recent malicious URLs / malware distribution activity
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"


def _hash_id(link: str) -> str:
    return hashlib.sha256(link.encode("utf-8")).hexdigest()[:16]


def fetch_rss_sources() -> list[dict]:
    items = []
    for feed_cfg in RSS_FEEDS:
        try:
            parsed = feedparser.parse(feed_cfg["url"])
        except Exception as exc:
            print(f"[warn] failed to fetch {feed_cfg['source']}: {exc}")
            continue

        if getattr(parsed, "bozo", False) and not parsed.entries:
            print(f"[warn] {feed_cfg['source']} returned no parseable entries (check the URL)")

        for entry in parsed.entries[:20]:
            link = entry.get("link", "")
            if not link:
                continue
            published = entry.get("published", entry.get("updated", ""))
            items.append({
                "id": _hash_id(link),
                "source": feed_cfg["source"],
                "title": re.sub(r'<[^>]+>', '', entry.get("title", "")).strip(),
                "link": link,
                "published": published,
                "raw_summary": re.sub(r'<[^>]+>', '', (entry.get("summary", "") or ""))[:3000],
                "default_track": feed_cfg["track"],
            })
    return items


def fetch_cisa_kev() -> list[dict]:
    """CISA's Known Exploited Vulnerabilities catalog: real-world, actively exploited CVEs."""
    items = []
    try:
        resp = requests.get(CISA_KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulnerabilities", [])[:50]:
            cve_id = vuln.get("cveID", "")
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            items.append({
                "id": _hash_id(link),
                "source": "CISA KEV Catalog",
                "title": f"{cve_id}: {vuln.get('vulnerabilityName', '')}",
                "link": link,
                "published": vuln.get("dateAdded", ""),
                "raw_summary": (
                    f"{vuln.get('shortDescription', '')} "
                    f"Required action: {vuln.get('requiredAction', '')} "
                    f"Vendor/product: {vuln.get('vendorProject', '')} {vuln.get('product', '')}."
                ),
                "default_track": "traditional_appsec",
                "cve_id": cve_id,
            })
    except Exception as exc:
        print(f"[warn] failed to fetch CISA KEV: {exc}")
    return items


def fetch_nvd_recent(start_iso: str, end_iso: str) -> list[dict]:
    """Recent published CVEs from NVD for a given date window (ISO 8601, e.g. 2026-08-01T00:00:00.000)."""
    items = []
    try:
        url = NVD_CVE_URL.format(start=start_iso, end=end_iso)
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        for vuln_wrapper in data.get("vulnerabilities", []):
            cve = vuln_wrapper.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            descriptions = cve.get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            cvss_score = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break

            items.append({
                "id": _hash_id(link),
                "source": "NVD",
                "title": f"{cve_id}",
                "link": link,
                "published": cve.get("published", ""),
                "raw_summary": desc_text[:3000],
                "default_track": "traditional_appsec",
                "cve_id": cve_id,
                "cvss_score": cvss_score,
            })
    except Exception as exc:
        print(f"[warn] failed to fetch NVD recent CVEs: {exc}")
    return items


def fetch_arxiv_ai_security() -> list[dict]:
    """Recent arXiv cs.CR papers touching LLM/agent security."""
    items = []
    try:
        resp = requests.get(ARXIV_API_URL, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        resp.raise_for_status()
        parsed = feedparser.parse(resp.text)
        for entry in parsed.entries:
            link = entry.get("link", "")
            if not link:
                continue
            items.append({
                "id": _hash_id(link),
                "source": "arXiv (cs.CR)",
                "title": entry.get("title", "").strip().replace("\n", " "),
                "link": link,
                "published": entry.get("published", ""),
                "raw_summary": (entry.get("summary", "") or "")[:3000].replace("\n", " "),
                "default_track": "ai_security",
            })
    except Exception as exc:
        print(f"[warn] failed to fetch arXiv: {exc}")
    return items


def fetch_urlhaus_recent() -> list[dict]:
    """abuse.ch URLhaus: recently reported malware-distribution URLs (active campaign signal)."""
    items = []
    try:
        resp = requests.get(URLHAUS_RECENT_URL, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        records = data.values() if isinstance(data, dict) else data
        for rec in list(records)[:30]:
            entry = rec[0] if isinstance(rec, list) else rec
            url_val = entry.get("url", "")
            if not url_val:
                continue
            items.append({
                "id": _hash_id(url_val),
                "source": "abuse.ch URLhaus",
                "title": f"Malware distribution URL flagged: {entry.get('threat', 'unknown threat')}",
                "link": entry.get("urlhaus_reference", url_val),
                "published": entry.get("dateadded", ""),
                "raw_summary": f"Tags: {', '.join(entry.get('tags', []) or [])}. Host: {entry.get('host', '')}.",
                "default_track": "traditional_appsec",
            })
    except Exception as exc:
        print(f"[warn] failed to fetch URLhaus: {exc}")
    return items


def fetch_all(nvd_start_iso: str | None = None, nvd_end_iso: str | None = None) -> list[dict]:
    items = []
    items.extend(fetch_rss_sources())
    items.extend(fetch_cisa_kev())
    items.extend(fetch_arxiv_ai_security())
    if nvd_start_iso and nvd_end_iso:
        items.extend(fetch_nvd_recent(nvd_start_iso, nvd_end_iso))

    seen = set()
    deduped = []
    for item in items:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        deduped.append(item)
    return deduped


if __name__ == "__main__":
    results = fetch_all()
    print(f"Fetched {len(results)} raw items.")
    print(json.dumps(results[:3], indent=2))
