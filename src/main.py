"""
main.py

End-to-end WorldRisk pipeline:
  1. Fetch raw items from all sources (fetch_feeds.py), including NVD CVEs
     published in the last RETENTION_DAYS days
  2. Classify + enrich with Claude (classify.py)
  3. Merge with existing docs/data.json (dedupe by id)
  4. Drop anything older than RETENTION_DAYS (today + last 30 days by default)
  5. Write docs/data.json for the dashboard

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python src/main.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from dateutil import parser as dateparser

from classify import classify_all
from fetch_feeds import fetch_all

RETENTION_DAYS = 30
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "data.json")


def load_existing() -> list[dict]:
    if not os.path.exists(DATA_PATH):
        return []
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            payload = json.load(f)
            return payload.get("items", [])
    except Exception as exc:
        print(f"[warn] could not read existing data.json: {exc}")
        return []


def parse_date_safe(value: str):
    if not value:
        return None
    try:
        dt = dateparser.parse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def within_retention(item: dict, cutoff: datetime) -> bool:
    dt = parse_date_safe(item.get("published", ""))
    if dt is None:
        # keep undated items rather than silently dropping them; they're rare
        # and usually from feeds that omit a clean timestamp
        return True
    return dt >= cutoff


def main():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RETENTION_DAYS)

    nvd_start = cutoff.strftime("%Y-%m-%dT00:00:00.000")
    nvd_end = now.strftime("%Y-%m-%dT23:59:59.999")

    print(f"Fetching raw items (retention window: last {RETENTION_DAYS} days)...")
    raw_items = fetch_all(nvd_start_iso=nvd_start, nvd_end_iso=nvd_end)
    print(f"Fetched {len(raw_items)} raw items.")

    existing = load_existing()
    existing_ids = {item["id"] for item in existing}
    new_items = [item for item in raw_items if item["id"] not in existing_ids]
    print(f"{len(new_items)} are new; classifying those with Claude...")

    classified_new = classify_all(new_items) if new_items else []

    merged = classified_new + existing
    merged = [item for item in merged if within_retention(item, cutoff)]

    # newest first when a parseable date exists
    merged.sort(key=lambda it: parse_date_safe(it.get("published", "")) or cutoff, reverse=True)

    payload = {
        "generated_at": now.isoformat(),
        "retention_days": RETENTION_DAYS,
        "count": len(merged),
        "items": merged,
    }

    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Wrote {len(merged)} items (last {RETENTION_DAYS} days) to {DATA_PATH}")


if __name__ == "__main__":
    main()
