# WorldRisk

A two-track threat-intelligence desk — **AI/LLM security** on one side, **traditional AppSec** on the other — built from live public feeds and enriched by Claude into full attack records: description, attack source, CVE/CVSS scoring, consequences, remediation, and reported losses.

Built as a portfolio project bridging QA, AppSec, and applied AI/LLM security.

## What it does

1. **Fetches** from a broad set of real public threat-intel sources on a schedule (see the full list below).
2. **Enriches** each new item with Claude: which track it belongs to, what type of item it is, a full plain-English description, the attack source (threat actor / malware family / research group, when known), any CVE ID and CVSS score, the consequences, how it was or can be remediated, and reported financial/data losses.
3. **Retains a rolling 30-day window** — today's items plus everything from the last 30 days — rather than an arbitrary item cap, so the dashboard always shows "what's happened lately," not just "the last N things fetched."
4. **Publishes** a two-column dashboard with a Today / Last 30 Days toggle. Clicking any item opens a full detail page with every field above, plus a link out to the original source.

## Architecture

```
 ┌────────────────┐     ┌──────────────────┐     ┌───────────────────┐
 │  Public feeds   │ --> │  fetch_feeds.py  │ --> │  raw items (JSON)  │
 │ NVD / CISA KEV  │     └──────────────────┘     └─────────┬─────────┘
 │ OWASP / blogs   │                                        │
 │ AI-sec sources  │                                        v
 │ abuse.ch, arXiv │                              ┌──────────────────┐
 └────────────────┘                              │   classify.py    │
                                                   │  (Claude API)    │
                                                   │  full enrichment │
                                                   └─────────┬────────┘
                                                              v
                                                   ┌──────────────────┐
                                                   │  main.py         │
                                                   │  30-day retention│
                                                   └─────────┬────────┘
                                                              v
                                                   ┌──────────────────┐
                                                   │  docs/data.json  │
                                                   └─────────┬────────┘
                                                              v
                                                   ┌──────────────────┐
                                                   │  docs/index.html │
                                                   │  Today / 30-day  │
                                                   │  two-track desk  │
                                                   └──────────────────┘
```

`main.py` runs the pipeline end to end and is meant to be triggered daily by `.github/workflows/update.yml`, which commits the refreshed `docs/data.json` back to the repo. GitHub Pages serves `docs/` as a live site.

## Sources

**Traditional AppSec**
- NVD (recent published CVEs, with CVSS scores, over the retention window)
- CISA Known Exploited Vulnerabilities (KEV) catalog — confirmed actively-exploited CVEs
- CISA Cybersecurity Advisories, CISA ICS Advisories
- abuse.ch URLhaus — recently reported malware-distribution URLs
- OWASP News
- The Hacker News, BleepingComputer, Dark Reading, SecurityWeek, Krebs on Security, The Record

**AI / LLM Security**
- OWASP GenAI Security Project (LLM Top 10) updates
- Simon Willison's Blog (prompt-injection and agent-security coverage)
- Embrace The Red (AI red-teaming blog)
- Lakera Blog, HiddenLayer Research
- arXiv `cs.CR` search for recent LLM/agent-security papers

> **Verify before you rely on it:** feed URLs occasionally change. Run `python src/fetch_feeds.py` and check the `[warn]` lines in stdout for any source that fails — fix or drop it rather than assuming silence means it worked.

## Every item includes

| Field | What it is |
|---|---|
| `description` | 3–5 sentence plain-English account of what happened |
| `attack_source` | Threat actor, malware family, or research group, or "N/A" |
| `cve_id` / `cvss_score` | If applicable — never invented, only from the source or NVD/CISA data |
| `consequences` | What was or could be affected |
| `remediation` | How it was or can be fixed/mitigated |
| `losses` | Reported financial cost, records exposed, or downtime, if disclosed |
| `tags` | 2–5 keyword tags |

Claude is explicitly instructed to use `null`/"N/A" rather than guess — a made-up CVSS score or loss figure is worse than an honest "not reported."

## Setup

```bash
cd worldrisk
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python src/main.py
```

This writes `docs/data.json`, keeping only items published in the last 30 days. Open `docs/index.html` in a browser (or run `python -m http.server` from `docs/`) to view the dashboard.

## Deploying the dashboard

1. Push this repo to GitHub.
2. In **Settings → Pages**, set source to the `docs/` folder on your default branch.
3. In **Settings → Secrets and variables → Actions**, add `ANTHROPIC_API_KEY`.
4. The workflow runs daily, refreshes `docs/data.json` within the 30-day window, and commits it — the Pages site updates automatically.

## Roadmap / extension ideas

- Diff against the current OWASP Top 10 (classic and LLM) to flag when an update actually changes a category, not just re-publishes it.
- Slack/email digest of the day's items.
- Full-text search across descriptions and tags.
- A "why this matters for AppSec engineers" field per item.

## Status

This repo ships with **sample data** in `docs/data.json` (14 entries spanning the last 30 days) so the dashboard and the Today/30-day toggle both render meaningfully on first look. Run the pipeline with a live `ANTHROPIC_API_KEY` to replace it with real, current data.
