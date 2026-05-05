# BGP Hijack Detector 🛡️

A real-time BGP route hijack detection system that connects to RIPE RIS Live and monitors for suspicious routing events — MOAS conflicts, subprefix hijacks, and unexpected origin changes — enriched with ASN reputation scoring, WHOIS/RDAP lookups, and a live filterable dashboard.

---

## Features

**Detection engines**
- MOAS (Multiple Origin AS) — same prefix announced from different ASes
- Subprefix Hijack — suspicious subnet announcement by a foreign AS
- New Origin — stable prefix suddenly announced by a new AS

**Reputation & enrichment**
- Spamhaus ASN DROP — flags known hijacker/spam ASNs
- BGP Ranking (CIRCL) — malicious activity score per ASN (0–1 scale)
- WHOIS/RDAP — network name, CIDR, RIR, country, abuse contact via `ipwhois`
- ASN geo + org name via RIPE Stat + ip-api
- Alert score 0–100 boosted by reputation, RPKI status, and cross-continent checks

**False-positive suppression**
- Same-org detection via RIPE Stat holder name matching
- Whitelisted major transit providers (NTT, Lumen, Cogent, HE, etc.)
- Cross-continent check — same-region subprefix announcements skipped
- RPKI validation — only flags if explicitly invalid OR cross-region

**Dashboard**
- Live map with color-coded markers (red = MOAS, amber = subprefix, blue = new origin)
- Per-alert cards showing type, score, rep flags, BGPRank bar, WHOIS (expandable)
- Filter bar: All / MOAS / Subprefix / New Origin / High Only / Spamhaus
- Live search by prefix, ASN, org, country, network name
- WebSocket real-time push with auto-reconnect indicator
- SQLite persistence — alerts survive restarts

---

## Project Structure

```
bgp-detector/
├── main.py          # Entry point, async orchestrator
├── listener.py      # RIPE RIS Live WebSocket client
├── detectors.py     # Detection logic (MOAS, subprefix, new origin) + scoring
├── enrichment.py    # ASN name, geo, reputation, WHOIS enrichment
├── reputation.py    # Spamhaus DROP + BGP Ranking + WHOIS/RDAP lookups
├── whitelist.py     # Known-safe transit ASNs
├── database.py      # SQLite init + alert storage
├── api.py           # FastAPI REST + WebSocket push + /api/asn/<asn> endpoint
├── static/
│   └── index.html   # Live dashboard (map + filterable feed)
├── alerts.db        # Auto-created on first run
├── requirements.txt
├── .gitignore
├── setup.bat        # First-time setup (Windows)
├── run.bat          # Start the detector (Windows)
└── stop.bat         # Clean shutdown helper (Windows)
```

---

## Quickstart (Windows)

**1. First-time setup**
```
setup.bat
```
Creates a virtual environment and installs all dependencies.

**2. Run**
```
run.bat
```
Open `http://127.0.0.1:8000` in your browser.

**3. Stop**
Press `Ctrl+C` — shuts down cleanly. If it hangs, run `stop.bat` to force kill all Python processes and free port 8000.

---

## Quickstart (Linux / Mac)

```bash
python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python main.py
```

---

## Alert Scoring

| Score | Level | Meaning |
|-------|-------|---------|
| 70–100 | HIGH | Investigate immediately |
| 40–69 | MED | Unusual, watch closely |
| 0–39 | LOW | Informational |

**Score boosters:**
- +50 Spamhaus ASN DROP listed
- +40 RPKI explicitly invalid
- +40 High BGP Ranking score (>0.01)
- +20 Cross-continent announcement
- −15 RPKI valid

---

## Reputation System

### Spamhaus ASN DROP
Fetched from `https://www.spamhaus.org/drop/asndrop.json` on startup. No API key needed. Any ASN on this list is a known hijacker or spam network — alerts get +50 score and a purple SPAMHAUS badge on the dashboard.

### BGP Ranking (CIRCL)
Fetched per-ASN from `https://bgpranking-ng.circl.lu/asn/<asn>`. Scores range 0–1:
- `> 0.02` → red, high malicious activity
- `0.005–0.02` → amber, elevated
- `< 0.005` → green, clean

Shown as a visual bar on each alert card.

### WHOIS / RDAP
Uses the `ipwhois` library (RDAP protocol — modern replacement for raw WHOIS). Returns: network name, CIDR block, RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC), country, and abuse contact email. Expandable on each card. Abuse email is clickable.

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | Last 200 alerts (JSON) |
| `/api/asn/{asn}` | GET | Reputation + WHOIS for any ASN |
| `/ws` | WebSocket | Real-time alert push |

---

## Detection Logic

**Why most subprefixes are NOT flagged**

Normal ISPs delegate subnets to customers constantly. A subprefix only fires if:
- RPKI status is invalid, OR
- The announcing AS is on a different continent than the parent prefix

Same-region + RPKI valid/unknown → silently skipped.

**Org matching**

Uses the `holder` field from RIPE Stat AS overview. If the first word of two ASes' holder names match → treated as same org → no alert.

**Deduplication**

Default window: 20 minutes. Edit `DEDUP_WINDOW` in `detectors.py` to change.

---

## Configuration

| File | What to edit |
|------|-------------|
| `whitelist.py` | Add/remove whitelisted transit ASNs |
| `detectors.py` | `DEDUP_WINDOW` (dedup window), `CONTINENT_GROUPS` (regional groupings) |
| `reputation.py` | Spamhaus/BGPRanking URLs, cache behavior |

---

## Dependencies

```
fastapi
uvicorn
websockets
requests
ipaddress
ipwhois
```

---

## Known Limitations

- RIPE RIS Live drops connections every ~15–30 min by design — auto-reconnect handles this
- RPKI, org, reputation lookups are cached per process run — restart clears cache
- ip-api free tier: 45 requests/min — may throttle on high alert volume
- BGP Ranking API may be slow under load — alerts still fire, rep data fills async
- Only monitors global BGP table (IPv4 + IPv6) — no local/private routes

---

## License

MIT — do whatever you want.