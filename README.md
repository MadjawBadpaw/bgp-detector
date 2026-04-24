# BGP Hijack Detector 🛡️

A real-time BGP route hijack detection system that connects to RIPE RIS Live and monitors for suspicious routing events — MOAS conflicts, subprefix hijacks, and unexpected origin changes.

Built with Python, FastAPI, and a live WebSocket dashboard.

---

## Features

- **Real-time BGP stream** via RIPE RIS Live WebSocket
- **3 detection engines:**
  - MOAS (Multiple Origin AS) — same prefix announced from different ASes
  - Subprefix Hijack — suspicious subnet announcement by foreign AS
  - New Origin — stable prefix suddenly announced by new AS
- **Smart false-positive suppression:**
  - Same-org detection via RIPE Stat holder name
  - Whitelisted major transit providers (NTT, Lumen, Cogent, HE, etc.)
  - Cross-continent check — same-region subprefix = skipped
  - RPKI validation — only flags if explicitly invalid OR cross-region
- **Alert scoring** (0–100) with RPKI and geo-context weighting
- **Live web dashboard** at `http://localhost:8000`
- **SQLite persistence** — alerts survive restarts
- **Enrichment** — company name, country, lat/lon via RIPE Stat + ip-api

---

## Project Structure

```
bgp-detector/
├── main.py          # Entry point, async orchestrator
├── listener.py      # RIPE RIS Live WebSocket client
├── detectors.py     # Core detection logic (MOAS, subprefix, new origin)
├── enrichment.py    # ASN name + geo enrichment
├── whitelist.py     # Known-safe transit ASNs
├── database.py      # SQLite init + alert storage
├── api.py           # FastAPI REST + WebSocket push
├── static/          # Dashboard frontend (HTML/JS)
├── alerts.db        # Auto-created on first run
├── requirements.txt
├── setup.bat        # First-time setup (Windows)
├── run.bat          # Start the detector (Windows)
└── stop.bat         # Clean shutdown helper (Windows)
```

---

## Requirements

- Python 3.10+
- pip
- Internet connection (streams from RIPE RIS Live)

---

## Quickstart (Windows)

### 1. First-time setup
```
setup.bat
```
Creates a virtual environment and installs all dependencies.

### 2. Run
```
run.bat
```
Starts the detector. Open `http://127.0.0.1:8000` in your browser.

### 3. Stop
Press `Ctrl+C` in the terminal — it will shut down cleanly.

#If it doesn't respond, run `stop.bat` to force kill all Python processes and free port 8000.#

---

## Quickstart (Manual / Linux / Mac)

```bash
# Create venv
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install deps
pip install -r requirements.txt

# Run
python main.py
```

---

## Alert Scoring

| Score | Level | Meaning |
|-------|-------|---------|
| 70–100 | HIGH  | Investigate — RPKI invalid + unknown/foreign org |
| 40–69  | MED   | Watch — unusual but possibly legitimate |
| 0–39   | LOW   | Informational — likely normal routing |

Score is boosted by:
- `+40` RPKI explicitly invalid
- `+20` Cross-continent announcement
- `-15` RPKI valid (less suspicious)

---

## Detection Logic

### Why most subprefixes are NOT flagged
Normal ISPs delegate subnets to customers constantly. A subprefix only fires if:
1. RPKI status is `invalid`, **OR**
2. The announcing AS is on a different continent than the parent prefix

Same-region + RPKI valid/unknown → silently skipped.

### RPKI via RIPE Stat
Uses `https://stat.ripe.net/data/rpki-validation/` — free, no API key needed.

### Org matching
Uses the `holder` field from RIPE Stat AS overview. If the first word of two ASes' holder names match → treated as same org → no alert.

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | Last 200 alerts (JSON) |
| `/ws` | WebSocket | Real-time alert push |

---

## Configuration

Edit `whitelist.py` to add/remove whitelisted ASNs.

Edit `detectors.py` → `DEDUP_WINDOW` to change deduplication window (default: 20 min).

Edit `detectors.py` → `CONTINENT_GROUPS` to adjust regional groupings.

---

## Dependencies

```
fastapi
uvicorn
websockets
requests
ipaddress
```

---

## Known Limitations

- RIPE RIS Live drops connections every ~15–30 min by design; auto-reconnect handles this
- RPKI + org lookups are cached per process run (restart clears cache)
- ip-api free tier: 45 requests/min — may throttle on high alert volume
- Only monitors global BGP table (IPv4 + IPv6); no local/private routes

---

## License

MIT — do whatever you want, don't blame me if your network burns down.