# enrichment.py

import requests
from functools import lru_cache
from reputation import get_asn_reputation, get_whois


@lru_cache(maxsize=2048)
def get_asn_info(asn: int) -> dict:
    try:
        url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
        r   = requests.get(url, timeout=6)
        d   = r.json().get("data", {})
        return {"name": d.get("holder", f"AS{asn}")}
    except Exception:
        pass

    # Fallback: bgpview.io
    try:
        r = requests.get(f"https://api.bgpview.io/asn/{asn}", timeout=6)
        d = r.json().get("data", {})
        name = d.get("description_short") or d.get("name") or f"AS{asn}"
        return {"name": name}
    except Exception:
        return {"name": f"AS{asn}"}


@lru_cache(maxsize=2048)
def get_geo(prefix: str) -> dict:
    try:
        ip = prefix.split("/")[0]
        r  = requests.get(f"http://ip-api.com/json/{ip}", timeout=6)
        d  = r.json()
        if d.get("status") == "success":
            return {
                "lat":     d.get("lat", 0.0),
                "lon":     d.get("lon", 0.0),
                "country": d.get("country", "Unknown"),
            }
    except Exception:
        pass
    return {"lat": 0.0, "lon": 0.0, "country": "Unknown"}


def enrich(alert: dict) -> dict:
    prefix  = alert.get("prefix", "0.0.0.0/0")
    asn     = alert.get("origin_as")

    # Existing geo + org
    geo     = get_geo(prefix)
    asn_inf = get_asn_info(int(asn)) if asn else {}

    # Reputation (Spamhaus + BGP Ranking)
    rep = get_asn_reputation(str(asn)) if asn else {}

    # WHOIS / RDAP
    whois = get_whois(prefix)

    return {
        **alert,
        # geo
        "lat":             geo["lat"],
        "lon":             geo["lon"],
        "country":         geo["country"],
        # org
        "org":             asn_inf.get("name", "Unknown"),
        # reputation
        "rep_score":       rep.get("rep_score", 0),
        "rep_flags":       rep.get("flags", []),
        "spamhaus_listed": rep.get("spamhaus_listed", False),
        "bgpranking_score": rep.get("bgpranking_score"),
        # whois
        "whois":           whois if not whois.get("error") else None,
    }