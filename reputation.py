import requests
import ipwhois
import functools

SPAMHAUS_URL = "https://www.spamhaus.org/drop/asndrop.json"
BGPRANKING_URL = "https://bgpranking-ng.circl.lu/asn"

_spamhaus_cache = set()
_rep_cache = {}

def load_spamhaus():
    global _spamhaus_cache
    if _spamhaus_cache:
        return
    try:
        data = requests.get(SPAMHAUS_URL, timeout=10).json()
        _spamhaus_cache = {str(entry["asn"]) for entry in data}
    except Exception:
        pass

def get_asn_reputation(asn: str) -> dict:
    """Returns rep score 0-100 (higher = more malicious), flags, and summary."""
    asn = str(asn).replace("AS", "")
    if asn in _rep_cache:
        return _rep_cache[asn]

    load_spamhaus()
    result = {
        "asn": asn,
        "spamhaus_listed": asn in _spamhaus_cache,
        "bgpranking_score": None,
        "rep_score": 0,
        "flags": [],
    }

    # BGP Ranking
    try:
        r = requests.get(f"{BGPRANKING_URL}/{asn}", timeout=8).json()
        rank = r.get("response", {}).get("ranking", {}).get("rank")
        if rank is not None:
            result["bgpranking_score"] = round(rank, 4)
            if rank > 0.01:
                result["rep_score"] += 40
                result["flags"].append("high BGP ranking score")
    except Exception:
        pass

    if result["spamhaus_listed"]:
        result["rep_score"] += 50
        result["flags"].append("Spamhaus ASN DROP listed")

    _rep_cache[asn] = result
    return result


def get_whois(ip_or_prefix: str) -> dict:
    """RDAP-based WHOIS for an IP or prefix."""
    # strip prefix length if given
    ip = ip_or_prefix.split("/")[0]
    try:
        obj = ipwhois.IPWhois(ip)
        rdap = obj.lookup_rdap(depth=1)
        return {
            "network_name": rdap.get("network", {}).get("name"),
            "org":          rdap.get("network", {}).get("remarks", [{}])[0].get("description"),
            "country":      rdap.get("network", {}).get("country"),
            "cidr":         rdap.get("network", {}).get("cidr"),
            "abuse_email":  _extract_abuse(rdap),
            "rir":          rdap.get("asn_registry"),
            "registration": rdap.get("network", {}).get("start_address"),
        }
    except Exception as e:
        return {"error": str(e)}


def _extract_abuse(rdap: dict) -> str | None:
    for entity in rdap.get("entities", []):
        for role in entity.get("roles", []):
            if role == "abuse":
                contact = entity.get("contact", {})
                emails = contact.get("email", [])
                if emails:
                    return emails[0].get("value")
    return None