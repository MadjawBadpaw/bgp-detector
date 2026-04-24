# detectors.py

import ipaddress
import requests
from collections import defaultdict
from datetime import datetime, timedelta
from functools import lru_cache
from whitelist import is_whitelisted

prefix_origins: dict[str, set] = defaultdict(set)
prefix_first_seen: dict[str, datetime] = {}
alert_queue: list[dict] = []

_seen_cache: dict[tuple, datetime] = {}
DEDUP_WINDOW = timedelta(minutes=20)

# Regional groupings — same region = almost always legitimate delegation
REGION_MAP = {
    # Europe
    "PL","DE","FR","GB","NL","IT","ES","SE","NO","FI","DK","BE","AT","CH",
    "CZ","SK","HU","RO","BG","HR","SI","RS","GR","PT","IE","LU","EE","LV",
    "LT","UA","BY","MD","AL","BA","MK","ME","XK","IS","MT","CY",
    # Asia-Pacific
    "CN","JP","KR","TW","HK","SG","AU","NZ","IN","ID","MY","TH","PH","VN",
    "BD","PK","LK","NP","MM","KH","LA","MN","KZ","UZ","TJ","KG","TM","AF",
    # Americas
    "US","CA","MX","BR","AR","CL","CO","PE","VE","EC","BO","PY","UY","GY",
    "SR","GT","BZ","HN","SV","NI","CR","PA","CU","DO","JM","TT","BB","HT",
    # Middle East / Africa
    "SA","AE","IL","TR","IR","IQ","SY","LB","JO","KW","QA","BH","OM","YE",
    "EG","ZA","NG","KE","GH","MA","TN","DZ","ET","TZ","UG","SN","CI","CM",
}

EUROPE = {"PL","DE","FR","GB","NL","IT","ES","SE","NO","FI","DK","BE","AT","CH",
          "CZ","SK","HU","RO","BG","HR","SI","RS","GR","PT","IE","LU","EE","LV",
          "LT","UA","BY","MD","AL","BA","MK","ME","XK","IS","MT","CY"}
APAC   = {"CN","JP","KR","TW","HK","SG","AU","NZ","IN","ID","MY","TH","PH","VN",
          "BD","PK","LK","NP","MM","KH","LA","MN","KZ","UZ","TJ","KG","TM","AF"}
AMER   = {"US","CA","MX","BR","AR","CL","CO","PE","VE","EC","BO","PY","UY","GY",
          "SR","GT","BZ","HN","SV","NI","CR","PA","CU","DO","JM","TT","BB","HT"}
MENA   = {"SA","AE","IL","TR","IR","IQ","SY","LB","JO","KW","QA","BH","OM","YE",
          "EG","ZA","NG","KE","GH","MA","TN","DZ","ET","TZ","UG","SN","CI","CM"}

CONTINENT_GROUPS = [EUROPE, APAC, AMER, MENA]


def same_continent(cc1: str, cc2: str) -> bool:
    """True if both country codes are in the same regional group."""
    if not cc1 or not cc2:
        return True   # unknown = assume same, don't false-positive
    cc1, cc2 = cc1.upper(), cc2.upper()
    if cc1 == cc2:
        return True
    for group in CONTINENT_GROUPS:
        if cc1 in group and cc2 in group:
            return True
    return False


# ── ASN info cache ────────────────────────────────────────────────────────────
@lru_cache(maxsize=4096)
def get_asn_meta(asn: int) -> dict:
    """
    Returns {"holder": str, "country": str} for an ASN.
    Cached forever per process run.
    """
    try:
        url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
        r = requests.get(url, timeout=5)
        data = r.json().get("data", {})
        holder = data.get("holder", "").lower()
        # country comes from a separate field in some responses
        # fall back to parsing from holder string if needed
        country = ""
        # Try routing data for country
        try:
            url2 = f"https://stat.ripe.net/data/routing-status/data.json?resource=AS{asn}"
            r2 = requests.get(url2, timeout=5)
            announced = r2.json().get("data", {}).get("announced_space", {})
            # Not reliable for country, use ip-api fallback below
        except Exception:
            pass
        return {"holder": holder, "country": country}
    except Exception:
        return {"holder": "", "country": ""}


@lru_cache(maxsize=4096)
def get_prefix_country(prefix: str) -> str:
    """Get country code for a prefix using ip-api (free, no key)."""
    try:
        ip = prefix.split("/")[0]
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        return r.json().get("countryCode", "")
    except Exception:
        return ""


def same_org(asn1, asn2) -> bool:
    """True if two ASNs appear to belong to the same organization."""
    try:
        a, b = int(asn1), int(asn2)
    except (TypeError, ValueError):
        return False
    if a == b:
        return True
    h1 = get_asn_meta(a).get("holder", "")
    h2 = get_asn_meta(b).get("holder", "")
    if not h1 or not h2:
        return False
    w1 = h1.split()[0] if h1.split() else ""
    w2 = h2.split()[0] if h2.split() else ""
    return bool(w1 and w1 == w2)


# ── RPKI validation ───────────────────────────────────────────────────────────
@lru_cache(maxsize=4096)
def rpki_status(prefix: str, origin_asn: int) -> str:
    """
    Returns 'valid', 'invalid', 'unknown', or 'not-found'.
    'invalid' is the only one that meaningfully raises suspicion.
    """
    try:
        url = (
            f"https://stat.ripe.net/data/rpki-validation/data.json"
            f"?resource=AS{origin_asn}&prefix={prefix}"
        )
        r = requests.get(url, timeout=6)
        return r.json().get("data", {}).get("status", "unknown")
    except Exception:
        return "unknown"


# ── Scoring ───────────────────────────────────────────────────────────────────
def score_alert(alert_type: str, prefix: str, origin_as, known_origins: set,
                cross_region: bool = False) -> int:
    score = 0

    if alert_type == "MOAS":
        score += 30
    elif alert_type == "SUBPREFIX_HIJACK":
        score += 30
    elif alert_type == "NEW_ORIGIN":
        score += 20

    # RPKI explicitly invalid = biggest red flag
    try:
        status = rpki_status(prefix, int(origin_as))
        if status == "invalid":
            score += 40
        elif status == "valid":
            score -= 15   # valid RPKI = less suspicious
    except Exception:
        pass

    # Cross-continent announcement = more suspicious
    if cross_region:
        score += 20

    # Brand new ASN never seen before anywhere
    if len(known_origins) == 0:
        score += 10

    return max(0, min(score, 100))


# ── Dedup ─────────────────────────────────────────────────────────────────────
def _is_duplicate(alert_type: str, prefix: str, origin_as) -> bool:
    key = (alert_type, prefix, str(origin_as))
    now = datetime.utcnow()
    last = _seen_cache.get(key)
    if last and (now - last) < DEDUP_WINDOW:
        return True
    _seen_cache[key] = now
    return False


# ── Main detection entry point ────────────────────────────────────────────────
def check_update(record: dict):
    prefix    = record.get("prefix")
    origin_as = record.get("origin_as")
    ts_raw    = record.get("ts")

    if not prefix or not origin_as:
        return
    if is_whitelisted(origin_as):
        return

    try:
        ts = datetime.fromtimestamp(float(ts_raw))
    except Exception:
        ts = datetime.utcnow()

    origin_str = str(origin_as)
    previous   = prefix_origins[prefix].copy()

    # ── Detector 1: MOAS ─────────────────────────────────────────────────────
    if previous and origin_str not in previous:
        all_same_org = all(same_org(origin_as, p) for p in previous)
        if not all_same_org and not _is_duplicate("MOAS", prefix, origin_as):
            # Check if cross-region
            prefix_cc  = get_prefix_country(prefix)
            origin_cc  = get_prefix_country(f"{origin_as}.asn")  # rough
            cross      = False  # MOAS cross-region check is less reliable, skip for now
            _fire("MOAS", record, previous, cross,
                  f"Prefix {prefix} was from AS{sorted(previous)}, now also AS{origin_str}")

    # ── Detector 2: Subprefix hijack ──────────────────────────────────────────
    # KEY CHANGE: only fire if RPKI invalid OR cross-continent
    # Normal ISP subprefix delegation (same region, RPKI valid/unknown) = SKIP
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        for known_prefix, known_origins in list(prefix_origins.items()):
            if known_prefix == prefix:
                continue
            try:
                known_net = ipaddress.ip_network(known_prefix, strict=False)
                if not net.subnet_of(known_net):
                    continue

                # ── All the reasons to SKIP this ──────────────────────────
                # 1. Child is whitelisted
                if is_whitelisted(origin_as):
                    break

                # 2. Parent is whitelisted transit — customer delegation, normal
                if all(is_whitelisted(k) for k in known_origins):
                    break

                # 3. Same org
                if any(same_org(origin_as, k) for k in known_origins):
                    break

                # 4. Same origin already known for this prefix
                if origin_str in known_origins:
                    break

                # ── Decide if worth flagging ───────────────────────────────
                # Get countries of child and parent
                child_cc  = get_prefix_country(prefix)
                parent_cc = get_prefix_country(known_prefix)
                cross_reg = not same_continent(child_cc, parent_cc)

                # Check RPKI
                r_status = rpki_status(prefix, int(origin_as))

                # ONLY fire if at least one of:
                # a) RPKI explicitly invalid
                # b) Cross-continent announcement
                # Normal same-region subprefix = skip entirely (too much noise)
                if r_status != "invalid" and not cross_reg:
                    break

                if not _is_duplicate("SUBPREFIX_HIJACK", prefix, origin_as):
                    reason = []
                    if r_status == "invalid":
                        reason.append("RPKI-INVALID")
                    if cross_reg:
                        reason.append(f"CROSS-REGION({parent_cc}→{child_cc})")
                    _fire(
                        "SUBPREFIX_HIJACK", record, known_origins, cross_reg,
                        f"AS{origin_str} claiming {prefix} "
                        f"(subnet of {known_prefix} | {' + '.join(reason)})"
                    )
                break
            except (ValueError, TypeError):
                continue
    except ValueError:
        pass

    # ── Detector 3: New origin for stable prefix ──────────────────────────────
    if prefix not in prefix_first_seen:
        prefix_first_seen[prefix] = ts
    else:
        age = ts - prefix_first_seen[prefix]
        if age > timedelta(hours=2) and origin_str not in previous:
            if not same_org(origin_as, next(iter(previous), 0)):
                # Also check cross-region for scoring
                prefix_cc = get_prefix_country(prefix)
                if previous:
                    parent_sample = next(iter(previous))
                    parent_cc = get_prefix_country(
                        # use prefix itself as proxy since we don't have parent prefix IP
                        prefix
                    )
                cross_reg = False  # conservative for new-origin
                if not _is_duplicate("NEW_ORIGIN", prefix, origin_as):
                    _fire(
                        "NEW_ORIGIN", record, previous, cross_reg,
                        f"Prefix {prefix} stable for {str(age).split('.')[0]}, "
                        f"new origin AS{origin_str}"
                    )

    prefix_origins[prefix].add(origin_str)


# ── Fire ──────────────────────────────────────────────────────────────────────
def _fire(alert_type, record, known_origins, cross_region, detail):
    s = score_alert(
        alert_type,
        record.get("prefix", ""),
        record.get("origin_as"),
        known_origins,
        cross_region,
    )
    alert = {
        "type":      alert_type,
        "prefix":    record.get("prefix"),
        "origin_as": record.get("origin_as"),
        "peer_asn":  record.get("peer_asn"),
        "as_path":   record.get("as_path", []),
        "detail":    detail,
        "score":     s,
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
    }
    alert_queue.append(alert)
    