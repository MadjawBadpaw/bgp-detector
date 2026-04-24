# whitelist.py

WHITELIST_ASNS = {
    # Hyperscalers
    13335, 20940, 54113, 16509, 15169, 8075, 32934, 2906, 714, 36351,
    # Major transit / backbone (they delegate subprefixes to customers constantly)
    2914,   # NTT Communications
    3356,   # Lumen / Level3
    1299,   # Telia Carrier
    174,    # Cogent
    6939,   # Hurricane Electric
    6461,   # Zayo
    3257,   # GTT
    5511,   # Orange / France Telecom
    1273,   # Vodafone
    3320,   # Deutsche Telekom
    9002,   # RETN
    12956,  # Telefonica
    6762,   # Telecom Italia Sparkle
    5400,   # BT
    2828,   # XO Communications
    7018,   # AT&T
    7922,   # Comcast
    20115,  # Charter
    209,    # CenturyLink / Lumen
    3491,   # PCCW
    4134,   # China Telecom
    4837,   # China Unicom
    9808,   # China Mobile
    4538,   # CERNET (edu)
    9829,   # BSNL
    55836,  # Reliance Jio
    17488,  # Hathway
    45609,  # Bharti Airtel (different ASN)
    9498,   # Bharti Airtel
    9488,   # Bharti Airtel Telemedia
}

def is_whitelisted(asn) -> bool:
    try:
        return int(asn) in WHITELIST_ASNS
    except (TypeError, ValueError):
        return False