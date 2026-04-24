# listener.py

import asyncio
import json
import websockets
from detectors import check_update

RIPE_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgp-hijack-detector-v1"

SUBSCRIBE = {
    "type": "ris_subscribe",
    "data": {
        "type":    "UPDATE",
        "require": "announcements",
    }
}


async def start_listener():
    print("[*] Connecting to RIPE RIS Live...")
    while True:                          # auto-reconnect on disconnect
        try:
            async with websockets.connect(RIPE_URL, ping_interval=20) as ws:
                await ws.send(json.dumps(SUBSCRIBE))
                print("[*] Subscribed. Receiving BGP updates...")

                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    if msg.get("type") != "ris_message":
                        continue

                    data = msg.get("data", {})
                    path = data.get("path", [])
                    origin_as = path[-1] if path else None

                    for ann in data.get("announcements", []):
                        for prefix in ann.get("prefixes", []):
                            check_update({
                                "ts":        data.get("timestamp"),
                                "prefix":    prefix,
                                "origin_as": origin_as,
                                "peer_asn":  data.get("peer_asn"),
                                "peer_ip":   data.get("peer"),
                                "as_path":   path,
                                "next_hop":  ann.get("next_hop"),
                            })

        except Exception as e:
            print(f"[!] Connection lost: {e}. Reconnecting in 5s...")
            await asyncio.sleep(5)