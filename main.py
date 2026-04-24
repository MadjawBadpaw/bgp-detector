# main.py

import asyncio
import sys
import uvicorn
from listener import start_listener
from detectors import alert_queue
from enrichment import enrich
from database import init_db, save_alert
from api import app, push_alert


async def alert_processor():
    last = 0
    while True:
        await asyncio.sleep(1)
        if len(alert_queue) > last:
            new_alerts = alert_queue[last:]
            for raw_alert in new_alerts:
                try:
                    enriched = enrich(raw_alert)
                    save_alert(enriched)
                    await push_alert(enriched)

                    # Print with company name now that we have enriched data
                    level = "HIGH" if enriched.get("score", 0) >= 70 else "MED " if enriched.get("score", 0) >= 40 else "LOW "
                    org     = enriched.get("org", "Unknown")
                    country = enriched.get("country", "?")
                    print(
                        f"[{level}] [{enriched['type']}] score={enriched['score']} | "
                        f"{enriched['prefix']} | {org} ({country}) | AS{enriched['origin_as']}"
                    )
                except Exception as e:
                    print(f"[!] Alert processing error: {e}")
            last = len(alert_queue)


async def main():
    init_db()
    print("[*] Database ready")
    print("[*] Dashboard → http://127.0.0.1:8000")
    print("[*] Press Ctrl+C to stop\n")

    server_config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="warning",
    )
    server = uvicorn.Server(server_config)
    server.install_signal_handlers = lambda: None

    loop = asyncio.get_running_loop()

    tasks = [
        loop.create_task(server.serve()),
        loop.create_task(start_listener()),
        loop.create_task(alert_processor()),
    ]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        # Cancel all remaining tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        print("[*] Done. Bye.")
    finally:
        loop.close()
        sys.exit(0)