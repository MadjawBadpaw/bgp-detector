# api.py

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from database import get_recent_alerts
import json
import asyncio

app = FastAPI()

_clients: list[WebSocket] = []
_lock = asyncio.Lock()


@app.get("/api/alerts")
def api_alerts():
    return JSONResponse(get_recent_alerts(200))


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    async with _lock:
        _clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        async with _lock:
            if ws in _clients:
                _clients.remove(ws)


async def push_alert(alert: dict):
    if not _clients:
        return
    message = json.dumps(alert)
    async with _lock:
        clients_copy = list(_clients)
    dead = []
    for client in clients_copy:
        try:
            await client.send_text(message)
        except Exception:
            dead.append(client)
    if dead:
        async with _lock:
            for d in dead:
                if d in _clients:
                    _clients.remove(d)


app.mount("/", StaticFiles(directory="static", html=True), name="static")