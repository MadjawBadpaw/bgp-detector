# database.py

import sqlite3
import json

DB_PATH = "alerts.db"


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT,
            prefix      TEXT,
            origin_as   TEXT,
            peer_asn    TEXT,
            as_path     TEXT,
            detail      TEXT,
            score       INTEGER,
            lat         REAL,
            lon         REAL,
            country     TEXT,
            org         TEXT,
            timestamp   TEXT
        )
    """)
    con.commit()
    con.close()


def save_alert(alert: dict):
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        INSERT INTO alerts
        (type, prefix, origin_as, peer_asn, as_path,
         detail, score, lat, lon, country, org, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        alert.get("type"),
        alert.get("prefix"),
        str(alert.get("origin_as")),
        str(alert.get("peer_asn")),
        json.dumps(alert.get("as_path", [])),
        alert.get("detail"),
        alert.get("score", 0),
        alert.get("lat", 0.0),
        alert.get("lon", 0.0),
        alert.get("country", "Unknown"),
        alert.get("org", "Unknown"),
        alert.get("timestamp"),
    ))
    con.commit()
    con.close()


def get_recent_alerts(limit: int = 200) -> list[dict]:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]