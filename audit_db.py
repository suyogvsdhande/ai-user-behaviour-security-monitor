import json
import os
import sqlite3
from datetime import datetime, timezone

AUDIT_COLUMNS = ("user_id", "session_id", "timestamp", "ip_address", "device_id", "browser", "screen_name", "action", "profile_id", "search_query", "copy_attempt", "download_attempt", "download_size", "api_endpoint", "api_request_count", "details")

def initialize_database(database_path):
    directory = os.path.dirname(database_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, session_id TEXT,
            timestamp TEXT NOT NULL, ip_address TEXT, device_id TEXT, browser TEXT, screen_name TEXT,
            action TEXT NOT NULL, profile_id TEXT, search_query TEXT,
            copy_attempt INTEGER NOT NULL DEFAULT 0, download_attempt INTEGER NOT NULL DEFAULT 0,
            download_size INTEGER, api_endpoint TEXT, api_request_count INTEGER NOT NULL DEFAULT 0,
            details TEXT)""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")

def write_audit_event(database_path, **event):
    unknown = set(event) - set(AUDIT_COLUMNS)
    if unknown:
        raise ValueError(f"Unsupported audit fields: {', '.join(sorted(unknown))}")
    values = {column: event.get(column) for column in AUDIT_COLUMNS}
    values["timestamp"] = values["timestamp"] or datetime.now(timezone.utc).isoformat(timespec="seconds")
    values["copy_attempt"] = int(bool(values["copy_attempt"]))
    values["download_attempt"] = int(bool(values["download_attempt"]))
    values["api_request_count"] = values["api_request_count"] or 0
    if isinstance(values["details"], (dict, list)):
        values["details"] = json.dumps(values["details"], separators=(",", ":"))
    placeholders = ", ".join("?" for _ in AUDIT_COLUMNS)
    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute(f"INSERT INTO audit_log ({', '.join(AUDIT_COLUMNS)}) VALUES ({placeholders})", tuple(values[c] for c in AUDIT_COLUMNS))
        return cursor.lastrowid

def read_recent_audit_events(database_path, limit=40):
    safe_limit = max(1, min(int(limit), 100))
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (safe_limit,)).fetchall()
    return [dict(row) for row in rows]

def count_audit_events(database_path, action):
    with sqlite3.connect(database_path) as connection:
        return connection.execute("SELECT COUNT(*) FROM audit_log WHERE action = ?", (action,)).fetchone()[0]
