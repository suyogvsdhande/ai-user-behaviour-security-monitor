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
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_timestamp ON audit_log(user_id, timestamp DESC)")
        connection.execute("""CREATE TABLE IF NOT EXISTS user_risk (
            user_id TEXT PRIMARY KEY, risk_score INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'LOW', status TEXT NOT NULL DEFAULT 'NORMAL',
            profile_views INTEGER NOT NULL DEFAULT 0, copy_attempts INTEGER NOT NULL DEFAULT 0,
            downloads INTEGER NOT NULL DEFAULT 0, api_requests INTEGER NOT NULL DEFAULT 0,
            breakdown TEXT NOT NULL DEFAULT '[]', last_activity TEXT, calculated_at TEXT NOT NULL)""")

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


def read_audit_user_ids(database_path):
    with sqlite3.connect(database_path) as connection:
        return [row[0] for row in connection.execute(
            "SELECT DISTINCT user_id FROM audit_log ORDER BY user_id").fetchall()]

def read_user_events(database_path, user_id, since_timestamp, session_id=None):
    query = "SELECT * FROM audit_log WHERE user_id = ? AND timestamp >= ?"
    parameters = [user_id, since_timestamp]
    if session_id is not None:
        query += " AND session_id = ?"
        parameters.append(session_id)
    query += " ORDER BY timestamp, id"
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query, parameters).fetchall()]

def save_user_risk(database_path, user_id, assessment, calculated_at=None):
    calculated_at = calculated_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    counts = assessment["counts"]
    with sqlite3.connect(database_path) as connection:
        connection.execute("""INSERT INTO user_risk
            (user_id, risk_score, risk_level, status, profile_views, copy_attempts,
             downloads, api_requests, breakdown, last_activity, calculated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET risk_score=excluded.risk_score,
             risk_level=excluded.risk_level, status=excluded.status,
             profile_views=excluded.profile_views, copy_attempts=excluded.copy_attempts,
             downloads=excluded.downloads, api_requests=excluded.api_requests,
             breakdown=excluded.breakdown, last_activity=excluded.last_activity,
             calculated_at=excluded.calculated_at""",
            (user_id, assessment["risk_score"], assessment["risk_level"], assessment["status"],
             counts["profile_views"], counts["copy_attempts"], counts["downloads"],
             counts["api_requests"], json.dumps(assessment["breakdown"], separators=(",", ":")),
             assessment.get("last_activity"), calculated_at))

def read_user_risks(database_path):
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM user_risk ORDER BY risk_score DESC, user_id").fetchall()
    results = []
    for row in rows:
        result = dict(row)
        try:
            result["breakdown"] = json.loads(result["breakdown"])
        except (json.JSONDecodeError, TypeError):
            result["breakdown"] = []
        results.append(result)
    return results

def count_high_risk_sessions(database_path, since_timestamp):
    from risk_engine import calculate_risk
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM audit_log WHERE timestamp >= ? AND session_id IS NOT NULL ORDER BY timestamp, id", (since_timestamp,)).fetchall()
    sessions = {}
    for row in rows:
        event = dict(row)
        sessions.setdefault((event["user_id"], event["session_id"]), []).append(event)
    return sum(calculate_risk(events)["risk_score"] >= 61 for events in sessions.values())
