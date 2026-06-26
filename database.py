import sqlite3
from datetime import datetime

DB_PATH = "ids_database.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            detail TEXT,
            src_ip TEXT,
            features_json TEXT,
            anomaly_score REAL,
            explanation TEXT,
            correlated INTEGER DEFAULT 0,
            window_id INTEGER,
            timestamp TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS session_summary (
            id INTEGER PRIMARY KEY,
            summary TEXT,
            updated_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_session_summary():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT summary FROM session_summary WHERE id=1")
    row = cursor.fetchone()
    conn.close()
    return row["summary"] if row else ""

def save_session_summary(summary):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO session_summary (id, summary, updated_at)
        VALUES (1, ?, datetime('now'))
    """, (summary,))
    conn.commit()
    conn.close()

def alert_exists_recently(alert_type, seconds=120):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM alerts
        WHERE type=? AND created_at >= datetime('now', ?)
    """, (alert_type, f'-{seconds} seconds'))
    row = cursor.fetchone()
    conn.close()
    return row["cnt"] > 0

def insert_alert(alert):
    if alert_exists_recently(alert.get("type", ""), seconds=120):
        return
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (type, severity, detail, src_ip, features_json, anomaly_score, explanation, correlated, window_id, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("type"),
        alert.get("severity"),
        alert.get("detail"),
        alert.get("src_ip"),
        alert.get("features_json"),
        alert.get("anomaly_score"),
        alert.get("explanation"),
        1 if alert.get("correlated") else 0,
        int(alert.get("window_id")) if alert.get("window_id") is not None else None,
        str(datetime.utcfromtimestamp(float(alert["timestamp"])).strftime("%Y-%m-%d %H:%M:%S")) if alert.get("timestamp") else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

def get_all_alerts(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_alerts_count():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_alerts_by_type():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT type, COUNT(*) as count FROM alerts GROUP BY type")
    rows = cursor.fetchall()
    conn.close()
    return {row["type"]: row["count"] for row in rows}

def clear_all_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()

def log_activity(username, action, details=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO activity_log (username, action, details)
        VALUES (?, ?, ?)
    """, (username, action, details))
    conn.commit()
    conn.close()

def get_activity_log(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

init_db()
