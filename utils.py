from datetime import datetime
from typing import Optional
import sqlite3
from zoneinfo import ZoneInfo

def log_access(conn: sqlite3.Connection, user_id: Optional[int], action: str, success: int):
    c = conn.cursor()
    timestamp = datetime.now(ZoneInfo("America/New_York")).isoformat()
    c.execute("INSERT INTO access_logs(user_id, action, timestamp, success) VALUES (?, ?, ?, ?)", (user_id, action, timestamp, success))
    conn.commit()