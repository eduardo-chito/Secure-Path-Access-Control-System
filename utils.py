from datetime import datetime
from typing import Optional
import sqlite3

def log_access(conn: sqlite3.Connection, user_id: Optional[int], action: str, success: int):
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO access_logs(user_id, action, timestamp, success) VALUES (?, ?, ?, ?)", (user_id, action, timestamp, success))
    conn.commit()