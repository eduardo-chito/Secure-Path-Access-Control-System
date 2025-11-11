from datetime import datetime
from typing import Optional
import sqlite3
from zoneinfo import ZoneInfo

def log_access(conn: sqlite3.Connection, user_id: Optional[int], action: str, success: int):
    c = conn.cursor()
    
    # Get the current time in New York (EST/EDT)
    now = datetime.now(ZoneInfo("America/New_York"))
    
    # Format: Month - Day - Year | Hour:Minute AM/PM TZ
    timestamp = now.strftime("%m - %d - %Y | %I:%M %p %Z")
    
    c.execute(
        "INSERT INTO access_logs(user_id, action, timestamp, success) VALUES (?, ?, ?, ?)",
        (user_id, action, timestamp, success)
    )
    conn.commit()
