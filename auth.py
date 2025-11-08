from fastapi import Depends, HTTPException, Request
from jose import jwt
import sqlite3


from database import get_db

SECRET_KEY = "super_secret_key"
ALGORITHM = "HS256"

async def get_current_user(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        c = conn.cursor()
        user = c.execute("SELECT id, username, role_id FROM users WHERE id =?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return dict(user)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

async def has_permission(user: dict, perm_name: str, conn: sqlite3.Connection):
    c = conn.cursor()
    perm_id = c.execute("SELECT id FROM permissions WHERE name=?", (perm_name,)).fetchone()
    if not perm_id:
        return False
    perm_id = perm_id[0]
    result = c.execute("SELECT * FROM role_permissions WHERE role_id=? AND permission_id=?", (user['role_id'], perm_id)).fetchone()
    return bool(result)