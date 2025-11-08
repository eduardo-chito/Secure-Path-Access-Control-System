from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import sqlite3
import bcrypt
from models import UserLogin
from auth import get_current_user, has_permission
from utils import log_access
from database import get_db
import time

SECRET_KEY = "super_secret_key"
ALGORITHM = "HS256"

router = APIRouter()
templates = Jinja2Templates(directory="templates")



@router.get("/", response_class=HTMLResponse)
async def index():
    return RedirectResponse(url='/login')

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login", response_class=HTMLResponse)
async def login(
        request:Request,
        username:str = Form(...),
        password:str = Form(...),
        response: Response = None, conn:sqlite3.Connection = Depends(get_db)):
    from jose import jwt
    c = conn.cursor()
    db_user = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if db_user and bcrypt.checkpw(password.encode('utf-8'), db_user["password"]):
        token = jwt.encode({'sub': str(db_user['id'])}, SECRET_KEY, algorithm=ALGORITHM)
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="access_token", value=token, httponly=True)
        log_access(conn, db_user['id'], "Login successful", 1)
        return response
    log_access(conn, None, f"Failed login attempt for {username}", 0)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password"})

@router.get("/logout")
async def logout(response: Response, conn: sqlite3.Connection=Depends(get_db), user:dict = Depends(get_current_user)):
    log_access(conn, user["id"], "Logout", 1)
    response = RedirectResponse(url=f"/login?t={int(time.time())}", status_code=status.HTTP_303_SEE_OTHER,
                            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, private", "Pragma": "no-cache", "Expires": "-1"})
    response.set_cookie(
        key="access_token",
        value="",
        httponly=True,
        secure=False,
        samesite="lax",
        expires=0
    )
    return response

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request:Request, user: dict = Depends(get_current_user), conn:sqlite3.Connection = Depends(get_db)):
    log_access(conn, user["id"], "Access dashboard", 1)
    permissions = {
        "manage_users": await has_permission(user, "manage_users", conn),
        "manage_roles": await has_permission(user, "manage_roles", conn),
        "manage_permissions": await has_permission(user, "manage_permissions", conn),
        "view_logs": await has_permission(user, "view_logs", conn)
    }

    response = templates.TemplateResponse("dashboard.html", {"request": request, "username": user['username'], "permissions": permissions})
    return response

@router.get("/users", response_class=HTMLResponse)
async def manage_users_get(request: Request, user: dict= Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    if not await has_permission(user, "manage_users", conn):
        log_access(conn, user["id"], "Attempted access to /users", 0)
        raise HTTPException(status_code=403, detail="Permission denied")
    c = conn.cursor()
    users = c.execute("SELECT u.id, u.username, r.name as role FROM users u JOIN roles r on u.role_id = r.id").fetchall()
    roles = c.execute("SELECT * FROM roles").fetchall()
    permissions = {
        "manage_users": True,
        "manage_roles": await has_permission(user, "manage_roles", conn),
        "manage_permissions": await has_permission(user, "manage_permissions", conn),
        "view_logs": await has_permission(user, "view_logs", conn)
    }
    return templates.TemplateResponse("users.html", {"request": request, "users": users, "roles": roles, "permissions": permissions})

@router.post("/users", response_class=RedirectResponse)
async def manage_user_post(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    if not await has_permission(user, "manage_users", conn):
        log_access(conn, user['id'], "Attempted user management", 0)
        raise HTTPException(status_code=403, detail="Permission denied")
    form = await request.form()
    c = conn.cursor()
    action = form.get("action")
    if action == "add":
        username = form.get("username")
        password = form.get("password")
        role_id = form.get("role_id")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users(username, password,role_id) VALUES (?, ?, ?)", (username, hashed, role_id))
    elif action == "delete":
        user_id = form.get("user_id")
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/roles", response_class=HTMLResponse)
async def manage_roles_get(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    if not await has_permission(user, "manage_roles", conn):
        log_access(conn, user['id'], "Attempted access to /roles", 0)
        raise HTTPException(status_code=403, detail="Permission denied")
    c = conn.cursor()
    roles = c.execute("SELECT * FROM roles").fetchall()
    permissions = {
        "manage_users": await has_permission(user, "manage_users", conn),
        "manage_roles": True,
        "manage_permissions": await has_permission(user, "manage_permissions", conn),
        "view_logs": await has_permission(user, "view_logs", conn)
    }
    return templates.TemplateResponse("roles.html", {"request": request, "roles": roles, "permissions": permissions})

@router.post("/roles", response_class=RedirectResponse)
async def manage_roles_post(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    if not await has_permission(user, "manage_roles", conn):
        log_access(conn, user["id"], "Attempted role management", 0)
        raise HTTPException(status_code=403,detail="Permission denied")

    form = await request.form()
    c = conn.cursor()
    action = form.get("action")
    if action == "add":
        name = form.get("name")
        c.execute("INSERT INTO roles(name) VALUES (?)", (name,))
    elif action == "delete":
        role_id = form.get("role_id")
        c.execute("DELETE FROM roles WHERE id=?", (role_id,))
        c.execute("DELETE FROM role_permissions WHERE role_id=?", (role_id,))
    conn.commit()
    return RedirectResponse(url="/roles", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/permissions", response_class=HTMLResponse)
async def manage_permissions_get(request: Request, user: dict = Depends(get_current_user), conn:sqlite3.Connection=Depends(get_db)):
    if not await has_permission(user, "manage_permissions", conn):
        log_access(conn, user["id"], "Attempted permission management", 0)
        raise HTTPException(status_code=403, detail="Permission denied")

    c = conn.cursor()
    permissions = c.execute("SELECT * FROM permissions").fetchall()
    roles = c.execute("SELECT * FROM roles").fetchall()
    role_perms = c.execute("SELECT rp.role_id, rp.permission_id, r.name as role, p.name as perm FROM role_permissions rp JOIN roles r ON rp.role_id=r.id JOIN permissions p ON rp.permission_id = p.id").fetchall()
    permissions_dict = {
        "manage_users": await has_permission(user, "manage_users", conn),
        "manage_roles": await has_permission(user, "manage_roles", conn),
        "manage_permissions": True,
        "view_logs": await has_permission(user, "view_logs", conn)
    }
    return templates.TemplateResponse("permissions.html", {"request": request, "permissions": permissions, "roles": roles, "role_perms": role_perms, "permissions_dict": permissions_dict})

@router.post("/permissions", response_class=RedirectResponse)
async def manage_permissions_post(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    if not await has_permission(user, "manage_permissions", conn):
        log_access(conn, user["id"], "Attempted permission management", 0)
        raise HTTPException(status_code=403, detail="Permission denied")

    form = await request.form()
    c = conn.cursor()
    action = form.get("action")
    if action == "add":
        name = form.get("name")
        desc = form.get("description")
        c.execute("INSERT INTO permissions (name,description) VALUES (?,?)", (name, desc))
    elif action == "delete":
        perm_id = form.get("perm_id")
        c.execute("DELETE FROM permissions WHERE id=?", (perm_id,))
        c.execute("DELETE FROM role_permissions WHERE permission_id=?", (perm_id,))
    elif action == "assign":
        role_id = form.get("role_id")
        perm_id = form.get("perm_id")
        c.execute("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?,?)", (role_id,perm_id))
    conn.commit()
    return RedirectResponse(url="/permissions", status_code = status.HTTP_303_SEE_OTHER)

@router.get("/logs", response_class=HTMLResponse)
async def view_logs(request: Request, user:dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    if not await has_permission(user, "view_logs", conn):
        log_access(conn, user["id"], "Attempted access to /logs", 0)
        raise HTTPException(status_code=403, detail="Permission denied")

    c = conn.cursor()
    logs = c.execute("SELECT l.id, u.username, l.action, l.timestamp, l.success FROM access_logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.timestamp DESC").fetchall()
    permissions = {
        "manage_users": await has_permission(user, "manage_users", conn),
        "manage_roles": await has_permission(user, "manage_roles", conn),
        "manage_permissions": await has_permission(user, "manage_permissions", conn),
        "view_logs": True
    }
    return templates.TemplateResponse("logs.html", {"request": request, "logs": logs, "permissions": permissions})
