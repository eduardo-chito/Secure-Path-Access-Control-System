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

async def _role_and_perms(user, conn):
    c = conn.cursor()
    row = c.execute("SELECT name FROM roles WHERE id=?", (user["role_id"],)).fetchone()
    role = (row["name"] if row else "Guest").lower()
    perms = {
        "manage_users": await has_permission(user, "manage_users", conn),
        "manage_roles": await has_permission(user, "manage_roles", conn),
        "manage_permissions": await has_permission(user, "manage_permissions", conn),
        "view_logs": await has_permission(user, "view_logs", conn),
        "access_company": await has_permission(user, "access_company", conn),
    }
    return role, perms

def build_nav(role: str, admin_mode: bool = False):
    if role == "admin":
        if admin_mode:
            return [
                {"href": "/company", "label": "Home"},
                {"href": "/logs", "label": "Logs"},
                {"href": "/users", "label": "Users"},
                {"href": "/roles", "label": "Roles"},
                {"href": "/permissions", "label": "Permissions"},
            ]
        else:
            return [
                {"href": "/company", "label": "Home"},
                {"href": "/company/news", "label": "News"},
                {"href": "/company/jobs", "label": "Jobs"},
                {"href": "/company/pay", "label": "Pay"},
                {"href": "/company/resources", "label": "Resources"},
                {"href": "/logs", "label": "Logs"},
                {"href": "/staff-dashboard", "label": "Staff Dashboard"},
                {"href": "/dashboard", "label": "Admin Dashboard"},
            ]
    elif role == "staff":
        return [
                {"href": "/company", "label": "Home"},
                {"href": "/company/news", "label": "News"},
                {"href": "/company/jobs", "label": "Jobs"},
                {"href": "/company/pay", "label": "Pay"},
                {"href": "/company/resources", "label": "Resources"},
                {"href": "/logs", "label": "Logs"},
                {"href": "/staff-dashboard", "label": "Staff Dashboard"},
        ]
    else:
        return [
            {"href": "/guest/about", "label": "About"},
            {"href": "/guest/mission", "label": "Mission"},
            {"href": "/guest/team", "label": "Team"},
            {"href": "/guest/contact", "label": "Contact"},
        ]

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
        response = RedirectResponse(url="/redirect-by-role", status_code=status.HTTP_303_SEE_OTHER)
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

@router.get("/redirect-by-role")
async def redirect_by_role(user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    c = conn.cursor()
    role = c.execute("SELECT name FROM roles WHERE id=?", (user["role_id"],)).fetchone()
    role_name = role["name"].lower() if role else "guest"

    if role_name == "guest":
        return RedirectResponse(url="/guest/about")
    else:
        return RedirectResponse(url="/company")

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request:Request, user: dict = Depends(get_current_user), conn:sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    log_access(conn, user["id"], "Access dashboard", 1)

    response = templates.TemplateResponse("dashboard.html", {"request": request, "username": user['username'], "permissions": perms, "nav": build_nav(role, admin_mode=True), "title": "Admin Dashboard"})
    return response

@router.get("/users", response_class=HTMLResponse)
async def manage_users_get(request: Request, user: dict= Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    if not perms["manage_users"]:
        log_access(conn, user["id"], "Attempted access to /users", 0)
        raise HTTPException(status_code=403, detail="Permission denied")
    c = conn.cursor()
    users = c.execute("SELECT u.id, u.username, r.name as role FROM users u JOIN roles r on u.role_id = r.id").fetchall()
    roles = c.execute("SELECT * FROM roles").fetchall()
   
    return templates.TemplateResponse("users.html", {"request": request, "users": users, "roles": roles, "permissions": perms, "username": user["username"], "nav": build_nav(role, admin_mode=True), "title": "Manage Users"})

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
    role, perms = await _role_and_perms(user, conn)
    if not perms["manage_roles"]:
        log_access(conn, user['id'], "Attempted access to /roles", 0)
        raise HTTPException(status_code=403, detail="Permission denied")
    c = conn.cursor()
    roles = c.execute("SELECT * FROM roles").fetchall()
    
    return templates.TemplateResponse("roles.html", {"request": request, "roles": roles, "username": user["username"], "permissions": perms,  "nav": build_nav(role, admin_mode=True), "title": "Manage Roles"})

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
    role, perms = await _role_and_perms(user, conn)
    if not perms["manage_permissions"]:
        log_access(conn, user["id"], "Attempted permission management", 0)
        raise HTTPException(status_code=403, detail="Permission denied")

    c = conn.cursor()
    permissions = c.execute("SELECT * FROM permissions").fetchall()
    roles = c.execute("SELECT * FROM roles").fetchall()
    role_perms = c.execute("SELECT rp.role_id, rp.permission_id, r.name as role, p.name as perm FROM role_permissions rp JOIN roles r ON rp.role_id=r.id JOIN permissions p ON rp.permission_id = p.id").fetchall()
    
    return templates.TemplateResponse("permissions.html", {"request": request, "permissions": permissions, "roles": roles, "role_perms": role_perms, "username": user["username"], "nav": build_nav(role, admin_mode=True), "title": "Manage Permissions"})

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
    role, perms = await _role_and_perms(user, conn)
    if not perms["view_logs"]:
        log_access(conn, user["id"], "Attempted access to /logs", 0)
        raise HTTPException(status_code=403, detail="Permission denied")

    c = conn.cursor()
    logs = c.execute("SELECT l.id, u.username, l.action, l.timestamp, l.success FROM access_logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.timestamp DESC").fetchall()
    
    return templates.TemplateResponse("logs.html", {"request": request, "logs": logs, "username": user["username"], "permissions": perms, "username": user["username"], "nav": build_nav(role), "title": "Access Logs"})

@router.get("/company", response_class=HTMLResponse)
async def company_root(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    if not perms["access_company"]:
        return RedirectResponse(url="/guest/about", status_code=303)
    
    

    return templates.TemplateResponse(
        "company_home.html",
        {
            "request": request,
            "username": user["username"],
            "permissions": perms,
            "nav": build_nav(role),
            "title": "Company Home",
            "header_title": "SecureTech Employee Portal"
        }
    )
    

@router.get("/company/news", response_class=HTMLResponse)
async def company_news(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    if not perms["access_company"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    return templates.TemplateResponse("company_news.html", {
        "request": request,
        "username": user["username"],
        "permissions": perms,
        "nav": build_nav(role),
        "title": "Company News",
        "header_title": "SecureTech Employee Portal"
    })

@router.get("/company/jobs", response_class=HTMLResponse)
async def company_jobs(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    if not perms["access_company"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    return templates.TemplateResponse("company_jobs.html", {
        "request": request,
        "username": user["username"],
        "permissions": perms,
        "nav": build_nav(role),
        "title": "Job Listings",
        "header_title": "SecureTech Employee Portal"
    })

@router.get("/company/pay", response_class=HTMLResponse)
async def company_pay(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    if not perms["access_company"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    return templates.TemplateResponse("company_pay.html", {
        "request": request,
        "username": user["username"],
        "permissions": perms,
        "nav": build_nav(role),
        "title": "Pay & Benefits",
        "header_title": "SecureTech Employee Portal"
    })

@router.get("/company/resources", response_class=HTMLResponse)
async def company_resources(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    if not await has_permission(user, "access_company", conn):
        raise HTTPException(status_code=403, detail="Permission denied")
    return templates.TemplateResponse("company_resources.html", {
        "request": request,
        "username": user["username"],
        "permissions": perms,
        "nav": build_nav(role),
        "title": "Company Resources",
        "header_title": "SecureTech Employee Portal"
    })

@router.get("/guest/about", response_class=HTMLResponse)
async def guest_about(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, _ = await _role_and_perms(user, conn)
    return templates.TemplateResponse("guest_about.html", {
        "request": request,
        "username": user["username"],
        "nav": build_nav("guest"),
        "title": "About SecureTech",
        "header_title": "SecureTech Guest Portal",
    })

@router.get("/guest/mission", response_class=HTMLResponse)
async def guest_mission(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, _ = await _role_and_perms(user, conn)
    return templates.TemplateResponse("guest_mission.html", {
        "request": request,
        "username": user["username"],
        "nav": build_nav("guest"),
        "title": "Our Mission",
        "header_title": "SecureTech Guest Portal"
    })

@router.get("/guest/team", response_class=HTMLResponse)
async def guest_team(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, _ = await _role_and_perms(user, conn)
    return templates.TemplateResponse("guest_team.html", {
        "request": request,
        "username": user["username"],
        "nav": build_nav("guest"),
        "title": "Our Team",
        "header_title": "SecureTech Guest Portal"
    })

@router.get("/guest/contact", response_class=HTMLResponse)
async def guest_contact(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, _ = await _role_and_perms(user, conn)
    return templates.TemplateResponse("guest_contact.html", {
        "request": request,
        "username": user["username"],
        "nav": build_nav("guest"),
        "title": "Contact Us",
        "header_title": "SecureTech Guest Portal"
    })

@router.get("/staff-dashboard", response_class=HTMLResponse)
async def staff_dashboard(request: Request, user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    role, perms = await _role_and_perms(user, conn)
    if not await has_permission(user, "access_company", conn):
        raise HTTPException(status_code=403, detail="Permission denied")
    
    return templates.TemplateResponse("staff_dashboard.html", { "request": request, "username": user["username"], "permissions": perms, "nav": build_nav(role), "title": "Staff Dashboard",})