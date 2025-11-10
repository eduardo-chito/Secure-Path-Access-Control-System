import sqlite3
import bcrypt

DB_NAME = "securepath.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role_id INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS roles 
                (id INTEGER PRIMARY KEY, name TEXT UNIQUE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS permissions
                (id INTEGER PRIMARY KEY, name TEXT UNIQUE, description TEXT )''')
    c.execute('''CREATE TABLE IF NOT EXISTS role_permissions
                (role_id INTEGER, permission_id INTEGER, PRIMARY KEY(role_id, permission_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs
                (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, timestamp TEXT, success INTEGER)''')

    roles = [('Admin', ), ('Staff',), ('Guest',)]
    c.executemany("INSERT OR IGNORE INTO roles (name) VALUES (?)", roles)

    permissions = [
        ('manage_users', 'Manage users'),
        ('manage_roles', 'Manage roles'),
        ('manage_permissions', 'Manage permissions'),
        ('view_logs', 'View access logs'),
        ('view_dashboard', 'View dashboard'),
        ('access_employee_page', 'Access employee functions'),
        ('access_guest_page', 'Access guest functions')
    ]
    c.executemany("INSERT OR IGNORE INTO permissions (name,description) VALUES (?,?)", permissions)
    conn.commit()

    admin_id = c.execute("SELECT id FROM roles WHERE name ='Admin'").fetchone()[0]
    staff_id = c.execute("SELECT id FROM roles WHERE name ='Staff'").fetchone()[0]
    guest_id = c.execute("SELECT id FROM roles WHERE name ='Guest'").fetchone()[0]

    perm_ids = {name: c.execute("SELECT id FROM permissions WHERE name=?", (name,)).fetchone()[0] for name, _ in permissions}

    admin_perms = [(admin_id, perm_ids[p]) for p in perm_ids]

    staff_perms = [
        (staff_id, perm_ids['view_dashboard']),
        (staff_id, perm_ids['view_logs']),
        (staff_id, perm_ids['access_employee_page'])
    ]

    guest_perms = [
        (guest_id, perm_ids['view_dashboard']),
        (guest_id, perm_ids['access_guest_page'])
    ]

    c.executemany("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?,?)",
                  admin_perms + staff_perms + guest_perms)

    hashed = bcrypt.hashpw(b'adminpass', bcrypt.gensalt())
    c.execute("INSERT OR IGNORE INTO users (username, password, role_id) VALUES (?, ?, ?)", ('admin', hashed, admin_id))

    # Optional: create staff and guest demo users
    hashed_staff = bcrypt.hashpw(b'staffpass', bcrypt.gensalt())
    c.execute("INSERT OR IGNORE INTO users (username, password, role_id) VALUES (?, ?, ?)", ('staff', hashed_staff, staff_id))

    hashed_guest = bcrypt.hashpw(b'guestpass', bcrypt.gensalt())
    c.execute("INSERT OR IGNORE INTO users (username, password, role_id) VALUES (?, ?, ?)", ('guest', hashed_guest, guest_id))

    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
