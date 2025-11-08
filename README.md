Secure Path Access Control System
=================================

Overview
--------

Secure Path is a web-based Role-Based Access Control (RBAC) prototype designed to manage user access securely and efficiently. Built with FastAPI, SQLite, and Jinja2 templates, it enforces role-based permissions, provides a user-friendly interface, and includes robust security features. This project aligns with the project charter’s requirements for security (2.4.2), usability (2.4.4), scope limits (2.4.5), and deliverables for the Week 15 demonstration (2.4.6).

### Key Features

*   **Role-Based Access Control (RBAC):** Assigns permissions (manage\_users, manage\_roles, manage\_permissions, view\_logs) to roles (e.g., Admin, Staff).
    
*   **Dynamic Navigation:** Hides navbar links for unauthorized routes based on user roles, improving usability.
    
*   **Secure Authentication:** Uses JWT tokens (httponly cookies) and bcrypt password hashing.
    
*   **Access Denied Page:** Displays a custom page for users attempting unauthorized access, replacing login redirects for 403 errors.
    
*   **Centered Login Form:** Flexbox-based, responsive login page for intuitive user experience.
    
*   **Back-Button Prevention:** Cache-control headers and AJAX checks prevent access to protected pages after logout.
    
*   **Audit Logging:** Tracks user actions and access attempts in an access\_logs table.
    


Prerequisites
-------------

*   Python 3.8+
    
*   pip for installing dependencies
    
*   SQLite (included with Python)
    

Installation
------------

1.  **Clone the Repository** (or set up the project directory with the provided files).
    
2.  Create and activate a virtual environment
``` 
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```
3. Install dependencies from requirements.txt
```
pip install -r requirements.txt
```
4. **Ensure Project Files:**
    
    *   Verify all Python files (main.py, routes.py, auth.py, database.py, models.py, utils.py) are in the root directory.
        
    *   Place style.css in static/.
        
    *   Place HTML templates (login.html, dashboard.html, users.html, roles.html, permissions.html, logs.html, access\_denied.html) in templates/.
        

Running the Application
-----------------------

1. If you are running the application for the first time
```uvicorn main:app --host 127.0.0.1 --port 8000 --reload``` 
    
2.  **Access the Application:**
    
    *   Open http://127.0.0.1:8000/ in a browser.
        
    *   Default credentials: admin/adminpass (Admin role with all permissions).

Database Setup
--------------

*   The database (securepath.db) is initialized automatically on first run via database.py.
    
*   **Default Data:**
    
    *   Roles: Admin (all permissions), Staff (view\_logs only).
        
    *   Permissions: manage\_users, manage\_roles, manage\_permissions, view\_logs.
        
    *   User: admin/adminpass (Admin role).
* If you want to reset the database run
        
```rm securepath.db;  uvicorn main:app --host 127.0.0.1 --port 8000 --reload```
    

Usage
-----

1.  **Login:**
    
    *   Visit http://127.0.0.1:8000/ and log in with admin/adminpass.
        
    *   The login form is centered and responsive for accessibility.
        
2.  **Dashboard:**
    
    *   After login, you’re redirected to /dashboard.
        
    *   The navbar displays links based on your role’s permissions (e.g., Admin sees all links; Staff sees only Dashboard, View Logs, Logout).
        
3.  **Management Pages:**
    
    *   /users: Add/delete users, assign roles (requires manage\_users).
        
    *   /roles: Add/delete roles (requires manage\_roles).
        
    *   /permissions: Add/delete permissions, assign to roles (requires manage\_permissions).
        
    *   /logs: View access logs (requires view\_logs).
        
4.  **Access Denied:**
    
    *   Attempting to access unauthorized routes (e.g., /users as Staff) shows the access\_denied.html page with a “Return to Dashboard” link.
        
5.  **Logout:**
    
    *   Click “Logout” to clear the JWT cookie and redirect to /login.
        

Testing Scenarios
-----------------

1.  **Admin Access:**
    
    *   Log in as admin/adminpass.
        
    *   Verify all navbar links appear (Dashboard, Manage Users, Manage Roles, Manage Permissions, View Logs, Logout) on all protected pages.
        
    *   Access /users, /roles, /permissions, /logs to confirm functionality.
        
2.  **Staff Access:**
    
    *   As admin, go to /users and create a user (e.g., staff1/staffpass, role: Staff).
        
    *   Log out and log in as staff1/staffpass.
        
    *   Verify navbar shows only Dashboard, View Logs, Logout on /dashboard and /logs.
        
    *   Attempt to access /users, /roles, or /permissions via URL (e.g., http://127.0.0.1:8000/users). Confirm the access denied page appears.
        
3.  **Back-Button Prevention:**
    
    *   Log out as staff1, use the browser’s back button to revisit /dashboard.
        
    *   Verify the AJAX auth check redirects to /login within 5 seconds.
        
4.  **Responsive Design:**
    
    *   Resize the browser to ~400px width to test mobile layout (navbar stacks vertically, login form remains centered).
        
5.  **Audit Logging:**
    
    *   sqlite3 securepath.dbSELECT \* FROM access\_logs WHERE success=0;
        
    *   Look for entries like “Attempted access to /users” for staff1.


Contact
-------

For issues, feedback, or contributions, contact the project team.