from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from routes import router as api_router
from database import init_db
from auth import get_current_user

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

#Middleware to prevent caching
@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response


# Custom exception handler for 401/403 errors
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": exc.detail},
            status_code=exc.status_code,
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, private", "Pragma": "no-cache",
                     "Expires": "-1"}
        )
    elif exc.status_code == 403:
        return templates.TemplateResponse(
            "access_denied.html",
            {"request": request, "error": exc.detail},
            status_code=exc.status_code,
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, private", "Pragma": "no-cache",
                     "Expires": "-1"}
        )
    return {"detail": exc.detail}

#Initialize the database
init_db()

#Include the routes
app.include_router(api_router)

# Endpoint for client-side auth check
@app.get("/check-auth")
async def check_auth(user: dict = Depends(get_current_user)):
    return {"status": "authenticated"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)