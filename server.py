from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pathlib import Path
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
ASSETS_DIR = Path(__file__).parent / Path("assets")
ALLOWED_EXTENSIONS = frozenset([Path(".js"), Path(".css")])
DATA_DIR = Path(__file__).parent / Path("data")
ADMIN_FILE = DATA_DIR / "admin.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"

security = HTTPBearer(auto_error=False)

class SetupRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def load_admin():
    if ADMIN_FILE.exists():
        with open(ADMIN_FILE, 'r') as f:
            return json.load(f)
    return None

def save_admin(username: str, password_hash: str):
    DATA_DIR.mkdir(exist_ok=True)
    with open(ADMIN_FILE, 'w') as f:
        json.dump({
            "username": username,
            "password_hash": password_hash,
            "created_at": datetime.now().isoformat()
        }, f)

def load_sessions():
    if SESSIONS_FILE.exists():
        with open(SESSIONS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_sessions(sessions: dict):
    DATA_DIR.mkdir(exist_ok=True)
    with open(SESSIONS_FILE, 'w') as f:
        json.dump(sessions, f)

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    sessions = load_sessions()
    sessions[token] = {
        "username": username,
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(days=7)).isoformat()
    }
    save_sessions(sessions)
    return token

def verify_session(credentials: Optional[HTTPAuthorizationCredentials]) -> bool:
    if not credentials:
        return False
    
    sessions = load_sessions()
    session = sessions.get(credentials.credentials)
    
    if not session:
        return False
    
    expires_at = datetime.fromisoformat(session["expires_at"])
    if datetime.now() > expires_at:
        del sessions[credentials.credentials]
        save_sessions(sessions)
        return False
    
    return True

@app.get("/5x-content/{file_path:path}")
@limiter.limit("500/minute")
async def serve_5x_content(request: Request, file_path: str):
    full_path = ASSETS_DIR / file_path
    
    if not full_path.exists() or not full_path.is_file():
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "code": "5xsoftware.invalid_file"
            }
        )
    
    file_ext = Path(full_path.suffix.lower())
    
    if file_ext not in ALLOWED_EXTENSIONS:
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "code": "5xsoftware.disallowed_file"
            }
        )
    
    try:
        full_path.resolve().relative_to(ASSETS_DIR.resolve())
    except ValueError:
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "code": "5xsoftware.disallowed_file"
            }
        )
    
    media_types = {
        Path(".js"): "application/javascript",
        Path(".css"): "text/css"
    }
    
    return FileResponse(
        full_path,
        media_type=media_types.get(file_ext, "text/plain")
    )

@app.get("/admin")
async def admin_page():
    admin = load_admin()
    if not admin:
        return FileResponse(ASSETS_DIR / "setup.html")
    return FileResponse(ASSETS_DIR / "login.html")

@app.post("/v1/api/setup")
@limiter.limit("10/minute")
async def setup(request: Request, data: SetupRequest):
    admin = load_admin()
    if admin:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "code": "5xsoftware.already_setup"
            }
        )
    
    if len(data.username) < 3 or len(data.password) < 8:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "code": "5xsoftware.invalid_credentials"
            }
        )
    
    password_hash = hash_password(data.password)
    save_admin(data.username, password_hash)
    
    token = create_session(data.username)
    
    return JSONResponse(
        content={
            "success": True,
            "token": token
        }
    )

@app.post("/v1/api/login")
@limiter.limit("10/minute")
async def login(request: Request, data: LoginRequest):
    admin = load_admin()
    
    if not admin:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "code": "5xsoftware.not_setup"
            }
        )
    
    password_hash = hash_password(data.password)
    
    if admin["username"] != data.username or admin["password_hash"] != password_hash:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "code": "5xsoftware.invalid_credentials"
            }
        )
    
    token = create_session(data.username)
    
    return JSONResponse(
        content={
            "success": True,
            "token": token
        }
    )

@app.get("/v1/api/verify")
async def verify(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if verify_session(credentials):
        return JSONResponse(content={"success": True, "authenticated": True})
    
    return JSONResponse(
        status_code=401,
        content={"success": False, "authenticated": False}
    )

@app.post("/v1/api/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return JSONResponse(
            status_code=401,
            content={"success": False}
        )
    
    sessions = load_sessions()
    if credentials.credentials in sessions:
        del sessions[credentials.credentials]
        save_sessions(sessions)
    
    return JSONResponse(content={"success": True})

@app.get("/{file_path:path}")
@limiter.limit("500/minute")
async def serve_generic(request: Request, file_path: str):
    full_path = ASSETS_DIR / file_path
    
    if not full_path.exists() or not full_path.is_file():
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "code": "5xsoftware.invalid_endpoint"
            }
        )
    
    return FileResponse(full_path)

if __name__ == "__main__":
    ASSETS_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=9123)