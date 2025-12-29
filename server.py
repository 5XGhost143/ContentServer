from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pathlib import Path
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, validator
import hashlib
import secrets
import json
import re
from datetime import datetime, timedelta
from typing import Optional
import html

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.local", "content.ghost143.de"]
)

ASSETS_DIR = Path(__file__).parent / Path("assets")
ALLOWED_EXTENSIONS = frozenset([Path(".js"), Path(".css")])
DATA_DIR = Path(__file__).parent / Path("data")
ADMIN_FILE = DATA_DIR / "admin.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"

security = HTTPBearer(auto_error=False)

class SetupRequest(BaseModel):
    username: str
    password: str

    @validator('username')
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError('Username must be between 3 and 32 characters')
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscore and dash')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Password must be between 8 and 128 characters')
        return v

class LoginRequest(BaseModel):
    username: str
    password: str

    @validator('username')
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError('Invalid credentials')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Invalid credentials')
        return v

def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    return add_security_headers(response)

def hash_password(password: str) -> str:
    salt = b"5xsoftware_salt_v1"
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def load_admin():
    if ADMIN_FILE.exists():
        try:
            with open(ADMIN_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None

def save_admin(username: str, password_hash: str):
    DATA_DIR.mkdir(exist_ok=True)
    data = {
        "username": username,
        "password_hash": password_hash,
        "created_at": datetime.now().isoformat()
    }
    temp_file = ADMIN_FILE.with_suffix('.tmp')
    with open(temp_file, 'w') as f:
        json.dump(data, f)
    temp_file.replace(ADMIN_FILE)

def load_sessions():
    if SESSIONS_FILE.exists():
        try:
            with open(SESSIONS_FILE, 'r') as f:
                sessions = json.load(f)
                current_time = datetime.now()
                valid_sessions = {}
                for token, session in sessions.items():
                    expires_at = datetime.fromisoformat(session["expires_at"])
                    if current_time <= expires_at:
                        valid_sessions[token] = session
                if len(valid_sessions) != len(sessions):
                    save_sessions(valid_sessions)
                return valid_sessions
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_sessions(sessions: dict):
    DATA_DIR.mkdir(exist_ok=True)
    temp_file = SESSIONS_FILE.with_suffix('.tmp')
    with open(temp_file, 'w') as f:
        json.dump(sessions, f)
    temp_file.replace(SESSIONS_FILE)

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(48)
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

def sanitize_path(file_path: str) -> str:
    file_path = file_path.replace('..', '').replace('//', '/')
    file_path = re.sub(r'[^\w\-./]', '', file_path)
    return file_path

@app.get("/5x-content/{file_path:path}")
@limiter.limit("500/minute")
async def serve_5x_content(request: Request, file_path: str):
    file_path = sanitize_path(file_path)
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
@limiter.limit("20/minute")
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
    
    try:
        password_hash = hash_password(data.password)
        save_admin(data.username, password_hash)
        token = create_session(data.username)
        
        return JSONResponse(
            content={
                "success": True,
                "token": token
            }
        )
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "code": "5xsoftware.invalid_credentials"
            }
        )

@app.post("/v1/api/login")
@limiter.limit("20/minute")
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
    
    try:
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
    except ValueError:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "code": "5xsoftware.invalid_credentials"
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
    file_path = sanitize_path(file_path)
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