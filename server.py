from fastapi import FastAPI, Request, HTTPException, Depends, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pathlib import Path
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, field_validator
import hashlib
import secrets
import json
import re
from datetime import datetime, timedelta
from typing import Optional, List
import html
import shutil
import mimetypes

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
USERS_FILE = DATA_DIR / "users.json"
FILES_DIR = Path(__file__).parent / Path("files")

security = HTTPBearer(auto_error=False)

class SetupRequest(BaseModel):
    username: str
    password: str

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError('Username must be between 3 and 32 characters')
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscore and dash')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Password must be between 8 and 128 characters')
        return v

class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError('Invalid credentials')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Invalid credentials')
        return v

class CreateUserRequest(BaseModel):
    username: str
    password: str

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError('Username must be between 3 and 32 characters')
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscore and dash')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Password must be between 8 and 128 characters')
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
        "created_at": datetime.now().isoformat(),
        "user_id": 1
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

def load_users():
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"users": [], "next_id": 2}
    return {"users": [], "next_id": 2}

def save_users(users_data: dict):
    DATA_DIR.mkdir(exist_ok=True)
    temp_file = USERS_FILE.with_suffix('.tmp')
    with open(temp_file, 'w') as f:
        json.dump(users_data, f)
    temp_file.replace(USERS_FILE)

def create_session(username: str, user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    sessions = load_sessions()
    sessions[token] = {
        "username": username,
        "user_id": user_id,
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(days=7)).isoformat()
    }
    save_sessions(sessions)
    return token

def verify_session(credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[dict]:
    if not credentials:
        return None
    
    sessions = load_sessions()
    session = sessions.get(credentials.credentials)
    
    if not session:
        return None
    
    expires_at = datetime.fromisoformat(session["expires_at"])
    if datetime.now() > expires_at:
        del sessions[credentials.credentials]
        save_sessions(sessions)
        return None
    
    return session

def sanitize_path(file_path: str) -> str:
    file_path = file_path.replace('..', '').replace('//', '/')
    file_path = re.sub(r'[^\w\-./]', '', file_path)
    return file_path

def get_user_files(user_id: int) -> List[dict]:
    user_dir = FILES_DIR / str(user_id)
    if not user_dir.exists():
        return []
    
    files = []
    metadata_file = user_dir / "metadata.json"
    if metadata_file.exists():
        try:
            with open(metadata_file, 'r') as f:
                files = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return files

def save_user_files(user_id: int, files: List[dict]):
    user_dir = FILES_DIR / str(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    metadata_file = user_dir / "metadata.json"
    temp_file = metadata_file.with_suffix('.tmp')
    with open(temp_file, 'w') as f:
        json.dump(files, f)
    temp_file.replace(metadata_file)

@app.get("/admin")
async def admin_page(request: Request):
    print(f"[DEBUG] /admin accessed from {request.client.host}")
    admin = load_admin()
    if not admin:
        print("[DEBUG] No admin found, serving setup.html")
        return FileResponse(ASSETS_DIR / "setup.html")
    print("[DEBUG] Admin exists, serving login.html")
    return FileResponse(ASSETS_DIR / "login.html")

@app.get("/panel")
async def panel_page(request: Request):
    print(f"[DEBUG] /panel accessed from {request.client.host}")
    print("[DEBUG] Serving panel.html - JavaScript will handle authentication")
    return FileResponse(ASSETS_DIR / "panel.html")

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

@app.post("/v1/api/setup")
@limiter.limit("20/minute")
async def setup(request: Request, data: SetupRequest):
    print(f"[DEBUG] Setup request from {request.client.host}")
    admin = load_admin()
    if admin:
        print("[DEBUG] Admin already exists")
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
        token = create_session(data.username, 1)
        
        print(f"[DEBUG] Admin created: {data.username}")
        print(f"[DEBUG] Token created: {token[:20]}...")
        
        return JSONResponse(
            content={
                "success": True,
                "token": token
            }
        )
    except ValueError as e:
        print(f"[DEBUG] Setup validation error: {e}")
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
    print(f"[DEBUG] Login request from {request.client.host} for user: {data.username}")
    admin = load_admin()
    
    if not admin:
        print("[DEBUG] No admin setup found")
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "code": "5xsoftware.not_setup"
            }
        )
    
    try:
        password_hash = hash_password(data.password)
        
        if admin["username"] == data.username and admin["password_hash"] == password_hash:
            token = create_session(data.username, 1)
            print(f"[DEBUG] Admin login successful, token: {token[:20]}...")
            return JSONResponse(
                content={
                    "success": True,
                    "token": token
                }
            )
        
        users_data = load_users()
        for user in users_data["users"]:
            if user["username"] == data.username and user["password_hash"] == password_hash:
                token = create_session(data.username, user["user_id"])
                print(f"[DEBUG] User login successful: {data.username}, token: {token[:20]}...")
                return JSONResponse(
                    content={
                        "success": True,
                        "token": token
                    }
                )
        
        print(f"[DEBUG] Invalid credentials for user: {data.username}")
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "code": "5xsoftware.invalid_credentials"
            }
        )
    except ValueError as e:
        print(f"[DEBUG] Login validation error: {e}")
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "code": "5xsoftware.invalid_credentials"
            }
        )

@app.get("/v1/api/verify")
async def verify(credentials: HTTPAuthorizationCredentials = Depends(security)):
    session = verify_session(credentials)
    if session:
        return JSONResponse(content={
            "success": True,
            "authenticated": True,
            "username": session["username"],
            "user_id": session["user_id"]
        })
    
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

@app.get("/v1/api/users")
async def get_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
    session = verify_session(credentials)
    if not session or session["user_id"] != 1:
        return JSONResponse(
            status_code=403,
            content={"success": False, "code": "5xsoftware.forbidden"}
        )
    
    users_data = load_users()
    users_list = [{"user_id": u["user_id"], "username": u["username"], "created_at": u["created_at"]} for u in users_data["users"]]
    
    return JSONResponse(content={"success": True, "users": users_list})

@app.post("/v1/api/users")
@limiter.limit("20/minute")
async def create_user(request: Request, data: CreateUserRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    session = verify_session(credentials)
    if not session or session["user_id"] != 1:
        return JSONResponse(
            status_code=403,
            content={"success": False, "code": "5xsoftware.forbidden"}
        )
    
    users_data = load_users()
    
    admin = load_admin()
    if admin and admin["username"] == data.username:
        return JSONResponse(
            status_code=400,
            content={"success": False, "code": "5xsoftware.username_exists"}
        )
    
    for user in users_data["users"]:
        if user["username"] == data.username:
            return JSONResponse(
                status_code=400,
                content={"success": False, "code": "5xsoftware.username_exists"}
            )
    
    password_hash = hash_password(data.password)
    new_user = {
        "user_id": users_data["next_id"],
        "username": data.username,
        "password_hash": password_hash,
        "created_at": datetime.now().isoformat()
    }
    
    users_data["users"].append(new_user)
    users_data["next_id"] += 1
    save_users(users_data)
    
    return JSONResponse(content={"success": True, "user": {"user_id": new_user["user_id"], "username": new_user["username"]}})

@app.delete("/v1/api/users/{user_id}")
async def delete_user(user_id: int, credentials: HTTPAuthorizationCredentials = Depends(security)):
    session = verify_session(credentials)
    if not session or session["user_id"] != 1:
        return JSONResponse(
            status_code=403,
            content={"success": False, "code": "5xsoftware.forbidden"}
        )
    
    if user_id == 1:
        return JSONResponse(
            status_code=400,
            content={"success": False, "code": "5xsoftware.cannot_delete_admin"}
        )
    
    users_data = load_users()
    users_data["users"] = [u for u in users_data["users"] if u["user_id"] != user_id]
    save_users(users_data)
    
    user_dir = FILES_DIR / str(user_id)
    if user_dir.exists():
        shutil.rmtree(user_dir)
    
    return JSONResponse(content={"success": True})

@app.post("/v1/api/upload")
@limiter.limit("50/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    print(f"[DEBUG] Upload request from {request.client.host}")
    session = verify_session(credentials)
    if not session:
        print("[DEBUG] Upload unauthorized")
        return JSONResponse(
            status_code=401,
            content={"success": False, "code": "5xsoftware.unauthorized"}
        )
    
    form_data = await request.form()
    is_private = form_data.get('is_private', 'false').lower() == 'true'
    print(f"[DEBUG] Upload is_private: {is_private}")
    
    user_id = session["user_id"]
    user_dir = FILES_DIR / str(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    
    file_id = secrets.token_urlsafe(16)
    file_ext = Path(file.filename).suffix
    safe_filename = re.sub(r'[^\w\-.]', '_', file.filename)
    stored_filename = f"{file_id}{file_ext}"
    
    file_path = user_dir / stored_filename
    
    content = await file.read()
    with open(file_path, 'wb') as f:
        f.write(content)
    
    file_token = secrets.token_urlsafe(32) if is_private else None
    print(f"[DEBUG] Generated token: {file_token[:20] if file_token else 'None'}...")
    
    file_metadata = {
        "file_id": file_id,
        "original_filename": safe_filename,
        "stored_filename": stored_filename,
        "size": len(content),
        "uploaded_at": datetime.now().isoformat(),
        "is_private": is_private,
        "token": file_token
    }
    
    files = get_user_files(user_id)
    files.append(file_metadata)
    save_user_files(user_id, files)
    
    download_url = f"{safe_filename}?id={user_id}"
    if is_private:
        download_url += f"&token={file_token}"
    
    print(f"[DEBUG] File uploaded: {safe_filename}, private: {is_private}")
    
    return JSONResponse(content={
        "success": True,
        "file": file_metadata,
        "download_url": download_url
    })

@app.get("/v1/api/files")
async def get_files(credentials: HTTPAuthorizationCredentials = Depends(security)):
    session = verify_session(credentials)
    if not session:
        return JSONResponse(
            status_code=401,
            content={"success": False, "code": "5xsoftware.unauthorized"}
        )
    
    user_id = session["user_id"]
    files = get_user_files(user_id)
    
    return JSONResponse(content={"success": True, "files": files})

@app.delete("/v1/api/files/{file_id}")
async def delete_file(file_id: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    session = verify_session(credentials)
    if not session:
        return JSONResponse(
            status_code=401,
            content={"success": False, "code": "5xsoftware.unauthorized"}
        )
    
    user_id = session["user_id"]
    files = get_user_files(user_id)
    
    file_to_delete = None
    for f in files:
        if f["file_id"] == file_id:
            file_to_delete = f
            break
    
    if not file_to_delete:
        return JSONResponse(
            status_code=404,
            content={"success": False, "code": "5xsoftware.file_not_found"}
        )
    
    user_dir = FILES_DIR / str(user_id)
    file_path = user_dir / file_to_delete["stored_filename"]
    if file_path.exists():
        file_path.unlink()
    
    files = [f for f in files if f["file_id"] != file_id]
    save_user_files(user_id, files)
    
    return JSONResponse(content={"success": True})

@app.get("/{file_path:path}")
@limiter.limit("500/minute")
async def serve_file(request: Request, file_path: str, id: Optional[int] = None, token: Optional[str] = None):
    if id is not None:
        files = get_user_files(id)
        
        file_metadata = None
        for f in files:
            if f["original_filename"] == file_path:
                file_metadata = f
                break
        
        if not file_metadata:
            return JSONResponse(
                status_code=404,
                content={"success": False, "code": "5xsoftware.file_not_found"}
            )
        
        if file_metadata["is_private"]:
            if not token or token != file_metadata["token"]:
                return JSONResponse(
                    status_code=403,
                    content={"success": False, "code": "5xsoftware.forbidden"}
                )
        
        user_dir = FILES_DIR / str(id)
        full_file_path = user_dir / file_metadata["stored_filename"]
        
        if not full_file_path.exists():
            return JSONResponse(
                status_code=404,
                content={"success": False, "code": "5xsoftware.file_not_found"}
            )
        
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = "application/octet-stream"
        
        return FileResponse(
            full_file_path,
            media_type=mime_type,
            filename=file_metadata["original_filename"]
        )
    
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
    FILES_DIR.mkdir(exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=9123)