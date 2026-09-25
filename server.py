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
import os
app = FastAPI()

# these ones are made with AI 
app.add_middleware(CORSMiddleware, allow_origins=['localhost', '127.0.0.1', '*.local', 'content.ghost143.de'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
limiter = Limiter(key_func=get_remote_address)
# these ones are made with AI 

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', '*.local', 'content.ghost143.de'])

# these ones are made with AI 
ASSETS_DIR = Path(__file__).parent / Path('assets')
ALLOWED_EXTENSIONS = frozenset([Path('.js'), Path('.css')])
DATA_DIR = Path(__file__).parent / Path('data')
ADMIN_FILE = DATA_DIR / 'admin.json'
SESSIONS_FILE = DATA_DIR / 'sessions.json'
USERS_FILE = DATA_DIR / 'users.json'
FILES_DIR = DATA_DIR / 'files'
INLINE_DISPLAY_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp', 'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm', 'audio/aac', 'audio/mp4', 'application/pdf', 'text/plain', 'text/css', 'text/javascript', 'application/javascript', 'application/json', 'application/xml', 'text/xml', 'text/csv'}
DOWNLOAD_EXTENSIONS = {'.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.xhtml'}
# these ones are made with AI 

security = HTTPBearer(auto_error=False) # copied from documentation

class FXA_SetupRequest(BaseModel):
    username: str
    password: str

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError('Username must be between 3 and 32 characters')
        if not re.match('^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscore and dash')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Password must be between 8 and 128 characters')
        return v

class FX_LoginRequest(BaseModel):
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

class FXA_CreateUserRequest(BaseModel):
    username: str
    password: str

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError('Username must be between 3 and 32 characters')
        if not re.match('^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscore and dash')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Password must be between 8 and 128 characters')
        return v

def FX_HashPassword(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f'{salt.hex()}${key.hex()}'

def FX_VerifyPassword(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, key_hex = stored_hash.split('$')
        salt = bytes.fromhex(salt_hex)
        new_key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        return secrets.compare_digest(new_key.hex(), key_hex)
    except Exception:
        return False

def FX_GetDeviceFingerprint(request: Request) -> str:
    user_agent = request.headers.get('user-agent', '')
    accept_lang = request.headers.get('accept-language', '')
    client_ip = get_remote_address(request)
    fingerprint_raw = f'{user_agent}|{accept_lang}|{client_ip}'
    return hashlib.sha256(fingerprint_raw.encode()).hexdigest()

def FXA_LoadAdmin():
    if ADMIN_FILE.exists():
        try:
            with open(ADMIN_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None

def FXA_SaveAdmin(username: str, password_hash: str):
    DATA_DIR.mkdir(exist_ok=True)
    data = {'username': username, 'password_hash': password_hash, 'created_at': datetime.now().isoformat(), 'user_id': 1}
    with open(ADMIN_FILE, 'w') as f:
        json.dump(data, f)

def FX_LoadSessions():
    if SESSIONS_FILE.exists():
        try:
            with open(SESSIONS_FILE, 'r') as f:
                sessions = json.load(f)
                current_time = datetime.now()
                valid_sessions = {}
                for token, session in sessions.items():
                    expires_at = datetime.fromisoformat(session['expires_at'])
                    if current_time <= expires_at:
                        valid_sessions[token] = session
                if len(valid_sessions) != len(sessions):
                    FX_SaveSessionTokens(valid_sessions)
                return valid_sessions
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def FX_SaveSessionTokens(sessions: dict):
    DATA_DIR.mkdir(exist_ok=True)
    with open(SESSIONS_FILE, 'w') as f:
        json.dump(sessions, f)

def FX_LoadUsers():
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {'users': [], 'next_id': 2}
    return {'users': [], 'next_id': 2}

def FX_SaveUsers(users_data: dict):
    DATA_DIR.mkdir(exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users_data, f)

def FX_CreateSession(username: str, user_id: int, device_fingerprint: str) -> str:
    token = secrets.token_urlsafe(48)
    sessions = FX_LoadSessions()
    sessions[token] = {
        'username': username, 'user_id': user_id, 'device_fingerprint': device_fingerprint, 'created_at': datetime.now().isoformat(), 'expires_at': (datetime.now() + timedelta(hours=12)).isoformat()
        }

    FX_SaveSessionTokens(sessions)
    return token

def FX_TryVerifySession(credentials: Optional[HTTPAuthorizationCredentials], request: Request) -> Optional[dict]:
    if not credentials:
        return None
    sessions = FX_LoadSessions()
    session = sessions.get(credentials.credentials)
    if not session:
        return None
    expires_at = datetime.fromisoformat(session['expires_at'])
    if datetime.now() > expires_at:
        del sessions[credentials.credentials]
        FX_SaveSessionTokens(sessions)
        return None
    current_fingerprint = FX_GetDeviceFingerprint(request)
    if session.get('device_fingerprint') != current_fingerprint:
        del sessions[credentials.credentials]
        FX_SaveSessionTokens(sessions)
        return None
    return session

def FX_Sanitize(file_path: str) -> str:
    file_path = file_path.replace('..', '').replace('//', '/')
    file_path = re.sub('[^\\w./-]', '', file_path)
    return file_path

def FXS_GetUserFiles(user_id: int) -> List[dict]:
    user_dir = FILES_DIR / str(user_id)
    if not user_dir.exists():
        return []

    files = []
    metadata_file = user_dir / 'metadata.json'

    if metadata_file.exists():
        try:
            with open(metadata_file, 'r') as f:
                files = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return files

def FXS_GetAllFiles() -> List[dict]:
    all_files = []
    if not FILES_DIR.exists():
        return all_files
    for user_dir in FILES_DIR.iterdir():
        if user_dir.is_dir():
            try:
                user_id = int(user_dir.name)
                files = FXS_GetUserFiles(user_id)
                for file in files:
                    file['owner_user_id'] = user_id
                all_files.extend(files)
            except ValueError:
                continue
    return all_files

def FXS_SaveUserFiles(user_id: int, files: List[dict]):
    user_dir = FILES_DIR / str(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    metadata_file = user_dir / 'metadata.json'
    with open(metadata_file, 'w') as f:
        json.dump(files, f)

def FXS_ShouldDisplayInline(mime_type: str, file_path: str) -> bool:
    file_ext = Path(file_path).suffix.lower()
    if file_ext in DOWNLOAD_EXTENSIONS:
        return False
    return mime_type in INLINE_DISPLAY_TYPES

@app.get('/admin')
async def FXA_AdminPage(request: Request):
    admin = FXA_LoadAdmin()
    if not admin:
        return FileResponse(ASSETS_DIR / 'setup.html')
    return FileResponse(ASSETS_DIR / 'login.html')

@app.get('/panel')
async def FX_PanelPage(request: Request):
    return FileResponse(ASSETS_DIR / 'panel.html')

@app.get('/5x-content/{file_path:path}')
@limiter.limit('500/minute')
async def FXS_Content(request: Request, file_path: str):
    file_path = FX_Sanitize(file_path)
    full_path = ASSETS_DIR / file_path
    if not full_path.exists() or not full_path.is_file():
        return JSONResponse(status_code=404, content={
            'success': False, 'code': '5xsoftware.invalid_file'
            })
    file_ext = Path(full_path.suffix.lower())
    if file_ext not in ALLOWED_EXTENSIONS:
        return JSONResponse(status_code=403, content={
            'success': False, 'code': '5xsoftware.disallowed_file'
            })
    try:
        full_path.resolve().relative_to(ASSETS_DIR.resolve())
    except ValueError:
        return JSONResponse(status_code=403, content={
            'success': False, 'code': '5xsoftware.disallowed_file'
            })
    media_types = {Path('.js'): 'application/javascript', Path('.css'): 'text/css'}
    return FileResponse(full_path, media_type=media_types.get(file_ext, 'text/plain'))

@app.post('/v1/api/setup')
@limiter.limit('20/minute')
async def FXA_Setup(request: Request, data: FXA_SetupRequest):
    admin = FXA_LoadAdmin()
    if admin:
        return JSONResponse(status_code=400, content={
            'success': False, 'code': '5xsoftware.already_setup'
            })
    try:
        password_hash = FX_HashPassword(data.password)
        FXA_SaveAdmin(data.username, password_hash)
        device_fingerprint = FX_GetDeviceFingerprint(request)
        token = FX_CreateSession(data.username, 1, device_fingerprint)
        return JSONResponse(content={'success': True, 'token': token})
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            'success': False, 'code': '5xsoftware.invalid_credentials'
            })

@app.post('/v1/api/login')
@limiter.limit('20/minute')
async def FX_Login(request: Request, data: FX_LoginRequest):
    admin = FXA_LoadAdmin()
    if not admin:
        return JSONResponse(status_code=400, content={
            'success': False, 'code': '5xsoftware.not_setup'
            })
    try:
        device_fingerprint = FX_GetDeviceFingerprint(request)
        if admin['username'] == data.username and FX_VerifyPassword(data.password, admin['password_hash']):
            token = FX_CreateSession(data.username, 1, device_fingerprint)
            return JSONResponse(content={
                'success': True, 'token': token
                })
        users_data = FX_LoadUsers()
        for user in users_data['users']:
            if user['username'] == data.username and FX_VerifyPassword(data.password, user['password_hash']):
                token = FX_CreateSession(data.username, user['user_id'], device_fingerprint)
                return JSONResponse(content={
                    'success': True, 'token': token
                    })

        return JSONResponse(status_code=401, content={
            'success': False, 'code': '5xsoftware.invalid_credentials'
            })

    except ValueError as e:
        return JSONResponse(status_code=401, content={
            'success': False, 'code': '5xsoftware.invalid_credentials'
            })

@app.get('/v1/api/verify')
async def FX_Verify(request: Request, credentials: HTTPAuthorizationCredentials=Depends(security)):
    session = FX_TryVerifySession(credentials, request)
    if session:
        return JSONResponse(content={
            'success': True, 'code': '5xsoftware.auth.success', 'authenticated': True, 'username': session['username'], 'user_id': session['user_id']
            })

    return JSONResponse(status_code=401, content={'success': False, 'code': '5xsoftware.auth.failed', 'authenticated': False})

@app.post('/v1/api/logout')
async def FX_Logout(request: Request, credentials: HTTPAuthorizationCredentials=Depends(security)):
    if not credentials:
        return JSONResponse(status_code=401, content={
            'success': False, 'code': '5xsoftware.FX_Logout.failed'
            })

    sessions = FX_LoadSessions()
    if credentials.credentials in sessions:
        del sessions[credentials.credentials]
        FX_SaveSessionTokens(sessions)
    return JSONResponse(content={
        'success': True, 'code': '5xsoftware.FX_Logout.success'
        })

@app.get('/v1/api/users')
async def FXA_GetUsers(request: Request, credentials: HTTPAuthorizationCredentials=Depends(security)):
    session = FX_TryVerifySession(credentials, request)
    if not session or session['user_id'] != 1:
        return JSONResponse(status_code=403, content={'success': False, 'code': '5xsoftware.forbidden'})

    users_data = FX_LoadUsers()
    users_list = [{'user_id': u['user_id'], 'username': u['username'], 'created_at': u['created_at']} for u in users_data['users']]
    return JSONResponse(content={'success': True, 'users': users_list})

@app.post('/v1/api/users')
@limiter.limit('20/minute')
async def FXA_CreateUser(request: Request, data: FXA_CreateUserRequest, credentials: HTTPAuthorizationCredentials=Depends(security)):
    session = FX_TryVerifySession(credentials, request)
    if not session or session['user_id'] != 1:
        return JSONResponse(status_code=403, content={'success': False, 'code': '5xsoftware.forbidden'})

    users_data = FX_LoadUsers()
    admin = FXA_LoadAdmin()

    if admin and admin['username'] == data.username:
        return JSONResponse(status_code=400, content={'success': False, 'code': '5xsoftware.username_exists'})

    for user in users_data['users']:
        if user['username'] == data.username:
            return JSONResponse(status_code=400, content={'success': False, 'code': '5xsoftware.username_exists'})

    password_hash = FX_HashPassword(data.password)

    new_user = {'user_id': users_data['next_id'], 'username': data.username, 'password_hash': password_hash, 'created_at': datetime.now().isoformat()}
    users_data['users'].append(new_user)
    users_data['next_id'] += 1

    FX_SaveUsers(users_data)
    return JSONResponse(content={'success': True, 'user': {'user_id': new_user['user_id'], 'username': new_user['username']}})

@app.delete('/v1/api/users/{user_id}')
async def FXA_DeleteUser(request: Request, user_id: int, credentials: HTTPAuthorizationCredentials=Depends(security)):
    session = FX_TryVerifySession(credentials, request)
    if not session or session['user_id'] != 1:
        return JSONResponse(status_code=403, content={'success': False, 'code': '5xsoftware.forbidden'})

    if user_id == 1:
        return JSONResponse(status_code=400, content={'success': False, 'code': '5xsoftware.cannot_delete_admin'})

    users_data = FX_LoadUsers()
    users_data['users'] = [u for u in users_data['users'] if u['user_id'] != user_id]

    FX_SaveUsers(users_data)
    user_dir = FILES_DIR / str(user_id)

    if user_dir.exists():
        shutil.rmtree(user_dir)
    return JSONResponse(content={'success': True})

@app.post('/v1/api/upload')
@limiter.limit('50/minute')
async def FXS_Upload(request: Request, file: UploadFile=File(...), credentials: HTTPAuthorizationCredentials=Depends(security)):
    session = FX_TryVerifySession(credentials, request)
    if not session:
        return JSONResponse(status_code=401, content={'success': False, 'code': '5xsoftware.unauthorized'})
    form_data = await request.form()

    is_private = form_data.get('is_private', 'false').lower() == 'true'

    user_id = session['user_id']
    user_dir = FILES_DIR / str(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)

    file_id = secrets.token_urlsafe(16)
    file_ext = Path(file.filename).suffix
    safe_filename = re.sub('[^\\w.-]', '_', Path(file.filename).name)
    stored_filename = f'{file_id}{file_ext}'
    file_path = user_dir / stored_filename
    total_size = 0

    with open(file_path, 'wb') as f:
        while (chunk := (await file.read(1024 * 1024))):
            total_size += len(chunk)
            f.write(chunk)
    file_token = secrets.token_urlsafe(32) if is_private else None
    file_metadata = {'file_id': file_id, 'original_filename': safe_filename, 'stored_filename': stored_filename, 'size': total_size, 'uploaded_at': datetime.now().isoformat(), 'is_private': is_private, 'token': file_token}
    files = FXS_GetUserFiles(user_id)
    files.append(file_metadata)
    FXS_SaveUserFiles(user_id, files)
    download_url = f'{safe_filename}?id={user_id}'
    if is_private:
        download_url += f'&token={file_token}'
    return JSONResponse(content={'success': True, 'file': file_metadata, 'download_url': download_url})

@app.get('/v1/api/files')
async def FXS_ListFiles(request: Request, credentials: HTTPAuthorizationCredentials=Depends(security)):
    session = FX_TryVerifySession(credentials, request)
    if not session:
        return JSONResponse(status_code=401, content={'success': False, 'code': '5xsoftware.unauthorized'})
    user_id = session['user_id']
    if user_id == 1:
        files = FXS_GetAllFiles()
    else:
        files = FXS_GetUserFiles(user_id)
        for file in files:
            file['owner_user_id'] = user_id
    return JSONResponse(content={'success': True, 'files': files})

@app.delete('/v1/api/files/{file_id}')
async def FXS_DeleteFile(request: Request, file_id: str, credentials: HTTPAuthorizationCredentials=Depends(security)):
    session = FX_TryVerifySession(credentials, request)
    if not session:
        return JSONResponse(status_code=401, content={'success': False, 'code': '5xsoftware.unauthorized'})
    user_id = session['user_id']
    if user_id == 1:
        all_files = FXS_GetAllFiles()
        file_to_delete = None
        owner_id = None
        for f in all_files:
            if f['file_id'] == file_id:
                file_to_delete = f
                owner_id = f.get('owner_user_id')
                break
        if not file_to_delete or owner_id is None:
            return JSONResponse(status_code=404, content={'success': False, 'code': '5xsoftware.file_not_found'})
        user_dir = FILES_DIR / str(owner_id)
        file_path = user_dir / file_to_delete['stored_filename']
        if file_path.exists():
            file_path.unlink()
        files = FXS_GetUserFiles(owner_id)
        files = [f for f in files if f['file_id'] != file_id]
        FXS_SaveUserFiles(owner_id, files)
    else:
        files = FXS_GetUserFiles(user_id)
        file_to_delete = None

        for f in files:
            if f['file_id'] == file_id:
                file_to_delete = f
                break

        if not file_to_delete:
            return JSONResponse(status_code=404, content={'success': False, 'code': '5xsoftware.file_not_found'})

        user_dir = FILES_DIR / str(user_id)
        file_path = user_dir / file_to_delete['stored_filename']

        if file_path.exists():
            file_path.unlink()

        files = [f for f in files if f['file_id'] != file_id]
        FXS_SaveUserFiles(user_id, files)
    return JSONResponse(content={'success': True})

@app.get('/{file_path:path}')
@limiter.limit('500/minute')
async def FXS_Files(request: Request, file_path: str, id: Optional[int]=None, token: Optional[str]=None):
    if id is not None:
        files = FXS_GetUserFiles(id)
        file_metadata = None
        for f in files:
            if f['original_filename'] == file_path:
                file_metadata = f
                break

        if not file_metadata:
            return JSONResponse(status_code=404, content={'success': False, 'code': '5xsoftware.file_not_found'})

        if file_metadata['is_private']:
            if not token or token != file_metadata['token']:
                return JSONResponse(status_code=403, content={'success': False, 'code': '5xsoftware.forbidden'})

        user_dir = FILES_DIR / str(id)
        full_file_path = user_dir / file_metadata['stored_filename']

        if not full_file_path.exists():
            return JSONResponse(status_code=404, content={'success': False, 'code': '5xsoftware.file_not_found'})

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'

        if FXS_ShouldDisplayInline(mime_type, file_path):
            return FileResponse(full_file_path, media_type=mime_type)
        else:
            return FileResponse(full_file_path, media_type=mime_type, filename=file_metadata['original_filename'])

    file_path = FX_Sanitize(file_path)
    full_path = ASSETS_DIR / file_path

    if not full_path.exists() or not full_path.is_file():
        return JSONResponse(status_code=404, content={'success': False, 'code': '5xsoftware.invalid_endpoint'})
    return FileResponse(full_path)

if __name__ == '__main__':
    ASSETS_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    FILES_DIR.mkdir(exist_ok=True)
    uvicorn.run(app, host='0.0.0.0', port=9123, limit_max_requests=None, timeout_keep_alive=300)
