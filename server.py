from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

app = FastAPI()


# Settings bru bru
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
ASSETS_DIR = Path(__file__).parent / Path("assets")
ALLOWED_EXTENSIONS = frozenset([Path(".js"), Path(".css")])


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
    uvicorn.run(app, host="0.0.0.0", port=9123)