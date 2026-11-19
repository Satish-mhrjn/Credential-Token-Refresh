import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("Set the JWT_SECRET environment variable before starting the server.")

ALGORITHM = "HS256"
app = FastAPI(title="Mock Auth Server", version="1.1.0")


class TokenRequest(BaseModel):
    access_token_expires_in: int = Field(default=60, ge=1, le=31536000)
    refresh_token_expires_in: int = Field(default=604800, ge=1, le=31536000)


class RefreshRequest(BaseModel):
    refresh_token: str
    access_token_expires_in: int = Field(default=60, ge=1, le=31536000)
    refresh_token_expires_in: int = Field(default=604800, ge=1, le=31536000)


def create_token(token_type: str, expires_in: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "token_type": token_type,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def validate_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("token_type") != expected_type:
        raise HTTPException(status_code=401, detail=f"Invalid {expected_type} token")
    return payload


@app.get("/")
def home():
    return FileResponse("index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/token")
def issue_tokens(request: TokenRequest):
    access_token = create_token("access", request.access_token_expires_in)
    refresh_token = create_token("refresh", request.refresh_token_expires_in)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "access_token_expires_in": request.access_token_expires_in,
        "refresh_token_expires_in": request.refresh_token_expires_in,
    }


@app.post("/refresh")
def refresh_tokens(request: RefreshRequest):
    # Stateless mock behavior: validate the supplied refresh token, then issue
    # a fresh pair. The previous refresh JWT is NOT revoked and remains usable
    # until its own exp time.
    validate_token(request.refresh_token, "refresh")
    access_token = create_token("access", request.access_token_expires_in)
    refresh_token = create_token("refresh", request.refresh_token_expires_in)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "access_token_expires_in": request.access_token_expires_in,
        "refresh_token_expires_in": request.refresh_token_expires_in,
        "refreshToken": [access_token ,refresh_token, "bearer", request.access_token_expires_in, request.refresh_token_expires_in ],
        "RefreshToken": {"access_tokens": {"accessToken": access_token},
                         "refreshInfo": {"refreshToken": refresh_token, "token_type": "bearer", "access_token_expires_in": request.access_token_expires_in, "refresh_token_expires_in":request.refresh_token_expires_in}
                        }
    }


@app.get("/access")
def access(authorization: Annotated[str | None, Header()] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    validate_token(token, "access")
    return {"message": "Access granted", "authenticated": True}
