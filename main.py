
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError(
        "Set the JWT_SECRET environment variable before starting the server."
    )

ALGORITHM = "HS256"

app = FastAPI(title="Mock Auth Server", version="1.4.0")

# One active API key per running process.
active_api_key: dict | None = None


# --------------------------------------------------
# Request models
# --------------------------------------------------

class TokenRequest(BaseModel):
    access_token_expires_in: int = Field(default=60, ge=1, le=31536000)
    refresh_token_expires_in: int = Field(default=604800, ge=1, le=31536000)


class RefreshRequest(BaseModel):
    refresh_token: str
    access_token_expires_in: int = Field(default=60, ge=1, le=31536000)
    refresh_token_expires_in: int = Field(default=604800, ge=1, le=31536000)


class ApiKeyRequest(BaseModel):
    # 0 means the API key never expires.
    expires_in: int = Field(default=3600, ge=0, le=31536000)

    # API key refresh token expiry.
    refresh_token_expires_in: int = Field(
        default=604800, ge=1, le=31536000
    )

    header_name: str = Field(
        default="X-API-Key",
        min_length=1,
        max_length=100
    )


class ApiKeyRefreshRequest(BaseModel):
    refresh_token: str

    # 0 means the replacement API key never expires.
    expires_in: int = Field(default=3600, ge=0, le=31536000)

    refresh_token_expires_in: int = Field(
        default=604800, ge=1, le=31536000
    )


# --------------------------------------------------
# JWT utilities
# --------------------------------------------------

def create_token(
    token_type: str,
    expires_in: int,
    extra_claims: dict | None = None
) -> str:

    now = datetime.now(timezone.utc)

    payload = {
        "token_type": token_type,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def validate_token(token: str, expected_type: str) -> dict:

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    if payload.get("token_type") != expected_type:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid {expected_type} token"
        )

    return payload


# --------------------------------------------------
# API key utilities
# --------------------------------------------------

def validate_header_name(header_name: str) -> str:

    # RFC 9110 HTTP header token characters.
    if not re.fullmatch(
        r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",
        header_name
    ):
        raise HTTPException(
            status_code=422,
            detail="Invalid HTTP header name"
        )

    return header_name


def create_api_key() -> str:
    return "sk_test_" + secrets.token_urlsafe(32)


def api_key_digest(api_key: str) -> str:
    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


def generate_api_key_pair(
    header_name: str,
    api_key_expires_in: int,
    refresh_token_expires_in: int
):

    global active_api_key

    now = datetime.now(timezone.utc)

    expires_at = (
        now + timedelta(seconds=api_key_expires_in)
        if api_key_expires_in
        else None
    )

    api_key = create_api_key()

    refresh_token = create_token(
        "api_key_refresh",
        refresh_token_expires_in,
        {
            "header_name": header_name,
        }
    )

    # Replace the previous API key immediately.
    active_api_key = {
        "digest": api_key_digest(api_key),
        "header_name": header_name,
        "expires_at": expires_at,
    }

    return {
        "api_key": api_key,
        "refresh_token": refresh_token,
        "header_name": header_name,
        "expires_in": api_key_expires_in,
        "refresh_token_expires_in": refresh_token_expires_in,
        "expires_at": (
            expires_at.isoformat()
            if expires_at
            else None
        ),
        "rotation_behavior": "previous_key_invalidated_immediately",
    }


# --------------------------------------------------
# General endpoints
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse("index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


# --------------------------------------------------
# Bearer JWT authentication
# --------------------------------------------------

@app.post("/token")
def issue_tokens(request: TokenRequest):

    access_token = create_token(
        "access",
        request.access_token_expires_in
    )

    refresh_token = create_token(
        "refresh",
        request.refresh_token_expires_in
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "access_token_expires_in": request.access_token_expires_in,
        "refresh_token_expires_in": request.refresh_token_expires_in,
    }


@app.post("/refresh")
def refresh_tokens(request: RefreshRequest):

    validate_token(
        request.refresh_token,
        "refresh"
    )

    access_token = create_token(
        "access",
        request.access_token_expires_in
    )

    refresh_token = create_token(
        "refresh",
        request.refresh_token_expires_in
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "access_token_expires_in": request.access_token_expires_in,
        "refresh_token_expires_in": request.refresh_token_expires_in,
    }


@app.get("/access")
def access(
    authorization: Annotated[str | None, Header()] = None
):

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header"
        )

    token = authorization.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing bearer token"
        )

    validate_token(token, "access")

    return {
        "message": "Access granted",
        "authenticated": True,
        "authentication_type": "bearer"
    }


# --------------------------------------------------
# API key authentication
# --------------------------------------------------

@app.post("/api-key")
def issue_api_key(request: ApiKeyRequest):

    header_name = validate_header_name(
        request.header_name
    )

    return generate_api_key_pair(
        header_name=header_name,
        api_key_expires_in=request.expires_in,
        refresh_token_expires_in=request.refresh_token_expires_in
    )


@app.post("/api-key/refresh")
def refresh_api_key(request: ApiKeyRefreshRequest):

    # Only API-key refresh tokens are accepted here.
    payload = validate_token(
        request.refresh_token,
        "api_key_refresh"
    )

    header_name = validate_header_name(
        payload.get("header_name", "")
    )

    return generate_api_key_pair(
        header_name=header_name,
        api_key_expires_in=request.expires_in,
        refresh_token_expires_in=request.refresh_token_expires_in
    )


@app.get("/api-key/protected")
def api_key_protected(request: Request):

    if active_api_key is None:
        raise HTTPException(
            status_code=401,
            detail="No API key has been generated"
        )

    header_name = active_api_key["header_name"]

    supplied_key = request.headers.get(header_name)

    if not supplied_key:
        raise HTTPException(
            status_code=401,
            detail=f"Missing {header_name} header"
        )

    expires_at = active_api_key["expires_at"]

    if (
        expires_at is not None
        and datetime.now(timezone.utc) >= expires_at
    ):
        raise HTTPException(
            status_code=401,
            detail="API key has expired"
        )

    supplied_digest = api_key_digest(supplied_key)

    if not hmac.compare_digest(
        active_api_key["digest"],
        supplied_digest
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    return {
        "message": "API key accepted",
        "authenticated": True,
        "authentication_type": "api_key",
        "header_name": header_name
    }
