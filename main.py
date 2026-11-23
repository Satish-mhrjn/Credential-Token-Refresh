import base64
import hashlib
import hmac
import json
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
app = FastAPI(title="Mock Auth Server", version="1.2.0")


class TokenRequest(BaseModel):
    access_token_expires_in: int = Field(default=60, ge=1, le=31536000)
    refresh_token_expires_in: int = Field(default=604800, ge=1, le=31536000)


class RefreshRequest(BaseModel):
    refresh_token: str
    access_token_expires_in: int = Field(default=60, ge=1, le=31536000)
    refresh_token_expires_in: int = Field(default=604800, ge=1, le=31536000)


class ApiKeyRequest(BaseModel):
    # 0 means the generated key does not expire.
    expires_in: int = Field(default=3600, ge=0, le=31536000)


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


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_api_key(expires_in: int) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {"iat": now, "exp": now + expires_in if expires_in else None}
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signed_value = f"sk_test_{encoded_payload}"
    signature = hmac.new(SECRET_KEY.encode(), signed_value.encode(), hashlib.sha256).digest()
    return f"{signed_value}.{_b64url_encode(signature)}"


def validate_api_key(api_key: str) -> None:
    try:
        signed_value, supplied_signature = api_key.rsplit(".", 1)
        if not signed_value.startswith("sk_test_"):
            raise ValueError("Invalid API key prefix")
        encoded_payload = signed_value[len("sk_test_"):]
        expected_signature = hmac.new(
            SECRET_KEY.encode(), signed_value.encode(), hashlib.sha256
        ).digest()
        actual_signature = _b64url_decode(supplied_signature)
        if not hmac.compare_digest(expected_signature, actual_signature):
            raise ValueError("Invalid API key signature")
        payload = json.loads(_b64url_decode(encoded_payload))
        expires_at = payload.get("exp")
        if expires_at is not None and datetime.now(timezone.utc).timestamp() >= expires_at:
            raise HTTPException(status_code=401, detail="API key has expired")
        if not isinstance(payload.get("iat"), int):
            raise ValueError("Invalid API key payload")
    except HTTPException:
        raise
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=401, detail="Invalid API key")


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
    # Stateless mock behavior: the previous refresh JWT remains valid until exp.
    validate_token(request.refresh_token, "refresh")
    access_token = create_token("access", request.access_token_expires_in)
    refresh_token = create_token("refresh", request.refresh_token_expires_in)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "access_token_expires_in": request.access_token_expires_in,
        "refresh_token_expires_in": request.refresh_token_expires_in,
        "refreshToken": [access_token, refresh_token, "bearer", request.access_token_expires_in, request.refresh_token_expires_in],
        "RefreshToken": {
            "access_tokens": {"accessToken": access_token},
            "refreshInfo": {
                "refreshToken": refresh_token,
                "token_type": "bearer",
                "access_token_expires_in": request.access_token_expires_in,
                "refresh_token_expires_in": request.refresh_token_expires_in,
            },
        },
    }


@app.get("/access")
def access(authorization: Annotated[str | None, Header()] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    validate_token(token, "access")
    return {"message": "Access granted", "authenticated": True, "authentication_type": "bearer"}


@app.post("/api-key")
def issue_api_key(request: ApiKeyRequest):
    api_key = create_api_key(request.expires_in)
    return {
        "api_key": api_key,
        "header_name": "X-API-Key",
        "expires_in": request.expires_in,
        "expires_at": (
            (datetime.now(timezone.utc) + timedelta(seconds=request.expires_in)).isoformat()
            if request.expires_in
            else None
        ),
    }


@app.get("/api-key/protected")
def api_key_protected(x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    validate_api_key(x_api_key)
    return {"message": "API key accepted", "authenticated": True, "authentication_type": "api_key"}
