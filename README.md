# Mock Authentication Server

A lightweight FastAPI mock authentication server with a plain HTML/CSS/JavaScript UI. It supports JWT bearer tokens and signed API keys without requiring a database or Redis.

## Endpoints

| Method | Endpoint | Purpose | Authentication |
|---|---|---|---|
| `POST` | `/token` | Issue an access token and refresh token | None |
| `POST` | `/refresh` | Validate a refresh token and issue a new token pair | Refresh token in JSON body |
| `GET` | `/access` | Protected resource for bearer-token testing | `Authorization: Bearer <access-token>` |
| `POST` | `/api-key` | Generate a signed API key | None |
| `GET` | `/api-key/protected` | Protected resource for API-key testing | `X-API-Key: <api-key>` |
| `GET` | `/health` | Health check | None |
| `GET` | `/docs` | Interactive API documentation | None |

## JWT behavior

`POST /token` accepts expiration values in seconds. Defaults are 60 seconds for access tokens and 604800 seconds (7 days) for refresh tokens. Values must be from 1 to 31536000 seconds.

`POST /refresh` accepts a refresh JWT and returns a new access/refresh pair. This is intentionally stateless: the old refresh JWT is not revoked and remains usable until it expires. This is suitable for a mock/testing server, not production-grade one-time-use refresh-token rotation.

Example request:

```json
{
  "refresh_token": "<refresh-token>",
  "access_token_expires_in": 60,
  "refresh_token_expires_in": 604800
}
```

## API key behavior

`POST /api-key` accepts `expires_in` in seconds. The default is 3600 seconds. Set it to `0` for a key that never expires. The endpoint returns the key, header name, expiry duration, and expiry timestamp (or `null` for no expiry).

Example request:

```json
{ "expires_in": 3600 }
```

Example response shape:

```json
{
  "api_key": "sk_test_<signed-value>",
  "header_name": "X-API-Key",
  "expires_in": 3600,
  "expires_at": "<UTC timestamp>"
}
```

Use the generated key like this:

```http
GET /api-key/protected
X-API-Key: sk_test_<signed-value>
```

A missing, malformed, tampered, or expired key returns `401 Unauthorized`. Keys are signed using `JWT_SECRET`, so they can be validated without storing them in a database. Consequently, they cannot be individually revoked before expiry. Changing `JWT_SECRET` invalidates all previously issued JWTs and API keys.

## Run locally (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:JWT_SECRET = "replace-this-with-a-long-random-local-secret"
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000` or `http://127.0.0.1:8000/docs`.

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Deploy to Vercel

1. Push this project to a Git repository.
2. Import the repository into Vercel.
3. Add `JWT_SECRET` in the Vercel project settings. Use a long, random secret and keep it private.
4. Deploy. The FastAPI application is exposed as `app` in `main.py`.

Do not use the example local secret in a public deployment.
