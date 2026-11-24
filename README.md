# Mock Authentication Server

A lightweight FastAPI mock authentication server with a plain HTML/CSS/JavaScript UI. It supports JWT bearer tokens and generated API keys without a database, Redis, or other external infrastructure.

## Endpoints

| Method | Endpoint | Purpose | Authentication |
|---|---|---|---|
| `POST` | `/token` | Issue an access token and refresh token | None |
| `POST` | `/refresh` | Validate a refresh token and issue a new token pair | Refresh token in JSON body |
| `GET` | `/access` | Protected resource for bearer-token testing | `Authorization: Bearer <access-token>` |
| `POST` | `/api-key` | Generate or rotate the active API key | None |
| `GET` | `/api-key/protected` | Protected resource for API-key testing | Configured API-key header |
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

- The server generates the API key; the client does not choose its value.
- You can configure the HTTP header name (default: `X-API-Key`). Header names are case-insensitive and must be valid HTTP token characters.
- `expires_in` is measured in seconds. The default is 3600. Set it to `0` for a key that does not expire.
- Only one API key is active at a time. Generating another key immediately replaces the previous key; there is no grace period or manual revocation endpoint.
- The API key is random and its SHA-256 digest is kept in process memory. The raw key is returned only when generated.

Example request:

```json
{
  "expires_in": 3600,
  "header_name": "X-Client-Key"
}
```

Example response shape:

```json
{
  "api_key": "sk_test_<random-value>",
  "header_name": "X-Client-Key",
  "expires_in": 3600,
  "expires_at": "<UTC timestamp>"
}
```

Use the generated key like this:

```http
GET /api-key/protected
X-Client-Key: sk_test_<random-value>
```

A missing, incorrect, or expired key returns `401 Unauthorized`. A new key invalidates the previous key immediately.

### In-memory limitation

The active API key is stored only in the running Python process. Restarting the server clears it, so generate a new key after a restart. This is reliable for local testing with one server process. It is not reliable on Vercel/serverless or multi-worker deployments: requests may reach different instances, and each instance can have separate or reset memory. No persistence or cross-instance synchronization is provided by this project.

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

The JWT endpoints are stateless and are suitable for serverless execution. The in-memory API-key lifecycle is not reliable across serverless instances; use the API-key feature locally or on a single persistent process if you need consistent rotation and validation.

Do not use the example local secret in a public deployment.
