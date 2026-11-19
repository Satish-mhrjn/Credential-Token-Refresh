# Mock Authentication Server

A lightweight FastAPI mock authentication server with a plain HTML/CSS/JavaScript UI.

## Endpoints

- `POST /token` — issues an access token and refresh token.
- `POST /refresh` — validates a refresh token and issues a new access/refresh token pair.
- `GET /access` — protected endpoint; requires `Authorization: Bearer <access-token>`.
- `GET /health` — health check.
- `GET /docs` — interactive API documentation.

## Important behavior: stateless refresh

This project intentionally uses **stateless JWTs** and does not require Redis or a database. `/refresh` returns a new token pair, but the previous refresh token is not revoked. It remains usable until its expiration time. This is suitable for a mock/testing server, but it is not secure one-time-use refresh-token rotation for production authentication.

Expiration values are supplied per request in seconds. Defaults are 60 seconds for access tokens and 604800 seconds (7 days) for refresh tokens. The API accepts values from 1 to 31536000 seconds.

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
3. Add the environment variable `JWT_SECRET` in the Vercel project settings. Use a long, random secret and keep it private.
4. Deploy. The FastAPI application is exposed as `app` in `main.py`.

Do not use the example local secret in a public deployment.
