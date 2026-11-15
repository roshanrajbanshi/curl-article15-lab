# curl-article15-lab

A deliberately vulnerable Flask application built to accompany "Full Chain: Recon to Report with Nothing But curl" — the capstone article of the *curl — The Request Engine You Never Learned Properly* series. It bundles five common real-world web app flaws into one target so you can practice a full recon → auth → attack → evasion → documentation workflow using nothing but curl, bash, and jq.

## How it works

- Flask app with JWT-based login (HS256, intentionally no `exp` claim)
- Broken role-based access control on `/api/admin` — checks token validity, not the `role` claim
- IDOR on `/api/v1/users/{id}` — no ownership check against the authenticated user
- File upload endpoint that validates only the client-supplied `Content-Type` header, not the real extension or file content
- Static, non-session-bound CSRF token on the `/profile` edit flow
- Auto-generated Swagger spec (Flasgger) at `/apispec_1.json`
- Self-signed TLS certificate served alongside plain HTTP

Every bug here is intentional and documented in the article step by step, with real curl commands and real output.

## Usage

```bash
git clone https://github.com/roshanrajbanshi/curl-article15-lab.git
cd curl-article15-lab
docker compose up --build -d
echo "127.0.0.1 flask-app.lab" | sudo tee -a /etc/hosts
```

- HTTP: `http://flask-app.lab:8015`
- HTTPS: `https://flask-app.lab:8443` (self-signed cert — use `-k` with curl)

Seeded accounts (all passwords in plaintext for lab purposes only):

| username | password | role |
|---|---|---|
| admin | admin | admin |
| j.doe | password123 | user |
| m.smith | password123 | user |
| a.khan | password123 | user |

## Files

- `app.py` — the Flask application with all five vulnerable endpoints
- `Dockerfile` — builds the container and generates a self-signed TLS cert at build time
- `requirements.txt` — Python dependencies (Flask, PyJWT, Flasgger, gunicorn)
- `docker-compose.yml` — maps HTTP to host port 8015 and HTTPS to host port 8443

## Disclaimer

For lab and educational use only. Do not deploy this application outside an isolated environment — every endpoint is deliberately insecure. Only test targets you own or are explicitly authorized to test.

## License

MIT — see [LICENSE](LICENSE)
