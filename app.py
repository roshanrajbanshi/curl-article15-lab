import os
import jwt
import secrets
import datetime
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flasgger import Swagger

app = Flask(__name__)
app.config['SECRET_KEY'] = 'lab-static-secret-do-not-use-in-prod'
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

swagger = Swagger(app)

# ---- fake user "database" ----
USERS = {
    1: {"id": 1, "username": "admin",   "password": "admin",        "role": "admin", "email": "admin@flask-app.lab"},
    2: {"id": 2, "username": "j.doe",   "password": "password123",  "role": "user",  "email": "j.doe@flask-app.lab"},
    3: {"id": 3, "username": "m.smith", "password": "password123",  "role": "user",  "email": "m.smith@flask-app.lab"},
    4: {"id": 4, "username": "a.khan",  "password": "password123",  "role": "user",  "email": "a.khan@flask-app.lab"},
}
USERS_BY_NAME = {u["username"]: u for u in USERS.values()}

# single static CSRF token for lab simplicity (extractable + reusable, as the article needs)
CSRF_TOKEN = "csrf_lab_static_8f3ac9"

# session cookie -> username, for the CSRF-protected profile flow
SESSIONS = {}


def issue_jwt(user):
    payload = {
        "username": user["username"],
        "role": user["role"],
        "id": user["id"],
        # intentionally no 'exp' enforced server-side (weak claim design)
        "iat": datetime.datetime.utcnow().timestamp(),
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")


def get_token_from_header():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1]
    return None


def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except Exception:
        return None


@app.route("/")
def index():
    return jsonify({"app": "flask-app.lab", "status": "ok"})


@app.route("/api/v1/login", methods=["POST"])
def login():
    """
    Login with username/password, returns a JWT.
    ---
    parameters:
      - name: body
        in: body
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: JWT token
      401:
        description: Invalid credentials
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    user = USERS_BY_NAME.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401

    token = issue_jwt(user)

    # also set a session cookie, for the CSRF profile-edit flow
    sid = secrets.token_hex(16)
    SESSIONS[sid] = username
    resp = make_response(jsonify({"token": token}))
    resp.set_cookie("session", sid)
    return resp


@app.route("/api/v1/users/me", methods=["GET"])
def users_me():
    token = get_token_from_header()
    claims = decode_token(token) if token else None
    if not claims:
        return jsonify({"error": "unauthorized"}), 401
    user = USERS.get(claims["id"])
    return jsonify({k: v for k, v in user.items() if k != "password"})


@app.route("/api/v1/users/<int:uid>", methods=["GET"])
def users_by_id(uid):
    """
    Get a user by ID. VULNERABLE: no ownership check (IDOR).
    ---
    parameters:
      - name: uid
        in: path
        type: integer
    responses:
      200:
        description: user object
      401:
        description: unauthorized
      404:
        description: not found
    """
    token = get_token_from_header()
    claims = decode_token(token) if token else None
    if not claims:
        return jsonify({"error": "unauthorized"}), 401
    user = USERS.get(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    # BUG: does not check claims["id"] == uid
    return jsonify({k: v for k, v in user.items() if k != "password"})


@app.route("/api/admin", methods=["GET"])
def admin_endpoint():
    """
    Admin-only data. VULNERABLE: only checks token presence, not role claim.
    ---
    responses:
      200:
        description: admin data
      401:
        description: unauthorized
    """
    token = get_token_from_header()
    claims = decode_token(token) if token else None
    if not claims:
        return jsonify({"error": "unauthorized"}), 401
    # BUG: should check claims["role"] == "admin" and does not
    return jsonify({
        "secret": "internal admin panel data",
        "all_users": [{"id": u["id"], "username": u["username"], "email": u["email"]} for u in USERS.values()]
    })


@app.route("/profile", methods=["GET"])
def profile():
    sid = request.cookies.get("session")
    username = SESSIONS.get(sid)
    if not username:
        return "Unauthorized", 401
    user = USERS_BY_NAME[username]
    html = f"""
    <html><body>
    <h3>Edit profile for {user['username']}</h3>
    <form action="/profile/edit" method="POST">
      <input type="hidden" name="csrf_token" value="{CSRF_TOKEN}">
      <input type="text" name="email" value="{user['email']}">
      <input type="submit">
    </form>
    </body></html>
    """
    return html


@app.route("/profile/edit", methods=["POST"])
def profile_edit():
    sid = request.cookies.get("session")
    username = SESSIONS.get(sid)
    if not username:
        return "Unauthorized", 401
    token = request.form.get("csrf_token")
    if token != CSRF_TOKEN:
        return jsonify({"error": "invalid csrf token"}), 403
    new_email = request.form.get("email")
    USERS_BY_NAME[username]["email"] = new_email
    return jsonify({"status": "updated", "email": new_email})


@app.route("/upload", methods=["POST"])
def upload():
    """
    File upload. VULNERABLE: validates by Content-Type only, not real content/extension.
    ---
    responses:
      200:
        description: upload accepted
      400:
        description: upload rejected
    """
    token = get_token_from_header()
    claims = decode_token(token) if token else None
    if not claims:
        return jsonify({"error": "unauthorized"}), 401

    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400

    f = request.files["file"]
    content_type = f.content_type or ""

    # BUG: only checks Content-Type header (attacker-controlled), not real extension/magic bytes
    allowed = ["image/jpeg", "image/png", "text/plain"]
    if content_type not in allowed:
        return jsonify({"error": f"content-type '{content_type}' not allowed"}), 400

    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)
    return jsonify({"status": "uploaded", "filename": f.filename, "content_type": content_type})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
