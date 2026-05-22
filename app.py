#!/usr/bin/env python3
"""
VulnDemo - A deliberately vulnerable web application for security education.
Each vulnerability has a vulnerable mode and a protected mode, toggled via ?mode=vulnerable or ?mode=secure.
"""

import sqlite3
import os
import subprocess
import pickle
import base64
import re
import html
import xml.etree.ElementTree as ET
import shlex
import json
from io import StringIO
from urllib.parse import urlparse
from functools import wraps

import flask
from flask import (
    Flask, request, render_template, render_template_string,
    redirect, url_for, session, make_response, g, jsonify
)

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE = os.path.join(os.path.dirname(__file__), "vulndemo.db")
ALLOWED_REDIRECT_HOSTS = {"localhost", "127.0.0.1", "example.com"}
ALLOWED_SSRF_HOSTS = {"httpbin.org", "example.com"}
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            bio TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            author TEXT,
            body TEXT,
            FOREIGN KEY(post_id) REFERENCES posts(id)
        );
        DELETE FROM users;
        DELETE FROM posts;
        DELETE FROM comments;
        INSERT INTO users (username, password, role, bio) VALUES ('admin', 'admin123', 'admin', 'I am the admin');
        INSERT INTO users (username, password, role, bio) VALUES ('alice', 'password1', 'user', 'Alice bio');
        INSERT INTO users (username, password, role, bio) VALUES ('bob', 'password2', 'user', 'Bob bio');
        INSERT INTO posts (user_id, title, content) VALUES (1, 'Welcome', 'Welcome to the platform');
        INSERT INTO posts (user_id, title, content) VALUES (2, 'Alice Post', 'Content by alice');
        INSERT INTO comments (post_id, author, body) VALUES (1, 'guest', 'Nice site!');
    """)
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

# ---------------------------------------------------------------------------
# Mode toggle helper
# ---------------------------------------------------------------------------
def is_vulnerable():
    return request.args.get("mode", "vulnerable") == "vulnerable"

def mode_label():
    return "VULNERABLE" if is_vulnerable() else "SECURE"

# ---------------------------------------------------------------------------
# Defensive middleware: Security Headers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https:; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if not is_vulnerable():
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# ---------------------------------------------------------------------------
# Rate limiter (simple per-IP)
# ---------------------------------------------------------------------------
RATE_LIMITS = {}
def rate_limit(max_requests=30, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            now = __import__("time").time()
            RATE_LIMITS.setdefault(ip, [])
            RATE_LIMITS[ip] = [t for t in RATE_LIMITS[ip] if now - t < window]
            if len(RATE_LIMITS[ip]) >= max_requests:
                return "Rate limit exceeded", 429
            RATE_LIMITS[ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------------------------------------------------------
# Login required decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

# ---------------------------------------------------------------------------
# Routes - Home
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", mode=mode_label())

# ===========================================================================
# 1. SQL INJECTION
# ===========================================================================
@app.route("/sql-injection", methods=["GET", "POST"])
def sql_injection():
    result = None
    error = None
    query = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if is_vulnerable():
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            conn = get_db()
            try:
                result = conn.execute(query).fetchall()
                result = [dict(r) for r in result]
            except Exception as e:
                error = str(e)
        else:
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            conn = get_db()
            try:
                result = conn.execute(query, (username, password)).fetchall()
                result = [dict(r) for r in result]
            except Exception as e:
                error = str(e)
    return render_template("sql_injection.html", result=result, error=error, query=query, mode=mode_label())

# ===========================================================================
# 2. XSS - Reflected
# ===========================================================================
@app.route("/xss-reflected", methods=["GET", "POST"])
def xss_reflected():
    output = None
    if request.method == "POST":
        user_input = request.form.get("input", "")
        if is_vulnerable():
            output = user_input
        else:
            output = html.escape(user_input)
    return render_template("xss_reflected.html", output=output, mode=mode_label())

# ---------------------------------------------------------------------------
# 2b. XSS - Stored (comments)
# ---------------------------------------------------------------------------
@app.route("/xss-stored", methods=["GET", "POST"])
def xss_stored():
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        body = request.form.get("body", "")
        conn = get_db()
        conn.execute("INSERT INTO comments (post_id, author, body) VALUES (1, ?, ?)", (author, body))
        conn.commit()
    conn = get_db()
    comments = conn.execute("SELECT author, body FROM comments WHERE post_id=1").fetchall()
    if is_vulnerable():
        rendered_comments = [(c["author"], c["body"]) for c in comments]
    else:
        rendered_comments = [(html.escape(c["author"]), html.escape(c["body"])) for c in comments]
    return render_template("xss_stored.html", comments=rendered_comments, mode=mode_label())

# ---------------------------------------------------------------------------
# 2c. XSS - DOM-based (client-side only, server provides the template)
# ---------------------------------------------------------------------------
@app.route("/xss-dom")
def xss_dom():
    return render_template("xss_dom.html", mode=mode_label())

# ===========================================================================
# 3. COMMAND INJECTION
# ===========================================================================
@app.route("/command-injection", methods=["GET", "POST"])
def command_injection():
    output = None
    error = None
    cmd = None
    if request.method == "POST":
        host = request.form.get("host", "127.0.0.1")
        if is_vulnerable():
            cmd = f"ping -c 1 {host}"
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode()
            except Exception as e:
                error = str(e)
        else:
            if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
                error = "Invalid hostname"
            else:
                cmd = ["ping", "-c", "1", host]
                try:
                    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5).decode()
                except Exception as e:
                    error = str(e)
    return render_template("command_injection.html", output=output, error=error, cmd=cmd, mode=mode_label())

# ===========================================================================
# 4. PATH TRAVERSAL
# ===========================================================================
@app.route("/path-traversal", methods=["GET", "POST"])
def path_traversal():
    content = None
    error = None
    filenames = ["notes.txt", "config.txt", "welcome.txt"]
    for fn in filenames:
        path = os.path.join(UPLOAD_DIR, fn)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(f"This is the contents of {fn}\n")
    if request.method == "POST":
        filename = request.form.get("filename", "")
        if is_vulnerable():
            target = os.path.join(UPLOAD_DIR, filename)
            try:
                with open(target) as f:
                    content = f.read()
            except Exception as e:
                error = str(e)
        else:
            safe_name = os.path.basename(filename)
            target = os.path.join(UPLOAD_DIR, safe_name)
            real_target = os.path.realpath(target)
            if not real_target.startswith(os.path.realpath(UPLOAD_DIR)):
                error = "Path traversal detected!"
            else:
                try:
                    with open(target) as f:
                        content = f.read()
                except Exception as e:
                    error = str(e)
    return render_template("path_traversal.html", content=content, error=error, mode=mode_label())

# ===========================================================================
# 5. CSRF
# ===========================================================================
@app.route("/csrf", methods=["GET", "POST"])
@login_required
def csrf():
    message = None
    if request.method == "POST":
        amount = request.form.get("amount", "0")
        to_user = request.form.get("to", "")
        if is_vulnerable():
            conn = get_db()
            conn.execute("UPDATE users SET bio = bio || ' TRANSFER: ' || ? || ' to ' || ? WHERE id = ?",
                         (amount, to_user, session["user_id"]))
            conn.commit()
            message = f"Transferred ${amount} to {to_user}"
        else:
            token = request.form.get("csrf_token", "")
            if token != session.get("csrf_token"):
                message = "CSRF token invalid!"
            else:
                conn = get_db()
                conn.execute("UPDATE users SET bio = bio || ' TRANSFER: ' || ? || ' to ' || ? WHERE id = ?",
                             (amount, to_user, session["user_id"]))
                conn.commit()
                message = f"Transferred ${amount} to {to_user} (secure)"
    if not is_vulnerable() and "csrf_token" not in session:
        session["csrf_token"] = os.urandom(32).hex()
    return render_template("csrf.html", message=message, mode=mode_label(),
                           csrf_token=session.get("csrf_token", ""))

# ===========================================================================
# 6. SSRF
# ===========================================================================
@app.route("/ssrf", methods=["GET", "POST"])
def ssrf():
    content = None
    error = None
    if request.method == "POST":
        url = request.form.get("url", "")
        if is_vulnerable():
            try:
                import requests as req
                resp = req.get(url, timeout=5)
                content = resp.text[:2000]
            except Exception as e:
                error = str(e)
        else:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            allowed = any(hostname.endswith("." + h) or hostname == h for h in ALLOWED_SSRF_HOSTS)
            if not allowed:
                error = f"URL not allowed (host: {hostname})"
            else:
                try:
                    import requests as req
                    resp = req.get(url, timeout=5)
                    content = resp.text[:2000]
                except Exception as e:
                    error = str(e)
    return render_template("ssrf.html", content=content, error=error, mode=mode_label())

# ===========================================================================
# 7. IDOR (Insecure Direct Object Reference)
# ===========================================================================
@app.route("/idor")
@login_required
def idor():
    profile_id = request.args.get("user_id", session.get("user_id", 1))
    conn = get_db()
    user = conn.execute("SELECT id, username, role, bio FROM users WHERE id = ?", (profile_id,)).fetchone()
    if not is_vulnerable() and int(profile_id) != session["user_id"]:
        return "Unauthorized: you can only view your own profile", 403
    return render_template("idor.html", user=dict(user) if user else None, mode=mode_label())

# ===========================================================================
# 8. XXE (XML External Entities)
# ===========================================================================
@app.route("/xxe", methods=["GET", "POST"])
def xxe():
    result = None
    error = None
    if request.method == "POST":
        xml_data = request.form.get("xml", "")
        if is_vulnerable():
            try:
                tree = ET.parse(StringIO(xml_data))
                root = tree.getroot()
                result = ET.tostring(root, encoding="unicode")
            except Exception as e:
                error = str(e)
        else:
            parser = ET.XMLParser()
            parser.parser.entity = {}
            try:
                tree = ET.parse(StringIO(xml_data), parser=parser)
                root = tree.getroot()
                result = ET.tostring(root, encoding="unicode")
            except Exception as e:
                error = str(e)
    return render_template("xxe.html", result=result, error=error, mode=mode_label())

# ===========================================================================
# 9. SSTI (Server-Side Template Injection)
# ===========================================================================
@app.route("/ssti", methods=["GET", "POST"])
def ssti():
    output = None
    error = None
    if request.method == "POST":
        template = request.form.get("template", "Hello {{ name }}")
        name = request.form.get("name", "World")
        if is_vulnerable():
            try:
                output = render_template_string(template.replace("{{ name }}", name))
            except Exception as e:
                error = str(e)
        else:
            safe_template = "Hello {{ name }}"
            try:
                output = render_template_string(safe_template, name=html.escape(name))
            except Exception as e:
                error = str(e)
    return render_template("ssti.html", output=output, error=error, mode=mode_label())

# ===========================================================================
# 10. BROKEN AUTHENTICATION
# ===========================================================================
@app.route("/broken-auth", methods=["GET", "POST"])
def broken_auth():
    message = None
    if request.method == "POST":
        action = request.form.get("action", "login")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        if action == "login":
            if is_vulnerable():
                user = conn.execute(
                    f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                ).fetchone()
            else:
                user = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND password = ?",
                    (username, password)
                ).fetchone()
            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                if is_vulnerable():
                    pass
                else:
                    session.permanent = True
                    app.permanent_session_lifetime = __import__("datetime").timedelta(minutes=30)
                message = f"Logged in as {user['username']}"
            else:
                message = "Invalid credentials"
        elif action == "register":
            if is_vulnerable():
                try:
                    conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
                    conn.commit()
                    message = "Registered (vulnerable)"
                except Exception as e:
                    message = str(e)
            else:
                if len(password) < 8:
                    message = "Password must be at least 8 characters"
                elif not re.search(r'[A-Z]', password):
                    message = "Password must contain an uppercase letter"
                elif not re.search(r'[0-9]', password):
                    message = "Password must contain a digit"
                else:
                    try:
                        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                                     (username, password))
                        conn.commit()
                        message = "Registered (secure)"
                    except Exception as e:
                        message = str(e)
    return render_template("broken_auth.html", message=message, mode=mode_label())

# ===========================================================================
# 11. UNVALIDATED REDIRECT
# ===========================================================================
@app.route("/redirect")
def unvalidated_redirect():
    target = request.args.get("url", "/")
    if is_vulnerable():
        return redirect(target)
    else:
        parsed = urlparse(target)
        if parsed.hostname is None or parsed.hostname in ALLOWED_REDIRECT_HOSTS:
            return redirect(target)
        return "Redirect target not allowed", 400

# ===========================================================================
# 12. INSECURE DESERIALIZATION (Pickle)
# ===========================================================================
@app.route("/deserialize", methods=["GET", "POST"])
def insecure_deserialization():
    result = None
    error = None
    if request.method == "POST":
        data = request.form.get("data", "")
        if is_vulnerable():
            try:
                obj = pickle.loads(base64.b64decode(data))
                result = f"Deserialized: {obj}"
            except Exception as e:
                error = str(e)
        else:
            try:
                obj = json.loads(base64.b64decode(data).decode())
                result = f"Deserialized (JSON): {obj}"
            except Exception as e:
                error = str(e)
    return render_template("deserialize.html", result=result, error=error, mode=mode_label())

# ===========================================================================
# Login/Logout for the demo
# ===========================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                            (username, password)).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(request.args.get("next", "/"))
        return "Login failed", 401
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("  VulnDemo - Security Education Platform")
    print("  Default mode: VULNERABLE")
    print("  Add ?mode=secure to any page for the secure version")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
