"""
!!! INTENTIONALLY VULNERABLE APPLICATION — DO NOT DEPLOY !!!

This tiny Flask app exists only to give the security pipeline in this repo
something real to find. Every flaw is deliberate and labelled with the CWE it
represents. See README.md for which scanner catches which issue.
"""
import base64
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, g, jsonify, render_template_string, request

app = Flask(__name__)

# CWE-798: hard-coded secrets (caught by Opengrep rule + Gitleaks)
app.config["SECRET_KEY"] = "s3cr3t-flask-key-for-demo-only"
PAYMENTS_API_KEY = "Xq7vT2mK9pL4wR8nZ3cF6hJ1bY5dG0sA"

DB_PATH = "/tmp/demo.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)"
        )
        g.db.execute(
            "INSERT OR IGNORE INTO users VALUES (1, 'alice', 'admin'), (2, 'bob', 'user')"
        )
        g.db.commit()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return (
        "<h1>AppSec pipeline demo</h1>"
        "<p>Intentionally vulnerable. Endpoints: /user?id=1, /ping?host=127.0.0.1, "
        "/fetch?url=https://example.com, /hello?name=world, POST /import, POST /restore, /health</p>"
    )


@app.route("/health")
def health():
    return jsonify(status="ok")


# CWE-89: SQL injection — user input formatted straight into the query
@app.route("/user")
def user():
    user_id = request.args.get("id", "1")
    rows = get_db().execute(f"SELECT id, name, role FROM users WHERE id = {user_id}").fetchall()
    return jsonify(rows)


# CWE-78: OS command injection — shell=True with user input
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return f"<pre>{out.stdout}{out.stderr}</pre>"


# CWE-918: server-side request forgery — fetches any URL the caller supplies
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    resp = requests.get(url, timeout=5)
    return resp.text[:2000]


# CWE-1336 / CWE-79: server-side template injection and reflected XSS
@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string(f"<h1>Hello {name}!</h1>")


# CWE-502: unsafe YAML deserialization
@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    return jsonify(loaded=str(config))


# CWE-502: unsafe pickle deserialization
@app.route("/restore", methods=["POST"])
def restore():
    state = pickle.loads(base64.b64decode(request.get_data()))
    return jsonify(restored=str(state))


if __name__ == "__main__":
    # CWE-489 / CWE-94: debug mode exposes the Werkzeug interactive debugger
    app.run(host="0.0.0.0", port=5000, debug=True)
