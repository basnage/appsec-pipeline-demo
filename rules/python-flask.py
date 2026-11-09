# Test cases for python-flask.yaml. Run with: opengrep test rules/
# Lines annotated with a rule id must match; lines annotated "ok" must not.
import os
import pickle
import subprocess
import json

import requests
import yaml
from flask import Flask, render_template, render_template_string, request

app = Flask(__name__)

# ruleid: flask-hardcoded-secret-key
app.config["SECRET_KEY"] = "hunter2"
# ruleid: flask-hardcoded-secret-key
app.secret_key = "hunter2"
# ok: flask-hardcoded-secret-key
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]


def sqli(db):
    uid = request.args.get("id")
    # ruleid: flask-sqli-formatted-query
    db.execute(f"SELECT * FROM users WHERE id = {uid}")
    # ruleid: flask-sqli-formatted-query
    db.execute("SELECT * FROM users WHERE id = %s" % uid)
    # ruleid: flask-sqli-formatted-query
    db.execute("SELECT * FROM users WHERE id = " + uid)
    # ok: flask-sqli-formatted-query
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))


def cmdi():
    host = request.args.get("host")
    # ruleid: flask-command-injection-shell-true
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ruleid: flask-command-injection-shell-true
    os.system("ping " + host)
    # ok: flask-command-injection-shell-true
    subprocess.run(["ping", "-c", "1", host])
    # ok: flask-command-injection-shell-true
    subprocess.run("uptime", shell=True)


def ssrf():
    url = request.args.get("url")
    # ruleid: flask-ssrf-requests
    requests.get(url)
    # ok: flask-ssrf-requests
    requests.get("https://api.example.com/status")


def ssti():
    name = request.args.get("name")
    # ruleid: flask-ssti-render-template-string
    render_template_string(f"<h1>Hello {name}</h1>")
    # ok: flask-ssti-render-template-string
    render_template_string("<h1>Hello {{ name }}</h1>", name=name)
    # ok: flask-ssti-render-template-string
    render_template("hello.html", name=name)


def deserialize(data):
    # ruleid: python-unsafe-yaml-load
    yaml.load(data, Loader=yaml.Loader)
    # ruleid: python-unsafe-yaml-load
    yaml.load(data)
    # ok: python-unsafe-yaml-load
    yaml.safe_load(data)
    # ok: python-unsafe-yaml-load
    yaml.load(data, Loader=yaml.SafeLoader)
    # ruleid: python-pickle-loads
    pickle.loads(data)
    # ok: python-pickle-loads
    json.loads(data)


if __name__ == "__main__":
    # ruleid: flask-debug-enabled
    app.run(host="0.0.0.0", debug=True)
    # ok: flask-debug-enabled
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
