"""
Deliberately INSECURE sample for Week 2 scanning practice.
Do NOT copy these patterns into real code. Find them with SAST + secret scanning.
"""
import sqlite3, hashlib, subprocess, ipaddress, os, bycrypt
from flask import Flask, request

app = Flask(__name__)

# CWE-798: hardcoded credentials / secret  (Gitleaks should flag this)
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89: SQL injection (string formatting into query)
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: OS command injection (shell=True with user input)
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        return "Invalid IP address", 400
    return subprocess.check_output(
        ["ping", "-c", "1", host],
        shell=False,
        timeout=5,
    )

def store_password(pw):
    # CWE-327: weak hash for passwords
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

if __name__ == "__main__":
    app.run(debug=False)  # CWE-489: debug mode in production
