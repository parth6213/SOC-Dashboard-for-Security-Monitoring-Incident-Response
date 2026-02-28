from flask import Flask, request, session, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import sqlite3
import secrets
import re
import os
import time
import datetime  # ✅ ADDED

closed_alerts = set()

app = Flask(__name__)

# -------------------- SECRET KEY --------------------
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# -------------------- SESSION SECURITY --------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

# -------------------- DATABASE --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()

# -------------------- PASSWORD POLICY --------------------
COMMON_PASSWORDS = {
    "admin",
    "admin123",
    "password",
    "password123",
    "welcome",
    "qwerty",
    "qwerty123",
    "user",
    "user123",
}


def is_strong_password(password, username):
    errors = []

    if len(password) < 8:
        errors.append("Minimum 8 characters required")
    if not re.search(r"[A-Z]", password):
        errors.append("At least one uppercase letter required")
    if not re.search(r"[a-z]", password):
        errors.append("At least one lowercase letter required")
    if not re.search(r"[0-9]", password):
        errors.append("At least one number required")
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]:;\"'<>,.?/]", password):
        errors.append("At least one special character required")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("Common passwords are not allowed")
    if username.lower() in password.lower():
        errors.append("Password too similar to username")

    return errors


# -------------------- CSRF --------------------
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf(token):
    return token and token == session.get("csrf_token")


# -------------------- LOGGING FUNCTION -------------------- ✅ ADDED
def write_log(user, action, ip, location="Unknown"):
    log = f"{datetime.datetime.now()} | USER: {user} | ACTION: {action} | IP: {ip} | LOCATION: {location}\n"

    with open("logs.txt", "a") as f:
        f.write(log)


def detect_brute_force():
    with open("logs.txt", "r") as f:
        logs = f.readlines()

    failed_attempts = {}

    for log in logs:
        if "LOGIN_FAILED" in log:
            parts = log.split("|")

            user = parts[1].split(":")[1].strip()
            ip = parts[3].split(":")[1].strip()

            key = f"{user}-{ip}"
            failed_attempts[key] = failed_attempts.get(key, 0) + 1

    alerts = []
    for key, count in failed_attempts.items():
        if count >= 3:
            user, ip = key.split("-")
            alerts.append(f"[HIGH] Brute Force → USER: {user} | IP: {ip}")

    return alerts

def detect_new_location():
    with open("logs.txt", "r") as f:
        logs = f.readlines()

    user_ips = {}
    alerts = []

    for log in logs:
        if "LOGIN_SUCCESS" in log:
            parts = log.split("|")

            user = parts[1].split(":")[1].strip()
            ip = parts[3].split(":")[1].strip()

            if user not in user_ips:
                user_ips[user] = set()

            if ip not in user_ips[user] and len(user_ips[user]) > 0:
                alerts.append(f"[MEDIUM] New Location → USER: {user} | IP: {ip}")

            user_ips[user].add(ip)

    return alerts

def detect_suspicious_activity():
    with open("logs.txt", "r") as f:
        logs = f.readlines()

    alerts = []

    for i in range(len(logs) - 1):
        if "LOGIN_FAILED" in logs[i] and "LOGIN_SUCCESS" in logs[i + 1]:
            parts = logs[i + 1].split("|")
            user = parts[1].split(":")[1].strip()
            ip = parts[3].split(":")[1].strip()

            alerts.append(f"[LOW] Suspicious Activity → USER: {user} | IP: {ip}")

    return alerts

def detect_odd_hours():
    with open("logs.txt", "r") as f:
        logs = f.readlines()

    alerts = []

    for log in logs:
        if "LOGIN_SUCCESS" in log:
            parts = log.split("|")

            time_part = parts[0].strip()   # e.g. 2026-02-27 01:19:18.776634
            user = parts[1].split(":")[1].strip()
            ip = parts[3].split(":")[1].strip()

            # time extract
            time_obj = datetime.datetime.strptime(time_part, "%Y-%m-%d %H:%M:%S.%f")
            hour = time_obj.hour

            # odd hours condition
            if hour < 6 or hour > 23:
                alerts.append(f"[MEDIUM] Odd Hours Login → USER: {user} | IP: {ip} | TIME: {hour}:00")

    return list(set(alerts))

def detect_same_ip_multiple_users():
    with open("logs.txt", "r") as f:
        logs = f.readlines()

    ip_users = {}
    alerts = []

    for log in logs:
        if "LOGIN_SUCCESS" in log:
            parts = log.split("|")

            user = parts[1].split(":")[1].strip()
            ip = parts[3].split(":")[1].strip()

            if ip not in ip_users:
                ip_users[ip] = set()

            ip_users[ip].add(user)

    for ip, users in ip_users.items():
        if len(users) >= 2:
            alerts.append(f"[HIGH] Same IP Multiple Users → IP: {ip} | USERS: {', '.join(users)}")

    return alerts

def get_action(alert_message):
    if "[HIGH]" in alert_message:
        return "Block IP + Force Password Reset"
    elif "[MEDIUM]" in alert_message:
        return "Verify User + Send Alert"
    elif "[LOW]" in alert_message:
        return "Monitor Activity"
    else:
        return "No Action"
# -------------------- ROUTES --------------------
@app.route("/")
def home():
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if not validate_csrf(request.form.get("csrf_token")):
            return "Invalid CSRF token", 403

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if password != confirm_password:
            return render_template(
                "register.html",
                errors=["Passwords do not match"],
                csrf_token=generate_csrf_token(),
            )

        errors = is_strong_password(password, username)
        if errors:
            return render_template(
                "register.html", errors=errors, csrf_token=generate_csrf_token()
            )

        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            conn.commit()
            conn.close()
            return redirect("/login")

        except sqlite3.IntegrityError:
            return render_template(
                "register.html",
                errors=["Username already exists"],
                csrf_token=generate_csrf_token(),
            )

    return render_template(
        "register.html", errors=None, csrf_token=generate_csrf_token()
    )


MAX_ATTEMPTS = 5
LOCK_TIME = 300


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    now = time.time()

    if "failed_attempts" not in session:
        session["failed_attempts"] = 0
    if "lock_until" not in session:
        session["lock_until"] = 0

    if session["lock_until"] > now:
        remaining = int(session["lock_until"] - now)
        error = f"Too many failed attempts. Try again in {remaining} seconds."
        return render_template(
            "login.html", error=error, csrf_token=generate_csrf_token()
        )

    if request.method == "POST":
        if not validate_csrf(request.form.get("csrf_token")):
            error = "Invalid request"
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            ip = request.remote_addr

            conn = get_db_connection()
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            conn.close()

            if user and check_password_hash(user["password"], password):
                write_log(username, "LOGIN_SUCCESS", ip)
                session.pop("failed_attempts", None)
                session.pop("lock_until", None)
                session["user"] = username
                return redirect("/dashboard")
            else:
                session["failed_attempts"] += 1
                write_log(username, "LOGIN_FAILED", ip)
                left = MAX_ATTEMPTS - session["failed_attempts"]

                if left <= 0:
                    session["lock_until"] = now + LOCK_TIME
                    error = "Too many failed attempts. Account locked for 5 minutes."
                else:
                    error = f"Invalid username or password. {left} attempts left."

    return render_template("login.html", error=error, csrf_token=generate_csrf_token())


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    alerts = detect_brute_force()
    location_alerts = detect_new_location()
    suspicious_alerts = detect_suspicious_activity()
    odd_alerts = detect_odd_hours()
    ip_alerts = detect_same_ip_multiple_users()  # 👈 ADD

    alerts = alerts + location_alerts + suspicious_alerts + odd_alerts + ip_alerts

    alerts = list(set(alerts))
    alerts.sort(reverse=True)
    unique_alerts = list(set(alerts))

    alerts = []
    for i, a in enumerate(unique_alerts):
        status = "CLOSED" if i in closed_alerts else "OPEN"

        # 🔥 SEVERITY EXTRACT
        if "[HIGH]" in a:
            severity = "HIGH"
        elif "[MEDIUM]" in a:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        alerts.append({
            "id": i,
            "message": a,
            "status": status,
            "severity": severity,  # 👈 NEW FIELD
            "action": get_action(a)
        })
    open_alerts = [a for a in alerts if a["status"] == "OPEN"]
    closed_alerts_list = [a for a in alerts if a["status"] == "CLOSED"]
    with open("logs.txt", "r") as f:
        logs = f.readlines()

    return render_template(
        "dashboard.html",
        open_alerts=open_alerts,
        closed_alerts_list=closed_alerts_list,
        logs=logs,
        username=escape(session["user"]),
        csrf_token=generate_csrf_token()
    )


@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf(request.form.get("csrf_token")):
        return "Invalid CSRF token", 403
    session.clear()
    return redirect("/login")

@app.route("/close_alert", methods=["POST"])
def close_alert():
    alert_id = request.form.get("alert_id")

    print("Closing alert ID:", alert_id)  # 👈 MUST
    print("Closed alerts set BEFORE:", closed_alerts)

    if alert_id:
        closed_alerts.add(int(alert_id))

    print("Closed alerts set AFTER:", closed_alerts)  # 👈 MUST

    return redirect("/dashboard")



if __name__ == "__main__":
    app.run()
