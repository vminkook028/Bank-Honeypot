from flask import Flask, request, render_template, jsonify, session, redirect, url_for, Response
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
from functools import wraps
import json, os, csv, io
import requests

# ─────────────────────────────────────────────
#  Load .env file (if python-dotenv is installed)
# ─────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, using system env vars

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY not set! Please add it to your .env file.")

app.secret_key = secret_key

socketio = SocketIO(app, cors_allowed_origins="*")

# Rate Limiter — 10 honeypot login attempts per minute per IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
LOG_FILE   = os.path.join("logs", "attacks.json")
ADMIN_USER = os.environ.get("ADMIN_USER")
ADMIN_PASS = os.environ.get("ADMIN_PASS")

if not ADMIN_USER or not ADMIN_PASS:
    raise RuntimeError("ADMIN_USER or ADMIN_PASS not set! Please add them to your .env file.")

os.makedirs("logs", exist_ok=True)


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def load_logs() -> list:
    """Load all attack logs from JSON file."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []


def save_log(entry: dict) -> None:
    """Append a new log entry to the JSON file."""
    logs = load_logs()
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)


def get_location(ip: str) -> str:
    """Resolve IP to city/country using ip-api.com."""
    if ip in ("127.0.0.1", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
        return "Local / Private"
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        city    = res.get("city", "")
        country = res.get("country", "")
        return f"{city}, {country}".strip(", ") or "Unknown"
    except Exception:
        return "Unknown"


def get_user_agent(req) -> str:
    """Return browser/OS user-agent string."""
    return req.headers.get("User-Agent", "Unknown")


def login_required(f):
    """Decorator to protect dashboard/admin routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
#  HONEYPOT ROUTES  (public-facing fake pages)
# ─────────────────────────────────────────────
@app.route("/")
def home():
    """Fake bank login page — the honeypot."""
    return render_template("login.html")


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    """Capture credentials submitted to honeypot."""
    ip        = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")

    entry = {
        "time":       timestamp,
        "ip":         ip,
        "location":   get_location(ip),
        "username":   request.form.get("username", ""),
        "password":   request.form.get("password", ""),
        "user_agent": get_user_agent(request),
        "method":     request.method,
        "path":       request.path,
    }

    save_log(entry)
    socketio.emit("new_attack", entry)

    return render_template("login.html", error="Invalid credentials. Please try again.")


# ─────────────────────────────────────────────
#  ADMIN AUTH ROUTES
# ─────────────────────────────────────────────
@app.route("/admin", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    """Real admin login — password-protected."""
    error = None
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USER and
                request.form.get("password") == ADMIN_PASS):
            session["authenticated"] = True
            session.permanent = False
            return redirect(url_for("dashboard"))
        error = "ACCESS DENIED — Invalid credentials."

    return render_template("admin.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin_login"))


# ─────────────────────────────────────────────
#  PROTECTED DASHBOARD ROUTES
# ─────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    """Live attack intelligence dashboard."""
    return render_template("dashboard.html")


@app.route("/api/logs")
@login_required
def api_logs():
    """Return all logs as JSON."""
    logs = load_logs()
    return jsonify(logs)


@app.route("/api/count")
@login_required
def api_count():
    """Return total log count."""
    return jsonify({"count": len(load_logs())})


@app.route("/api/stats")
@login_required
def api_stats():
    """Return aggregated stats for dashboard widgets."""
    logs = load_logs()

    ip_counts  = {}
    loc_counts = {}
    ua_counts  = {}
    hourly     = {}

    for log in logs:
        ip  = log.get("ip", "Unknown")
        loc = log.get("location", "Unknown")
        ua  = log.get("user_agent", "Unknown")
        t   = log.get("time", "")

        ip_counts[ip]   = ip_counts.get(ip, 0) + 1
        loc_counts[loc] = loc_counts.get(loc, 0) + 1
        ua_counts[ua]   = ua_counts.get(ua, 0) + 1

        if len(t) >= 13:
            hour = t[:13] + ":00"
            hourly[hour] = hourly.get(hour, 0) + 1

    return jsonify({
        "total":         len(logs),
        "unique_ips":    len(ip_counts),
        "ip_counts":     ip_counts,
        "loc_counts":    loc_counts,
        "ua_counts":     ua_counts,
        "hourly":        hourly,
        "last_attack":   logs[-1]["time"] if logs else None,
    })


@app.route("/api/export/csv")
@login_required
def export_csv():
    """Export all logs as a downloadable CSV file."""
    logs = load_logs()

    output = io.StringIO()
    fieldnames = ["time", "ip", "location", "username", "password", "user_agent", "method", "path"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(logs)

    csv_data = output.getvalue()
    filename = f"nexus_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/api/clear", methods=["POST"])
@login_required
def clear_logs():
    """Clear all logs (admin action)."""
    with open(LOG_FILE, "w") as f:
        json.dump([], f)
    socketio.emit("logs_cleared", {})
    return jsonify({"status": "ok", "message": "Logs cleared."})


# ─────────────────────────────────────────────
#  RATE LIMIT ERROR HANDLER
# ─────────────────────────────────────────────
@app.errorhandler(429)
def rate_limit_handler(e):
    return render_template("login.html", error="Too many attempts. Please wait."), 429


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("""
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
  Honeypot v2.0 | Starting...
    """)
    socketio.run(app, debug=False, host="0.0.0.0", port=5000)