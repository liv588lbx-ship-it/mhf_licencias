# manage.py
import os
import sqlite3
import secrets
import time
import smtplib
from email.message import EmailMessage
from functools import wraps

from flask import Flask, request, redirect, url_for, flash, render_template_string, jsonify

# ---------- Config ----------
DB_PATH = os.path.join(os.getcwd(), "licenses.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")  # cambia en producción
FLASK_SECRET = os.environ.get("FLASK_SECRET", "devsecret")
ACTIVATION_LINK = os.environ.get("ACTIVATION_LINK", "http://127.0.0.1:5001/activate")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
FROM_NAME = os.environ.get("FROM_NAME", "Support")

# ---------- App ----------
app = Flask(__name__)
app.secret_key = FLASK_SECRET

# ---------- DB ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Tabla sin columna id explícita (usamos rowid internamente)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT UNIQUE,
        email TEXT,
        issued INTEGER,
        duration_hours INTEGER DEFAULT 36,
        activated_at INTEGER,
        expires INTEGER,
        used INTEGER DEFAULT 0
    );
    """)
    conn.commit()
    conn.close()

# ---------- Token creation ----------
def create_token(email, duration_hours=36):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO tokens(token,email,issued,duration_hours,activated_at,expires,used) VALUES(?,?,?,?,?,?,0)",
        (token, email, now, duration_hours, None, None)
    )
    conn.commit()
    conn.close()
    return token

# ---------- Activation logic (usa rowid) ----------
def verify_and_activate(token):
    now = int(time.time())
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # usamos rowid porque la tabla puede no tener columna id
    cur.execute("SELECT rowid, email, used, duration_hours FROM tokens WHERE token = ?", (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"ok": False, "error": "invalid token"}
    rowid_, email, used, duration_hours = row
    if used:
        conn.close()
        return {"ok": False, "error": "token already used"}
    expires = now + int(duration_hours) * 3600
    cur.execute("UPDATE tokens SET activated_at = ?, expires = ?, used = 1 WHERE rowid = ?", (now, expires, rowid_))
    conn.commit()
    conn.close()
    return {"ok": True, "email": email, "expires": expires}

# ---------- Email sending ----------
def send_email(to_email, subject, body):
    if not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP_USER or SMTP_PASS not set in environment")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{FROM_NAME} <{SMTP_USER}>"
    msg["To"] = to_email
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
        s.ehlo()
        if SMTP_PORT == 587:
            s.starttls()
            s.ehlo()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

# ---------- Helpers ----------
def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        pw = request.cookies.get("admin_pw") or request.args.get("admin_pw") or request.form.get("admin_pw")
        if pw == ADMIN_PASSWORD:
            return f(*args, **kwargs)
        return redirect(url_for("admin_login"))
    return wrapped

def human_time(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "N/A"

# ---------- Routes ----------
@app.route("/")
def index():
    return redirect(url_for("activate_page"))

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        pw = request.form.get("password")
        if pw == ADMIN_PASSWORD:
            resp = redirect(url_for("admin_panel"))
            resp.set_cookie("admin_pw", pw)
            return resp
        flash("Bad password")
    return render_template_string("""
    <h2>Admin login</h2>
    <form method="post">
      <input name="password" type="password" placeholder="Password"/>
      <button type="submit">Login</button>
    </form>
    """)

@app.route("/admin")
@admin_required
def admin_panel():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT token,email,issued,activated_at,expires,used FROM tokens ORDER BY issued DESC LIMIT 200")
    rows = cur.fetchall()
    conn.close()
    rows_html = "<br>".join([f"{r[1]} | {r[0]} | issued: {human_time(r[2])} | activated: {human_time(r[3])} | expires: {human_time(r[4])} | used: {r[5]}" for r in rows])
    return render_template_string("""
    <h2>Admin panel</h2>
    <form method="post" action="{{ url_for('admin_issue') }}">
      <input name="email" placeholder="email"/>
      <button type="submit">Create & Send Token</button>
    </form>
    <h3>Recent tokens</h3>
    <div style="font-family:monospace">{{ rows|safe }}</div>
    """, rows=rows_html)

@app.route("/admin/issue", methods=["POST"])
@admin_required
def admin_issue():
    email = request.form.get("email")
    if not email:
        flash("Missing email")
        return redirect(url_for("admin_panel"))

    token = create_token(email)

    subject = "Your activation code"
    body = f"""Hello {email},

Thank you for your purchase.

Your activation code is:

{token}

Important: your access period (36 hours) will start only when you redeem this code. The code does not activate automatically when issued.

How to redeem:
1. Open the activation page: {ACTIVATION_LINK}
2. Paste the code in the "Enter Token" field and click Activate.

If you did not request this, please contact support.

Regards,
Your Service Team
"""
    try:
        send_email(email, subject, body)
        flash("Token created and sent")
    except Exception as e:
        flash(f"Token created but failed to send email: {e}")

    return redirect(url_for("admin_panel"))

@app.route("/activate", methods=["GET", "POST"])
def activate_page():
    message = ""
    if request.method == "POST":
        token = request.form.get("token")
        res = verify_and_activate(token)
        if not res.get("ok"):
            message = f"Error: {res.get('error')}"
        else:
            expires = res.get("expires")
            expires_human = human_time(expires)
            try:
                send_email(res.get("email"),
                           "Your access is active",
                           f"Hello,\n\nYour access is now active and will expire on {expires_human}.\n\nRegards.")
            except Exception:
                pass
            message = f"Activated. Expires: {expires_human}"
    return render_template_string("""
    <h2>Activate</h2>
    <form method="post">
      <input name="token" placeholder="Enter Token"/>
      <button type="submit">Activate</button>
    </form>
    <div>{{ message }}</div>
    """, message=message)

@app.route("/api/redeem", methods=["POST"])
def api_redeem():
    data = request.get_json(force=True)
    token = data.get("token")
    res = verify_and_activate(token)
    if not res.get("ok"):
        return jsonify(res), 400
    return jsonify({"ok": True, "expires": res.get("expires"), "expires_human": human_time(res.get("expires"))})

# ---------- Start ----------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
