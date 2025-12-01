# manage_gui.py
import os
import sqlite3
import secrets
import time
import smtplib
from email.message import EmailMessage
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

DB_PATH = os.path.join(os.getcwd(), "licenses.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
FROM_NAME = os.environ.get("FROM_NAME", "Support")
ACTIVATION_LINK = os.environ.get("ACTIVATION_LINK", "local app")

# --- DB init and helpers ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
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

def verify_and_activate(token):
    now = int(time.time())
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
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

def list_tokens(limit=100):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT token,email,issued,activated_at,expires,used FROM tokens ORDER BY issued DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

# --- Email ---
def send_email(to_email, subject, body):
    if not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP_USER or SMTP_PASS not set")
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

# --- UI ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("License Manager")
        self.geometry("700x500")
        self.create_widgets()

    def create_widgets(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        # Admin tab
        admin_frame = ttk.Frame(nb)
        nb.add(admin_frame, text="Admin")

        ttk.Label(admin_frame, text="Admin password").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.admin_pw = ttk.Entry(admin_frame, show="*")
        self.admin_pw.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(admin_frame, text="Email to issue").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.issue_email = ttk.Entry(admin_frame, width=40)
        self.issue_email.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(admin_frame, text="Create & Send Token", command=self.issue_token).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(admin_frame, text="Recent tokens").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.tokens_box = scrolledtext.ScrolledText(admin_frame, width=80, height=20)
        self.tokens_box.grid(row=3, column=0, columnspan=3, padx=5, pady=5)
        ttk.Button(admin_frame, text="Refresh", command=self.refresh_tokens).grid(row=4, column=0, padx=5, pady=5)

        # Activate tab
        act_frame = ttk.Frame(nb)
        nb.add(act_frame, text="Activate")

        ttk.Label(act_frame, text="Enter token").grid(row=0, column=0, padx=5, pady=5)
        self.token_entry = ttk.Entry(act_frame, width=60)
        self.token_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(act_frame, text="Activate", command=self.activate_token).grid(row=0, column=2, padx=5, pady=5)

        self.act_result = ttk.Label(act_frame, text="")
        self.act_result.grid(row=1, column=0, columnspan=3, padx=5, pady=10)

        self.refresh_tokens()

    def check_admin(self):
        return self.admin_pw.get() == ADMIN_PASSWORD

    def issue_token(self):
        if not self.check_admin():
            messagebox.showerror("Auth", "Bad admin password")
            return
        email = self.issue_email.get().strip()
        if not email:
            messagebox.showerror("Input", "Enter email")
            return
        token = create_token(email)
        subject = "Your activation code"
        body = f"""Hello {email},

Thank you for your purchase.

Your activation code is:

{token}

Important: your access period (36 hours) will start only when you redeem this code. The code does not activate automatically when issued.

How to redeem:
1. Open the activation page in the app.
2. Paste the code and click Activate.

Regards,
Your Service Team
"""
        try:
            send_email(email, subject, body)
            messagebox.showinfo("OK", "Token created and email sent")
        except Exception as e:
            messagebox.showwarning("Email failed", f"Token created but email failed: {e}")
        self.refresh_tokens()

    def refresh_tokens(self):
        rows = list_tokens(200)
        self.tokens_box.delete("1.0", tk.END)
        for r in rows:
            issued = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[2])) if r[2] else "N/A"
            activated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[3])) if r[3] else "N/A"
            expires = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[4])) if r[4] else "N/A"
            line = f"{r[1]} | {r[0]} | issued: {issued} | activated: {activated} | expires: {expires} | used: {r[5]}\n"
            self.tokens_box.insert(tk.END, line)

    def activate_token(self):
        token = self.token_entry.get().strip()
        if not token:
            messagebox.showerror("Input", "Enter token")
            return
        res = verify_and_activate(token)
        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error"))
            return
        expires = res.get("expires")
        expires_human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires))
        try:
            send_email(res.get("email"), "Your access is active", f"Hello,\n\nYour access is now active and will expire on {expires_human}.\n\nRegards.")
        except Exception:
            pass
        messagebox.showinfo("Activated", f"Activated. Expires: {expires_human}")
        self.refresh_tokens()

if __name__ == "__main__":
    init_db()
    app = App()
    app.mainloop()
