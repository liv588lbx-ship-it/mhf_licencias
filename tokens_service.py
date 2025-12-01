# tokens_service.py
import sqlite3, secrets, time, os
from email.message import EmailMessage
import smtplib

DB_PATH = os.environ.get("DB_PATH", "licenses.db")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
FROM_NAME = os.environ.get("FROM_NAME", "Soporte")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS tokens
                    (token TEXT PRIMARY KEY, email TEXT, issued INTEGER, expires INTEGER, used INTEGER DEFAULT 0)""")
    conn.commit()
    conn.close()

def create_token(email, hours=36):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + hours * 3600
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO tokens(token,email,issued,expires,used) VALUES(?,?,?,?,0)",
                 (token, email, now, expires))
    conn.commit()
    conn.close()
    return token, expires

def send_token_email(to_email, token, expires_ts):
    expires_human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires_ts))
    msg = EmailMessage()
    msg["Subject"] = "Tu código de activación - 36 horas"
    msg["From"] = f"{FROM_NAME} <{SMTP_USER}>"
    msg["To"] = to_email
    body = f"""Gracias por tu compra.

Tu código de activación es:

{token}

Validez: hasta {expires_human} (36 horas desde la emisión).

Instrucciones:
1) Volvé a la página de activación.
2) Pegá el código en el campo "Ingresar Token" y presioná Activar.

Si no fuiste vos, ignorá este correo.
"""
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
