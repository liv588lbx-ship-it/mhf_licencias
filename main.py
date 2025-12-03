import os
import logging
import smtplib
from email.mime.text import MIMEText
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from license_generator import make_license

# -------------------------------
# LOGGING PARA RENDER
# -------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger(__name__)

app = FastAPI()

ADMIN_KEY = os.environ.get("ADMIN_KEY")

class TokenRequest(BaseModel):
    tx_id: str
    email: str

def send_email(to_email, token):
    log.info("🔍 Entrando a send_email()")

    smtp_host = os.environ.get("EMAIL_HOST")
    smtp_port = int(os.environ.get("EMAIL_PORT", 587))
    smtp_user = os.environ.get("EMAIL_USER")
    smtp_pass = os.environ.get("EMAIL_PASS")

    log.info(f"EMAIL_HOST={smtp_host}")
    log.info(f"EMAIL_PORT={smtp_port}")
    log.info(f"EMAIL_USER={smtp_user}")
    log.info(f"EMAIL_PASS={'SET' if smtp_pass else 'NOT SET'}")

    try:
        msg = MIMEText(f"Tu token de licencia es: {token}")
        msg["Subject"] = "Tu licencia"
        msg["From"] = smtp_user
        msg["To"] = to_email

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()

        log.info(f"📧 Email enviado correctamente a {to_email}")

    except Exception as e:
        log.error(f"❌ ERROR enviando email: {e}")

@app.post("/admin/generate-token")
def generate_token(req: TokenRequest, x_admin_key: str = Header(None)):

    if x_admin_key != ADMIN_KEY:
        log.warning("Intento NO autorizado")
        raise HTTPException(status_code=401, detail="Unauthorized")

    log.info(f"🔐 Admin autorizado, generando token para: {req.email}")

    token, payload = make_license(req.email)

    send_email(req.email, token)

    return {
        "token": token,
        "email": req.email,
        "status": "ok (revisar logs para estado del email)"
    }
