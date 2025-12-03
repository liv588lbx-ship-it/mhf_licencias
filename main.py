import logging
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from license_generator import make_license
import smtplib
from email.mime.text import MIMEText
import os

# -------------------
# CONFIG DE LOGGING
# -------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

log = logging.getLogger(__name__)

app = FastAPI()

ADMIN_KEY = os.environ.get("ADMIN_KEY")

class TokenRequest(BaseModel):
    tx_id: str
    email: str

def send_email(to_email, token):

    log.info("=== INICIANDO ENVÍO DE EMAIL ===")
    log.info(f"EMAIL_USER={os.environ.get('EMAIL_USER')}")
    log.info(f"EMAIL_HOST={os.environ.get('EMAIL_HOST')}")
    log.info(f"EMAIL_PORT={os.environ.get('EMAIL_PORT')}")

    try:
        smtp_host = os.environ.get("EMAIL_HOST")
        smtp_port = int(os.environ.get("EMAIL_PORT", 587))
        smtp_user = os.environ.get("EMAIL_USER")
        smtp_pass = os.environ.get("EMAIL_PASS")

        msg = MIMEText(f"Tu token de licencia es: {token}")
        msg["Subject"] = "Tu licencia"
        msg["From"] = smtp_user
        msg["To"] = to_email

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(1)

        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()

        log.info(f"Correo enviado correctamente a {to_email}")

    except Exception as e:
        log.error(f"ERROR al enviar correo: {e}")

@app.post("/admin/generate-token")
def generate_token(req: TokenRequest, x_admin_key: str = Header(None)):

    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    token, payload = make_license(req.email)

    log.info(f"GENERANDO TOKEN PARA {req.email}: {token}")

    send_email(req.email, token)
    
    return {
        "token": token,
        "status": "email sent (o error, revisar logs stream)",
        "email": req.email
    }
