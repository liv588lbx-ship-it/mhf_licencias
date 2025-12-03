from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from license_generator import make_license
import smtplib
from email.mime.text import MIMEText
import os

app = FastAPI()

# Admin key
ADMIN_KEY = os.environ.get("ADMIN_KEY")

class TokenRequest(BaseModel):
    tx_id: str
    email: str

def send_email(to_email, token):
    try:
        smtp_host = os.environ.get("EMAIL_HOST")
        smtp_port = int(os.environ.get("EMAIL_PORT", 587))
        smtp_user = os.environ.get("EMAIL_USER")
        smtp_pass = os.environ.get("EMAIL_PASS")

        # ---- Debug SMTP ----
        print(">>> SMTP DEBUG >>>")
        print("SMTP_HOST:", smtp_host)
        print("SMTP_PORT:", smtp_port)
        print("SMTP_USER:", smtp_user)
        print("SMTP_PASS:", "(OK)" if smtp_pass else "None")
        print("EMAIL TO:", to_email)
        print("----------------------")

        msg = MIMEText(f"Tu token de licencia es: {token}")
        msg["Subject"] = "Tu licencia"
        msg["From"] = smtp_user
        msg["To"] = to_email

        # Crear conexión
        print("Conectando a SMTP...")
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(1)  # Log interno de smtplib

        print("Iniciando TLS...")
        server.starttls()

        print("Haciendo login...")
        server.login(smtp_user, smtp_pass)

        print("Enviando mensaje...")
        server.send_message(msg)
        server.quit()

        print(f"✅ Correo enviado a {to_email} correctamente")

    except Exception as e:
        print("❌ ERROR SMTP:", repr(e))


@app.post("/admin/generate-token")
def generate_token(req: TokenRequest, x_admin_key: str = Header(None)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    token, payload = make_license(req.email)

    print(">>>> GENERANDO TOKEN PARA:", req.email)

    send_email(req.email, token)

    return {
        "token": token,
        "status": "sent (o fallo en email, revisar logs)",
        "email": req.email,
    }
