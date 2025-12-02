from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from license_generator import make_license
import smtplib
from email.mime.text import MIMEText
import os

app = FastAPI()

# Cargar Admin Key de variables de entorno
ADMIN_KEY = os.environ.get("ADMIN_KEY")

class TokenRequest(BaseModel):
    tx_id: str
    email: str

def send_email(to_email, token):
    smtp_host = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")

    msg = MIMEText(f"Tu token de licencia es: {token}")
    msg["Subject"] = "Tu licencia"
    msg["From"] = smtp_user
    msg["To"] = to_email

    server = smtplib.SMTP(smtp_host, smtp_port)
    server.starttls()
    server.login(smtp_user, smtp_pass)
    server.send_message(msg)
    server.quit()

@app.post("/admin/generate-token")
def generate_token(req: TokenRequest, x_admin_key: str = Header(None)):
    # Verificar Admin Key
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Generar token
    token, payload = make_license(req.email)
    
    # Enviar email
    send_email(req.email, token)
    
    return {"token": token, "status": "sent", "email": req.email}
