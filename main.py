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
    try:
        smtp_host = "smtp.gmail.com"
        smtp_port = 587
        smtp_user = os.environ.get("SMTP_USER")
        smtp_pass = os.environ.get("SMTP_PASS")

        msg = MIMEText(f"Tu token de licencia es: {token}")
        msg["Subject"] = "Tu licencia"
        msg["From"] = smtp_user
        msg["To"] = to_email

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(1)  # 🔹 Muestra todos los pasos SMTP en logs
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        print(f"✅ Correo enviado a {to_email} correctamente")
    except Exception as e:
        print(f"❌ ERROR enviando email a {to_email}: {e}")
        # No detener la API, solo loguea el error

@app.post("/admin/generate-token")
def generate_token(req: TokenRequest, x_admin_key: str = Header(None)):
    # Verificar Admin Key
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Generar token
    token, payload = make_license(req.email)
    
    # Intentar enviar email
    send_email(req.email, token)
    
    return {
        "token": token,
        "status": "sent (o fallo en email, revisar logs)",
        "email": req.email
    }
