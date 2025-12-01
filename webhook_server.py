# webhook_server.py
import os
import json
import sqlite3
import time
import base64
import smtplib
from email.mime.text import MIMEText

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Importación de la lógica de generación de licencias
from license_generator import make_license

# --- CONFIGURACIÓN DE VARIABLES DE ENTORNO ---

# Stripe (Desactivado por defecto)
stripe_api_key = os.environ.get("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

# Email (SMTP)
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = os.environ.get("EMAIL_PORT")
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")

# Clave de Administración (para proteger la ruta /admin/generate-token)
ADMIN_KEY = os.environ.get("ADMIN_KEY")

# --- INICIALIZACIÓN DE SERVICIOS ---

# Manejo Condicional de Stripe
if stripe_api_key:
    import stripe
    stripe.api_key = stripe_api_key
    print("Stripe API key configurada.")
else:
    print("Warning: STRIPE_API_KEY no definida. El manejo de Webhooks de Stripe estará deshabilitado.")

DB_PATH = os.environ.get("DB_PATH", "licenses.db")
PRIV_KEY_PATH = os.environ.get("PRIV_KEY_PATH", "priv.pem")
PUB_KEY_PATH = os.environ.get("PUB_KEY_PATH", "pub.pem") # Usaremos esta ruta para validación

app = Flask(__name__)

# --- FUNCIONES DE BASE DE DATOS ---

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY,
        user_email TEXT,
        token TEXT,
        issued INTEGER,
        expires INTEGER,
        meta TEXT,
        revoked BOOLEAN DEFAULT 0
    )""")
    conn.commit()
    conn.close()

init_db()

def save_license_record(payload, token):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO licenses (id, user_email, token, issued, expires, meta) VALUES (?, ?, ?, ?, ?, ?)",
            (
                payload["license_id"], 
                payload["user"], 
                token, 
                payload["issued"], 
                payload["expires"], 
                json.dumps(payload.get("extra", {}))
            )
        )
        conn.commit()
    except Exception as e:
        print(f"Error guardando licencia en DB: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

# --- FUNCIONES DE EMAIL ---

def send_license_email(recipient_email, token):
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS]):
        print("ERROR: Faltan credenciales de email. No se pudo enviar el token.")
        return False

    msg = MIMEText(f"Gracias por tu compra. Aquí está tu token de licencia de 36 horas:\n\n{token}\n\nEste token expira {36} horas después de su emisión. Actívalo en tu aplicación.", "plain", "utf-8")
    msg["Subject"] = "Tu Licencia de Bolsa de Mercenarios"
    msg["From"] = EMAIL_USER
    msg["To"] = recipient_email

    try:
        server = smtplib.SMTP(EMAIL_HOST, int(EMAIL_PORT))
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, [recipient_email], msg.as_string())
        server.quit()
        print(f"ÉXITO: Token enviado a {recipient_email}")
        return True
    except Exception as e:
        print(f"ERROR enviando email: {e}")
        return False


# --- FUNCIONES DE VALIDACIÓN DE TOKEN (Tomadas de client_verify.py) ---

def load_public_key(path=PUB_KEY_PATH):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def _b64url_decode_padded(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding_needed = (4 - len(s) % 4) % 4
    s += "=" * padding_needed
    return base64.b64decode(s)

def validar_licencia(token):
    try:
        pub = load_public_key(PUB_KEY_PATH)
        if "." not in token:
            return False, "invalid_format", None
            
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode_padded(payload_b64)
        sig = _b64url_decode_padded(sig_b64)
        
        # Verificar firma
        pub.verify(
            sig,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        data = json.loads(payload)
        now = int(time.time())
        
        if data.get("expires", 0) < now:
            return False, "expired", data
            
        # Opcional: Verificar revocación en DB
        # if is_revoked(data.get("license_id")): return False, "revoked", data

        return True, "valid", data
    except Exception as e:
        # Esto captura errores de firma (SignatureVerificationError) o archivo no encontrado
        return False, str(e), None

# --- RUTAS DE LA APLICACIÓN ---

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "stripe_enabled": bool(stripe_api_key)}), 200

# Ruta de salud para Render
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"}), 200

# Ruta de Webhook (Antigua, sigue como guardia de Stripe)
@app.route("/webhook", methods=["POST"])
def webhook():
    if not stripe_api_key:
        return jsonify({"error": "Stripe no configurado en el servidor."}), 400
    
    # ... (El resto de la lógica de Stripe webhook)
    return jsonify({"status": "ignored"}), 200


# -----------------------------------------------------------------
# NUEVA RUTA: Generación y Envío (Usado por el Administrador/Tú)
# -----------------------------------------------------------------
@app.route("/admin/generate-token", methods=["POST"])
def generate_and_send():
    # Requiere la clave de administrador para evitar uso no autorizado
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized: Falta o es incorrecta la clave de administración."}), 401

    data = request.get_json()
    user_email = data.get("email")
    
    if not user_email:
        return jsonify({"error": "Falta el email del usuario."}), 400

    # 1. Generar token (36 horas)
    token, payload = make_license(user_email, validity_hours=36)
    
    # 2. Guardar en DB
    save_license_record(payload, token)
    
    # 3. Enviar por email
    success = send_license_email(user_email, token)
    
    return jsonify({
        "status": "success", 
        "message": "Licencia generada y enviada. Revisa los logs para el estado del email.",
        "license_id": payload["license_id"],
        "token_sent": success
    }), 200

# -----------------------------------------------------------------
# NUEVA RUTA: Validación de Licencia (Usado por la App del Cliente)
# -----------------------------------------------------------------
@app.route("/api/validate-token", methods=["POST"])
def validate_license_route():
    data = request.get_json()
    token = data.get("token")
    
    if not token:
        return jsonify({"valid": False, "message": "Falta el token."}), 400
        
    is_valid, message, payload = validar_licencia(token)
    
    return jsonify({
        "valid": is_valid, 
        "message": message, 
        "data": payload
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)