import os
import json
import sqlite3
import time
import base64
import hashlib
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

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
EMAIL_FROM = os.environ.get("EMAIL_FROM", EMAIL_USER)

# Clave de Administración (para proteger la ruta /admin/generate-token)
ADMIN_KEY = os.environ.get("ADMIN_KEY")

# --- INICIALIZACIÓN DE SERVICIOS ---

# Manejo Condicional de Stripe
if stripe_api_key:
    import stripe
    stripe.api_key = stripe_api_key

DB_PATH = os.environ.get("DB_PATH", "licenses.db")
PUB_KEY_PATH = os.environ.get("PUB_KEY_PATH", "pub.pem")

app = Flask(__name__)

# --- FUNCIONES DE BASE DE DATOS ---

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY,
        user_email TEXT,
        token TEXT,
        token_hash TEXT,
        payment_id TEXT,
        issued INTEGER,
        expires INTEGER,
        meta TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        activated_at TIMESTAMP,
        activation_ip TEXT,
        activation_user_agent TEXT,
        revoked BOOLEAN DEFAULT 0
    )""")
    conn.commit()
    conn.close()

def save_license_record(payload, token, payment_id=None):
    """
    Guarda el registro de licencia. Guarda también token_hash y status = pending.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        c.execute(
            """INSERT INTO licenses
               (id, user_email, token, token_hash, payment_id, issued, expires, meta, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                payload["license_id"],
                payload["user"],
                token,
                token_hash,
                payment_id,
                payload.get("issued", int(time.time())),
                payload.get("expires", 0),
                json.dumps(payload.get("extra", {})),
                "pending"
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        print(f"Warning: registro con id {payload.get('license_id')} ya existe.")
    except Exception as e:
        print(f"Error guardando licencia en DB: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def find_license_by_token_hash(token_hash):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, user_email, token_hash, payment_id, status, created_at, activated_at, expires FROM licenses WHERE token_hash = ?", (token_hash,))
    row = c.fetchone()
    conn.close()
    return row

def mark_license_used(token_hash, activation_ip=None, activation_user_agent=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    activated_at = datetime.utcnow()
    expires_at = activated_at + timedelta(hours=36)
    c.execute(
        """UPDATE licenses
           SET status = 'used',
               activated_at = ?,
               expires = ?,
               activation_ip = ?,
               activation_user_agent = ?
           WHERE token_hash = ?""",
        (activated_at.isoformat(), int(expires_at.timestamp()), activation_ip, activation_user_agent, token_hash)
    )
    conn.commit()
    conn.close()
    return activated_at, expires_at

# --- FUNCIONES DE EMAIL ---

def send_license_email(recipient_email, token):
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS]):
        print("ERROR: Faltan credenciales de email. No se pudo enviar el token.")
        return False

    # Mensaje claro: el token no expira hasta que se active; al activarlo, el servicio funcionará 36 horas.
    body = (
        "Gracias por tu compra.\n\n"
        "Aquí está tu token de licencia. Este token no expirará hasta que lo actives. "
        "Una vez activado, el servicio funcionará durante 36 horas desde el momento de la activación.\n\n"
        f"{token}\n\n"
        "No compartas este token. Solo funciona para la cuenta asociada a este correo.\n"
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "Tu Licencia de Bolsa de Mercenarios"
    msg["From"] = EMAIL_FROM
    msg["To"] = recipient_email

    try:
        server = smtplib.SMTP(EMAIL_HOST, int(EMAIL_PORT))
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_FROM, [recipient_email], msg.as_string())
        server.quit()
        print(f"ÉXITO: Token enviado a {recipient_email}")
        return True
    except Exception as e:
        print(f"ERROR enviando email: {e}")
        return False

# --- FUNCIONES DE VALIDACIÓN DE TOKEN (Tomadas de client_verify.py) ---

def load_public_key(path=PUB_KEY_PATH):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    full_path = os.path.join(script_dir, path)
    with open(full_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def _b64url_decode_padded(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding_needed = (4 - len(s) % 4) % 4
    s += "=" * padding_needed
    return base64.b64decode(s)

def validar_licencia(token):
    """
    Verifica formato y firma. No rechaza por expiración si el payload no contiene expires > 0.
    Devuelve (True/False, mensaje, payload_dict_or_None)
    """
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
        # Si el token trae un campo expires > 0, se puede validar aquí; si es 0 o ausente, no lo rechazamos.
        now = int(time.time())
        expires = data.get("expires", 0)
        if expires and expires < now:
            return False, "expired", data

        return True, "valid", data
    except Exception as e:
        return False, str(e), None

# --- RUTAS DE LA APLICACIÓN ---

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "stripe_enabled": bool(stripe_api_key)}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"}), 200

@app.route("/webhook", methods=["POST"])
def webhook():
    if not stripe_api_key:
        return jsonify({"error": "Stripe no configurado en el servidor."}), 400
    # Lógica de Stripe (si se habilita) iría aquí.
    return jsonify({"status": "ignored"}), 200

# -----------------------------------------------------------------
# RUTA: Generación y Envío (Usado por el Administrador/Tú)
# -----------------------------------------------------------------
@app.route("/admin/generate-token", methods=["POST"])
def generate_and_send():
    # Asegurar que la tabla exista
    init_db()

    # Validación de la clave de administración
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized: Falta o es incorrecta la clave de administración."}), 401

    data = request.get_json() or {}
    user_email = data.get("email")
    payment_id = data.get("payment_id")  # opcional, pero recomendable

    if not user_email:
        return jsonify({"error": "Falta el email del usuario."}), 400

    # Determinar valid_hours: si el admin lo envía, usarlo; por defecto 1 hora
    try:
        valid_hours = int(data.get("valid_hours", 1))
    except Exception:
        valid_hours = 1

    if valid_hours <= 0:
        # Evitar 0 o negativos que provoquen expiración inmediata
        valid_hours = 1

    # 1. Generar token. Preferimos pasar valid_hours al generador si lo soporta.
    #    Si make_license no soporta valid_hours, ajustamos el payload después.
    try:
        token, payload = make_license(user_email, validity_hours=valid_hours)
    except TypeError:
        # Fallback si make_license solo acepta (email) o (email, validity_hours=...)
        try:
            token, payload = make_license(user_email)
        except Exception as e:
            return jsonify({"error": "generate_failed", "detail": str(e)}), 500

    # Asegurarnos de que payload tenga issued y expires coherentes
    issued = int(payload.get("issued", int(time.time())))
    expires = int(payload.get("expires", 0))

    # Si expires no está en el futuro, recalculamos usando valid_hours
    if not expires or expires <= issued:
        expires = issued + int(valid_hours * 3600)
        payload["issued"] = issued
        payload["expires"] = expires
        payload["valid_hours"] = valid_hours

    # 2. Guardar en DB (status = pending)
    save_license_record(payload, token, payment_id=payment_id)

    # 3. Enviar por email (mensaje actualizado)
    success = send_license_email(user_email, token)

    return jsonify({
        "status": "success",
        "message": "Licencia generada y enviada. Revisa los logs para el estado del email.",
        "license_id": payload.get("license_id"),
        "token_sent": success,
        "issued": payload.get("issued"),
        "expires": payload.get("expires")
    }), 200

# -----------------------------------------------------------------
# RUTA: Activación del token (single-use)
# -----------------------------------------------------------------
@app.route("/activate", methods=["POST"])
def activate_token():
    """
    Endpoint para activar un token. Requiere JSON con:
      - token: el token recibido por email
      - user_email: email del usuario que intenta activar (o usar autenticación en headers)
    Validaciones:
      - token firma válida
      - token existe en DB y status == 'pending'
      - token asociado al mismo user_email
      - marcar status = 'used' y setear activated_at y expires = now + 36h
    """
    try:
        init_db()
        data = request.get_json() or {}
        token = data.get("token")
        user_email = data.get("user_email")

        if not token or not user_email:
            return jsonify({"error": "Faltan token o user_email."}), 400

        # 1) Verificar firma y obtener payload (DEBUG: imprimir resultado de validación)
        is_valid, message, payload = validar_licencia(token)
        print("DEBUG: validar_licencia ->", is_valid, message)
        if payload is not None:
            try:
                # Intentamos serializar el payload para inspección; truncamos para evitar logs enormes
                print("DEBUG: payload (truncado 1000 chars) ->", json.dumps(payload)[:1000])
            except Exception as e:
                print("DEBUG: no se pudo serializar payload:", e)
        if not is_valid:
            # Devolvemos el mismo 400 al cliente pero dejamos rastro en la consola
            return jsonify({"error": "Token inválido", "detail": message}), 400

        # 2) Buscar registro en DB por token_hash
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = find_license_by_token_hash(token_hash)
        if not row:
            return jsonify({"error": "Token no encontrado."}), 404

        db_id, db_email, db_token_hash, db_payment_id, db_status, db_created_at, db_activated_at, db_expires = row

        # 3) Validaciones de estado y usuario
        if db_status != "pending":
            return jsonify({"error": "Token ya usado o inválido."}), 400

        if db_email.lower() != user_email.lower():
            # Si el usuario no coincide, rechazamos. Alternativa: enviar verificación por email.
            return jsonify({"error": "El token no corresponde a este usuario."}), 403

        # 4) Marcar como usado y setear activated_at y expires_at
        activation_ip = request.remote_addr
        activation_user_agent = request.headers.get("User-Agent", "")
        activated_at, expires_at = mark_license_used(token_hash, activation_ip=activation_ip, activation_user_agent=activation_user_agent)

        # 5) Activar el servicio para el usuario (aquí debes integrar con tu lógica de activación)
        #    Ejemplo: llamar a license_generator.make_license(...) o actualizar tabla de servicios.
        #    Dejamos esto como hook para que integres según tu modelo de datos.

        return jsonify({
            "status": "activated",
            "license_id": db_id,
            "activated_at": activated_at.isoformat(),
            "expires_at": expires_at.isoformat()
        }), 200

    except Exception as e:
        # Imprime traceback completo en la consola del servidor para diagnóstico
        import traceback
        print("=== EXCEPCION EN /activate ===")
        traceback.print_exc()
        print("=== FIN EXCEPCION ===")
        # Devuelve respuesta JSON con detalle mínimo para el cliente
        return jsonify({"error": "internal_error", "detail": str(e)}), 500

# -----------------------------------------------------------------
# RUTA: Validación simple (solo firma) para la app cliente
# -----------------------------------------------------------------
@app.route("/api/validate-token", methods=["POST"])
def validate_license_route():
    data = request.get_json() or {}
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
    # En producción no usar debug=True
    app.run(host="0.0.0.0", port=port, debug=False)
