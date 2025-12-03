import os
import json
import sqlite3
import time
import base64
import hashlib
import smtplib
import logging
import ssl # <--- ¡IMPORTACIÓN AÑADIDA!
from email.mime.text import MIMEText
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, Response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Importación de la lógica de generación de licencias
from license_generator import make_license

# Logging de arranque para verificar despliegue
logging.basicConfig(level=logging.INFO)
logging.info("WEBHOOK_SERVER LOADED - CASADEY v3")

app = Flask(__name__)

# Configuración de otras variables de entorno
stripe_api_key = os.environ.get("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = os.environ.get("EMAIL_PORT")
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
EMAIL_FROM = os.environ.get("EMAIL_FROM", EMAIL_USER)

# -------------------------------------------------------
# Función para enviar email (CORREGIDA para STARTTLS/587 con SendGrid)
# -------------------------------------------------------
def send_email(to_address, subject, body):
    host = os.environ.get("EMAIL_HOST")
    # Usamos 587 como default, que es el puerto estándar para STARTTLS
    port = int(os.environ.get("EMAIL_PORT") or 587) 
    user = os.environ.get("EMAIL_USER")
    password = os.environ.get("EMAIL_PASS")
    from_addr = os.environ.get("EMAIL_FROM", user)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_address
    
    # 1. Usamos SMTP (sin _SSL) para iniciar la conexión
    s = smtplib.SMTP(host, port, timeout=10)
    
    try:
        logging.info(f"Intentando login SMTP con {user} en el puerto {port}...")
        
        if user and password:
            # 2. Hacemos el upgrade a conexión segura con STARTTLS (Requiere puerto 587)
            s.starttls() 
            s.login(user, password) 
        
        s.sendmail(from_addr, [to_address], msg.as_string())
        logging.info(f"Correo enviado exitosamente a {to_address}")

    except smtplib.SMTPAuthenticationError as auth_err:
        logging.error(f"❌ Error de autenticación SMTP: {auth_err}")
        # Relanzamos para capturar el error en la ruta Flask
        raise Exception("Error de autenticación al enviar el email. Revisar EMAIL_PASS/USER.")

    except Exception as e:
        logging.error(f"❌ Error general al enviar el email: {e}")
        # Relanzamos para capturar el error en la ruta Flask (ej: bloqueo de firewall/red)
        raise Exception(f"Error de conexión SMTP: {e}. Revisar HOST/PORT.")

    finally:
        s.quit()

# -------------------------------------------------------
# Ruta admin para generar token manualmente (CORREGIDA - Ya contiene la lógica de envío)
# -------------------------------------------------------
@app.route("/admin/generate-token", methods=["POST"])
def generate_token():
    expected_key = os.environ.get("ADMIN_KEY")
    provided_key = request.headers.get("X-Admin-Key")

    if not expected_key:
        logging.error("ADMIN_KEY no está definida en el entorno")
        return Response("Server misconfigured", status=500)

    if provided_key != expected_key:
        logging.info("Unauthorized attempt to /admin/generate-token")
        return Response("Unauthorized", status=401)

    try:
        payload = request.get_json(force=True)
        email = payload.get("email")
        if not email:
            return jsonify({"error": "email required"}), 400

        # 1. Generar Token
        token = make_license(email)

        # 2. Preparar el Email 
        subject = "Tu licencia - Mercenary Help Finder"
        body = (
            "Gracias por tu compra (Generada Manualmente).\n\n"
            "Tu token es:\n"
            f"{token}\n\n"
            "Pegalo en la UI para activar tu licencia."
        )

        # 3. Enviar el Email
        logging.info(f"Intentando enviar email manual a: {email}")
        send_email(email, subject, body)

        return jsonify({"token": token, "message": "Email enviado"}), 200

    except Exception as e:
        # Esto capturará si falla la contraseña o el host y lo mostrará en el log
        logging.exception("Error en el proceso de generar token / enviar email")
        # El error capturado es el que relanza la función send_email
        return jsonify({"error": str(e)}), 500

# -------------------------------------------------------
# Webhook genérico
# -------------------------------------------------------
@app.route("/webhook", methods=["POST"])
def webhook_handler():
    expected_key = os.environ.get("ADMIN_KEY")
    provided_key = request.headers.get("X-Admin-Key")

    if not expected_key:
        logging.error("ADMIN_KEY no está definida en el entorno")
        return Response("Server misconfigured", status=500)

    if provided_key != expected_key:
        logging.info("Unauthorized webhook call")
        return Response("Unauthorized", status=401)

    try:
        data = request.get_json(force=True)
        logging.info("Received webhook event")
        return jsonify({"status": "ok"}), 200
    except Exception:
        logging.exception("Error processing webhook")
        return jsonify({"error": "internal error"}), 500

# -------------------------------------------------------
# 🌟 WEBHOOK DE PAYPAL — GENERA Y ENVÍA EL TOKEN
# -------------------------------------------------------
@app.route("/paypal-webhook", methods=["POST"])
def paypal_webhook():
    try:
        data = request.get_json(force=True)

        logging.info("📩 PAYPAL WEBHOOK RECIBIDO")
        logging.info(json.dumps(data, indent=2))

        event_type = data.get("event_type")

        if event_type not in ["PAYMENT.SALE.COMPLETED", "PAYMENT.CAPTURE.COMPLETED"]:
            logging.info(f"Ignorado evento PayPal: {event_type}")
            return jsonify({"status": "ignored"}), 200

        # ---------------------------------------------------
        # 1) INTENTO ANTIGUO (payer -> payer_info)
        # ---------------------------------------------------
        email = (
            data.get("resource", {})
                .get("payer", {})
                .get("payer_info", {})
                .get("email")
        )

        # ---------------------------------------------------
        # 2) INTENTO NUEVO (resource -> payer -> email_address)
        # ---------------------------------------------------
        if not email:
            email = (
                data.get("resource", {})
                    .get("payer", {})
                    .get("email_address")
            )

        # ---------------------------------------------------
        # 3) FORMATO MÁS NUEVO AÚN (purchase_units[n].shipping/email)
        # ---------------------------------------------------
        if not email:
            purchase_units = data.get("resource", {}).get("purchase_units", [])
            if purchase_units and isinstance(purchase_units, list):
                shipping = purchase_units[0].get("shipping", {})
                email = shipping.get("email") or shipping.get("email_address")

        # ---------------------------------------------------
        # Si sigue sin email: error
        # ---------------------------------------------------
        if not email:
            logging.error("❌ No se pudo encontrar el email del comprador (ningún formato conocido).")
            return jsonify({"error": "email not found"}), 400

        logging.info(f"📨 Email detectado: {email}")

        # Generar token
        token = make_license(email)

        subject = "Tu licencia - Mercenary Help Finder"
        body = (
            "Gracias por tu compra.\n\n"
            "Tu token es:\n"
            f"{token}\n\n"
            "Pegalo en la UI para activar tu licencia."
        )

        send_email(email, subject, body)

        logging.info(f"✔️ Token enviado a {email}")

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logging.exception("Error en PayPal webhook")
        return jsonify({"error": "internal error"}), 500

# -------------------------------------------------------
# Punto de entrada local
# -------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)