import os
import json
import sqlite3
import time
import base64
import hashlib
import smtplib
import logging
from email.mime.text import MIMEText
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, Response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Importación de la lógica de generación de licencias
from license_generator import make_license

# Logging de arranque para verificar despliegue
logging.basicConfig(level=logging.INFO)
logging.info("WEBHOOK_SERVER LOADED - CASADEY v2")

app = Flask(__name__)

# Configuración de otras variables de entorno (leídas cuando se usan)
stripe_api_key = os.environ.get("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = os.environ.get("EMAIL_PORT")
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
EMAIL_FROM = os.environ.get("EMAIL_FROM", EMAIL_USER)

# -------------------------------------------------------
# Función para enviar email
# -------------------------------------------------------
def send_email(to_address, subject, body):
    host = os.environ.get("EMAIL_HOST")
    port = int(os.environ.get("EMAIL_PORT") or 25)
    user = os.environ.get("EMAIL_USER")
    password = os.environ.get("EMAIL_PASS")
    from_addr = os.environ.get("EMAIL_FROM", user)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_address

    s = smtplib.SMTP(host, port, timeout=10)
    try:
        if user and password:
            s.starttls()
            s.login(user, password)
        s.sendmail(from_addr, [to_address], msg.as_string())
    finally:
        s.quit()

# -------------------------------------------------------
# Ruta admin para generar token manualmente
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

        token = make_license(email)
        return jsonify({"token": token}), 200
    except Exception as e:
        logging.exception("Error generating token")
        return jsonify({"error": "internal error"}), 500

# -------------------------------------------------------
# Webhook genérico (no afecta PayPal)
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
# 🌟 WEBHOOK DE PAYPAL — AQUÍ SE GENERA Y ENVÍA EL TOKEN
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

        payer_info = (
            data.get("resource", {})
                .get("payer", {})
                .get("payer_info", {})
        )

        email = payer_info.get("email") or payer_info.get("email_address")

        if not email:
            logging.error("❌ No se pudo encontrar el email del comprador.")
            return jsonify({"error": "email not found"}), 400

        token = make_license(email)

        subject = "Tu licencia - Mercenary Help Finder"
        body = f"Gracias por tu compra.\n\nTu token es:\n{token}\n\nPegalo en la UI para activar tu licencia."

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
