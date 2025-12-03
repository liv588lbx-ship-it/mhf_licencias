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

from license_generator import make_license

logging.basicConfig(level=logging.INFO)
logging.info("WEBHOOK_SERVER LOADED - CASADEY v4 🔥")

app = Flask(__name__)

# Variables
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = os.environ.get("EMAIL_PORT")
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
EMAIL_FROM = os.environ.get("EMAIL_FROM", EMAIL_USER)
ADMIN_KEY = os.environ.get("ADMIN_KEY")


# -------------------------------------------------------
# Enviar Email
# -------------------------------------------------------
def send_email(to_address, subject, body):
    logging.info("📧 Enviando email:")
    logging.info(f"  Host: {EMAIL_HOST}")
    logging.info(f"  Port: {EMAIL_PORT}")
    logging.info(f"  User: {EMAIL_USER}")
    logging.info(f"  To:   {to_address}")

    try:
        host = EMAIL_HOST
        port = int(EMAIL_PORT or 587)
        user = EMAIL_USER
        password = EMAIL_PASS
        from_addr = EMAIL_FROM

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_address

        s = smtplib.SMTP(host, port, timeout=20)
        s.set_debuglevel(1)   # LOG SMTP COMPLETO

        if user and password:
            s.starttls()
            s.login(user, password)

        s.sendmail(from_addr, [to_address], msg.as_string())
        s.quit()
        logging.info("✔️ Email enviado correctamente")

    except Exception as e:
        logging.error(f"❌ ERROR enviando email: {e}")


# -------------------------------------------------------
# Admin — generar token manual
# -------------------------------------------------------
@app.route("/admin/generate-token", methods=["POST"])
def admin_generate_token():
    logging.info("📩 /admin/generate-token llamado")

    provided_key = request.headers.get("X-Admin-Key")
    if provided_key != ADMIN_KEY:
        logging.error("⛔ Admin-Key incorrecta")
        return Response("Unauthorized", 401)

    try:
        payload = request.get_json(force=True)
        email = payload.get("email")
        if not email:
            return jsonify({"error": "email required"}), 400

        token = make_license(email)

        logging.info(f"✔️ Token generado: {token}")

        # Enviar email
        subject = "Tu licencia - Mercenary Help Finder"
        body = f"Tu token es:\n{token}\n\nGracias por tu compra."

        send_email(email, subject, body)

        return jsonify({"token": token, "sent_to": email}), 200

    except Exception as e:
        logging.exception("🔥 ERROR en /admin/generate-token")
        return jsonify({"error": "internal error"}), 500


# -------------------------------------------------------
# Webhook PayPal (NO TOCAMOS NADA)
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

        # Buscar email del comprador en diferentes formatos
        email = (
            data.get("resource", {})
                .get("payer", {})
                .get("payer_info", {})
                .get("email")
        )

        if not email:
            email = (
                data.get("resource", {})
                    .get("payer", {})
                    .get("email_address")
            )

        if not email:
            purchase_units = data.get("resource", {}).get("purchase_units", [])
            if purchase_units and isinstance(purchase_units, list):
                shipping = purchase_units[0].get("shipping", {})
                email = shipping.get("email") or shipping.get("email_address")

        if not email:
            logging.error("❌ Email no encontrado")
            return jsonify({"error": "email not found"}), 400

        logging.info(f"📨 Email detectado: {email}")

        token = make_license(email)

        subject = "Tu licencia - Mercenary Help Finder"
        body = f"Tu token es:\n{token}\n\nPegalo en la UI."

        send_email(email, subject, body)

        logging.info(f"✔️ Enviado token a {email}")

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logging.exception("Error en PayPal webhook")
        return jsonify({"error": "internal error"}), 500


# -------------------------------------------------------
# Main local
# -------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
