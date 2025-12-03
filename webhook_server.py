import os
import json
import sqlite3
import time
import base64
import hashlib
import smtplib
import logging
import ssl 
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, Response
# Estas son librerías de criptografía que deberían estar importadas
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Importación de la lógica de generación y VERIFICACIÓN de licencias
# ASUMIMOS que license_generator.py AHORA CONTIENE make_license Y check_license
from license_generator import make_license, check_license # <--- IMPORTACIÓN DE check_license AÑADIDA

# Logging de arranque para verificar despliegue
logging.basicConfig(level=logging.INFO)
logging.info("WEBHOOK_SERVER LOADED - CASADEY v4 (Final)")

app = Flask(__name__)

# --- CONFIGURACIÓN DE VARIABLES DE ENTORNO ---
EMAIL_FROM = os.environ.get("EMAIL_FROM")
DISPLAY_NAME = os.environ.get("EMAIL_DISPLAY_NAME", "TotalHelper")
DEFAULT_LANG = os.environ.get("DEFAULT_LANG", "en")
# -------------------------------------------------------

# --- MENSAJES BILINGÜES ---
MESSAGES = {
    "es": {
        "subject": "Tu Licencia - Mercenary Help Finder",
        "greeting": "Hola Guerrero, Muchas gracias por tu compra.",
        "manual_note": "(Generada Manualmente).",
        "token_line": "Tu Token es:",
        "instruction": "Asegúrate de Leer las Instrucciones de Uso en el Software Mercenary Finder, Activar tu Licencia y a disfrutar del Intercambio de Mercenarios. ¡Apurate, el tiempo corre!"
    },
    "en": {
        "subject": "Your License - Mercenary Help Finder",
        "greeting": "Hello Warrior, Thank you very much for your purchase.",
        "manual_note": "(Manually Generated).",
        "token_line": "Your Token is:",
        "instruction": "Be sure to Read the Usage Instructions in the Mercenary Finder Software, Activate your License and enjoy the Mercenary Exchange. Hurry up, time is ticking!"
    }
}
# -------------------------------------------------------


# -------------------------------------------------------
# Función para enviar email (Sin cambios)
# -------------------------------------------------------
def send_email(to_address, subject, body):
    host = os.environ.get("EMAIL_HOST")
    port = int(os.environ.get("EMAIL_PORT") or 587)
    user = os.environ.get("EMAIL_USER")
    password = os.environ.get("EMAIL_PASS")
    from_addr = os.environ.get("EMAIL_FROM", user)
    display_name = os.environ.get("EMAIL_DISPLAY_NAME", "TotalHelper")

    if not host or not user or not password or not from_addr:
        logging.error("❌ Faltan credenciales de email (HOST, USER, PASS, FROM).")
        raise Exception("Faltan variables de entorno SMTP requeridas.")

    full_from_address = str(Header(f"{display_name} <{from_addr}>"))

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = full_from_address
    msg["To"] = to_address
    
    s = smtplib.SMTP(host, port, timeout=10)
    
    try:
        logging.info(f"Intentando login SMTP con {user} en el puerto {port}...")
        s.starttls()
        s.login(user, password)
        s.sendmail(from_addr, [to_address], msg.as_string())
        logging.info(f"Correo enviado exitosamente a {to_address}")

    except smtplib.SMTPAuthenticationError as auth_err:
        logging.error(f"❌ Error de autenticación SMTP: {auth_err}")
        raise Exception("Error de autenticación al enviar el email. Revisar EMAIL_PASS/USER.")

    except Exception as e:
        logging.error(f"❌ Error general al enviar el email: {e}")
        raise Exception(f"Error de conexión SMTP: {e}. Revisar HOST/PORT o EMAIL_FROM.")

    finally:
        s.quit()

# -------------------------------------------------------
# Ruta admin para generar token manualmente (Sin cambios)
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

        # Generar Token: DESEMPAQUETAR TUPLA
        token, metadata = make_license(email)

        # SELECCIONAR IDIOMA
        lang = DEFAULT_LANG
        texts = MESSAGES.get(lang, MESSAGES["en"])

        # Preparar el Email
        subject = texts["subject"]
        body = (
            f"{texts['greeting']} {texts['manual_note']}\n\n"
            f"{texts['token_line']}\n"
            f"{token}\n\n"
            f"{texts['instruction']}"
        )

        # Enviar el Email
        logging.info(f"Intentando enviar email manual a: {email}")
        send_email(email, subject, body)

        # Devolver solo el token y el mensaje limpio en el JSON de respuesta
        return jsonify({"token": token, "message": "Email enviado"}), 200

    except Exception as e:
        logging.exception("Error en el proceso de generar token / enviar email")
        return jsonify({"error": str(e)}), 500

# -------------------------------------------------------
# Webhook genérico (Sin Cambios)
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
# 🔑 RUTA AÑADIDA: VALIDACIÓN DE LICENCIA (/license/check)
# -------------------------------------------------------
@app.route("/license/check", methods=["POST"])
def check_license_route():
    """Verifica la validez de un token usando la lógica de check_license."""
    try:
        data = request.get_json(force=True)
        token_to_check = data.get("token")

        if not token_to_check:
            return jsonify({"status": "error", "message": "Token requerido"}), 400

        logging.info(f"🔎 Recibida solicitud para verificar token: {token_to_check[:15]}...")

        # Llama a check_license, que lanza una excepción si es inválido/expirado
        metadata = check_license(token_to_check)

        # Si no lanzó excepción, es válido
        logging.info(f"✔️ Token verificado exitosamente. Usuario: {metadata.get('user')}")
        return jsonify({
            "status": "valid",
            "message": "Licencia válida.",
            "metadata": metadata
        }), 200

    except Exception as e:
        # Captura la excepción lanzada por check_license (expirado, firma inválida, etc.)
        logging.error(f"❌ Error al validar el token: {e}")
        return jsonify({
            "status": "invalid",
            "message": f"El token no es válido: {str(e)}"
        }), 401


# -------------------------------------------------------
# 🌟 WEBHOOK DE PAYPAL — GENERA Y ENVÍA EL TOKEN (Sin cambios)
# -------------------------------------------------------
@app.route("/paypal-webhook", methods=["POST"])
def paypal_webhook():
    try:
        data = request.get_json(force=True)
        logging.info("📩 PAYPAL WEBHOOK RECIBIDO")
        event_type = data.get("event_type")

        if event_type not in ["PAYMENT.SALE.COMPLETED", "PAYMENT.CAPTURE.COMPLETED"]:
            logging.info(f"Ignorado evento PayPal: {event_type}")
            return jsonify({"status": "ignored"}), 200

        # Lógica para extraer el email del JSON de PayPal
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
            logging.error("❌ No se pudo encontrar el email del comprador (ningún formato conocido).")
            return jsonify({"error": "email not found"}), 400

        logging.info(f"📨 Email detectado: {email}")

        # Generar token: DESEMPAQUETAR TUPLA
        token, metadata = make_license(email)

        # SELECCIONAR IDIOMA
        lang = DEFAULT_LANG
        texts = MESSAGES.get(lang, MESSAGES["en"])

        subject = texts["subject"]
        body = (
            f"{texts['greeting']}\n\n"
            f"{texts['token_line']}\n"
            f"{token}\n\n"
            f"{texts['instruction']}"
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