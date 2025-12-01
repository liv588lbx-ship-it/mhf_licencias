# webhook_server.py
import os
import json
import sqlite3
import time
from flask import Flask, request, jsonify
import stripe

# Importa la función make_license y save_license_record desde license_generator.py
from license_generator import make_license

# CONFIGURACIÓN
DB_PATH = os.environ.get("DB_PATH", "licenses.db")
PRIV_KEY_PATH = os.environ.get("PRIV_KEY_PATH", "priv.pem")
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

if not STRIPE_API_KEY:
    raise RuntimeError("Falta STRIPE_API_KEY en variables de entorno")

stripe.api_key = STRIPE_API_KEY

app = Flask(__name__)

# Inicializar DB simple SQLite
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY,
        user_email TEXT,
        token TEXT,
        issued INTEGER,
        expires INTEGER,
        meta TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

def save_license_record(payload, token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (id, user_email, token, issued, expires, meta) VALUES (?, ?, ?, ?, ?, ?)",
        (payload["license_id"], payload["user"], token, payload["issued"], payload["expires"], json.dumps(payload.get("extra", {})))
    )
    conn.commit()
    conn.close()

@app.route("/webhook", methods=["POST"])
def webhook():
    # Validar que exista el secret configurado
    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "Webhook secret not configured"}), 500

    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", None)
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({"error": "Invalid signature"}), 400

    # Procesar eventos de pago completado
    if event["type"] in ("checkout.session.completed", "payment_intent.succeeded"):
        obj = event["data"]["object"]

        # Obtener email del cliente
        customer_email = None
        if "customer_details" in obj:
            customer_email = obj.get("customer_details", {}).get("email")
        if not customer_email:
            customer_email = obj.get("receipt_email") or obj.get("customer_email")

        # Determinar cantidad comprada
        quantity = 1
        try:
            if event["type"] == "checkout.session.completed":
                session_id = obj.get("id")
                if session_id:
                    session = stripe.checkout.Session.retrieve(session_id, expand=["line_items"])
                    items = session.get("line_items", {}).get("data", [])
                    if items:
                        quantity = sum(int(it.get("quantity", 1)) for it in items)
        except Exception:
            quantity = 1

        if not customer_email:
            return jsonify({"error": "No email found in event"}), 400

        tokens = []
        for _ in range(int(quantity)):
            token, payload = make_license(customer_email, validity_hours=36, priv_key_path=PRIV_KEY_PATH, extra={"source":"stripe"})
            save_license_record(payload, token)
            tokens.append({"license_id": payload["license_id"], "token": token, "expires": payload["expires"]})

        # En pruebas devolvemos los tokens en la respuesta JSON
        return jsonify({"status": "ok", "licenses": tokens}), 200

    return jsonify({"status": "ignored"}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"}), 200

if __name__ == "__main__":
    # Ejecutar en modo desarrollo local
    app.run(host="0.0.0.0", port=5000, debug=True)
