# webhook_server.py
import os
import json
import sqlite3
import time
from flask import Flask, request, jsonify
# import stripe

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
import os
from flask import Flask, request, jsonify

# Manejo seguro de la clave de Stripe: no falla si falta la variable
stripe_api_key = os.environ.get("STRIPE_API_KEY")
if stripe_api_key:
    import stripe
    stripe.api_key = stripe_api_key
else:
    print("Warning: STRIPE_API_KEY no definida. Stripe deshabilitado en este entorno.")

app = Flask(__name__)

# Ejemplo de ruta básica
@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "stripe_enabled": bool(stripe_api_key)}), 200

# Ejemplo de webhook (ajustá según tu lógica)
@app.route("/webhook", methods=["POST"])
def webhook():
    if not stripe_api_key:
        return jsonify({"error": "Stripe no configurado"}), 400

    # Si usás webhooks de Stripe, procesalos aquí.
    # body = request.get_data(as_text=True)
    # sig_header = request.headers.get("Stripe-Signature")
    # try:
    #     event = stripe.Webhook.construct_event(body, sig_header, endpoint_secret)
    # except Exception as e:
    #     return jsonify({"error": str(e)}), 400
    return jsonify({"received": True}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
