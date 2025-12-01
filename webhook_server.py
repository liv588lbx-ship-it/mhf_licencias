# webhook_server.py
import os
import json
import sqlite3
import time
from flask import Flask, request, jsonify

# CORRECCIÓN: Solo importamos make_license, porque save_license_record no está en ese archivo
from license_generator import make_license

# --- INICIALIZACIÓN DE CONFIGURACIÓN Y SERVICIOS ---

stripe_api_key = os.environ.get("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

# Manejo Condicional de Stripe
if stripe_api_key:
    import stripe
    stripe.api_key = stripe_api_key
    print("Stripe API key configurada.")
else:
    print("Warning: STRIPE_API_KEY no definida. El manejo de Webhooks de Stripe estará deshabilitado.")

# CONFIGURACIÓN DE RUTAS Y BASE DE DATOS
DB_PATH = os.environ.get("DB_PATH", "licenses.db")
# NOTA: Asegúrate de que este archivo (priv.pem) exista en Render o fallará al generar licencias
PRIV_KEY_PATH = os.environ.get("PRIV_KEY_PATH", "priv.pem") 

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

# --- FUNCIONES DE AYUDA (Agregada aquí porque no estaba en license_generator) ---

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
        if conn:
            conn.close()

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

    # Procesar eventos de pago
    if event["type"] in ("checkout.session.completed", "payment_intent.succeeded"):
        # AQUÍ IRÍA TU LÓGICA DE EXTRACCIÓN DE DATOS DE STRIPE
        # Por ahora simulamos que todo salió bien para probar el deploy
        return jsonify({"status": "ok", "message": "Webhook processed"}), 200

    return jsonify({"status": "ignored"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)