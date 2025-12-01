# webhook_server.py
import os
import json
import sqlite3
import time
from flask import Flask, request, jsonify

# Importa la función make_license y save_license_record desde license_generator.py
# Asegúrate de que ambas funciones existen y son exportadas correctamente.
from license_generator import make_license, save_license_record 

# --- INICIALIZACIÓN DE CONFIGURACIÓN Y SERVICIOS ---

# 1. Obtenemos las claves del entorno. Si no están, son None (Null).
stripe_api_key = os.environ.get("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

# 2. Manejo Condicional de Stripe: Solo importa y configura si la clave existe.
if stripe_api_key:
    import stripe
    stripe.api_key = stripe_api_key
    print("Stripe API key configurada.")
else:
    # Si la clave falta, mostramos el warning y la app continúa.
    print("Warning: STRIPE_API_KEY no definida. El manejo de Webhooks de Stripe estará deshabilitado.")


# CONFIGURACIÓN DE RUTAS Y BASE DE DATOS
DB_PATH = os.environ.get("DB_PATH", "licenses.db")
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

# --- RUTAS DE LA APLICACIÓN ---

@app.route("/", methods=["GET"])
def index():
    # Ruta de chequeo de estado
    return jsonify({"status": "ok", "stripe_enabled": bool(stripe_api_key)}), 200


@app.route("/health", methods=["GET"])
def health():
    # Ruta de salud de Render
    return jsonify({"status":"ok"}), 200


@app.route("/webhook", methods=["POST"])
def webhook():
    # 3. Guardias de seguridad: si Stripe no arrancó, sale aquí.
    if not stripe_api_key:
        return jsonify({"error": "Stripe no configurado en el servidor."}), 400

    # Validar que exista el secret configurado
    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "Webhook secret not configured"}), 500

    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", None)
    
    try:
        # Aquí usamos la función de Stripe, que sabemos que existe si la clave es válida.
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET) 
    except ValueError:
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({"error": "Invalid signature"}), 400

    # Procesar eventos de pago completado
    if event["type"] in ("checkout.session.completed", "payment_intent.succeeded"):
        # Lógica de procesamiento de licencias
        return jsonify({"status": "ok", "message": "License processing simulated successfully"}), 200

    return jsonify({"status": "ignored"}), 200


if __name__ == "__main__":
    # Ejecutar en modo desarrollo local
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)