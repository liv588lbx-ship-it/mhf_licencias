# app.py (resumen)
from flask import Flask, request, jsonify
import os, secrets, hashlib, sqlite3, smtplib, json, datetime, requests

app = Flask(__name__)
DB = "licenses.db"
PAYPAL_VERIFY_URL = os.getenv("PAYPAL_VERIFY_URL","https://api-m.sandbox.paypal.com/v1/notifications/verify-webhook-signature")
PAYPAL_AUTH = os.getenv("PAYPAL_BEARER")  # Bearer token for verify endpoint

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS licenses(
            id INTEGER PRIMARY KEY, tx_id TEXT, buyer_email TEXT, token_hash TEXT UNIQUE,
            issued_at TEXT, activated_at TEXT, expires_at TEXT, used INTEGER DEFAULT 0)""")

def hash_token(t): return hashlib.sha256(t.encode()).hexdigest()

def send_email(to, subject, body):
    smtp_host = os.getenv("SMTP_HOST"); smtp_user=os.getenv("SMTP_USER"); smtp_pass=os.getenv("SMTP_PASS")
    msg = f"From:{smtp_user}\nTo:{to}\nSubject:{subject}\n\n{body}"
    s = smtplib.SMTP(smtp_host); s.starttls(); s.login(smtp_user,smtp_pass); s.sendmail(smtp_user,[to],msg); s.quit()

@app.route("/webhooks/paypal", methods=["POST"])
def paypal_webhook():
    # 1) verify signature with PayPal API
    transmission_id = request.headers.get("Paypal-Transmission-Id")
    transmission_sig = request.headers.get("Paypal-Transmission-Sig")
    transmission_time = request.headers.get("Paypal-Transmission-Time")
    cert_url = request.headers.get("Paypal-Cert-Url")
    auth_algo = request.headers.get("Paypal-Auth-Algo")
    webhook_id = os.getenv("PAYPAL_WEBHOOK_ID")
    event_body = request.get_json()

    verify_payload = {
      "transmission_id": transmission_id,
      "transmission_time": transmission_time,
      "transmission_sig": transmission_sig,
      "cert_url": cert_url,
      "auth_algo": auth_algo,
      "webhook_id": webhook_id,
      "webhook_event": event_body
    }
    headers = {"Content-Type":"application/json","Authorization":f"Bearer {PAYPAL_AUTH}"}
    r = requests.post(PAYPAL_VERIFY_URL, json=verify_payload, headers=headers)
    if r.status_code!=200 or r.json().get("verification_status")!="SUCCESS":
        return "invalid", 400

    # 2) on successful payment create token and email
    # adapt event type check to sale/completed
    payer_email = event_body.get("resource",{}).get("payer",{}).get("email_address") or event_body.get("resource",{}).get("payer_email")
    tx_id = event_body.get("resource",{}).get("id")
    token = secrets.token_urlsafe(32)
    th = hash_token(token)
    now = datetime.datetime.utcnow().isoformat()
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO licenses(tx_id,buyer_email,token_hash,issued_at) VALUES(?,?,?,?)",
                  (tx_id,payer_email,th,now))
    send_email(payer_email, "Tu token de licencia", f"Tu token: {token}\nPégalo en la UI para activar la licencia.")
    return "", 200

@app.route("/api/licenses/activate", methods=["POST"])
def activate():
    data = request.get_json() or {}
    token = data.get("token","").strip()
    if not token: return jsonify({"error":"token requerido"}),400
    th = hash_token(token)
    with sqlite3.connect(DB) as c:
        cur = c.cursor()
        cur.execute("SELECT id,used FROM licenses WHERE token_hash=?",(th,))
        row = cur.fetchone()
        if not row: return jsonify({"error":"token inválido"}),404
        if row[1]: return jsonify({"error":"token ya usado"}),400
        activated = datetime.datetime.utcnow()
        expires = activated + datetime.timedelta(hours=36)
        c.execute("UPDATE licenses SET used=1, activated_at=?, expires_at=? WHERE id=?",
                  (activated.isoformat(), expires.isoformat(), row[0]))
    return jsonify({"status":"activated","expires_at":expires.isoformat()})

if __name__=="__main__":
    init_db()
    app.run(port=8000)
