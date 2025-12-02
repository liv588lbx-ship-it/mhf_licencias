# insert_test_token.py
import sqlite3, os, time, uuid, sys
DB = os.environ.get("DB_PATH", "licenses.db")
if not os.path.exists(DB):
    print("ERROR: no se encontró", DB); sys.exit(1)
conn = sqlite3.connect(DB)
cur = conn.cursor()
token = "TEST-TOKEN-12345"
email = "test@example.com"
issued = int(time.time())
expires = issued + 3600*24
cur.execute(
    "INSERT INTO tokens (token, email, issued, expires, used, activated_at, issued_expires, duration_hours, token_hash, payment_id, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))",
    (token, email, issued, expires, 0, None, None, 36, None, "test-pay-123", "pending")
)
conn.commit()
print("Insertado token de prueba:", token)
conn.close()

