# find_pending.py
import sqlite3, os, json, sys
DB = os.environ.get('DB_PATH', 'licenses.db')
if not os.path.exists(DB):
    print("ERROR: no se encontró", DB)
    sys.exit(1)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT rowid, token, email, token_hash, token_sent, status, created_at FROM tokens WHERE token_sent IS NULL OR token_sent=0 ORDER BY rowid DESC;")
rows = cur.fetchall()
if not rows:
    print("No hay tokens pendientes (token_sent false).")
else:
    for r in rows:
        print(dict(zip(["rowid","token","email","token_hash","token_sent","status","created_at"], r)))
conn.close()
