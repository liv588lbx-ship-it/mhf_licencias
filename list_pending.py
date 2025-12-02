# list_pending.py
import sqlite3, os, sys, pprint
DB = os.environ.get('DB_PATH', 'licenses.db')
if not os.path.exists(DB):
    print("ERROR: no se encontró", DB)
    sys.exit(1)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT rowid, token, email, token_hash, status, used, created_at FROM tokens WHERE status='pending' OR used=0 ORDER BY rowid DESC;")
rows = cur.fetchall()
if not rows:
    print("No hay tokens con status='pending' ni filas con used=0.")
else:
    for r in rows:
        pprint.pprint(dict(zip(['rowid','token','email','token_hash','status','used','created_at'], r)))
conn.close()
