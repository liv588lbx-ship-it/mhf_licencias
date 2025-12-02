# verify_tokens.py
import sqlite3, os, sys, pprint
DB = os.environ.get('DB_PATH', 'licenses.db')
if not os.path.exists(DB):
    print("ERROR: no se encontró", DB)
    sys.exit(1)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT rowid, email, status, used, token, token_hash, activated_at FROM tokens ORDER BY rowid DESC;")
rows = cur.fetchall()
if not rows:
    print("No hay filas en la tabla tokens.")
else:
    for r in rows:
        pprint.pprint(dict(zip(['rowid','email','status','used','token','token_hash','activated_at'], r)))
conn.close()
