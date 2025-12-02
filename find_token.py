# find_token.py
import sqlite3, os, json, sys

DB = os.environ.get("DB_PATH", "licenses.db")
if not os.path.exists(DB):
    print("ERROR: no se encontró", DB)
    sys.exit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("PRAGMA table_info(tokens);")
cols = [r[1] for r in cur.fetchall()]

cur.execute("SELECT rowid, * FROM tokens WHERE token = ? COLLATE NOCASE", ("TEST-TOKEN-12345",))
rows = cur.fetchall()

if not rows:
    print("No se encontró ninguna fila con token = TEST-TOKEN-12345")
else:
    for r in rows:
        obj = {"rowid": r[0]}
        for i, c in enumerate(cols):
            obj[c] = r[i+1]
        print(json.dumps(obj, ensure_ascii=False, indent=2))

conn.close()
