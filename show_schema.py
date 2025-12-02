# show_schema.py
import sqlite3, os, sys
DB = os.environ.get('DB_PATH', 'licenses.db')
if not os.path.exists(DB):
    print("ERROR: no se encontró", DB)
    sys.exit(1)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute('PRAGMA table_info(tokens);')
cols = cur.fetchall()
for c in cols:
    print(c)
conn.close()
