import sqlite3, os
DB = os.environ.get("DB_PATH", "licenses.db")
if not os.path.exists(DB):
    print("ERROR: no se encontró", DB)
else:
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    rows = cur.fetchall()
    if not rows:
        print("No hay tablas en la base de datos.")
    else:
        print("Tablas en la DB:")
        for r in rows:
            print("-", r[0])
    conn.close()
