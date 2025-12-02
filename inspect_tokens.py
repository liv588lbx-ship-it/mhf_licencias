# inspect_tokens.py
import sqlite3, os, json

DB = os.environ.get("DB_PATH", "licenses.db")

if not os.path.exists(DB):
    print("ERROR: No se encontró", DB)
    raise SystemExit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

print("Conectado a:", DB)
print("\n--- Tablas en la DB ---")
cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
for r in cur.fetchall():
    print("-", r[0])

print("\n--- Estructura de la tabla 'tokens' (PRAGMA table_info) ---")
try:
    cur.execute("PRAGMA table_info(tokens);")
    cols = cur.fetchall()
    if not cols:
        print("La tabla 'tokens' no existe o está vacía.")
    else:
        for c in cols:
            # c: (cid, name, type, notnull, dflt_value, pk)
            print(f"{c[1]} | {c[2]} | notnull={c[3]} | default={c[4]} | pk={c[5]}")
except Exception as e:
    print("Error al obtener PRAGMA table_info(tokens):", e)

print("\n--- Primeras 10 filas de tokens (si existen) ---")
try:
    cur.execute("SELECT * FROM tokens LIMIT 10;")
    rows = cur.fetchall()
    if not rows:
        print("No hay filas en tokens.")
    else:
        # imprimir columnas y filas en JSON para legibilidad
        col_names = [d[1] for d in cur.description]
        print("Columnas:", col_names)
        for r in rows:
            obj = dict(zip(col_names, r))
            print(json.dumps(obj, ensure_ascii=False))
except Exception as e:
    print("Error al leer filas de tokens:", e)

conn.close()
print("\n--- FIN ---")
