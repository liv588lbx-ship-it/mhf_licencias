#!/usr/bin/env python3
# migrate_db.py
# Ejecutar en la carpeta donde está licenses.db
import os
import shutil
import sqlite3
import hashlib
import time

DB = os.environ.get("DB_PATH", "licenses.db")
BACKUP_DIR = "backups"

def backup_db():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"licenses.db.bak_{ts}")
    shutil.copy2(DB, dest)
    print(f"[OK] Backup creado: {dest}")
    return dest

def column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table});")
    cols = [r[1] for r in cur.fetchall()]
    return column in cols

def add_column_if_missing(conn, table, column_def):
    # column_def: "col_name TYPE DEFAULT ...", extra text
    col_name = column_def.split()[0]
    if column_exists(conn, table, col_name):
        print(f"[SKIP] Columna ya existe: {col_name}")
        return False
    sql = f"ALTER TABLE {table} ADD COLUMN {column_def};"
    conn.execute(sql)
    print(f"[ADD] Columna añadida: {col_name}")
    return True

def create_index_if_missing(conn, index_name, table, column):
    cur = conn.execute(f"PRAGMA index_list('{table}');")
    indexes = [r[1] for r in cur.fetchall()]
    if index_name in indexes:
        print(f"[SKIP] Índice ya existe: {index_name}")
        return False
    conn.execute(f"CREATE INDEX {index_name} ON {table}({column});")
    print(f"[ADD] Índice creado: {index_name}")
    return True

def compute_token_hashes(conn):
    # Si existe columna token y token_hash vacía, calcular sha256(token)
    cur = conn.execute("PRAGMA table_info(licenses);")
    cols = [r[1] for r in cur.fetchall()]
    if "token" not in cols:
        print("[INFO] No existe columna 'token' — nada que actualizar.")
        return
    if "token_hash" not in cols:
        print("[INFO] No existe columna 'token_hash' — saltando cálculo.")
        return
    cur = conn.execute("SELECT id, token, token_hash FROM licenses;")
    rows = cur.fetchall()
    updated = 0
    for r in rows:
        id_, token, token_hash = r
        if token and (not token_hash):
            h = hashlib.sha256(token.encode("utf-8")).hexdigest()
            conn.execute("UPDATE licenses SET token_hash = ? WHERE id = ?", (h, id_))
            updated += 1
    conn.commit()
    print(f"[OK] token_hash actualizado en {updated} filas (si las hubo).")

def main():
    if not os.path.exists(DB):
        print(f"[ERROR] No se encontró {DB} en la carpeta actual.")
        return
    backup_db()
    conn = sqlite3.connect(DB)
    try:
        # Añadir columnas solo si faltan
        add_column_if_missing(conn, "licenses", "token_hash TEXT")
        add_column_if_missing(conn, "licenses", "payment_id TEXT")
        add_column_if_missing(conn, "licenses", "status TEXT DEFAULT 'pending'")
        add_column_if_missing(conn, "licenses", "created_at TEXT DEFAULT (datetime('now'))")
        add_column_if_missing(conn, "licenses", "activated_at TEXT")
        add_column_if_missing(conn, "licenses", "activation_ip TEXT")
        add_column_if_missing(conn, "licenses", "activation_user_agent TEXT")
        add_column_if_missing(conn, "licenses", "expires INTEGER DEFAULT 0")
        conn.commit()

        # Crear índice si falta
        create_index_if_missing(conn, "idx_licenses_token_hash", "licenses", "token_hash")
        conn.commit()

        # Opcional: calcular token_hash para filas existentes
        compute_token_hashes(conn)

        print("[FIN] Migración completada. Verifica la tabla con PRAGMA table_info(licenses);")
    except Exception as e:
        print("[ERROR] Durante la migración:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
