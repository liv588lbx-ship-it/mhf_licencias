#!/usr/bin/env python3
# migrate_tokens_fix.py
import os, sqlite3, time, shutil

DB = os.environ.get("DB_PATH", "licenses.db")
BACKUP_DIR = "backups_fix"

def backup_db():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"licenses.db.bak_fix_{ts}")
    shutil.copy2(DB, dest)
    print(f"[OK] Backup creado: {dest}")
    return dest

def column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table});")
    cols = [r[1] for r in cur.fetchall()]
    return column in cols

def add_column_if_missing(conn, table, column_def):
    col_name = column_def.split()[0]
    if column_exists(conn, table, col_name):
        print(f"[SKIP] Columna ya existe: {col_name}")
        return False
    sql = f"ALTER TABLE {table} ADD COLUMN {column_def};"
    conn.execute(sql)
    print(f"[ADD] Columna añadida: {col_name}")
    return True

def set_created_at_now(conn, table, col_name="created_at"):
    # Poner created_at = ahora (ISO) donde sea NULL o vacío
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn.execute(f"UPDATE {table} SET {col_name} = ? WHERE {col_name} IS NULL OR {col_name} = ''", (now_iso,))
    updated = conn.total_changes
    conn.commit()
    print(f"[OK] {col_name} actualizado en filas (si las hubo).")

def main():
    if not os.path.exists(DB):
        print(f"[ERROR] No se encontró {DB} en la carpeta actual.")
        return
    backup_db()
    conn = sqlite3.connect(DB)
    try:
        # Añadir columnas sin defaults problemáticos
        add_column_if_missing(conn, "tokens", "created_at TEXT")
        add_column_if_missing(conn, "tokens", "activation_ip TEXT")
        add_column_if_missing(conn, "tokens", "activation_user_agent TEXT")
        conn.commit()

        # Rellenar created_at para filas existentes
        set_created_at_now(conn, "tokens", "created_at")

        print("[FIN] Corrección completada. Verifica la estructura de la tabla.")
    except Exception as e:
        print("[ERROR] Durante la corrección:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
