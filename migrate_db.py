# migrate_db.py
import sqlite3, os, sys

DB = os.environ.get("DB_PATH", os.path.join(os.getcwd(), "licenses.db"))

expected_columns = {
    "activated_at": "INTEGER",
    "expires": "INTEGER",
    "issued_expires": "INTEGER",
    "duration_hours": "INTEGER DEFAULT 36",
    "used": "INTEGER DEFAULT 0"
}

def get_columns(conn):
    cur = conn.execute("PRAGMA table_info(tokens);")
    return {row[1] for row in cur.fetchall()}

def add_column(conn, name, definition):
    sql = f"ALTER TABLE tokens ADD COLUMN {name} {definition};"
    print("Executing:", sql)
    conn.execute(sql)

def main():
    if not os.path.exists(DB):
        print("DB not found:", DB)
        sys.exit(1)
    conn = sqlite3.connect(DB)
    cols = get_columns(conn)
    to_add = [(n,d) for n,d in expected_columns.items() if n not in cols]
    if not to_add:
        print("No columns to add. DB schema already up to date.")
        conn.close()
        return
    for name, definition in to_add:
        try:
            add_column(conn, name, definition)
            conn.commit()
            print("Added column:", name)
        except Exception as e:
            print("Failed to add", name, ":", e)
    conn.close()
    print("Migration finished.")

if __name__ == "__main__":
    main()
