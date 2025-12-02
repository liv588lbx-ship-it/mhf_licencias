#!/usr/bin/env python3
import os, sys, base64, json, sqlite3, requests

DB_PATH = "licenses.db"
API_BASE = "http://127.0.0.1:5000"

def b64url_decode(s):
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def try_json_from_part(token, index):
    parts = token.split('.')
    if len(parts) <= index:
        return None, "no_part"
    part = parts[index]
    try:
        raw = b64url_decode(part)
    except Exception as e:
        return None, f"b64_error: {e}"
    try:
        text = raw.decode('utf-8')
    except Exception:
        text = raw.decode('utf-8', errors='replace')
    try:
        return json.loads(text), None
    except Exception as e:
        return text, f"json_error: {e}"

def decode_token(token):
    print("\n--- Header ---")
    hdr, err = try_json_from_part(token, 0)
    if err:
        print("Header decode issue:", err)
        print(hdr)
    else:
        print(json.dumps(hdr, indent=2, ensure_ascii=False))

    print("\n--- Payload ---")
    payload, err = try_json_from_part(token, 1)
    if err:
        print("Payload decode issue:", err)
        print(payload)
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))

def regen_token(email):
    admin_key = os.environ.get("ADMIN_KEY")
    if not admin_key:
        print("ERROR: ADMIN_KEY no está definida en esta sesión.")
        return None
    url = f"{API_BASE}/admin/generate-token"
    headers = {"Content-Type":"application/json", "X-Admin-Key": admin_key}
    data = {"email": email}
    try:
        r = requests.post(url, json=data, headers=headers, timeout=10)
        print("Admin generate-token response:", r.status_code, r.text)
        return r.json() if r.headers.get("Content-Type","").startswith("application/json") else None
    except Exception as e:
        print("Error llamando /admin/generate-token:", e)
        return None

def get_latest_token_for_email(email):
    if not os.path.exists(DB_PATH):
        print("No se encontró", DB_PATH)
        return None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT rowid, id, user_email, token, status, created_at, issued FROM licenses WHERE user_email=? ORDER BY rowid DESC LIMIT 1", (email,))
    row = cur.fetchone()
    conn.close()
    if not row:
        print("No hay filas para ese email.")
        return None
    rowid, id_, user_email, token, status, created_at, issued = row
    print("\n--- Fila encontrada ---")
    print("rowid:", rowid)
    print("id:", id_)
    print("user_email:", user_email)
    print("status:", status)
    print("created_at:", created_at)
    print("issued:", issued)
    return token

def activate_token(token, email):
    url = f"{API_BASE}/activate"
    headers = {"Content-Type":"application/json"}
    data = {"token": token, "user_email": email}
    try:
        r = requests.post(url, json=data, headers=headers, timeout=10)
        print("\nActivate response:", r.status_code)
        print(r.text)
        return r
    except Exception as e:
        print("Error llamando /activate:", e)
        return None

def main():
    print("Script de gestión de tokens\n")
    email = "shamanes@gmail.com"
    print("Email objetivo:", email)
    print("Asegurate de haber arrancado el servidor Flask en esta máquina.\n")

    # Paso A: regenerar token si el usuario quiere
    choice = input("1) ¿Querés regenerar un token nuevo ahora? (s/n) [n]: ").strip().lower() or "n"
    new_info = None
    if choice == "s":
        new_info = regen_token(email)

    # Paso B: obtener el token más reciente desde la DB
    choice2 = input("\n2) ¿Querés extraer el token más reciente desde la DB para este email? (s/n) [s]: ").strip().lower() or "s"
    token = None
    if choice2 == "s":
        token = get_latest_token_for_email(email)
        if token:
            print("\nToken (preview 200 chars):\n", token[:200])

    # Paso C: decodificar header/payload si hay token
    if token:
        decode_choice = input("\n3) ¿Querés decodificar header/payload del token encontrado? (s/n) [s]: ").strip().lower() or "s"
        if decode_choice == "s":
            decode_token(token)

    # Paso D: activar token
    if token:
        act_choice = input("\n4) ¿Activar este token ahora? (s/n) [n]: ").strip().lower() or "n"
        if act_choice == "s":
            activate_token(token, email)

    print("\nFin. Si necesitás repetir, ejecutá el script otra vez.")

if __name__ == "__main__":
    try:
        import requests
    except Exception:
        print("Este script requiere la librería 'requests'. Instalala con:")
        print("  pip install requests")
        sys.exit(1)
    main()
