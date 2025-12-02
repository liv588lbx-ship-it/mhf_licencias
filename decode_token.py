import base64, json

# Pega aquí el token completo entre comillas
t = "eyJleHBpcmVzIjoxNzY0NjQyMzcwLCJleHRyYSI6e30sImlzc3VlZCI6MTc2NDY0MjM3MCwibGljZW5zZV9pZCI6IjAyNjNjZmUxLTQ1ZDgtNDg1MS1iZTMwLTg5M2E0MzlhYTU4MSIsInVzZXIiOiJzaGFtYW5lc0BnbWFpbC5jb20iLCJ2YWxpZF9ob3VycyI6MH0.MSjGdn8SR1iIJXadBlkaRraTC0A1UV1ybsxkObgloXyDbTEfAQNUD6BfgxlvpMkbRlkTbzfHbV_xkQfEXS6d4Iz46mpnPPamp-lJRUxphgOMrvxSbmL_yB2MJ-M99rWWrBgNVooYZkE00FCu6Zxb8oAf4i65CsM1dQqoZjEXTMVPkR2HDgtyd8czymVrcrK0Zwr33QNU4o-VZJYakHaEYWxAzvLYROT8g-jYLV7ok7Icw1mF-5B-a21dFubOZD9_bPlYgk4nXc-pj-Znesutx_189n8ISyskpX3CnhyV-ceo2HGuoIkn3cLWIuajNV0AXqFNyjiwV6T_Gzq6kJBhQQ"

parts = t.split('.')
if len(parts) < 2:
    raise SystemExit("Token inválido: formato incorrecto")

payload_b64 = parts[1]
pad = '=' * ((4 - len(payload_b64) % 4) % 4)
payload_bytes = base64.urlsafe_b64decode(payload_b64 + pad)

# Intentar decodificar como UTF-8; si falla, mostrar con reemplazo para inspección
try:
    payload_text = payload_bytes.decode('utf-8')
except UnicodeDecodeError:
    payload_text = payload_bytes.decode('utf-8', errors='replace')

# Cargar JSON y mostrarlo formateado
try:
    payload_json = json.loads(payload_text)
    print(json.dumps(payload_json, indent=2, ensure_ascii=False))
    # Mostrar campos útiles
    print("\n--- Campos clave ---")
    print("license_id:", payload_json.get("license_id"))
    print("user:", payload_json.get("user"))
    print("issued:", payload_json.get("issued"))
    print("expires:", payload_json.get("expires"))
except Exception as e:
    print("No se pudo parsear JSON del payload:", e)
    print("Payload (texto):")
    print(payload_text)
