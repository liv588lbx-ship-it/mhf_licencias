import os
import json
import base64
import time
from datetime import datetime, timedelta, timezone

# Criptografía (RSA + SHA256)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# ------------------------------
# Utilidades de carga de claves
# ------------------------------

def _load_private_key():
    """
    Carga SIEMPRE la misma clave privada desde:
    1) Variable de entorno PRIVATE_KEY_PEM (preferida)
    2) /etc/secrets/priv.pem (Secret Files de Render)
    3) /opt/render/project/src/priv.pem (legacy)
    """
    pem = os.getenv("PRIVATE_KEY_PEM")
    if pem:
        return load_pem_private_key(pem.encode("utf-8"), password=None)

    for path in ("/etc/secrets/priv.pem", "/opt/render/project/src/priv.pem"):
        try:
            with open(path, "rb") as f:
                data = f.read()
            return load_pem_private_key(data, password=None)
        except FileNotFoundError:
            continue

    raise FileNotFoundError("No se encontró PRIVATE_KEY_PEM ni priv.pem en las rutas conocidas.")

def _get_public_key():
    """Deriva la clave pública desde la misma privada para garantizar sincronía."""
    return _load_private_key().public_key()

# ------------------------------
# Firma y verificación cripto
# ------------------------------

def sign_bytes(payload_bytes: bytes) -> bytes:
    """Firma bytes con la clave privada unificada (RSA PKCS1v15 + SHA256)."""
    priv = _load_private_key()
    return priv.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_bytes(payload_bytes: bytes, signature: bytes) -> None:
    """
    Verifica con la clave pública derivada de la misma privada.
    Lanza excepción (InvalidSignature) si la verificación falla.
    """
    pub = _get_public_key()
    pub.verify(
        signature,
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

# ------------------------------
# Helpers de token
# ------------------------------

def _now_ts():
    return int(time.time())

def _to_iso(ts: int):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

def _canonical_json(data: dict) -> bytes:
    """
    Serializa en JSON con orden estable y sin espacios, para que
    la firma/verificación siempre use los mismos bytes.
    """
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)

# ------------------------------
# API principal: generación y check
# ------------------------------

def make_license(user_email: str, duration_hours: int = 24):
    """
    Genera un token firmado para user_email con una expiración fija.
    Devuelve (token, metadata).
    - token: string seguro, con payload y firma en base64url.
    - metadata: dict útil para logs/UI.
    """
    if not user_email or "@" not in user_email:
        raise ValueError("Email inválido para generar licencia.")

    iat = _now_ts()
    exp = iat + duration_hours * 3600

    payload = {
        "user": user_email,
        "issued_at": iat,
        "expires": exp,
        "version": 1
    }

    payload_bytes = _canonical_json(payload)
    signature = sign_bytes(payload_bytes)

    token_struct = {
        "payload": _b64url_encode(payload_bytes),
        "sig": _b64url_encode(signature),
        "alg": "RS256",
        "typ": "MHF-LIC"
    }

    token = _b64url_encode(_canonical_json(token_struct))

    metadata = {
        "user": user_email,
        "issued_at": _to_iso(iat),
        "expires": _to_iso(exp),
        "duration_hours": duration_hours
    }

    return token, metadata

def check_license(token: str) -> dict:
    """
    Verifica el token:
    - Estructura válida
    - Firma válida
    - No expirado

    Devuelve metadata dict con 'user' y 'expires' si es válido.
    Lanza excepciones con mensajes específicos si es inválido.
    """
    if not token or not isinstance(token, str):
        raise Exception("TOKEN INVÁLIDO: Formato de token vacío o incorrecto.")

    try:
        token_json_bytes = _b64url_decode(token)
        token_struct = json.loads(token_json_bytes.decode("utf-8"))
    except Exception:
        raise Exception("TOKEN INVÁLIDO: No se pudo decodificar el contenedor base64/JSON.")

    # Validación mínima del contenedor
    if token_struct.get("typ") != "MHF-LIC" or token_struct.get("alg") != "RS256":
        raise Exception("TOKEN INVÁLIDO: Tipo/algoritmo desconocido.")

    payload_b64 = token_struct.get("payload")
    sig_b64 = token_struct.get("sig")
    if not payload_b64 or not sig_b64:
        raise Exception("TOKEN INVÁLIDO: Falta payload o firma.")

    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
    except Exception:
        raise Exception("TOKEN INVÁLIDO: No se pudo decodificar payload/firma.")

    # Verificar firma
    try:
        verify_bytes(payload_bytes, signature)
    except Exception:
        raise Exception("Falló la verificación de la firma. Claves desincronizadas.")

    # Parsear payload y chequear expiración
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise Exception("TOKEN INVÁLIDO: Payload ilegible.")

    exp = payload.get("expires")
    user = payload.get("user")
    if not isinstance(exp, int) or not user:
        raise Exception("TOKEN INVÁLIDO: Campos requeridos ausentes (user/expires).")

    now = _now_ts()
    if now >= exp:
        raise Exception("LICENCIA EXPIRADA: El token ya no es válido.")

    # OK: token válido
    return {
        "user": user,
        "issued_at": _to_iso(payload.get("issued_at", now)),
        "expires": _to_iso(exp),
        "version": payload.get("version", 1)
    }
