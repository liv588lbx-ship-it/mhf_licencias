# license_generator.py
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
# API principal: generación, activación y check
# ------------------------------

def make_license(user_email: str, duration_hours: int = 36):
    """
    Genera un token firmado para user_email.
    Diseño: el token NO está activado por defecto (no tiene expires efectivo).
    - duration_hours: cuántas horas durará la licencia una vez activada (por defecto 36).
    Devuelve (token, metadata).
    """
    if not user_email or "@" not in user_email:
        raise ValueError("Email inválido para generar licencia.")

    iat = _now_ts()

    # No fijamos expires en la emisión: la licencia se activa más tarde.
    # Guardamos duration_hours para que la activación calcule la expiración.
    payload = {
        "user": user_email,
        "issued_at": iat,
        "activated_at": None,        # None hasta que se active
        "expires": None,             # None hasta que se active
        "duration_hours": int(duration_hours),
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
        "duration_hours": int(duration_hours)
    }

    return token, metadata

def activate_license(token: str, force_duration_hours: int = None):
    """
    Activa un token NO activado:
    - Verifica firma del token original.
    - Si ya está activado, devuelve el token original (o puede regenerar).
    - Si no está activado, genera un NUEVO token firmado con:
        activated_at = now
        expires = activated_at + duration_hours*3600
      donde duration_hours se toma de payload['duration_hours'] o de force_duration_hours si se pasa.
    Devuelve (new_token, metadata).
    """
    if not token or not isinstance(token, str):
        raise Exception("TOKEN INVÁLIDO: Formato de token vacío o incorrecto.")

    # Decodificar contenedor
    try:
        token_json_bytes = _b64url_decode(token)
        token_struct = json.loads(token_json_bytes.decode("utf-8"))
    except Exception:
        raise Exception("TOKEN INVÁLIDO: No se pudo decodificar el contenedor base64/JSON.")

    # Validación mínima
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

    # Verificar firma del token original
    try:
        verify_bytes(payload_bytes, signature)
    except Exception:
        raise Exception("Falló la verificación de la firma. Claves desincronizadas.")

    # Parsear payload
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise Exception("TOKEN INVÁLIDO: Payload ilegible.")

    # Si ya está activado, devolvemos el token tal cual (o podríamos regenerarlo)
    if payload.get("activated_at"):
        # Ya activado: devolver info actual
        return token, {
            "user": payload.get("user"),
            "activated_at": _to_iso(payload.get("activated_at")),
            "expires": _to_iso(payload.get("expires")) if payload.get("expires") else None,
            "duration_hours": payload.get("duration_hours", None)
        }

    # Determinar duración a usar
    duration = None
    try:
        duration = int(payload.get("duration_hours")) if payload.get("duration_hours") else None
    except Exception:
        duration = None
    if force_duration_hours is not None:
        duration = int(force_duration_hours)
    if not duration:
        # fallback seguro
        duration = int(os.getenv("LICENSE_DURATION_HOURS", "36"))

    # Calcular activated_at y expires
    activated_at = _now_ts()
    expires = activated_at + int(duration) * 3600

    # Actualizar payload y firmar nuevo token
    payload["activated_at"] = activated_at
    payload["expires"] = expires
    payload["duration_hours"] = int(duration)

    new_payload_bytes = _canonical_json(payload)
    new_signature = sign_bytes(new_payload_bytes)

    new_token_struct = {
        "payload": _b64url_encode(new_payload_bytes),
        "sig": _b64url_encode(new_signature),
        "alg": "RS256",
        "typ": "MHF-LIC"
    }

    new_token = _b64url_encode(_canonical_json(new_token_struct))

    metadata = {
        "user": payload.get("user"),
        "activated_at": _to_iso(activated_at),
        "expires": _to_iso(expires),
        "duration_hours": int(duration)
    }

    return new_token, metadata

def check_license(token: str) -> dict:
    """
    Verifica el token:
    - Estructura válida
    - Firma válida
    - Si está activado: comprobar expiración (activated_at + duration_hours)
    - Si NO está activado: lanzar excepción indicando que no está activado

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

    # Parsear payload
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise Exception("TOKEN INVÁLIDO: Payload ilegible.")

    user = payload.get("user")
    if not user:
        raise Exception("TOKEN INVÁLIDO: Campo 'user' ausente.")

    # Si el token trae 'activated_at' y 'duration_hours', calcular expiración
    activated_at = payload.get("activated_at")
    expires_field = payload.get("expires")
    duration_hours = payload.get("duration_hours")

    # Caso 1: token ya activado (payload contiene activated_at y expires)
    if isinstance(activated_at, int) and isinstance(duration_hours, int):
        # calcular expiración por seguridad (aceptar expires si coincide)
        computed_expires = int(activated_at) + int(duration_hours) * 3600
        now = _now_ts()
        if now >= computed_expires:
            raise Exception("LICENCIA EXPIRADA: El token ya no es válido.")
        # OK
        return {
            "user": user,
            "issued_at": _to_iso(payload.get("issued_at", activated_at)),
            "activated_at": _to_iso(activated_at),
            "expires": _to_iso(computed_expires),
            "version": payload.get("version", 1)
        }

    # Caso 2: token no activado aún -> no es válido para iniciar uso
    # (según tu diseño, el token no tiene fecha de expiración hasta activarse)
    raise Exception("LICENCIA NO ACTIVADA: El token aún no fue activado.")

# ------------------------------
# Fin del módulo
# ------------------------------
