# license_generator.py
import json
import base64
import time
import uuid
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Variable global para almacenar la clave una vez cargada
_PRIVATE_KEY_CACHE = None 
PRIV_KEY_PATH = "priv.pem"  # Mantiene compatibilidad, aunque ya no se usa

def load_private_key(path=PRIV_KEY_PATH):
    """
    Carga la clave privada desde la variable de entorno PRIVATE_KEY_PEM.
    Mantiene caché para evitar lecturas repetidas.
    """
    global _PRIVATE_KEY_CACHE

    if _PRIVATE_KEY_CACHE is not None:
        return _PRIVATE_KEY_CACHE

    # Intentar leer desde la variable de entorno
    priv_key_pem = os.environ.get("PRIVATE_KEY_PEM")
    if not priv_key_pem:
        raise FileNotFoundError(
            "No se encontró la clave privada en la variable de entorno PRIVATE_KEY_PEM"
        )

    try:
        key = serialization.load_pem_private_key(
            priv_key_pem.encode("utf-8"),
            password=None
        )
        _PRIVATE_KEY_CACHE = key
        return key
    except Exception as e:
        print(f"CRITICAL ERROR: No se pudo cargar la clave privada desde PRIVATE_KEY_PEM: {e}")
        raise e

def make_license(user_email, validity_hours=36, priv_key_path=PRIV_KEY_PATH, extra=None):
    """
    Crea un token firmado que representa una licencia.
    """
    # 2. Cargar la clave privada (de la variable de entorno)
    priv = load_private_key(priv_key_path)

    issued = int(time.time())
    expires = issued + int(validity_hours * 3600)
    license_id = str(uuid.uuid4())

    # Payload de la licencia
    payload = {
        "license_id": license_id,
        "user": user_email,
        "issued": issued,
        "expires": expires,
        "valid_hours": validity_hours,
        "extra": extra or {}
    }

    # Serializar de forma determinista
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # Firmar la licencia
    signature = priv.sign(
        payload_json,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # Generar token final (payload + firma codificados en base64)
    token = (
        base64.urlsafe_b64encode(payload_json).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(signature).decode().rstrip("=")
    )

    return token, payload
