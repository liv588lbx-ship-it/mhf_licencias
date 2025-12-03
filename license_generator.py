import json
import base64
import time
import uuid
import os
import datetime # Nuevo: Importado para calcular la expiración a 100 años
import logging  # Nuevo: Para manejo de errores en el servidor
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature # Nuevo: Para manejar el error 401 específicamente

logging.basicConfig(level=logging.INFO)

# --- CONFIGURACIÓN Y CACHÉ DE CLAVE PRIVADA (GENERACIÓN) ---

_PRIVATE_KEY_CACHE = None
PRIV_KEY_PATH = "priv.pem" 

def load_private_key(path=PRIV_KEY_PATH):
    # Carga la clave privada desde la variable de entorno PRIVATE_KEY_PEM
    global _PRIVATE_KEY_CACHE

    if _PRIVATE_KEY_CACHE is not None:
        return _PRIVATE_KEY_CACHE

    priv_key_pem = os.environ.get("PRIVATE_KEY_PEM")
    if not priv_key_pem:
        logging.error("CRÍTICO: No se encontró PRIVATE_KEY_PEM en variables de entorno.")
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
        logging.critical(f"CRITICAL ERROR: No se pudo cargar la clave privada desde PRIVATE_KEY_PEM: {e}")
        raise e

# --- FUNCIÓN DE GENERACIÓN (make_license) ---

def make_license(user_email, validity_hours=36, priv_key_path=PRIV_KEY_PATH, extra=None):
    """
    Crea un token firmado que representa una licencia.
    La expiración se establece a 100 años para simular "nunca expira hasta la activación".
    """
    try:
        priv = load_private_key(priv_key_path)
    except Exception:
        # Fallo si la clave privada no se carga
        raise Exception("Error interno: Clave privada no cargada para firmar.")


    issued = int(time.time())
    
    # === CORRECCIÓN DE LÓGICA DE EXPIRACIÓN (100 AÑOS) ===
    # Establece una expiración lejana para que el token no caduque antes del primer uso.
    far_future = datetime.datetime.now() + datetime.timedelta(days=365 * 100)
    expires = int(far_future.timestamp())
    # ======================================================
    
    license_id = str(uuid.uuid4())

    payload = {
        "license_id": license_id,
        "user": user_email,
        "issued": issued,
        "expires": expires,          # <-- ¡Ahora es a 100 años!
        "valid_hours": validity_hours, # <-- Horas reales de uso
        "extra": extra or {}
    }

    # Asegura que la serialización JSON sea consistente para la firma
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    signature = priv.sign(
        payload_json,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    token = (
        base64.urlsafe_b64encode(payload_json).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(signature).decode().rstrip("=")
    )

    return token, payload

# ==============================================================================
# LÓGICA DE VERIFICACIÓN
# ==============================================================================

_PUBLIC_KEY_CACHE = None

def load_public_key(path="pub.pem"):
    """Carga la clave pública desde el archivo pub.pem."""
    global _PUBLIC_KEY_CACHE
    if _PUBLIC_KEY_CACHE is not None:
        return _PUBLIC_KEY_CACHE

    try:
        # CRÍTICO: Abre el archivo con el nombre 'pub.pem'
        with open(path, "rb") as f:
            key = serialization.load_pem_public_key(f.read())
            _PUBLIC_KEY_CACHE = key
            return key
    except FileNotFoundError:
        logging.error(f"Error: No se encontró la clave pública en {path}. ¡Despliegue incompleto!")
        raise Exception(f"Falta archivo de clave: {path}")
    except Exception as e:
        logging.error(f"Error al cargar la clave pública: {e}")
        raise Exception(f"Error de formato al cargar la clave: {path}")

def _b64url_decode_padded(s: str) -> bytes:
    """Restaura el padding faltante para base64 urlsafe."""
    s = s.replace("-", "+").replace("_", "/")
    padding_needed = (4 - len(s) % 4) % 4
    s += "=" * padding_needed
    return base64.b64decode(s)

def check_license_base(token, pub_key_path="pub.pem"):
    """Función de validación base que devuelve (ok, msg, data)."""
    try:
        pub = load_public_key(pub_key_path)
        if "." not in token:
            return False, "invalid_format", None
        
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode_padded(payload_b64)
        sig = _b64url_decode_padded(sig_b64)
        
        # Verificar firma (si falla, lanza InvalidSignature)
        pub.verify(
            sig,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        data = json.loads(payload)
        now = int(time.time())
        
        # Verificación de la expiración criptográfica (la de 100 años)
        if data.get("expires", 0) < now:
            return False, "expired", data
            
        return True, "valid", data
        
    except InvalidSignature:
        # ¡Este es el error 401 persistente!
        logging.error("FALLO DE FIRMA CRÍTICO: El token no coincide con la clave pública (pub.pem).")
        return False, "Falló la verificación de la firma. Claves desincronizadas.", None

    except Exception as e:
        # Error de formato o cualquier otro problema criptográfico
        return False, str(e), None

def check_license(token):
    """
    Función requerida por webhook_server.py.
    Verifica el token y lanza una excepción si es inválido o expirado.
    """
    ok, msg, data = check_license_base(token)

    if ok:
        # Éxito: Devuelve los metadatos.
        return data
    elif msg == "expired":
        # Fallo: Lanza excepción específica.
        raise Exception("LICENCIA EXPIRADA. El token ha superado su vigencia criptográfica de 100 años.")
    else:
        # Fallo: Lanza excepción para firma inválida, etc.
        raise Exception(f"TOKEN INVÁLIDO o FALLO DE FIRMA: {msg}")