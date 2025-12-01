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
PRIV_KEY_PATH = "priv.pem" 

def load_private_key(path=PRIV_KEY_PATH):
    """
    Carga la clave privada desde archivo PEM. 
    Usa caché para evitar lecturas repetidas y retrasa la lectura inicial.
    """
    global _PRIVATE_KEY_CACHE
    
    # 2. Si ya está en caché, la devolvemos inmediatamente (Lazy Loading)
    if _PRIVATE_KEY_CACHE is not None:
        return _PRIVATE_KEY_CACHE
        
    try:
        # FIX: Usar os.path.realpath para encontrar la clave de forma segura en Render/Gunicorn
        script_dir = os.path.dirname(os.path.realpath(__file__))
        full_path = os.path.join(script_dir, path)
        
        with open(full_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            _PRIVATE_KEY_CACHE = key # 3. Guardar la clave en caché para futuros usos
            return key
    except Exception as e:
        # Si la clave no se carga, el error es crítico y lo mostraremos.
        print(f"CRITICAL ERROR: No se pudo cargar la clave privada en {full_path}: {e}")
        raise e 


def make_license(user_email, validity_hours=36, priv_key_path=PRIV_KEY_PATH, extra=None):
    """
    Crea un token firmado que representa una licencia.
    """
    # 4. load_private_key ahora activa la carga la primera vez que se llama a make_license
    # Esto ocurre DESPUÉS de que Gunicorn inicia Flask.
    priv = load_private_key(priv_key_path)
    
    issued = int(time.time())
    expires = issued + int(validity_hours * 3600)
    license_id = str(uuid.uuid4())
    
    # ... (El resto de la función es idéntico) ...
    
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
    
    signature = priv.sign(
        payload_json,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    token = base64.urlsafe_b64encode(payload_json).decode().rstrip("=") + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return token, payload