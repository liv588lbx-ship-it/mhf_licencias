# license_generator.py
import json
import base64
import time
import uuid
import os # Necesario para la corrección de la ruta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(path="priv.pem"):
    """Carga la clave privada desde archivo PEM (sin passphrase)."""
    # FIX: Usar os.path.realpath para encontrar la clave de forma segura en Render/Gunicorn
    script_dir = os.path.dirname(os.path.realpath(__file__))
    full_path = os.path.join(script_dir, path)
    
    with open(full_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def make_license(user_email, validity_hours=36, priv_key_path="priv.pem", extra=None):
    """
    Crea un token firmado que representa una licencia.
    Devuelve (token, payload_dict).
    Formato del token: base64url(payload_json) + "." + base64url(signature)
    """
    priv = load_private_key(priv_key_path)
    issued = int(time.time())
    expires = issued + int(validity_hours * 3600)
    license_id = str(uuid.uuid4())
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