# client_verify.py
import base64, json, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_public_key(path="pub.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def _b64url_decode_padded(s: str) -> bytes:
    # Restaurar padding faltante para base64 urlsafe
    s = s.replace("-", "+").replace("_", "/")
    padding_needed = (4 - len(s) % 4) % 4
    s += "=" * padding_needed
    return base64.b64decode(s)

def validar_licencia(token, pub_key_path="pub.pem"):
    try:
        pub = load_public_key(pub_key_path)
        if "." not in token:
            return False, "invalid_format", None
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode_padded(payload_b64)
        sig = _b64url_decode_padded(sig_b64)
        # Verificar firma
        pub.verify(
            sig,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        data = json.loads(payload)
        now = int(time.time())
        if data.get("expires", 0) < now:
            return False, "expired", data
        return True, "valid", data
    except Exception as e:
        return False, str(e), None

if __name__ == "__main__":
    token = input("Pega token: ").strip()
    ok, msg, data = validar_licencia(token)
    print(ok, msg, data)
