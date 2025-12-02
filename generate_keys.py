# generate_keys.py
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def main():
    # Carpeta segura en el perfil del usuario
    secure_dir = Path.home() / "secrets" / "mhf_keys"
    secure_dir.mkdir(parents=True, exist_ok=True)

    # Generar par de claves RSA 4096
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    priv_path = secure_dir / "priv.pem"
    pub_path = secure_dir / "pub.pem"

    # Escribir archivos
    priv_path.write_bytes(priv)
    pub_path.write_bytes(pub)

    # Intentar aplicar permisos tipo Unix (no falla en Windows)
    try:
        priv_path.chmod(0o600)
    except Exception:
        # En Windows, chmod puede no aplicar; se sugiere usar icacls desde PowerShell/CMD
        pass

    print("Claves generadas en:", secure_dir)
    print("Asegurate de no commitear estos archivos y de añadirlos a .gitignore")

if __name__ == "__main__":
    main()
