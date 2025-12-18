# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64
import os


# ==========================================================
# TAMBAHAN: INPUT USERNAME & CHECK EXISTING KEYS
# ==========================================================
# Menanyakan username agar file tidak tertukar antar user
username_input = input("Masukkan username untuk session ini: ").strip()
priv_file = f"{username_input}_priv.pem"
pub_file = f"{username_input}_pub.pem"

# Logika agar kunci TIDAK di-generate ulang jika file sudah ada
if os.path.exists(priv_file):
    with open(priv_file, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    pub_key = priv_key.public_key()
    print(f"[OK] Kunci lama ditemukan untuk '{username_input}'. Menggunakan kunci tersebut.")
else:
    # Jika belum ada, baru buat kunci baru
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    
    # Simpan private key dengan nama user
    with open(priv_file, "wb") as f:
        f.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Simpan public key dengan nama user
    with open(pub_file, "wb") as f:
        f.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[OK] Private key & public key baru berhasil dibuat untuk '{username_input}'!")

# ==========================================================
# SYMMETRIC ENCRYPTION (FERNET)
# ==========================================================

sym_key = Fernet.generate_key()
cipher = Fernet(sym_key)

print("[OK] Symmetric key (Fernet AES-128) dibuat!")

def encrypt_message(message: str) -> str:
    encrypted = cipher.encrypt(message.encode())
    encrypted_b64 = base64.b64encode(encrypted).decode()
    print("[OK] Pesan terenkripsi (base64):", encrypted_b64)
    return encrypted_b64

def decrypt_message(encrypted_b64: str) -> str:
    decrypted = cipher.decrypt(base64.b64decode(encrypted_b64)).decode()
    print("[OK] Pesan terdekripsi:", decrypted)
    return decrypted

# ==========================================================
# SIGN MESSAGE
# ==========================================================

def sign_message(message: str) -> str:
    # Gunakan priv_key yang sudah di-load/generate di atas
    signature = priv_key.sign(message.encode('utf-8'))
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    print("[OK] Signature message (base64):", signature_b64)
    return signature_b64

# ==========================================================
# PDF HASH & SIGNATURE
# ==========================================================

def hash_pdf(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        pdf_bytes = f.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_bytes)
    pdf_hash = digest.finalize()

    print("[OK] Hash PDF berhasil dibuat!")
    return pdf_hash

def sign_pdf_hash(pdf_hash: bytes) -> str:
    signature = priv_key.sign(pdf_hash)
    signature_b64 = base64.b64encode(signature).decode()

    print("[OK] Signature PDF (base64):", signature_b64)
    return signature_b64

# ==========================================================
# DEMO RUN
# ==========================================================

if __name__ == "__main__":

    print(f"\n=== DEMO CLIENT (User: {username_input}) ===")

    # Message demo
    message = "Ini pesan rahasia dari client!"

    encrypted_msg = encrypt_message(message)
    decrypt_message(encrypted_msg)

    msg_signature = sign_message(message)

    # PDF demo
    pdf_path = "pdf kid.pdf"  # pastikan file ada
    if not os.path.exists(pdf_path):
        print("[ERROR] File PDF tidak ditemukan!")
    else:
        pdf_hash = hash_pdf(pdf_path)
        pdf_signature = sign_pdf_hash(pdf_hash)

    print("\n[INFO] File yang dihasilkan:")
    print(f" - {priv_file}")
    print(f" - {pub_file}")
    print(f"\nUpload {pub_file} ke endpoint /store")
    print(f"Gunakan signature di atas untuk /verify dengan username '{username_input}'")