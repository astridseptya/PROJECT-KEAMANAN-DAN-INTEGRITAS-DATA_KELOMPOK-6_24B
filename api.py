# File utama API yang menjadi core logic dari layanan keamanan (security service)
# TIPS: proyek ini sengaja dibuat sederhana, jadi penyimpanan menggunakan file .txt / .pem saja

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi import Form
from fastapi import Depends
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from jose import jwt, JWTError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import json
import hashlib
import base64
import os

app = FastAPI(
    title="Punk Records API",
    version="1.0.0",
    openapi_components={
        "securitySchemes": {
            "HTTPBearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        }
    },
    openapi_security=[
        {
            "HTTPBearer": []
        }
    ]
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# JWT CONFIG
# =========================
SECRET_KEY = "ini-secret-key-vegapunk"
ALGORITHM = "HS256"

security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials
    try:
        # Decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username is None:
            raise HTTPException(status_code=401, detail="Token tidak mengandung username")
            
        return username

    except JWTError: 
        raise HTTPException(status_code=401, detail="Token expired atau tidak valid")

USERS_FILE = "users.json"
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


# Static users (simulasi peneliti Egghead)
USERS = {
    "alice": {
        "pubkey": None
    },
    "bob": {
        "pubkey": None
    }
}

# Pastikan folder storage ada
if not os.path.exists("storage"):
    os.makedirs("storage")

# Fungsi contoh untuk memeriksa apakah layanan berjalan dengan baik (health check)
# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------
@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

# Fungsi akses pada lokasi "root" atau "index"
# ---------------------------------------------------------
# INDEX
# ---------------------------------------------------------
@app.get("/")
async def index():
    return {
        "message": "Hello world! Please visit http://localhost:8080/docs to use the API."
    }

# Fungsi contoh untuk mengunggah file pdf
# Akses API pada URL http://localhost:8080/upload-pdf
# ---------------------------------------------------------
# UPLOAD PDF (contoh)
# ---------------------------------------------------------
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    try:
        content = await file.read()

        save_path = os.path.join("storage", file.filename)
        with open(save_path, "wb") as f:
            f.write(content)

        return {
            "message": "File uploaded!",
            "filename": file.filename,
            "content_type": file.content_type
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# ---------------------------------------------------------
# REGISTER
# ---------------------------------------------------------
@app.post("/register")
async def register_user(
    username: str = Form(...),
    password: str = Form(...)
):
    users = load_users()

    # Validasi sederhana
    if len(username) < 3 or len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Username minimal 3 karakter dan password minimal 6 karakter"
        )

    if username in users:
        raise HTTPException(
            status_code=400,
            detail="Username sudah terdaftar"
        )

    # Hash password (SHA-256)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    users[username] = {
        "password_hash": password_hash,
        "created_at": datetime.now().isoformat()
    }

    save_users(users)

    return {
        "message": "User berhasil didaftarkan",
        "username": username
    }

# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...)
):
    users = load_users()

    if username not in users:
        raise HTTPException(status_code=401, detail="User tidak ditemukan")

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if password_hash != users[username]["password_hash"]:
        raise HTTPException(status_code=401, detail="Password salah")

    token_data = {
        "sub": username
    }

    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# Fungsi API untuk menerima public key dan memastikan keutuhan file public key yang diterima
# TODO:
# Lengkapi fungsi berikut untuk menerima unggahan, memeriksa keutuhan file, lalu
# menyimpan public key milik user siapa
# Tentukan parameters fungsi yang diperlukan untuk kebutuhan ini
# ---------------------------------------------------------
# STORE PUBLIC KEY
# ---------------------------------------------------------
@app.post("/store")
async def store_pubkey(
    username: str,
    pubkey: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    # JWT check memastikan token valid & user sesuai
    if username != current_user:
        raise HTTPException(
            status_code=403,
            detail="Tidak boleh menyimpan public key user lain"
        )

    USERS = load_users() 

    # Static entry check
    if username not in USERS:
        raise HTTPException(
            status_code=404,
            detail="User tidak terdaftar (static entry)"
        )

    try:
        # Pastikan folder storage ada
        os.makedirs("storage", exist_ok=True)

        # Baca isi public key
        content = await pubkey.read()

        # Hitung hash (integrity check)
        pubkey_hash = hashlib.sha256(content).hexdigest()

        # Simpan public key
        pubkey_path = os.path.join("storage", f"{username}_pub.pem")
        with open(pubkey_path, "wb") as f:
            f.write(content)

        # Simpan hash public key
        hash_path = os.path.join("storage", f"{username}_pub.hash")
        with open(hash_path, "w") as f:
            f.write(pubkey_hash)

        return {
            "status": "success",
            "message": f"Public key stored for user '{username}'",
            "username": username,
            "pubkey_file": f"{username}_pub.pem",
            "pubkey_hash": pubkey_hash
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Fungsi API untuk memverifikasi signature yang dibuat oleh seorang pengguna
# TODO:
# Lengkapi fungsi berikut untuk menerima signature, menghitung signature dari "tampered message"
# Lalu kembalikan hasil perhitungan signature ke requester
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
# ---------------------------------------------------------
# VERIFY SIGNATURE
# ---------------------------------------------------------
@app.post("/verify")
async def verify_signature(
    username: str,
    message: str,
    signature: str,
    current_user: str = Depends(get_current_user)
):
    # Cegah user verifikasi atas nama user lain
    if username != current_user:
        raise HTTPException(
            status_code=403,
            detail="Tidak boleh memverifikasi atas nama user lain"
        )

    pubkey_path = os.path.join("storage", f"{username}_pub.pem")

    if not os.path.exists(pubkey_path):
        raise HTTPException(
            status_code=404,
            detail="Public key user tidak ditemukan"
        )

    # Load public key
    try:
        with open(pubkey_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gagal memuat public key"
        )

    # Decode signature dari base64
    try:
        # Menangani padding base64  
        missing_padding = len(signature) % 4
        if missing_padding:
            signature += '=' * (4 - missing_padding)
        signature_bytes = base64.b64decode(signature)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Format signature tidak valid (base64)"
        )

    # Verifikasi signature (Ed25519)
    try:
        clean_message = message.replace('+', ' ') 
        
        pub_key.verify(
            signature_bytes,
            clean_message.encode('utf-8')
        )
        status = "VALID"
    except Exception as e:
        print(f"Verification Error: {e}")
        status = "INVALID"

    return {
        "username": username,
        "signature_status": status,
        "message_checked": message
    }

# ---------------------------------------------------------
# VERIFY PDF
# ---------------------------------------------------------
@app.post("/verify-pdf")
async def verify_pdf(
    username: str,
    signature: str,
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    # Cegah verifikasi PDF user lain
    if username != current_user:
        raise HTTPException(
            status_code=403,
            detail="Tidak boleh memverifikasi PDF milik user lain"
        )

    # 1. Baca file PDF
    pdf_bytes = await file.read()

    # 2. Hash ulang PDF (SHA-256)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_bytes)
    pdf_hash = digest.finalize()

    # 3. Load public key user
    pubkey_path = os.path.join("storage", f"{username}_pub.pem")

    if not os.path.exists(pubkey_path):
        raise HTTPException(
            status_code=404,
            detail="Public key user tidak ditemukan"
        )

    try:
        with open(pubkey_path, "rb") as f:
            pubkey_data = f.read()
        pub_key = serialization.load_pem_public_key(pubkey_data)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gagal memuat public key"
        )

    # 4. Decode signature dari base64
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Format signature tidak valid"
        )

    # 5. Verifikasi signature PDF (Ed25519)
    try:
        pub_key.verify(signature_bytes, pdf_hash)
        return {
            "status": "VALID",
            "message": "PDF ASLI dan signature cocok",
            "filename": file.filename
        }
    except Exception:
        return {
            "status": "INVALID",
            "message": "PDF TIDAK VALID atau SUDAH DIUBAH",
            "filename": file.filename
        }

# Fungsi API untuk relay pesan ke user lain yang terdaftar
# TODO:
# Lengkapi fungsi berikut untuk menerima pesan yang aman ke server, 
# untuk selanjutnya diteruskan ke penerima yang dituju (ditentukan oleh pengirim)
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
# ---------------------------------------------------------
# RELAY MESSAGE
# ---------------------------------------------------------
@app.post("/relay")
async def relay_message(
    receiver: str,
    encrypted_message: str,
    current_user: str = Depends(get_current_user)
):
    sender = current_user

    inbox_folder = "inbox"
    if not os.path.exists(inbox_folder):
        os.makedirs(inbox_folder)

    # File akan tetap dibuat berdasarkan nama receiver yang diinput di Swagger
    save_path = os.path.join(inbox_folder, f"{receiver}.txt")

    try:
        with open(save_path, "a") as f:
            f.write(f"From: {sender}\n")
            f.write(f"Encrypted Message: {encrypted_message}\n")
            f.write("----\n")

        return {
            "status": "success",
            "from": sender,
            "to": receiver,
            "message": f"Pesan terenkripsi berhasil dikirim ke {receiver}"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))