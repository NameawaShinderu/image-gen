from fastapi import FastAPI, HTTPException, Depends, UploadFile, Form, File, Request, Response, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import sqlite3
import os
import base64
import hashlib
import secrets
import nacl.secret
import nacl.utils
from pathlib import Path
from typing import Optional, Dict, Any
import uuid
import time
import json
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer
import time
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response


# Create directories
BLOB_STORAGE = "blob_storage"
Path(BLOB_STORAGE).mkdir(parents=True, exist_ok=True)

# Initialize FastAPI
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DB_CONN = sqlite3.connect("zkp_secure_image_vault.db", check_same_thread=False)
CURSOR = DB_CONN.cursor()

# Update database schema to include token expiration and refresh tokens
CURSOR.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        verifier TEXT NOT NULL,
        salt TEXT NOT NULL
    )
""")

CURSOR.execute("""
    CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        site_name TEXT NOT NULL,
        blob_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        salt TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
""")

# New table for token management
CURSOR.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT NOT NULL,
        access_expiry INTEGER NOT NULL,
        refresh_expiry INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
""")

DB_CONN.commit()

# Models
class UserRegister(BaseModel):
    username: str
    verifier: str
    salt: str

class LoginRequest(BaseModel):
    username: str
    response: str

class ZKPChallenge(BaseModel):
    username: str

class TokenRefresh(BaseModel):
    username: str
    refresh_token: str

class DownloadRequest(BaseModel):
    username: str
    token: str
    password: str
    image_id: int

class ImageListRequest(BaseModel):
    username: str
    token: str

class LogoutRequest(BaseModel):
    username: str
    token: str

# Add rate limiting middleware
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.request_records = {}
        self.MAX_REQUESTS = 60
        self.TIME_WINDOW = 60  # seconds
    
    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Initialize client records if not present
        if client_ip not in self.request_records:
            self.request_records[client_ip] = []
        
        # Remove old timestamps
        current_time = time.time()
        self.request_records[client_ip] = [
            timestamp for timestamp in self.request_records[client_ip]
            if timestamp > current_time - self.TIME_WINDOW
        ]
        
        # Check rate limit
        if len(self.request_records[client_ip]) >= self.MAX_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."}
            )
        
        # Record new request
        self.request_records[client_ip].append(current_time)
        
        # Clean up old records periodically
        if len(self.request_records) > 1000:
            # Keep only the 100 most recent clients
            self.request_records = {
                ip: timestamps for ip, timestamps in 
                sorted(self.request_records.items(), key=lambda x: len(x[1]), reverse=True)[:100]
            }
        
        # Continue with request
        return await call_next(request)

# Add middleware to app
app.add_middleware(RateLimitMiddleware)

#can only use with version 2 /uplaod-images
# Make the blob storage more secure by adding random subdirectories
def secure_blob_path(blob_id: str) -> str:
    """Create a more secure path for blob storage with subdirectories"""
    # Use first 2 chars for primary directory, next 2 for secondary
    primary_dir = blob_id[:2]
    secondary_dir = blob_id[2:4]
    
    # Create directory structure
    path = os.path.join(BLOB_STORAGE, primary_dir, secondary_dir)
    Path(path).mkdir(parents=True, exist_ok=True)
    
    # Return full path
    return os.path.join(path, blob_id)


# Security storage
challenges = {}

# Helper functions
def get_user(username: str):
    CURSOR.execute("SELECT id, verifier, salt FROM users WHERE username = ?", (username,))
    return CURSOR.fetchone()

def get_user_by_id(user_id: int):
    CURSOR.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    result = CURSOR.fetchone()
    return result[0] if result else None

def create_tokens(user_id: int):
    """Create new access and refresh tokens with expiration times"""
    access_token = secrets.token_urlsafe(64)
    refresh_token = secrets.token_urlsafe(64)
    
    # Access token expires in 30 minutes, refresh token in 7 days
    current_time = int(time.time())
    access_expiry = current_time + (30 * 60)  # 30 minutes
    refresh_expiry = current_time + (7 * 24 * 60 * 60)  # 7 days
    
    # Store tokens in database
    CURSOR.execute("""
        INSERT INTO tokens (user_id, access_token, refresh_token, access_expiry, refresh_expiry)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, access_token, refresh_token, access_expiry, refresh_expiry))
    DB_CONN.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_expiry": access_expiry,
        "refresh_expiry": refresh_expiry
    }

# Update the token validation to use constant-time comparison
def validate_token(username: str, token: str):
    """Validate access token and check if it's expired using constant time comparison"""
    CURSOR.execute("""
        SELECT t.access_token, t.access_expiry, t.user_id 
        FROM tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.username = ?
    """, (username,))
    
    results = CURSOR.fetchall()
    if not results:
        return None
    
    current_time = int(time.time())
    
    # Check each token with constant-time comparison
    for stored_token, expiry, user_id in results:
        if secrets.compare_digest(stored_token, token) and current_time <= expiry:
            return user_id
            
    return None

def revoke_tokens(username: str, token: str):
    """Revoke a user's tokens"""
    CURSOR.execute("""
        DELETE FROM tokens
        WHERE user_id = (SELECT id FROM users WHERE username = ?)
        AND access_token = ?
    """, (username, token))
    DB_CONN.commit()

# API Endpoints
@app.post("/register")
async def register(user: UserRegister):
    try:
        CURSOR.execute(
            "INSERT INTO users (username, verifier, salt) VALUES (?, ?, ?)",
            (user.username, user.verifier, user.salt)
        )
        DB_CONN.commit()
        return {"message": "Registration successful"}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username already exists")

@app.post("/challenge")
async def create_challenge(request: ZKPChallenge):
    user = get_user(request.username)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    challenge = secrets.token_hex(16)
    challenges[request.username] = challenge
    return {"challenge": challenge}

@app.post("/login")
async def login(login: LoginRequest, response: Response):
    user = get_user(login.username)
    if not user:
        raise HTTPException(404, "User not found")
    
    user_id, verifier, salt = user
    challenge = challenges.get(login.username)
    
    if not challenge:
        raise HTTPException(400, "No active challenge")
    
    expected = hashlib.sha256((challenge + verifier).encode()).hexdigest()
    
    if not secrets.compare_digest(expected, login.response):
        raise HTTPException(401, "Invalid credentials")
    
    # Create tokens
    tokens = create_tokens(user_id)
    del challenges[login.username]
    
    # Set refresh token as HttpOnly cookie
    response.set_cookie(
        key="refresh_token", 
        value=tokens["refresh_token"],
        httponly=True,
        secure=True,  # Enable in production with HTTPS
        samesite="strict",
        expires=tokens["refresh_expiry"]
    )
    
    return {
        "token": tokens["access_token"],
        "expiry": tokens["access_expiry"],
        "user_id": user_id
    }

@app.post("/refresh-token")
async def refresh_token(request: TokenRefresh, response: Response):
    # Validate refresh token
    CURSOR.execute("""
        SELECT t.user_id, t.refresh_expiry
        FROM tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.username = ? AND t.refresh_token = ?
    """, (request.username, request.refresh_token))
    
    result = CURSOR.fetchone()
    if not result:
        raise HTTPException(401, "Invalid refresh token")
    
    user_id, expiry = result
    current_time = int(time.time())
    
    if current_time > expiry:
        raise HTTPException(401, "Refresh token expired")
    
    # Revoke old tokens
    CURSOR.execute("""
        DELETE FROM tokens
        WHERE user_id = ? AND refresh_token = ?
    """, (user_id, request.refresh_token))
    DB_CONN.commit()
    
    # Create new tokens
    tokens = create_tokens(user_id)
    
    # Set new refresh token as HttpOnly cookie
    response.set_cookie(
        key="refresh_token", 
        value=tokens["refresh_token"],
        httponly=True,
        secure=True,  # Enable in production with HTTPS
        samesite="strict",
        expires=tokens["refresh_expiry"]
    )
    
    return {
        "token": tokens["access_token"],
        "expiry": tokens["access_expiry"]
    }

@app.get("/verifier/{username}")
async def get_verifier(username: str):
    user = get_user(username)
    if not user:
        raise HTTPException(404, "User not found")
    
    _, verifier, salt = user
    return {
        "verifier": verifier,
        "salt": salt
    }
#normal blob -  REVIEW JOSHI
@app.post("/upload-image")
async def upload_image(
    username: str = Form(...),
    site_name: str = Form(...),
    file: UploadFile = File(...),
    token: str = Form(...),
    password: str = Form(...)
):
    # Validate session
    user_id = validate_token(username, token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired token")
    
    try:
        # Read the file
        file_content = await file.read()
        
        # Generate cryptographic parameters
        salt = secrets.token_hex(16)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        nonce_hex = base64.b64encode(nonce).decode()
        
        # Derive key from password
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            600000, 
            dklen=32
        )
        
        # Create encryption box
        box = nacl.secret.SecretBox(key)
        
        # Encrypt file
        encrypted = box.encrypt(file_content, nonce=nonce)
        
        # Generate a unique blob identifier using UUID
        blob_id = str(uuid.uuid4())
        file_path = os.path.join(BLOB_STORAGE, blob_id)
        
        # Save encrypted file
        with open(file_path, "wb") as f:
            f.write(encrypted)
        
        # Store in database
        CURSOR.execute(
            "INSERT INTO images (user_id, site_name, blob_id, nonce, salt) VALUES (?, ?, ?, ?, ?)",
            (user_id, site_name, blob_id, nonce_hex, salt)
        )
        DB_CONN.commit()
        
        return {"message": "Image uploaded successfully"}
    except Exception as e:
        DB_CONN.rollback()
        raise HTTPException(500, f"Upload failed: {str(e)}")
'''
# Update the upload-image endpoint to use the secure_blob_path
@app.post("/upload-image")
async def upload_image(
    username: str = Form(...),
    site_name: str = Form(...),
    file: UploadFile = File(...),
    token: str = Form(...),
    password: str = Form(...)
):
    # Validate session
    user_id = validate_token(username, token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired token")
    
    try:
        # Read the file
        file_content = await file.read()
        
        # Generate cryptographic parameters
        salt = secrets.token_hex(16)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        nonce_hex = base64.b64encode(nonce).decode()
        
        # Derive key from password
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            600000, 
            dklen=32
        )
        
        # Create encryption box
        box = nacl.secret.SecretBox(key)
        
        # Encrypt file
        encrypted = box.encrypt(file_content, nonce=nonce)
        
        # Generate a unique blob identifier using UUID
        blob_id = str(uuid.uuid4())
        file_path = secure_blob_path(blob_id)  # Use the new secure path function
        
        # Save encrypted file
        with open(file_path, "wb") as f:
            f.write(encrypted)
        
        # Store in database
        CURSOR.execute(
            "INSERT INTO images (user_id, site_name, blob_id, nonce, salt) VALUES (?, ?, ?, ?, ?)",
            (user_id, site_name, blob_id, nonce_hex, salt)
        )
        DB_CONN.commit()
        
        return {"message": "Image uploaded successfully"}
    except Exception as e:
        DB_CONN.rollback()
        raise HTTPException(500, f"Upload failed: {str(e)}")
'''


@app.post("/images")
async def get_images(request: ImageListRequest):
    # Verify session
    user_id = validate_token(request.username, request.token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired token")
    
    CURSOR.execute("""
        SELECT id, site_name FROM images
        WHERE user_id = ?
    """, (user_id,))
    
    images = CURSOR.fetchall()
    
    return [{"id": row[0], "site_name": row[1]} for row in images]

@app.post("/download")
async def download_image(request: DownloadRequest):
    user_id = validate_token(request.username, request.token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired token")
    
    try:
        # Get image information
        CURSOR.execute("""
            SELECT blob_id, nonce, salt, site_name FROM images 
            WHERE id = ? AND user_id = ?
        """, (request.image_id, user_id))
        
        result = CURSOR.fetchone()
        if not result:
            raise HTTPException(404, "Image not found")
        
        blob_id, nonce_hex, salt, site_name = result
        file_path = os.path.join(BLOB_STORAGE, blob_id)
        
        # Read encrypted file
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        
        # Convert nonce from base64
        nonce = base64.b64decode(nonce_hex)
        
        # Derive key from password
        key = hashlib.pbkdf2_hmac(
            'sha256', 
            request.password.encode(), 
            salt.encode(), 
            600000, 
            dklen=32
        )
        
        # Create secret box
        box = nacl.secret.SecretBox(key)
        
        # Decrypt the data
        decrypted_data = box.decrypt(encrypted_data)
        
        # Return decrypted data
        return {
            "image_data": base64.b64encode(decrypted_data).decode(),
            "filename": f"{site_name}_image.png"
        }
    
    except nacl.exceptions.CryptoError:
        raise HTTPException(401, "Decryption failed - incorrect password")
    except Exception as e:
        raise HTTPException(500, f"Download failed: {str(e)}")

@app.post("/logout")
async def logout(request: LogoutRequest, response: Response):
    revoke_tokens(request.username, request.token)
    
    # Clear the refresh token cookie
    response.delete_cookie(key="refresh_token")
    
    return {"message": "Logged out"}

# Cleanup expired tokens periodically
@app.on_event("startup")
async def setup_token_cleanup():
    def cleanup_expired_tokens():
        try:
            current_time = int(time.time())
            CURSOR.execute("DELETE FROM tokens WHERE refresh_expiry < ?", (current_time,))
            DB_CONN.commit()
        except Exception as e:
            print(f"Error cleaning up tokens: {e}")
    
    # Run cleanup on startup
    cleanup_expired_tokens()