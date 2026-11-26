from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt

hostName = "127.0.0.1"
serverPort = 8080
db_file = "totally_not_my_privateKeys.db"

password_hasher = PasswordHasher()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def get_aes_key() -> bytes:
    """Derive a 32-byte AES-256 key from the NOT_MY_KEY environment variable."""
    raw_key = os.environ.get("NOT_MY_KEY")
    if not raw_key:
        raise EnvironmentError("NOT_MY_KEY environment variable is not set.")
    return hashlib.sha256(raw_key.encode("utf-8")).digest()


def encrypt_private_key(pem_bytes: bytes) -> bytes:
    """Encrypt PEM key bytes using AES-256-GCM with a random 12-byte nonce."""
    aesgcm = AESGCM(get_aes_key())
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, pem_bytes, None)
    return nonce + ciphertext


def decrypt_private_key(encrypted_blob: bytes) -> bytes:
    """Decrypt an AES-256-GCM encrypted key BLOB back to PEM bytes."""
    aesgcm = AESGCM(get_aes_key())
    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


class RateLimiter:
    """Thread-safe rate limiter with slideing window"""
    def __init__(self, max_requests: int = 10, window_seconds: float = 1.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps = deque()
        self.lock = threading.Lock()

    def allow_request(self) -> bool:
        """Return True if the request is within the rate limit, False otherwise."""
        now = time.monotonic()
        with self.lock:
            while self.timestamps and (now - self.timestamps[0]) >= self.window_seconds:
                self.timestamps.popleft()
            if len(self.timestamps) >= self.max_requests:
                return False
            self.timestamps.append(now)
            return True

    def reset(self) -> None:
        """Clear recorded request timestamps."""
        with self.lock:
            self.timestamps.clear()

rate_limiter = RateLimiter(max_requests=10, window_seconds=1.0)


class DatabaseManager:
    """Handles all SQLite database connections and parameterized queries."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def init_db(self) -> None:
        """Create required tables and seed one expired and one valid RSA key."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_ip TEXT NOT NULL,
                    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            conn.commit()

        now = int(time.time())
        self.generate_and_save_key(now - 3600)  #Expired 1 hour ago
        self.generate_and_save_key(now + 3600)  #Expires in 1 hour

    def generate_and_save_key(self, exp_timestamp: int) -> None:
	"""Generate an RSA key, encrypt it with AES, and store it in SQLite."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        encrypted_blob = encrypt_private_key(pem_bytes)

        with self._connect() as conn:
            conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (encrypted_blob, exp_timestamp)
            )
            conn.commit()


def get_key_from_db(expired=False):
#stuff

def get_all_valid_keys(self):
#stuff

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/auth":
            # Read request body if present (Gradebot sends JSON or Basic Auth)
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                _ = self.rfile.read(content_length)

            query_params = parse_qs(parsed_path.query)
            expired = 'expired' in query_params

            row = get_key_from_db(expired=expired)
            if not row:
                self.send_response(500)
                self.end_headers()
                return

            kid, pem_data, exp = row
            if isinstance(pem_data, str):
                pem_data = pem_data.encode('utf-8')

            private_key = serialization.load_pem_private_key(pem_data, password=None)

            headers = {"kid": str(kid)}
            payload = {
                "user": "userABC",
                "exp": exp
            }

            encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

            self.send_response(200)
            self.send_header("Content-type", "application/txt")
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/.well-known/jwks.json":
            rows = get_all_valid_keys()
            jwks = {"keys": []}

            for kid, pem_data, _ in rows:
                if isinstance(pem_data, str):
                    pem_data = pem_data.encode('utf-8')

                private_key = serialization.load_pem_private_key(pem_data, password=None)
                public_numbers = private_key.public_key().public_numbers()

                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e)
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    init_db()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started on http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")    


