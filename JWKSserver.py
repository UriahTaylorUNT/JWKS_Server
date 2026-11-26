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

HOST_NAME = "127.0.0.1"
SERVER_PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"

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

    def get_key(self, expired: bool = False):
        """Fetch one expired or valid key row from the database."""
        now = int(time.time())
        query = (
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
            if expired
            else "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
        )
        with self._connect() as conn:
            cursor = conn.execute(query, (now,))
            return cursor.fetchone()

    def get_all_valid_keys(self):
        """Fetch all unexpired key rows from the database."""
        now = int(time.time())
        with self._connect() as conn:
            cursor = conn.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
            return cursor.fetchall()

    def create_user(self, username: str, password_hash: str, email: str) -> int:
        """Insert a new user into the users table and return the new user ID."""
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, password_hash, email)
            )
            conn.commit()
            return cursor.lastrowid

    def get_user_id_by_username(self, username: str):
        """Look up a user's ID by username, returning None if not found."""
        if not username:
            return None
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()
            return row[0] if row else None

    def log_auth_request(self, request_ip: str, user_id) -> None:
        """Record a successful authentication request in auth_logs."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
                (request_ip, user_id)
            )
            conn.commit()

db = DatabaseManager(DB_FILE)


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

    def _read_json_body(self) -> dict:
        """Read and parse a JSON request body if present."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        raw_body = self.rfile.read(content_length)
        try:
            return json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _extract_username(self, body: dict):
        """Extract username from JSON payload or HTTP Basic Auth header."""
        if isinstance(body, dict) and body.get("username"):
            return body.get("username")

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                return decoded.split(":", 1)[0]
            except (ValueError, UnicodeDecodeError):
                return None
        return None

    def _handle_register(self):
        """Handle POST /register requests."""
        body = self._read_json_body()
        username = body.get("username")
        email = body.get("email")

        if not username:
            self.send_response(400)
            self.end_headers()
            return

        plain_password = str(uuid.uuid4())
        hashed_password = password_hasher.hash(plain_password)

        try:
            db.create_user(username, hashed_password, email)
        except sqlite3.IntegrityError:
            self.send_response(409)
            self.end_headers()
            return

        response_payload = json.dumps({"password": plain_password}).encode("utf-8")
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response_payload)

    def _handle_auth(self, parsed_path):
        """Handle POST /auth requests with rate limiting and auth logging."""
        if not rate_limiter.allow_request():
            self.send_response(429)
            self.end_headers()
            return

        body = self._read_json_body()
        username = self._extract_username(body) or "userABC"
        query_params = parse_qs(parsed_path.query)
        expired = "expired" in query_params

        row = db.get_key(expired=expired)
        if not row:
            self.send_response(500)
            self.end_headers()
            return

        kid, encrypted_blob, exp = row
        pem_bytes = decrypt_private_key(encrypted_blob)
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)

        headers = {"kid": str(kid)}
        payload = {"user": username, "exp": exp}
        encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

        user_id = db.get_user_id_by_username(username)
        db.log_auth_request(self.client_address[0], user_id)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(encoded_jwt.encode("utf-8"))

    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/register":
            self._handle_register()
            return
        if parsed_path.path == "/auth":
            self._handle_auth(parsed_path)
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/.well-known/jwks.json":
            rows = db.get_all_valid_keys()
            jwks = {"keys": []}

            for kid, encrypted_blob, _ in rows:
                pem_bytes = decrypt_private_key(encrypted_blob)
                private_key = serialization.load_pem_private_key(pem_bytes, password=None)
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
    db.init_db()
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    print(f"Server started on http://{HOST_NAME}:{SERVER_PORT}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")


