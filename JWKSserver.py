from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import sqlite3
import time

hostName = "127.0.0.1"
serverPort = 8080
db_file = "totally_not_my_privateKeys.db"


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def generate_and_save_key(exp_timestamp):
    """Generate an RSA private key, serialize to PEM, and save to SQLite."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.NoEncryption()
    )

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp_timestamp))
    conn.commit()
    conn.close()

def init_db():
    """Create the SQLite database table and populate initial keys."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

    #Generate and store at least one expired key and one valid key
    now = int(time.time())
    generate_and_save_key(now - 3600)  #Expired 1 hour ago
    generate_and_save_key(now + 3600)  #1 hour expiration

def get_key_from_db(expired=False):
    """Fetch a single expired or unexpired key from the database."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    now = int(time.time())

    if expired:
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (now,))
    else:
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (now,))

    row = cursor.fetchone()
    conn.close()
    return row


def get_all_valid_keys():
    """Fetch all unexpired keys from the database."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    now = int(time.time())
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
    rows = cursor.fetchall()
    conn.close()
    return rows


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
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,)


