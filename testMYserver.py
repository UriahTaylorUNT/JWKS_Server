import os
import sqlite3
import threading
import time
import uuid
import jwt
import pytest
import requests

from JWKSserver import DB_FILE, MyServer, HTTPServer, db, decrypt_private_key, rate_limiter

os.environ["NOT_MY_KEY"] = "pytest_temporary_aes_secret_key"

BASE_URL = "http://127.0.0.1:8080"


@pytest.fixture(scope="module")
def server():
    # Remove old DB file if it exists to start fresh
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    rate_limiter.reset()
    db.init_db()

    webServer = HTTPServer(("127.0.0.1", 8080), MyServer)
    server_thread = threading.Thread(target=webServer.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)
    yield
    webServer.shutdown()
    webServer.server_close()


def test_private_keys_are_encrypted_in_db(server):
    """Verify keys exist in SQLite and are AES-encrypted rather than plaintext PEM."""
    assert os.path.exists(DB_FILE)
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("SELECT kid, key, exp FROM keys").fetchall()

    assert len(rows) >= 2
    for _, encrypted_blob, _ in rows:
        assert isinstance(encrypted_blob, bytes)
        assert b"BEGIN RSA PRIVATE KEY" not in encrypted_blob
        decrypted = decrypt_private_key(encrypted_blob)
        assert b"BEGIN RSA PRIVATE KEY" in decrypted


def test_register_user_and_argon2_hash(server):
    """Verify POST /register returns a UUIDv4 password and stores an Argon2 hash."""
    payload = {"username": "test_user", "email": "test_user@example.com"}
    response = requests.post(f"{BASE_URL}/register", json=payload)
    assert response.status_code in (200, 201)

    data = response.json()
    assert "password" in data
    parsed_uuid = uuid.UUID(data["password"])
    assert parsed_uuid.version == 4

    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            "SELECT username, password_hash, email FROM users WHERE username = ?",
            ("test_user",),
        ).fetchone()

    assert row is not None
    assert row[0] == "test_user"
    assert row[1].startswith("$argon2")
    assert row[2] == "test_user@example.com"


def test_register_duplicate_and_missing_username(server):
    """Verify duplicate registration returns 409 and missing username returns 400."""
    dup = requests.post(
        f"{BASE_URL}/register",
        json={"username": "test_user", "email": "test_user@example.com"},
    )
    assert dup.status_code == 409

    bad = requests.post(f"{BASE_URL}/register", json={"email": "no_user@example.com"})
    assert bad.status_code == 400


def test_jwks_endpoint_returns_valid_keys(server):
    """Verify GET /.well-known/jwks.json returns only valid RSA keys."""
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    for key in data["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "kid" in key


def test_auth_valid_jwt_and_logging(server):
    """Verify POST /auth returns a valid JWT and logs the request with user_id."""
    rate_limiter.reset()
    response = requests.post(
        f"{BASE_URL}/auth",
        json={"username": "test_user", "password": "ignored_mock_password"},
    )
    assert response.status_code == 200
    token = response.text
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] > time.time()

    with sqlite3.connect(DB_FILE) as conn:
        user_id = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("test_user",)
        ).fetchone()[0]
        log_row = conn.execute(
            "SELECT request_ip, user_id FROM auth_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert log_row is not None
    assert log_row[0] == "127.0.0.1"
    assert log_row[1] == user_id


def test_auth_expired_jwt_basic_auth(server):
    """Verify POST /auth?expired=true with Basic Auth returns an expired JWT."""
    rate_limiter.reset()
    response = requests.post(
        f"{BASE_URL}/auth?expired=true",
        auth=("test_user", "password123"),
    )
    assert response.status_code == 200
    decoded = jwt.decode(response.text, options={"verify_signature": False})
    assert decoded["exp"] <= time.time()


def test_auth_rate_limiter_and_unlogged_429(server):
    """Verify >10 req/sec returns 429 and does not log rejected requests."""
    rate_limiter.reset()
    with sqlite3.connect(DB_FILE) as conn:
        initial_logs = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]

    statuses = []
    for _ in range(12):
        resp = requests.post(f"{BASE_URL}/auth", json={"username": "test_user"})
        statuses.append(resp.status_code)

    assert statuses[:10].count(200) == 10
    assert 429 in statuses[10:]

    with sqlite3.connect(DB_FILE) as conn:
        final_logs = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]

    assert final_logs - initial_logs == 10


def test_invalid_methods(server):
    """Verify unsupported HTTP methods and paths return 405."""
    for method in (requests.put, requests.patch, requests.delete, requests.head):
        assert method(f"{BASE_URL}/auth").status_code == 405
        assert method(f"{BASE_URL}/.well-known/jwks.json").status_code == 405

    assert requests.get(f"{BASE_URL}/auth").status_code == 405
    assert requests.post(f"{BASE_URL}/.well-known/jwks.json").status_code == 405
