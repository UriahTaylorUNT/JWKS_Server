import os
import sqlite3
import threading
import time
import jwt
import pytest
import requests
from JWKSserver import MyServer, HTTPServer, init_db, db_file


@pytest.fixture(scope="module")
def server():
    # Remove old DB file if it exists to start fresh
    if os.path.exists(db_file):
        os.remove(db_file)

    init_db()
    webServer = HTTPServer(("127.0.0.1", 8080), MyServer)
    server_thread = threading.Thread(target=webServer.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.5)
    yield
    webServer.shutdown()
    webServer.server_close()


def test_db_file_and_keys_exist(server):
    assert os.path.exists(db_file)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]
    conn.close()
    assert count >= 2


def test_jwks_endpoint_only_valid_keys(server):
    response = requests.get("http://127.0.0.1:8080/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    for key in data["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "kid" in key


def test_auth_valid_jwt_with_json_payload(server):
    payload = {"username": "userABC", "password": "password123"}
    response = requests.post("http://127.0.0.1:8080/auth", json=payload)
    assert response.status_code == 200
    token = response.text
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] > time.time()


def test_auth_expired_jwt_with_basic_auth(server):
    response = requests.post(
        "http://127.0.0.1:8080/auth?expired=true",
        auth=("userABC", "password123")
    )
    assert response.status_code == 200
    token = response.text
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] <= time.time()


def test_invalid_methods(server):
    for method in [requests.put, requests.patch, requests.delete, requests.head]:
        resp1 = method("http://127.0.0.1:8080/auth")
        assert resp1.status_code == 405
        resp2 = method("http://127.0.0.1:8080/.well-known/jwks.json")
        assert resp2.status_code == 405

    assert requests.get("http://127.0.0.1:8080/auth").status_code == 405
    assert requests.post("http://127.0.0.1:8080/.well-known/jwks.json").status_code == 405
