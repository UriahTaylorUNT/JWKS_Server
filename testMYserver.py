import pytest
import requests
import threading
import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from server import BestServer, HTTPServer, keys

#Inject test keys into the server
keys["goodKID_test"] = {"private_key": rsa.generate_private_key(public_exponent=65537, key_size=2048), "expiry": int(time.time()) + 3600}
keys["expiredKID_test"] = {"private_key": rsa.generate_private_key(public_exponent=65537, key_size=2048), "expiry": int(time.time()) - 3600}

@pytest.fixture(scope="module")
def server():
    	webServer = HTTPServer(("127.0.0.1", 8080), BestServer)
    	server_thread = threading.Thread(target=webServer.serve_forever)
    	server_thread.daemon = True
    	server_thread.start()
    	time.sleep(1)
    	yield
    	webServer.shutdown()
    	webServer.server_close()

def test_jwks_endpoint_excludes_expired(server):
    	response = requests.get("http://127.0.0.1:8080/.well-known/jwks.json")
    	assert response.status_code == 200
    	data = response.json()
    	assert "keys" in data

    	for key in data["keys"]:
        	kid = key["kid"]
        	assert keys[kid]["expiry"] > time.time()

def test_auth_endpoint_valid_jwt(server):
    	response = requests.post("http://127.0.0.1:8080/auth")
    	assert response.status_code == 200
    	data = response.json()
    	assert "token" in data

    	token = data["token"]
    	unverified_headers = jwt.get_unverified_header(token)
    	assert "kid" in unverified_headers
    	assert keys[unverified_headers["kid"]]["expiry"] > time.time()

def test_auth_endpoint_expired_jwt(server):
    	response = requests.post("http://127.0.0.1:8080/auth?expired=true")
    	assert response.status_code == 200
    	data = response.json()
    	assert "token" in data

    	token = data["token"]
    	unverified_headers = jwt.get_unverified_header(token)
    	assert "kid" in unverified_headers
    	assert keys[unverified_headers["kid"]]["expiry"] < time.time()

def test_invalid_http_methods(server):
    	response = requests.get("http://127.0.0.1:8080/auth")
    	assert response.status_code == 405

    	response = requests.post("http://127.0.0.1:8080/.well-known/jwks.json")
    	assert response.status_code == 405
