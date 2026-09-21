from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import json
import time
import base64
from urllib.parse import urlparse, parse_qs
import uuid

hostName = "127.0.0.1"
serverPort = 8080

#Storing keys and their expiration timestamps
keys = {}

def int_to_base64(value):
    	value_hex = format(value, 'x')
    	if len(value_hex) % 2 == 1:
        	value_hex = '0' + value_hex
    	value_bytes = bytes.fromhex(value_hex)
    	encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    	return encoded.decode('utf-8')

class BestServer(BaseHTTPRequestHandler):
	def doPost(self):
		parsed_path = urlparse(self.path)
		if parsed_path.path == "/auth":
            		query_params = parse_qs(parsed_path.query)
            		expired = 'expired' in query_params

			#Select key that matches requirement
			target_kid = None
			for kid, key_data in keys.items():
                		is_expired = key_data["expiry"] < time.time()
                		if expired and is_expired:
                    			target_kid = kid
                    			break
                		elif not expired and not is_expired:
                    			target_kid = kid
                    			break

			#If no match is found, generate new key
			if not target_kid:
                		private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
                		target_kid = str(uuid.uuid4())
                		expiry = int(time.time()) - 3600 if expired else int(time.time()) + 3600
                		keys[target_kid] = {"private_key": private_key,"expiry": expiry}
            		else:
                		private_key = keys[target_kid]["private_key"]

            		headers = {"kid": target_kid}
            		payload = {"user": "fake_user","exp": keys[target_kid]["expiry"]}

			encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
            		self.send_response(200)
            		self.send_header("Content-type", "application/json")
            		self.end_headers()
            		self.wfile.write(bytes(json.dumps({"token": encoded_jwt}), "utf-8"))
            		return

		self.send_response(405)
        	self.end_headers()
        	return

	def doGet(self):
		parsed_path = urlparse(self.path)
		if parsed_path.path == "/.well-known/jwks.json":
            	jwks = {"keys": []}
            	for kid, key_data in keys.items():
                	if key_data["expiry"] > time.time():
                    		private_key = key_data["private_key"]
                    		public_key = private_key.public_key()
                    		public_numbers = public_key.public_numbers()

				jwks["keys"].append({
                        		"alg": "RS256",
                        		"kty": "RSA",
                        		"use": "sig",
                        		"kid": kid,
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
		return


if __name__ == "__main__":
	#Pre-populate keys
	good_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    	keys["goodKID"] = {"private_key": good_key, "expiry": int(time.time()) + 3600}

    	expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    	keys["expiredKID"] = {"private_key": expired_key, "expiry": int(time.time()) - 3600}

    	webServer = HTTPServer((hostName, serverPort), BestServer)
    	print(f"Server started on http://{hostName}:{serverPort}")
	try:
        	webServer.serve_forever()
    	except KeyboardInterrupt:
        	pass
    	webServer.server_close()
    	print("Server stopped.")



