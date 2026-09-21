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

	def doGet(self):
		parsed_path = urlparse(self.path)
