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


