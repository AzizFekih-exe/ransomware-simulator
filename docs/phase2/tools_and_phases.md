Phase 2: Tools and Phases — C2 Component
## 1. Overview of the C2 Component

The Command-and-Control (C2) server is a central part of the simulation. It allows "victims" (simulated clients) to register, submit encrypted session keys, and enables an "admin" to manage these registrations.

In this phase, we implement a safe, educational simulation of a ransomware-style C2 server using Python and standard security libraries.

## 2. Tools Used
Flask
Purpose: Flask is a lightweight web framework for Python used to build RESTful APIs.
Role in C2 simulation:
Hosts endpoints such as /register, /getkey/<victim_id>, and /status.
Receives simulated victim registration data.
Serves encrypted AES keys securely to the admin.
Advantages for this project:
Easy to set up and lightweight — ideal for a school project.
Fully supports REST APIs for structured JSON communication.
Integrates easily with HTTPS via SSL/TLS.
pyOpenSSL / SSL Context
Purpose: pyOpenSSL provides Python bindings for OpenSSL, enabling HTTPS communication.
Role in C2 simulation:
Protects network communication between the simulated dropper and C2 server.
Ensures all data (especially RSA-wrapped AES keys) is encrypted in transit.
Implementation:
We generate a self-signed certificate (cert.pem) and private key (key.pem) for local testing.
Flask’s SSL context is configured using context.load_cert_chain('cert.pem', 'key.pem').
Rationale for HTTPS:
In real ransomware, C2 communication is encrypted to prevent network interception.
Even in a safe simulation, HTTPS demonstrates the importance of transport-layer security.
Prevents exposure of sensitive keys in transit.
HTTPS Rationale
Why HTTPS?
All communication between the dropper and C2 involves encryption keys.
Using plain HTTP would expose keys in clear text.
HTTPS (TLS) ensures confidentiality and integrity.
Self-signed certificate:
Adequate for local testing and simulation.
Does not require trusted CA certificates.
For production scenarios, a CA-signed certificate would be necessary.
## 3. Simulation Flow
The dropper generates a random AES session key.
The AES key is encrypted using the attacker’s RSA-2048 public key (from config.py).
The dropper sends a POST request to /register with:
Victim ID (hash of hostname + MAC)
RSA-encrypted AES key
Hostname and timestamp
The C2 server stores this data in memory.
The admin can:
View the list of registered victims via /status.
Retrieve the encrypted AES key via /getkey/<victim_id> after simulating “payment received.”
## 4. Security and Educational Notes
The simulation is fully harmless: no real files are encrypted or damaged.
The design demonstrates:
How modern ransomware uses asymmetric key wrapping to protect AES session keys.
The use of HTTPS for secure communications.
Proper handling of admin tokens to prevent unauthorized access.
Students gain hands-on experience with Flask, RSA encryption, and HTTPS in a controlled environment.