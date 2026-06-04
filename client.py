import json
import os
import sys
import time

import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


RESULT_LOG_FILE = os.environ.get("RESULT_LOG_FILE", os.path.abspath("run_results.json"))


def _append_result_log(record):
    try:
        if os.path.exists(RESULT_LOG_FILE):
            with open(RESULT_LOG_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)

            if isinstance(existing, dict) and isinstance(existing.get("runs"), list):
                payload = existing
            elif isinstance(existing, list):
                payload = {"runs": existing}
            else:
                payload = {"runs": []}
        else:
            payload = {"runs": []}

        payload["runs"].append(record)

        with open(RESULT_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    except Exception as error:
        print(f"warning: failed to write JSON result log: {error}")


# valid modes: 'plain', 'rsa', 'aes'
VALID_MODES = ("plain", "rsa", "aes")

if len(sys.argv) < 2 or sys.argv[1] not in VALID_MODES:
    print(f"usage: python client.py <{'|'.join(VALID_MODES)}> [--proxy <url>]")
    sys.exit(1)

mode = sys.argv[1]

# optional proxy: --proxy <url> (e.g. http://127.0.0.1:8080)
proxy_url = None
if "--proxy" in sys.argv:
    i = sys.argv.index("--proxy")
    if i + 1 < len(sys.argv):
        proxy_url = sys.argv[i + 1]
    else:
        print("error: --proxy requires a URL (e.g. --proxy http://127.0.0.1:8080)")
        sys.exit(1)

# load rsa public key if needed
if mode == "rsa":
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

# load aes key if needed
# aes-cbc config: key size 256-bit (32 bytes), block size 128-bit (16 bytes), padding pkcs7
if mode == "aes":
    with open("aes_key.bin", "rb") as f:
        aes_key = f.read()  # 32 bytes = 256-bit key

print(f"client application [mode: {mode.upper()}]")
print("input otp dari authenticator app\n")

# user input — timer has NOT started yet; waiting time is excluded from measurement
user_input = input("masukkan otp: ")

# timer starts here — after user finishes typing
start_total = time.time()

if mode == "rsa":
    # rsa-oaep encryption with sha-256
    start_encrypt = time.time()

    data_to_send = public_key.encrypt(
        user_input.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypt_runtime = (time.time() - start_encrypt) * 1000
    print(f"\n[client] encryption runtime (rsa-oaep) : {encrypt_runtime:.3f} ms")

elif mode == "aes":
    # aes-cbc encryption
    # iv: 16 bytes random, generated fresh per request (must never be reused with same key)
    # padding: pkcs7 to pad otp to 128-bit block boundary
    start_encrypt = time.time()

    iv = os.urandom(16)  # 16 bytes = 128-bit iv, matches aes block size

    padder = PKCS7(128).padder()  # 128 = block size in bits
    padded_plaintext = padder.update(user_input.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # prepend iv to ciphertext so server can extract it: [ iv (16 bytes) | ciphertext ]
    data_to_send = iv + ciphertext

    encrypt_runtime = (time.time() - start_encrypt) * 1000
    print(f"\n[client] encryption runtime (aes-cbc)  : {encrypt_runtime:.3f} ms")

else:
    # plain mode — no encryption
    print(f"\n[client] no encryption (mode: plain)")
    data_to_send = user_input.encode()
    encrypt_runtime = 0.0

# send to server
# if proxy_url provided, use it (proxy will forward to real server)
if proxy_url:
    base_url = proxy_url
    verify_setting = False
else:
    tls_enabled = os.path.exists("server.crt") and os.path.exists("server.key")
    base_url = "https://127.0.0.1:5000" if tls_enabled else "http://127.0.0.1:5000"
    verify_setting = "server.crt" if tls_enabled else True

start_server = time.time()

try:
    response = requests.post(
        f"{base_url}/verify?mode={mode}",
        data=data_to_send,
        verify=verify_setting,
        timeout=10
    )
    request_error = None
except requests.exceptions.RequestException as error:
    response = None
    request_error = error

server_runtime = (time.time() - start_server) * 1000
total_runtime  = (time.time() - start_total) * 1000

print(f"[server] response time           : {server_runtime:.3f} ms")
print(f"[total]  end-to-end time         : {total_runtime:.3f} ms")

print("\nserver response")
response_payload = None
if response is not None:
    try:
        response_payload = response.json()
    except ValueError:
        response_payload = response.text

    print(response_payload)
else:
    print(f"request failed: {request_error}")

_append_result_log(
    {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": mode,
        "proxy_url": proxy_url,
        "encryption_runtime_ms": round(encrypt_runtime, 3),
        "server_runtime_ms": round(server_runtime, 3),
        "total_runtime_ms": round(total_runtime, 3),
        "response_status_code": response.status_code if response is not None else None,
        "response": response_payload,
        "request_error": str(request_error) if request_error is not None else None,
    }
)