import os
import time

import pyotp
from flask import Flask, request
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# load rsa private key
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# load aes key
# aes-cbc config: key 256-bit (32 bytes), block size 128-bit (16 bytes), padding pkcs7
with open("aes_key.bin", "rb") as f:
    aes_key = f.read()  # 32 bytes = 256-bit key

# load totp shared secret
with open("shared_secret.txt", "r") as f:
    shared_secret = f.read().strip()

totp = pyotp.TOTP(shared_secret)

app = Flask(__name__)





@app.route("/verify", methods=["POST"])
def verify():
    start_time = time.time()

    mode = request.args.get("mode", "plain")
    data = request.data

    # detect ssl stripping: request came in over plain http (not secure)
    # attacker view printing moved to ssl_stripper_totp.py proxy

    decrypt_runtime = 0.0

    if mode == "rsa":
        # decrypt with rsa-oaep sha-256
        start_decrypt = time.time()

        decrypted_otp = private_key.decrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        decrypt_runtime = (time.time() - start_decrypt) * 1000
        print(f"\n[server-rsa] received encrypted otp ({len(data)} bytes)")
        print(f"[server-rsa] decryption runtime : {decrypt_runtime:.3f} ms")

    elif mode == "aes":
        # extract iv (first 16 bytes) then decrypt aes-cbc, then unpad pkcs7
        start_decrypt = time.time()

        iv = data[:16]         # 16 bytes = 128-bit iv
        ciphertext = data[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()  # 128 = block size in bits
        decrypted_otp = (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()

        decrypt_runtime = (time.time() - start_decrypt) * 1000
        print(f"\n[server-aes] received encrypted otp ({len(data)} bytes)")
        print(f"[server-aes] decryption runtime : {decrypt_runtime:.3f} ms")

    else:
        # plain mode — no decryption needed
        decrypted_otp = data.decode()
        print(f"\n[server-plain] received otp (no decryption)")

    print(f"[server] otp value       : {decrypted_otp}")

    # verify otp using totp
    start_verify = time.time()
    is_valid = totp.verify(decrypted_otp)
    verify_runtime = (time.time() - start_verify) * 1000

    status = "verification success" if is_valid else "verification failed"
    total_runtime = (time.time() - start_time) * 1000

    print(f"[server] verify runtime  : {verify_runtime:.3f} ms")
    print(f"[server] total runtime   : {total_runtime:.3f} ms")
    print(f"[server] status          : {status}")

    return {
        "status": status,
        "mode": mode,
        "decrypt_runtime_ms": round(decrypt_runtime, 3),
        "verify_runtime_ms": round(verify_runtime, 3),
        "total_runtime_ms": round(total_runtime, 3)
    }


if __name__ == "__main__":
    cert_file = "server.crt"
    key_file  = "server.key"

    force_no_tls = os.environ.get("FORCE_NO_TLS") == "1"

    if not force_no_tls and os.path.exists(cert_file) and os.path.exists(key_file):
        print("starting server with tls (https) on port 5000")
        app.run(host="0.0.0.0", port=5000, ssl_context=(cert_file, key_file))
    else:
        print("starting server without tls (http) on port 5000")
        app.run(host="0.0.0.0", port=5000)