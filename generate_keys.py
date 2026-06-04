import os
import ipaddress
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import pyotp


# generate rsa key pair (2048-bit) for rsa-oaep mode
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("rsa key pair generated  →  private_key.pem, public_key.pem")


# generate aes-cbc shared key (256-bit = 32 bytes) and iv placeholder
# key is stored as hex string; a fresh iv is generated per request at runtime
aes_key = os.urandom(32)  # aes-256: 32 bytes key, block size always 128-bit (16 bytes)

with open("aes_key.bin", "wb") as f:
    f.write(aes_key)

print("aes-cbc key generated   →  aes_key.bin  (256-bit key, block size 128-bit)")


# generate shared secret for totp
shared_secret = pyotp.random_base32()

with open("shared_secret.txt", "w") as f:
    f.write(shared_secret)

print("totp shared secret generated  →  shared_secret.txt")


# generate self-signed tls certificate for https (localhost)
tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

with open("server.key", "wb") as f:
    f.write(
        tls_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Some-State"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Locality"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Org"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(tls_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow() - timedelta(days=1))
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    )
    .sign(tls_key, hashes.SHA256())
)

with open("server.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("self-signed tls cert generated  →  server.crt, server.key")