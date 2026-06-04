# TOTP Authentication System

Simulasi sistem autentikasi TOTP dengan tiga mode enkripsi payload (plain, RSA-OAEP,
AES-CBC) dan pengujian keamanan SSL stripping. Dibangun untuk keperluan akademik —
mengukur overhead enkripsi dan membuktikan perlunya enkripsi aplikasi-layer saat TLS
di-strip oleh attacker.

---

## Daftar isi

- [Struktur proyek](#struktur-proyek)
- [Cara kerja sistem](#cara-kerja-sistem)
- [Spesifikasi kriptografi](#spesifikasi-kriptografi)
- [Persiapan & instalasi](#persiapan--instalasi)
- [Menjalankan proyek](#menjalankan-proyek)
- [Mode operasi](#mode-operasi)
- [Alur sistem](#alur-sistem)

---


## Cara kerja sistem

```
totp_generator.py          client.py                    server.py
──────────────────         ──────────────────────────   ──────────────────────────
generate OTP tiap 30s  →   user input OTP               terima payload
                           enkripsi payload          →   dekripsi payload
                           kirim via HTTP(S)         →   verifikasi OTP via TOTP
                                                         kembalikan status + runtime
```

Client dan server berbagi:
- `shared_secret.txt` — untuk TOTP (keduanya generate OTP yang identik secara independen)
- `public_key.pem` / `private_key.pem` — untuk mode RSA
- `aes_key.bin` — untuk mode AES

---

## Spesifikasi kriptografi

# Cryptographic Configuration

## Python Environment

| Library      | Version   | Purpose                                |
| ------------ | --------- | -------------------------------------- |
| pyotp        | >= 2.9.0  | TOTP generation and verification       |
| cryptography | >= 42.0.0 | RSA-OAEP, AES-CBC, PKCS#7 padding      |
| flask        | >= 3.0.0  | Verification server                    |
| requests     | >= 2.31.0 | HTTPS client                           |
| pyOpenSSL    | >= 24.0.0 | Self-signed TLS certificate generation |

---

## RSA-OAEP Configuration

| Parameter          | Value        |
| ------------------ | ------------ |
| Algorithm          | RSA-OAEP     |
| Key Size           | 2048-bit     |
| OAEP Hash          | SHA-256      |
| MGF                | MGF1-SHA256  |
| Public Key Format  | SPKI         |
| Private Key Format | PKCS#8       |
| Key Encoding       | PEM          |
| Ciphertext Size    | 256 bytes    |
| Library            | cryptography |

### Usage

* OTP is encrypted on the client using `public_key.pem`.
* Server decrypts using `private_key.pem`.
* OAEP padding provides semantic security and prevents deterministic RSA encryption attacks.

---

## AES-CBC Configuration

| Parameter      | Value              |
| -------------- | ------------------ |
| Algorithm      | AES-CBC            |
| Key Size       | 256-bit (32 bytes) |
| Block Size     | 128-bit (16 bytes) |
| IV Size        | 128-bit (16 bytes) |
| Padding        | PKCS#7             |
| IV Generation  | os.urandom(16)     |
| Payload Format | IV | Ciphertext    |
| Library        | cryptography       |

### Plaintext Processing

| Component         | Size     |
| ----------------- | -------- |
| OTP (6 digits)    | 6 bytes  |
| PKCS#7 Padded OTP | 16 bytes |
| IV                | 16 bytes |
| Ciphertext        | 16 bytes |
| Total Payload     | 32 bytes |

### Notes

* A fresh IV is generated for every request.
* IV reuse with the same key is prohibited.
* PKCS#7 padding is required because AES-CBC operates on fixed-size blocks.

---

## TOTP Configuration

| Parameter       | Value      |
| --------------- | ---------- |
| Standard        | RFC 6238   |
| Algorithm       | TOTP       |
| Underlying HMAC | HMAC-SHA1  |
| Time Step       | 30 seconds |
| OTP Length      | 6 digits   |
| Secret Encoding | Base32     |
| Library         | pyotp      |

### Notes

* Parameters follow the default implementation of `pyotp`.
* OTP values change every 30 seconds.
* Compatible with common authenticator applications.

---

## TLS Configuration

| Parameter                       | Value                |
| ------------------------------- | -------------------- |
| Protocol                        | TLS                  |
| Certificate Type                | Self-Signed          |
| Key Algorithm                   | RSA                  |
| Key Size                        | 2048-bit             |
| Signature Hash                  | SHA-256              |
| Certificate Format              | X.509                |
| Encoding                        | PEM                  |
| Validity Period                 | 365 days             |
| Subject Alternative Names (SAN) | localhost, 127.0.0.1 |
| Library                         | pyOpenSSL            |

### Client Verification

```python
requests.post(
    url,
    verify="server.crt"
)
```

### Notes

* Self-signed certificates are used for local experimentation.
* Certificate validation is intentionally bypassed during SSL stripping simulations.

---

# Experimental Modes

| Mode  | TLS | Additional Encryption |
| ----- | --- | --------------------- |
| Plain | ✓   | None                  |
| RSA   | ✓   | RSA-OAEP              |
| AES   | ✓   | AES-256-CBC           |

---

# Security Evaluation Scenarios

## Runtime Benchmark

| Scenario | Description           |
| -------- | --------------------- |
| Plain    | TOTP + TLS            |
| RSA      | TOTP + TLS + RSA-OAEP |
| AES      | TOTP + TLS + AES-CBC  |

## SSL Stripping Attack Simulation

| Scenario              | Description                  |
| --------------------- | ---------------------------- |
| Plain + SSL Stripping | OTP transmitted in plaintext |
| RSA + SSL Stripping   | RSA ciphertext intercepted   |
| AES + SSL Stripping   | AES ciphertext intercepted   |

---

# Design Rationale

| Component   | Justification                                                                                                                                                   |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RSA-OAEP    | Modern asymmetric encryption scheme recommended in cryptographic literature for semantic security.                                                              |
| AES-256-CBC | Chosen as the symmetric encryption mode because CBC operation, IV usage, and padding mechanisms are extensively discussed in Stallings' cryptography reference. |
| TOTP        | Widely adopted time-based one-time password standard defined in RFC 6238.                                                                                       |
| TLS         | Represents the standard transport-layer protection used in modern web applications and serves as the target of SSL stripping attacks in this study.             |


---

## Persiapan & instalasi

**1. Clone / download proyek**

```bash
git clone <repo-url>
cd <folder-proyek>
```

**2. Buat virtual environment (direkomendasikan)**

```bash
python -m venv .venv

# linux / macos
source .venv/bin/activate

# windows
.venv\Scripts\activate
```

**3. Instal dependensi**

```bash
pip install -r requirements.txt
```

Isi `requirements.txt`:

```
pyotp>=2.9.0
cryptography>=42.0.0
flask>=3.0.0
requests>=2.31.0
pyOpenSSL>=24.0.0
```

**4. Generate semua kunci kriptografi**

```bash
python generate_keys.py
```

Perintah ini menghasilkan:

| File               | Isi                                        |
|--------------------|--------------------------------------------|
| `private_key.pem`  | RSA-2048 private key (PKCS#8, PEM)         |
| `public_key.pem`   | RSA-2048 public key (SPKI, PEM)            |
| `aes_key.bin`      | AES-256 key (32 bytes raw)                 |
| `shared_secret.txt`| TOTP shared secret (Base32 string)         |
| `server.crt`       | Self-signed X.509 certificate (PEM)        |
| `server.key`       | TLS private key (TraditionalOpenSSL, PEM)  |

Jalankan ulang `generate_keys.py` setiap kali ingin reset semua kunci.

---

## Menjalankan proyek

```bash
python main.py
```

`main.py` akan:
1. Cek keberadaan file kunci yang wajib ada
2. Tampilkan menu pilihan mode
3. Spawn `server.py` sebagai subprocess
4. Spawn `totp_generator.py` sebagai subprocess
5. Jalankan `client.py` secara interaktif
6. Terminate semua subprocess setelah client selesai

Ketika prompt muncul, salin OTP dari tampilan `totp_generator.py` dan masukkan ke client.

Setiap kali `main.py` selesai menjalankan client, ringkasan hasil run akan ditambahkan ke file `run_results.json` di folder proyek.

---

## Mode operasi

### Performance benchmark (ukur overhead enkripsi)

| Pilihan | Mode    | Enkripsi payload | Transport |
|---------|---------|------------------|-----------|
| 1       | plain   | tidak ada        | HTTPS     |
| 2       | rsa     | RSA-OAEP         | HTTPS     |
| 3       | aes     | AES-CBC          | HTTPS     |

Ketiganya berjalan di atas TLS. Output client dan server mencatat:
- `encryption_runtime_ms` — waktu enkripsi di client
- `decrypt_runtime_ms` — waktu dekripsi di server
- `verify_runtime_ms` — waktu verifikasi TOTP di server
- `total_runtime_ms` — end-to-end dari setelah input OTP

---

### Security test — SSL stripping

| Pilihan | Mode             | Enkripsi payload | Transport |
|---------|------------------|------------------|-----------|
| 4       | ssl-strip-plain  | tidak ada        | HTTP (!)  |
| 5       | ssl-strip-rsa    | RSA-OAEP         | HTTP (!)  |
| 6       | ssl-strip-aes    | AES-CBC          | HTTP (!)  |

TLS sengaja dimatikan (server berjalan HTTP, client tidak verify cert). Ini mensimulasikan
skenario attacker yang melakukan SSL stripping di tengah jaringan.

- Mode 4: OTP terkirim plaintext — attacker dapat langsung membaca OTP.
- Mode 5 & 6: OTP terenkripsi di level aplikasi — attacker hanya melihat ciphertext
  meski TLS sudah di-strip, membuktikan enkripsi aplikasi-layer sebagai defense-in-depth.

---

## Catatan keamanan

Proyek ini adalah simulasi akademik, bukan untuk production.
