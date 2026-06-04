import subprocess
import sys
import os
import time


# valid modes: plain, rsa, aes, ssl-strip-plain, ssl-strip-rsa, ssl-strip-aes
ENCRYPTION_MODES = {
    "1": ("plain",           "no extra encryption          (ukur runtime)"),
    "2": ("rsa",             "with rsa-oaep encryption     (ukur runtime)"),
    "3": ("aes",             "with aes-cbc encryption      (ukur runtime)"),
    "4": ("ssl-strip-plain", "ssl stripping + plain         (uji keamanan)"),
    "5": ("ssl-strip-rsa",   "ssl stripping + rsa-oaep     (uji keamanan)"),
    "6": ("ssl-strip-aes",   "ssl stripping + aes-cbc      (uji keamanan)"),
}

REQUIRED_FILES = [
    "public_key.pem",
    "private_key.pem",
    "shared_secret.txt",
]

TLS_FILES = [
    "server.crt",
    "server.key",
]

SSL_STRIPPER_SCRIPT = "ssl_stripper_totp.py"
PROXY_PORT          = 8080
SERVER_PORT         = 5000


# ============================================================
# STEP 1 — CHECK REQUIRED FILES
# ============================================================

missing_files = [f for f in REQUIRED_FILES if not os.path.exists(f)]

if missing_files:
    print("error: required files not found.\n")
    for f in missing_files:
        print(f"  missing  →  {f}")
    print("\nplease run:")
    print("  python generate_keys.py\n")
    sys.exit(1)

print("all required files detected.\n")


while True:

    # ============================================================
    # STEP 2 — MODE SELECTION
    # ============================================================

    print("=" * 58)
    print("  pilih mode operasi")
    print("=" * 58)
    print("  [ performance benchmark ]")
    for key in ("1", "2", "3"):
        mode_str, label = ENCRYPTION_MODES[key]
        print(f"  {key}.  {label}")
    print()
    print("  [ security test — ssl stripping ]")
    for key in ("4", "5", "6"):
        mode_str, label = ENCRYPTION_MODES[key]
        print(f"  {key}.  {label}")
    print("=" * 58)

    choice = input("\npilih (1–6): ").strip()

    if choice not in ENCRYPTION_MODES:
        print("invalid choice!")
        continue

    mode, mode_label = ENCRYPTION_MODES[choice]
    is_ssl_strip     = mode.startswith("ssl-strip")

    # derive the actual encryption mode sent to client/server
    # e.g. "ssl-strip-rsa" → underlying payload mode is "rsa"
    underlying_mode = mode.replace("ssl-strip-", "") if is_ssl_strip else mode

    print(f"\nmode dipilih  →  {mode_label}\n")


    # ============================================================
    # STEP 3 — ENSURE TLS FILES
    # ============================================================

    missing_tls = [f for f in TLS_FILES if not os.path.exists(f)]

    if missing_tls:
        print("tls files not found. generating keys and tls certificate...\n")
        subprocess.run([sys.executable, "generate_keys.py"], check=True)

        still_missing = [f for f in TLS_FILES if not os.path.exists(f)]
        if still_missing:
            print("error: tls files still missing after generation.")
            print("please check generate_keys.py output.")
            sys.exit(1)

    if is_ssl_strip:
        print("ssl stripping mode  →  server tetap https.")
        print("proxy attacker di port 8080 akan intercept traffic http dari client.\n")


    # ============================================================
    # STEP 4 — START SERVER (selalu https)
    # ============================================================

    print("starting server...\n")

    server_process = subprocess.Popen(
        [sys.executable, "server.py"]
    )

    time.sleep(2)


    # ============================================================
    # STEP 5 — START SSL STRIPPER PROXY (hanya ssl-strip modes)
    # ============================================================

    proxy_process = None

    if is_ssl_strip:
        if not os.path.exists(SSL_STRIPPER_SCRIPT):
            print(f"error: {SSL_STRIPPER_SCRIPT} tidak ditemukan.")
            server_process.terminate()
            sys.exit(1)

        print("starting ssl stripper proxy...\n")

        proxy_process = subprocess.Popen(
            [sys.executable, SSL_STRIPPER_SCRIPT]
        )

        time.sleep(1)


    # ============================================================
    # STEP 6 — START TOTP GENERATOR
    # ============================================================

    print("starting realtime totp generator...\n")

    totp_process = subprocess.Popen(
        [sys.executable, "totp_generator.py"]
    )

    time.sleep(1)


    # ============================================================
    # STEP 7 — START CLIENT
    # ============================================================

    print("starting client application...\n")
    print("-" * 58)

    client_args = [sys.executable, "client.py", underlying_mode]
    client_env  = os.environ.copy()
    client_env["RESULT_LOG_FILE"] = os.path.abspath("run_results.json")

    if is_ssl_strip:
        # arahkan client ke proxy, bukan langsung ke server
            # when running ssl-strip modes, instruct client to use local proxy
            client_args.extend(["--proxy", "http://127.0.0.1:8080"])

    subprocess.run(client_args, env=client_env)


    # ============================================================
    # STEP 8 — CLEANUP
    # ============================================================

    print("-" * 58)
    print("\nterminating processes...")

    server_process.terminate()
    totp_process.terminate()

    if proxy_process is not None:
        proxy_process.terminate()
        proxy_process.wait(timeout=5)

    server_process.wait(timeout=5)
    totp_process.wait(timeout=5)

    print("processes terminated.")


    # ============================================================
    # STEP 9 — CONTINUE OR EXIT
    # ============================================================

    print()
    again = input("jalankan mode lain? (y/n): ").strip().lower()

    if again != "y":
        break

    print()


print("\napplication closed.")