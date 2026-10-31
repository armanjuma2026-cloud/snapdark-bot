# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import base64
import shutil
import subprocess
import re
import zipfile
import io

def check_dependencies():
    missing = []
    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing.append("pycryptodome")
    try:
        from argon2.low_level import hash_secret_raw, Type as ArgonType
    except ImportError:
        missing.append("argon2-cffi")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required modules {missing} not found. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    from Crypto.Cipher import AES
    from argon2.low_level import hash_secret_raw, Type as ArgonType
    return AES

AES = check_dependencies()
from argon2.low_level import hash_secret_raw, Type as ArgonType

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

CREDITS = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell"}

APK_PATH = "/storage/emulated/0/MT2/apks/Solid Tunnel VPN_v1.0.8.8.apks"
PACKAGE = "solid.solidudptunnel.vpn"
PASSWORD = "NurChickenPowder"
OUTPUT_FILE = "/sdcard/VPNs/Solid Tunnel VPN ☠️.json"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

# ---------------- LAYER 1/2 : Argon2id KDF + AES-256-GCM ----------------
# blob layout: salt16 || nonce12 || ciphertext || tag16   (aad = salt)

_key_cache = {}

def _argon_key(pw, salt):
    return hash_secret_raw(secret=pw.encode("utf-8"), salt=salt, time_cost=3,
                           memory_cost=8192, parallelism=1, hash_len=32,
                           type=ArgonType.ID, version=19)

def _key_for(salt):
    if salt not in _key_cache:
        _key_cache[salt] = _argon_key(PASSWORD, salt)
    return _key_cache[salt]

def b64_decode(s):
    s = re.sub(r"\s", "", s)
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def decrypt_blob(blob):
    if len(blob) < 28:
        return None
    salt, nonce, body = blob[:16], blob[16:28], blob[28:]
    key = _key_for(salt)
    for aad in (salt, b""):
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if aad:
                cipher.update(aad)
            if len(body) >= 16:
                return cipher.decrypt_and_verify(body[:-16], body[-16:])
            return cipher.decrypt_and_verify(b"", body)
        except Exception:
            continue
    return None

_B64_RE = re.compile(r'^[A-Za-z0-9+/]{44,}={0,2}$')

def recursive_l2(node, stats):
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str) and _B64_RE.match(v) and len(v) % 4 != 1:
                try:
                    blob = b64_decode(v)
                except Exception:
                    blob = None
                if blob is not None:
                    pt = decrypt_blob(blob)
                    if pt is not None:
                        node[k] = pt.decode("utf-8", "replace")
                        stats[0] += 1
            elif isinstance(v, (dict, list)):
                recursive_l2(v, stats)
    elif isinstance(node, list):
        for x in node:
            recursive_l2(x, stats)
    return stats[0]

# ---------------- Embedded asset reader ----------------

def read_embedded_b64():
    with zipfile.ZipFile(APK_PATH) as outer:
        base_name = [n for n in outer.namelist() if n.endswith("base.apk")][0]
        with outer.open(base_name) as fh:
            inner_bytes = fh.read()
    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
        return inner.read("assets/configfile.json").decode("utf-8").strip()

# ---------------- Output ----------------

def save_output(path, config):
    final_json = dict(CREDITS)
    final_json.update(config)
    out_str = json.dumps(final_json, indent=4, ensure_ascii=False)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: {path}", C_GREEN)
    except (PermissionError, OSError):
        local_out = os.path.basename(path)
        with open(local_out, "w", encoding="utf-8") as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: ./{local_out}", C_GREEN)

def main():
    print("")
    print_bar(C_CYAN)
    print_c("Solid Tunnel VPN Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_c(f"Package: {PACKAGE}  |  APK: Solid Tunnel VPN_v1.0.8.8.apks", C_CYAN)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Reading embedded asset (assets/configfile.json)...", C_BLUE)
    try:
        b64 = read_embedded_b64()
        blob = b64_decode(b64)
        print_c(f"[+] Embedded payload ready ({len(blob)} bytes blob)", C_GREEN)
    except Exception as e:
        print_c(f"[-] Embedded read failure: {e}", C_RED)
        return

    print("")
    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : Argon2id KDF (t=3, m=8192, p=1) + AES-256-GCM", C_CYAN)
    print_c("Layout    : salt16 || nonce12 || ciphertext || tag16  (aad = salt)", C_CYAN)
    time.sleep(1)

    try:
        parsed = json.loads(decrypt_blob(blob))
        print_c("[+] Layer 1 breached successfully", C_GREEN)
    except Exception as e:
        print_c(f"[-] Layer 1 failure: {e}", C_RED)
        return

    print("")
    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : same Argon2id + AES-256-GCM, per-field salt", C_CYAN)
    print_c("Scope     : Servers + Networks (ServerIPHost, OVPN*, UDP_*, SlowDNS*, V2ray*, Payload, SNI, ...)", C_CYAN)
    time.sleep(1)

    stats = [0]
    recursive_l2(parsed, stats)
    print_c(f"[+] Layer 2 inner fields decrypted : {stats[0]}", C_GREEN)

    print("")
    print_c(f"[*] Version : {parsed.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Servers : {len(parsed.get('Servers', []))}", C_BLUE)
    print_c(f"[*] Networks : {len(parsed.get('Networks', []))}", C_BLUE)
    print("")

    save_output(OUTPUT_FILE, parsed)
    print("")

if __name__ == "__main__":
    main()
