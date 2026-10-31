# Python By @snapdark_decoder 🇧🇩
import os
import re
import sys
import json
import time
import base64
import shutil
import zipfile
import subprocess
import io
from concurrent.futures import ThreadPoolExecutor

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        import Crypto.Cipher
    except ImportError:
        missing.append("pycryptodome")
    try:
        import argon2.low_level
    except ImportError:
        missing.append("argon2-cffi")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + ("[*] Auto-installing: " + ", ".join(missing)).center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q"] + missing)

check_dependencies()
import requests
from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

APK_PATH = "/storage/emulated/0/MT2/apks/MM Tunnel_v1.10.5.1.apks"
EMBEDDED_ASSET = "assets/configfile.json"
OUTPUT_FILE = "/sdcard/VPNs/MM Tunnel VPN ☠️.json"
LIVE_URL = "https://strongteam.co/nets/"

PASSWORD = b"NewDecryptLibPassword"
TIME_COST = 3
MEMORY_COST = 16384
PARALLELISM = 1
HASH_LEN = 32
B64RX = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
_SALT_CACHE = {}

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}{C_RESET}")

def derive_key(salt):
    key = _SALT_CACHE.get(salt)
    if key is None:
        key = hash_secret_raw(secret=PASSWORD, salt=salt, time_cost=TIME_COST,
                              memory_cost=MEMORY_COST, parallelism=PARALLELISM,
                              hash_len=HASH_LEN, type=Type.ID)
        _SALT_CACHE[salt] = key
    return key

def decrypt_blob(s):
    if not isinstance(s, str) or not B64RX.match(s):
        return s
    try:
        data = base64.b64decode(s)
    except Exception:
        return s
    if len(data) < 28:
        return s
    salt = data[:16]
    nonce = data[16:28]
    body = data[28:]
    try:
        cipher = AES.new(derive_key(salt), AES.MODE_GCM, nonce=nonce)
        cipher.update(salt)
        ct = body[:-16] if len(body) > 16 else b''
        tag = body[-16:]
        plaintext = cipher.decrypt_and_verify(ct, tag)
        return plaintext.decode('utf-8', 'replace')
    except Exception:
        return s

def decrypt_field(path, value):
    return path, value, decrypt_blob(value), (decrypt_blob(value) != value)

def read_embedded_blob():
    candidates = [EMBEDDED_ASSET, 'assets/' + os.path.basename(EMBEDDED_ASSET)]
    with zipfile.ZipFile(APK_PATH) as zf:
        for entry in zf.namelist():
            if entry.endswith('.apk'):
                inner = zipfile.ZipFile(io.BytesIO(zf.read(entry)))
                for cand in candidates:
                    if cand in inner.namelist():
                        return inner.read(cand).decode('utf-8', 'replace')
        for cand in candidates:
            if cand in zf.namelist():
                return zf.read(cand).decode('utf-8', 'replace')
    raise FileNotFoundError(f"{EMBEDDED_ASSET} not found inside {APK_PATH}")

def unwrap(blob):
    try:
        return json.loads(blob)
    except Exception:
        fresh = decrypt_blob(blob)
        if fresh == blob:
            return json.loads(blob)
        return json.loads(fresh)

def decrypt_tree(obj):
    strings = []

    def collect(o):
        if isinstance(o, dict):
            for k, v in o.items():
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)
        elif isinstance(o, str):
            strings.append(o)
    collect(obj)

    candidates = [s for s in strings if s and B64RX.match(s)]
    nfields = 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda s: (s, decrypt_blob(s)), candidates))
    rmap = {}
    for value, dec in results:
        if dec != value:
            nfields += 1
        rmap[value] = dec

    def apply(o):
        if isinstance(o, dict):
            return {k: apply(v) for k, v in o.items()}
        if isinstance(o, list):
            return [apply(v) for v in o]
        if o in rmap:
            return rmap[o]
        return o
    return apply(obj), nfields

def save_output(path, parsed, source, nfields):
    data = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell",
            "_decrypted_fields": nfields}
    data.update(parsed)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def main():
    print("")
    print_bar(C_CYAN)
    print_c("MM Tunnel Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_c("App : co.strongteam.marvsudp | Default user sandoki", C_BLUE)
    print_bar(C_CYAN)
    print("")

    source = None
    blob = None
    try:
        response = requests.get(LIVE_URL, headers={'User-Agent': 'okhttp/4.9.0'}, timeout=20)
        if response.status_code == 200 and len(response.content) > 100:
            blob = response.text
            source = LIVE_URL
            print_c(f"[+] Live encrypted payload downloaded ({len(blob)} chars)...", C_GREEN)
        else:
            print_c(f"[-] Live endpoint unreachable (HTTP {response.status_code})...", C_YELLOW)
    except Exception as e:
        print_c(f"[-] Live fetch failed: {e}", C_YELLOW)

    if blob is None:
        print_c("[*] Falling back to embedded asset (assets/configfile.json)...", C_BLUE)
        try:
            blob = read_embedded_blob()
            source = f"{APK_PATH}!/{EMBEDDED_ASSET}"
            print_c(f"[+] Embedded payload ready ({len(blob)} chars)...", C_GREEN)
        except Exception as e2:
            print_c(f"[-] Embedded read failure: {e2}", C_RED)
            return

    print("")
    print_c(">>> DECRYPTION LAYER <<<", C_YELLOW)
    print_c("Cipher    : AES-256-GCM (argon2id key derivation)", C_CYAN)
    print_c("Password  : NewDecryptLibPassword (t=3, m=16MiB, p=1, 32B)", C_CYAN)
    print_c("Container : base64 | salt16 || nonce12 || ct(+tag16)", C_CYAN)
    print_c("AAD       : 16-byte salt | Scope: whole config + fields", C_CYAN)
    time.sleep(1)

    try:
        parsed = unwrap(blob)
        parsed, nfields = decrypt_tree(parsed)
        print_c("[+] Config Successfully Breached..", C_GREEN)
        print_c(f"[+] Inner argon2/AES-GCM fields decrypted : {nfields}", C_GREEN)
    except Exception as e:
        print_c(f"[-] Decryption failure: {e}", C_RED)
        return

    servers = parsed.get('Servers', [])
    networks = parsed.get('Networks', [])
    print("")
    print_c(f"[*] Version        : {parsed.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Telegram       : {parsed.get('Telegram', 'N/A')}", C_BLUE)
    print_c(f"[*] Servers        : {len(servers)}", C_BLUE)
    print_c(f"[*] Networks       : {len(networks)}", C_BLUE)
    print_c(f"[*] DefOVPNUser    : {parsed.get('DefOVPNUser', 'N/A')}", C_BLUE)
    print("")

    save_output(OUTPUT_FILE, parsed, source, nfields)
    print_c(f"[+] Saved -> {OUTPUT_FILE}", C_GREEN)
    print("")

if __name__ == "__main__":
    main()