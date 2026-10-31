# Python By @snapdark_decoder 🇧🇩
import os
import re
import sys
import json
import time
import base64
import shutil
import struct
import zipfile
import subprocess
import io

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + ("[*] Auto-installing: " + ", ".join(missing)).center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q"] + missing)

check_dependencies()
import requests

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

CONFIG_URLS = [
    "https://raw.githubusercontent.com/pipoyrichards/RMPSYSTEM/refs/heads/main/RMPPRO",
    "https://raw.githubusercontent.com/pipoyrichards/RMPSYSTEM/refs/heads/main/RMPLITE",
]
APK_PATH = "/storage/emulated/0/MT2/apks/RMP TUNNEL PRO_RMP-5.apks"
EMBEDDED_ASSET = "assets/gremlin.json"
OUTPUT_FILE = "/sdcard/VPNs/RMP TUNNEL PRO VPN ☠️.json"

XXTEA_KEY = b'...|...'
M32 = 0xffffffff
DELTA = (-0x61a8d64f) & M32
B64RX = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}{C_RESET}")

def _mx(s, y, z, p, e, key):
    v0 = (((z >> 5) & M32) ^ ((y << 2) & M32)) & M32
    v1 = (((y >> 3) & M32) ^ ((z << 4) & M32)) & M32
    v0 = (v0 + v1) & M32
    p0 = (s ^ y) & M32
    p0 = (p0 + (key[((p & 3) ^ e) & 3] ^ z)) & M32
    return p0 ^ v0

def words_le(data):
    n = len(data) // 4 + (1 if len(data) % 4 else 0)
    return list(struct.unpack('<%dI' % n, data.ljust(n * 4, b'\0')))

def key_words(key16):
    return list(struct.unpack('<4I', key16[:16].ljust(16, b'\0')))

def xxtea_decrypt(data, key16):
    v = words_le(data)
    n = len(v)
    if n < 2:
        return struct.pack('<%dI' % n, *v)
    key = key_words(key16)
    rounds = (52 // n) + 6
    s = (rounds * DELTA) & M32
    while s != 0:
        e = (s >> 2) & 3
        y = v[0]
        p = n - 1
        while p > 0:
            v[p] = (v[p] - _mx(s, y, v[p - 1], p, e, key)) & M32
            y = v[p]
            p -= 1
        v[0] = (v[0] - _mx(s, y, v[n - 1], 0, e, key)) & M32
        s = (s - DELTA) & M32
    return struct.pack('<%dI' % n, *v)

def xxtea_encrypt(pt, key16):
    v = words_le(pt)
    v.append(len(pt))
    n = len(v)
    key = key_words(key16)
    s = 0
    for _ in range((52 // n) + 6):
        s = (s + DELTA) & M32
        e = (s >> 2) & 3
        z = v[n - 1]
        for p in range(n - 1):
            v[p] = (v[p] + _mx(s, v[p + 1], z, p, e, key)) & M32
            z = v[p]
        v[n - 1] = (v[n - 1] + _mx(s, v[0], z, n - 1, e, key)) & M32
    return struct.pack('<%dI' % n, *v)

def b64d(s):
    if isinstance(s, str):
        s = s.encode()
    s = bytes(c for c in s if c not in b' \r\n\t')
    return base64.b64decode(s + b'=' * (-len(s) % 4))

def xxtea_try(ct):
    if not ct or len(ct) % 4:
        return None
    pt = xxtea_decrypt(ct, XXTEA_KEY)
    n = len(pt) // 4
    length = struct.unpack('<I', pt[-4:])[0]
    if not (n * 4 - 7 <= length <= n * 4 - 4):
        return None
    return pt[:length]

def unwrap(text):
    raw = b64d(text)
    pt = xxtea_try(raw)
    if pt is None:
        raise ValueError("XXTEA padding check failed (wrong key or corrupt blob)")
    return pt.decode('utf-8')

def decrypt_field(v):
    if not isinstance(v, str) or len(v) % 4 or not B64RX.match(v):
        return v
    try:
        pt = xxtea_try(b64d(v))
    except Exception:
        return v
    if pt is None:
        return v
    try:
        return pt.decode('utf-8')
    except UnicodeDecodeError:
        return v

def decrypt_tree(x):
    hits = 0
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            nv, h = decrypt_tree(v)
            out[k] = nv
            hits += h
        return out, hits
    if isinstance(x, list):
        out = []
        for i in x:
            ni, h = decrypt_tree(i)
            out.append(ni)
            hits += h
        return out, hits
    dec = decrypt_field(x)
    return dec, (1 if dec != x else 0)

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
    print_c("RMP TUNNEL PRO Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    source = None
    blob = None
    for url in CONFIG_URLS:
        try:
            response = requests.get(url, headers={'User-Agent': 'okhttp/4.9.0'}, timeout=25)
            response.raise_for_status()
            blob = response.text
            source = url
            print_c(f"[+] Live encrypted payload downloaded ({len(blob)} chars)...", C_GREEN)
            break
        except Exception as e:
            print_c(f"[-] Live fetch failed ({url.split('/')[-1]}: {e})", C_YELLOW)

    if blob is None:
        print_c("[*] Falling back to embedded asset (assets/gremlin.json)...", C_BLUE)
        try:
            blob = read_embedded_blob()
            source = f"{APK_PATH}!/{EMBEDDED_ASSET}"
            print_c(f"[+] Embedded payload ready ({len(blob)} chars)...", C_GREEN)
        except Exception as e2:
            print_c(f"[-] Embedded read failure: {e2}", C_RED)
            return

    print("")
    print_c(">>> DECRYPTION LAYER <<<", C_YELLOW)
    print_c("Algorithm : XXTEA (modified DELTA=0x9E5729B1, key '...|...')", C_CYAN)
    print_c("Container : base64 standard alphabet, length-word stripped", C_CYAN)
    print_c("Scope     : Whole config + nested base64+XXTEA fields (per-field)", C_CYAN)
    time.sleep(1)

    try:
        parsed = json.loads(unwrap(blob))
        parsed, nfields = decrypt_tree(parsed)
        print_c("[+] Config Successfully Breached..", C_GREEN)
        print_c(f"[+] Inner XXTEA-protected fields decrypted : {nfields}", C_GREEN)
    except Exception as e:
        print_c(f"[-] Decryption failure: {e}", C_RED)
        return

    print("")
    print_c(f"[*] Version        : {parsed.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Free Servers   : {len(parsed.get('Free_servers', []))}", C_BLUE)
    print_c(f"[*] Premium Servers: {len(parsed.get('Premium_servers', []))}", C_BLUE)
    print_c(f"[*] Vip Servers    : {len(parsed.get('Vip_servers', []))}", C_BLUE)
    print_c(f"[*] Private Servers: {len(parsed.get('Private_servers', []))}", C_BLUE)
    print_c(f"[*] Tweaks/Payloads: {len(parsed.get('Payloads', []))}", C_BLUE)
    print("")

    save_output(OUTPUT_FILE, parsed, source, nfields)
    print_c(f"[+] Saved -> {OUTPUT_FILE}", C_GREEN)
    print("")

if __name__ == "__main__":
    main()
