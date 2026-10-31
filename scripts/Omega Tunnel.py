# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import base64
import shutil
import struct
import hashlib
import subprocess

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        import Crypto
    except ImportError:
        missing.append("pycryptodome")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + ("[*] Auto-installing: " + ", ".join(missing)).center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q"] + missing)

check_dependencies()
import requests
from Crypto.Cipher import AES

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

CONFIG_URLS = [
    "https://raw.githubusercontent.com/uptechvpn/Omega-Tunnel/refs/heads/main/Omega%20Tunnel",
    "https://raw.githubusercontent.com/uptechvpn/Kaidtunnelnew/refs/heads/main/Kaidtunnelnew",
]
OUTPUT_FILE = "/sdcard/VPNs/Omega Tunnel VPN ☠️.json"
APK_PATH = "/storage/emulated/0/MT2/apks/Omega Tunnel_1.0.apks"
RAW_ENTRY = "res/raw/noobdev.js"

XXTEA_KEY = ('\u3164' * 32).encode('utf-8')
ES_PLAIN = "                                                             '            .        "
OO0_PLAIN = '                             .                                 '
ES_IV = bytes([0x4e, 0x6a, 0x2c, 0x81, 0x53, 0xd9, 0xb4, 0xa7, 0x90, 0x3f, 0x68, 0x5c, 0xa1, 0xef, 0x24, 0x79])
OO0_IV = bytes([0x3c, 0x7f, 0x1a, 0x9d, 0x55, 0xe3, 0xc0, 0xb2, 0x8e, 0x21, 0x6d, 0x4a, 0x97, 0xff, 0x13, 0x62])

M32 = 0xffffffff
DELTA = (-0x658c6c4c) & M32

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

def _mx(s, p1, p2, p3, p4, key):
    v0 = (((p2 >> 5) & M32) ^ ((p1 << 2) & M32)) & M32
    v1 = (((p1 >> 3) & M32) ^ ((p2 << 4) & M32)) & M32
    v0 = (v0 + v1) & M32
    p0 = (s ^ p1) & M32
    p0 = (p0 + (key[((p3 & 3) ^ p4) & 3] ^ p2)) & M32
    return p0 ^ v0

def xxtea_decrypt(data, key16):
    n = len(data) // 4 + (1 if len(data) % 4 else 0)
    data = data.ljust(n * 4, b'\0')
    v = list(struct.unpack('<%dI' % n, data))
    if n < 2:
        return struct.pack('<%dI' % n, *v)
    key = list(struct.unpack('<4I', key16[:16]))
    rounds = (52 // n) + 6
    s = (rounds * DELTA) & M32
    z = v[0]
    while s != 0:
        e = (s >> 2) & 3
        p = n - 1
        while p > 0:
            v[p] = (v[p] - _mx(s, z, v[p - 1], p, e, key)) & M32
            z = v[p]
            p -= 1
        v[0] = (v[0] - _mx(s, z, v[n - 1], 0, e, key)) & M32
        z = v[0]
        s = (s - DELTA) & M32
    return struct.pack('<%dI' % n, *v)

def b64d(s):
    return base64.b64decode(s + '=' * (-len(s) % 4))

def es_cfb(v):
    key = hashlib.sha256(ES_PLAIN.encode('utf-8')).digest()
    return AES.new(key, AES.MODE_CFB, ES_IV, segment_size=128).decrypt(b64d(v))

def oo0_cbc(v):
    ct = b64d(v)
    if not ct or len(ct) % 16:
        return None
    key = hashlib.md5(OO0_PLAIN.encode()).hexdigest().encode()
    pt = AES.new(key, AES.MODE_CBC, OO0_IV).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    return pt

import re as _re
def _printable(t):
    return all(32 <= ord(c) < 127 or c in ' \r\n\t' or ord(c) > 0x2000 for c in t)

def decrypt_field(v):
    if not isinstance(v, str) or len(v) < 4 or not _re.fullmatch(r'[A-Za-z0-9+/=]{4,}', v):
        return v
    for fn in (oo0_cbc, es_cfb):
        try:
            raw = fn(v)
            if raw is None:
                continue
            s = raw.decode('utf-8')
            if _printable(s):
                return s
        except Exception:
            pass
    return v

def decrypt_tree(x):
    if isinstance(x, dict):
        return {k: decrypt_tree(v) for k, v in x.items()}
    if isinstance(x, list):
        return [decrypt_tree(i) for i in x]
    return decrypt_field(x)

def unwrap(text):
    text = text.strip().encode()
    raw = base64.b64decode(text + b'=' * (-len(text) % 4))
    pt = xxtea_decrypt(raw, XXTEA_KEY[:16])
    length = int.from_bytes(pt[-4:], 'little')
    if not (len(pt) - 7 <= length <= len(pt)):
        raise ValueError("bad XXTEA length")
    return json.loads(pt[:length].decode('utf-8'))

def fetch_live():
    last = None
    for url in CONFIG_URLS:
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            txt = r.text.strip()
            return unwrap(txt), url
        except Exception as e:
            last = e
    raise RuntimeError(str(last))

import zipfile

def load_embedded(apk=None):
    path = apk or (APK_PATH if os.path.exists(APK_PATH) else None)
    if not path or not os.path.exists(path):
        raise RuntimeError(f"APK not found: {path}")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if RAW_ENTRY in names:
            blob = z.read(RAW_ENTRY)
        else:
            bases = [n for n in names if n.endswith('.apk') and 'base' in n] or [n for n in names if n.endswith('.apk')]
            if not bases:
                raise RuntimeError("no base apk inside bundle")
            with zipfile.ZipFile(zipfile.io.BytesIO(z.read(bases[0]))) as z2:
                if RAW_ENTRY not in z2.namelist():
                    raise RuntimeError("res/raw/noobdev.js not found in apk")
                blob = z2.read(RAW_ENTRY)
    return unwrap(blob.decode('utf-8', 'ignore')), f"embedded:{os.path.basename(path)}::{RAW_ENTRY}"

def save_output(path, obj, source):
    final_json = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell"}
    final_json.update(obj)
    out_str = json.dumps(final_json, indent=4, ensure_ascii=False)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: {path}", C_GREEN)
    except (PermissionError, OSError):
        local_out = os.path.basename(path)
        with open(local_out, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: ./{local_out}", C_GREEN)

def main():
    print("")
    print_bar(C_CYAN)
    print_c("Omega Tunnel Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    config = None
    source = None

    args = sys.argv[1:]
    mode = 'live'
    apk_arg = None
    file_arg = None
    i = 0
    while i < len(args):
        if args[i] in ('--embedded', '--apk', '-e') and i + 1 < len(args):
            mode, apk_arg = 'embedded', args[i + 1]; i += 2
        elif args[i] in ('--embedded', '--apk', '-e'):
            mode = 'embedded'; i += 1
        elif args[i] in ('--file', '-f') and i + 1 < len(args):
            mode, file_arg = 'file', args[i + 1]; i += 2
        else:
            i += 1

    try:
        if mode == 'embedded':
            print_c("[*] Reading embedded res/raw/noobdev.js from APK...", C_BLUE)
            enc, source = load_embedded(apk_arg)
        elif mode == 'file':
            print_c(f"[*] Reading file: {file_arg}", C_BLUE)
            enc, source = unwrap(open(file_arg, 'rb').read().decode('utf-8', 'ignore')), file_arg
        else:
            print_c("[*] Fetching live config (GitHub raw, public)...", C_BLUE)
            enc, source = fetch_live()
        print_c("[+] Config received, decrypting...", C_GREEN)
        config = decrypt_tree(enc)
    except Exception as e:
        print_c(f"[-] Failed: {e}", C_RED)
        print_c("[*] Check internet / GitHub access / apk path and try again.", C_YELLOW)
        return

    print("")
    print_c(">>> DECRYPTION SUMMARY <<<", C_YELLOW)
    print_c("Envelope : XXTEA-variant key=U+3164x32 delta=0x9A7393B4", C_CYAN)
    print_c("Field 1  : Sm.c  AES-256-CFB  key=SHA256(83ch const) fixed IV", C_CYAN)
    print_c("Field 2  : Sm.d  AES-128-CBC  key=hex(MD5(63ch const)) fixed IV", C_CYAN)
    print_c("Update   : Kaidtunnelnew JSON (update_version / apk_url / version_rules)", C_CYAN)
    print("")

    print_c(f"[*] Config Version  : {config.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Config URL      : {config.get('DefUpdateURL', 'N/A')[:70]}", C_BLUE)
    print_c(f"[*] Telegram        : {config.get('cardLink', 'N/A')}", C_BLUE)
    servers = config.get('Servers', [])
    tweaks = config.get('Tweaks', [])
    print_c(f"[*] Servers         : {len(servers)}", C_BLUE)
    for s in servers:
        print_c(f"    - {s.get('Name', '').strip()} | {s.get('Flag', '')} | {s.get('ServerIPHost', '')} | {s.get('Username', '')}:{s.get('Password', '')}", C_CYAN)
    print_c(f"[*] Tweaks          : {len(tweaks)}", C_BLUE)
    for t in tweaks:
        print_c(f"    - {t.get('Name', '').strip()} | Mode {t.get('Mode', '')} | {t.get('ProxyHost', '')}:{t.get('ProxyPort', '')}", C_CYAN)
    msg = config.get('Message', '')
    if msg:
        print("")
        print_bar(C_YELLOW)
        print(msg)
        print_bar(C_YELLOW)
    print("")

    save_output(OUTPUT_FILE, config, source)
    print("")

if __name__ == "__main__":
    main()
