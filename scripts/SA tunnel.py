# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import base64
import hashlib
import shutil
import subprocess
import re
import zipfile
import io

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
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
    import requests
    from Crypto.Cipher import AES
    from argon2.low_level import hash_secret_raw, Type as ArgonType
    return requests, AES

requests, AES = check_dependencies()
from argon2.low_level import hash_secret_raw, Type as ArgonType

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

URL = "https://strongteam.co/api/satunnelvpn/sav1.txt"
KEY_LIVE = "PTIPR@XYVPNPaSSII"
KEY_EMBED = "PTIPR@XYVPNPaSS"
OUTPUT_FILE = "/sdcard/VPNs/SA Tunnel VPN ☠️.json"
EMBEDDED_FILE = "/sdcard/VPNs/SA Tunnel VPN (Embedded) ☠️.json"
APK_PATH = "/storage/emulated/0/MT2/apks/SA Tunnel VPN_v1.02.apks"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

# ---------------- LAYER 1 : Argon2id KDF (password -> AES key) ----------------

def sa_argon_key(pw, salt):
    return hash_secret_raw(secret=pw, salt=salt, time_cost=3, memory_cost=8192,
                           parallelism=1, hash_len=32, type=ArgonType.ID, version=19)

_key_cache = {}

def _cache_keys(salt):
    return (_key_for(KEY_LIVE, salt), _key_for(KEY_EMBED, salt))

def _key_for(pw_key, salt):
    if pw_key not in _key_cache:
        _key_cache[pw_key] = {}
    bucket = _key_cache[pw_key]
    if salt not in bucket:
        bucket[salt] = sa_argon_key(pw_key.encode('utf-8'), salt)
    return bucket[salt]

# ---------------- LAYER 2 : AES-256-GCM (AAD = blob[:16], nonce = blob[16:28]) ----------------

def sa_b64_decode(s):
    s = re.sub(r"\s", "", s)
    return base64.b64decode(s + "=" * (-len(s) % 4))

def sa_decrypt_blob(blob):
    if len(blob) < 44:
        raise ValueError("blob too short")
    last = None
    for key in _cache_keys(blob[:16]):
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=blob[16:28])
            cipher.update(blob[:16])
            return cipher.decrypt_and_verify(blob[28:-16], blob[-16:])
        except Exception as e:
            last = e
    raise last

# ---------------- LAYER 3 : recursive per-field decryption ----------------

def read_embedded_blob():
    z = zipfile.ZipFile(APK_PATH)
    base = z.read([n for n in z.namelist() if n.endswith("base.apk")][0])
    inner = zipfile.ZipFile(io.BytesIO(base))
    return sa_b64_decode(inner.read("assets/configfile.json").decode().strip())

# ---------------- Output helper ----------------

_B64_RE = re.compile(r'^[A-Za-z0-9+/]{44,}={0,2}$')
_HEX_RE = re.compile(r'^[0-9a-fA-F]{40,}$')
_JSON_RE = re.compile(r'^\s*[\[{]')
_NUM_RE = re.compile(r'^\d+\.?\d*$')

def _is_already_plain(v):
    if _HEX_RE.match(v) or _JSON_RE.match(v) or _NUM_RE.match(v) or len(v) < 60:
        return True
    return False

def _try_field_dec(b64):
    try:
        raw = sa_b64_decode(b64)
    except Exception:
        return None
    if len(raw) < 44:
        return None
    salt = raw[:16]
    for key in (_key_for(KEY_LIVE, salt), _key_for(KEY_EMBED, salt)):
        for aad in (salt, b''):
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=raw[16:28])
                if aad:
                    cipher.update(aad)
                pt = cipher.decrypt_and_verify(raw[28:-16], raw[-16:])
                txt = pt.decode('utf-8', errors='strict')
                if txt and all(0x20 <= ord(c) < 0x7f or c in '\r\n\t' for c in txt):
                    return txt
                return txt
            except Exception:
                pass
    return None

def recursive_l2(node, count=[0]):
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str) and _B64_RE.match(v) and not _is_already_plain(v):
                d = _try_field_dec(v)
                if d is not None:
                    node[k] = d
                    count[0] += 1
            elif isinstance(v, (dict, list)):
                recursive_l2(v, count)
    elif isinstance(node, list):
        for x in node:
            recursive_l2(x, count)
    return count[0]

def save_output(path, config, source):
    final_json = { "CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell" }
    final_json.update(config)

    out_str = json.dumps(final_json, indent=4, ensure_ascii=False)
    
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: {path}", C_GREEN)
    except (PermissionError, OSError):
        print_c(f"[-] Permission denied for {path}. Trying local dir...", C_RED)
        local_out = os.path.basename(path)
        with open(local_out, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: ./{local_out}", C_GREEN)

def main():
    print("")
    print_bar(C_CYAN)
    print_c("SA Tunnel VPN Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Fetching encrypted payload from Server...", C_BLUE)
    time.sleep(0.5)

    live_failed = False
    try:
        response = requests.get(URL, headers={'User-Agent': 'okhttp/4.9.0'}, timeout=25)
        response.raise_for_status()
        blob = sa_b64_decode(response.text)
        print_c(f"[+] Encrypted payload downloaded ({len(blob)} bytes blob)...", C_GREEN)
    except Exception as e:
        live_failed = True
        print_c(f"[-] Live fetch failed ({e})", C_RED)
        print_c("[*] Falling back to embedded asset (assets/configfile.json)...", C_YELLOW)
        try:
            blob = read_embedded_blob()
            print_c(f"[+] Embedded payload ready ({len(blob)} bytes blob)...", C_GREEN)
        except Exception as e2:
            print_c(f"[-] Embedded read failure: {e2}", C_RED)
            return

    print("")

    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : Argon2id KDF (t=3, m=8192, p=1, Version 19)", C_CYAN)
    time.sleep(1)

    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : Argon2id KDF + AES-256-GCM (same password, per-field)", C_CYAN)
    print_c("Scope     : Servers + Networks (ServerIPHost, OVPN*, SlowDNS*, V2ray*, Payload, SNI, BugDNS, CustomCertificate, H2pass, UDP_user ...)", C_CYAN)
    time.sleep(1)

    try:
        json_str = sa_decrypt_blob(blob)
        parsed = json.loads(json_str)
        n2 = recursive_l2(parsed)
        print_c("[+] Layer 1 & 2 Successfully Breached..", C_GREEN)
        print_c(f"[+] Layer 2 inner fields decrypted : {n2} (incl. empty placeholders)", C_GREEN)
    except Exception as e:
        print_c(f"[-] Complete decryption breach failure: {e}", C_RED)
        return

    print("")
    print_c(f"[*] Version : {parsed.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Servers : {len(parsed.get('Servers', []))}", C_BLUE)
    print_c(f"[*] Networks : {len(parsed.get('Networks', []))}", C_BLUE)
    print("")

    save_output(OUTPUT_FILE, parsed, URL if not live_failed else "embedded-fallback")

    print("")
    if not live_failed:
        print_bar(C_CYAN)
        print_c(">>> EMBEDDED ASSET (assets/configfile.json) <<<", C_YELLOW)
        print_bar(C_CYAN)
        time.sleep(0.5)
        try:
            emb_blob = read_embedded_blob()
            emb_str = sa_decrypt_blob(emb_blob)
            emb = json.loads(emb_str)
            n2 = recursive_l2(emb)
            print_c("[+] Embedded config Successfully Breached..", C_GREEN)
            print_c(f"[+] Embedded Layer 2 inner fields decrypted : {n2}", C_GREEN)
            print_c(f"[*] Version : {emb.get('Version', 'N/A')}", C_BLUE)
            print_c(f"[*] Servers : {len(emb.get('Servers', []))}", C_BLUE)
            print("")
            save_output(EMBEDDED_FILE, emb, "assets/configfile.json")
        except Exception as e:
            print_c(f"[-] Embedded decrypt failure: {e}", C_RED)
    print("")

if __name__ == "__main__":
    main()