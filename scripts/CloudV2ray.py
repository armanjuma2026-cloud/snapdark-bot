# Python By @SnapDark
import os
import sys
import json
import time
import base64
import hashlib
import shutil
import subprocess
import re

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
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required modules {missing} not found. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    import requests
    from Crypto.Cipher import AES
    return requests, AES

requests, AES = check_dependencies()

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

URL = "https://pakhi.xyz/uploads/json/pakhivpn.json"
KEY = "sabrinapro"
SIG = "Telegram@noob_xman"
OUTPUT_FILE = "/sdcard/VPNs/CLOUD V2RAY VPN ☠️.json"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

# ---------------- LAYER 1 : CJK Base4096 + AES-256-CBC ----------------

def is_chinese(text):
    return isinstance(text, str) and len(text) > 0 and '\u4e00' <= text[0] <= '\u5dff'

def chinese_to_bytes(text):
    length = len(text)
    n = length * 12 // 8
    n = n // 16 * 16
    if n == 0 and length > 0:
        n = length * 12 // 8
    out = bytearray(n)
    acc = bits = idx = 0
    for c in text:
        if not ('\u4e00' <= c <= '\u5dff'):
            continue
        acc = (acc << 12) | ((ord(c) - 0x4E00) & 0xFFF)
        bits += 12
        while bits >= 8 and idx < n:
            bits -= 8
            out[idx] = (acc >> bits) & 0xFF
            idx += 1
    return bytes(out)

def aes_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()

def decrypt_cjk_aes(text, password):
    from Crypto.Util.Padding import unpad
    ciphertext = chinese_to_bytes(text)
    if not ciphertext:
        return None
    cipher = AES.new(aes_key(password), AES.MODE_CBC, bytes([0] * 16))
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

def peel_cjk(text, password):
    current = text
    while is_chinese(current):
        try:
            decrypted = decrypt_cjk_aes(current, password)
            if not decrypted or decrypted == current:
                break
            current = decrypted
        except Exception:
            break
    return current

# ---------------- LAYER 2 : Modified XXTEA (TeaBase64) ----------------

DELTA = 0x2e0ba747

def tea_b64decode(s):
    try:
        pad = len(s) % 4
        if pad:
            s += "=" * (4 - pad)
        return base64.b64decode(s)
    except Exception:
        return None

def to_int_array(data, include_length=False):
    n = (len(data) + 3) // 4
    result = [0] * (n + 1 if include_length else n)
    if include_length:
        result[n] = len(data)
    for i, b in enumerate(data):
        result[i >> 2] |= (b & 0xFF) << ((i & 3) << 3)
    return result

def to_byte_array(data, include_length=True):
    n = len(data) << 2
    if include_length:
        m = data[-1]
        if m > 0x7FFFFFFF:
            m -= 0x100000000
        if m < n - 7 or m > n - 4:
            return None
        n = m
    result = bytearray(n)
    for i in range(n):
        result[i] = (data[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(result)

def fix_key(key):
    key = key.encode('utf-8') if isinstance(key, str) else key
    if len(key) == 16:
        return key
    fixed = bytearray(16)
    fixed[:min(len(key), 16)] = key[:16]
    return bytes(fixed)

def xxtea_decrypt(data, key):
    v = to_int_array(data, False)
    k = to_int_array(fix_key(key), False)
    n = len(v)
    if n < 2:
        return b''
    q = 52 // n + 6
    s = (q * DELTA) & 0xFFFFFFFF
    y = v[0]
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        mx = (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ ((s ^ y) + (k[(0 & 3) ^ e] ^ z))
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        y = v[0]
        s = (s - DELTA) & 0xFFFFFFFF
    return to_byte_array(v, True)

def is_tea_blob(s):
    if len(s) < 12:
        return False
    if s.lower().startswith(('http', 'www', 'ssh', 'vless', 'vmess')):
        return False
    return re.match(r'^[A-Za-z0-9+/]+={0,2}$', s) is not None

def main():
    print("")
    print_bar(C_CYAN)
    print_c("CLOUD V2RAY Config Decryptor - By @SnapDark🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Fetching encrypted payload from Server...", C_BLUE)
    time.sleep(0.5)

    try:
        response = requests.get(URL, headers={'User-Agent': 'Mozilla/5.0'}, timeout=30, verify=False)
        response.raise_for_status()
        enc_str = response.text.strip()
    except Exception as e:
        print_c(f"[-] Failed to fetch config: {e}", C_RED)
        return

    print_c(f"[+] Encrypted payload downloaded ({len(enc_str)} chars)...", C_GREEN)
    print("")

    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : CJK Base4096 + AES-256-CBC (Double Layer, Zero IV)", C_CYAN)
    print_c(f"Key : {KEY}", C_CYAN)
    time.sleep(1)

    peeled = peel_cjk(enc_str, KEY)
    try:
        if peeled.startswith(SIG):
            peeled = peeled[len(SIG):]
        json_start = peeled.index('{')
        peeled = peeled[json_start:]
        parsed = json.loads(peeled)
        print_c("[+] Layer 1 Successfully Breached...", C_GREEN)
    except Exception as e:
        print_c(f"[-] Failed to decode or parse JSON: {e}", C_RED)
        return

    print("")
    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : Modified XXTEA (DELTA 0x2E0BA747)", C_CYAN)
    print_c(f"Target : Servers & Config Fields (Inner Payloads)", C_CYAN)
    print_c(f"Key : {KEY}", C_CYAN)
    time.sleep(1)

    success_count = 0

    def recursive_decrypt(node):
        nonlocal success_count
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and v and is_tea_blob(v):
                    raw = tea_b64decode(v)
                    dec = None
                    if raw:
                        out = xxtea_decrypt(raw, KEY)
                        if out:
                            try:
                                text = out.decode('utf-8')
                                if text and all(ord(c) >= 32 or c in '\n\r\t' for c in text):
                                    dec = text
                            except Exception:
                                pass
                    if dec is not None:
                        node[k] = dec
                        success_count += 1
                else:
                    recursive_decrypt(v)
        elif isinstance(node, list):
            for item in node:
                recursive_decrypt(item)

    recursive_decrypt(parsed)

    print_c("[+] Layer 2 Successfully Breached..", C_GREEN)
    print_c(f"[+] Decrypted {success_count} Fields Successfully...", C_GREEN)
    print("")

    print_c(f"[*] Version : {parsed.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Servers : {len(parsed.get('Servers', []))}", C_BLUE)
    print("")

    final_json = { "CREDITS": "Decrypted By @SnapDark 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell" }
    final_json.update(parsed)

    out_str = json.dumps(final_json, indent=4, ensure_ascii=False)
    
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: {OUTPUT_FILE}", C_GREEN)
    except (PermissionError, OSError):
        print_c(f"[-] Permission denied for {OUTPUT_FILE}. Trying local dir...", C_RED)
        local_out = os.path.basename(OUTPUT_FILE)
        with open(local_out, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: ./{local_out}", C_GREEN)
    print("")

if __name__ == "__main__":
    main()
