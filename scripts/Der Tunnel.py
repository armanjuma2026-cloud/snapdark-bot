# Python By @SnapDark 🇧🇩
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
    try:
        import requests
    except ImportError:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + "[*] Required modules missing. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])

check_dependencies()
import requests

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

CONFIG_URL = "https://5gnetvpn.com/api/app?json=292439858870d9ffc7f1"
OUTPUT_FILE = "/sdcard/VPNs/Der Tunnel VPN ☠️.json"
OUTPUT_EMBEDDED = "/sdcard/VPNs/Der Tunnel VPN (Embedded) ☠️.json"
APK_PATH = "/storage/emulated/0/MT2/apks/Der Tunnel_1.1.apks"
EMBEDDED_ASSET = "assets/der.json"

KEY = "Princie!"
DELTA = 0x9E5729B1
MASK32 = 0xFFFFFFFF

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

# ---------------- LAYER 1 : lsparanoid getString (Sb.a) ----------------
# key 'Princie!' + charset 'UTF-8'  (id 0x3916699A1D242516)

# ---------------- LAYER 2 : Custom Chained XXTEA (DELTA 0x9E5729B1) ----------------

def _to_int_array(data, include_length):
    n = len(data)
    m = (n + 3) // 4
    if include_length:
        result = [0] * (m + 1)
        result[m] = n
    else:
        result = [0] * m
    for i in range(n):
        result[i // 4] |= (data[i] & 0xFF) << ((i % 4) * 8)
    return result

def _to_byte_array(data, include_length):
    n = len(data)
    max_bytes = n * 4
    if include_length:
        m = data[n - 1]
        if m < (max_bytes - 7) or m > (max_bytes - 4):
            return None
        length = m
    else:
        length = max_bytes
    result = bytearray(length)
    for i in range(length):
        result[i] = (data[i // 4] >> ((i % 4) * 8)) & 0xFF
    return bytes(result)

def _xxtea_mx(sum_val, y, z, p, e, key):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (key[(p & 3) ^ e] ^ z))) & MASK32

def _xxtea_decrypt(int_data, key_ints):
    n = len(int_data)
    if n < 2:
        return int_data
    rounds = 52 // n + 6
    total_sum = (rounds * DELTA) & MASK32
    carry = int_data[0]
    while total_sum != 0:
        e = (total_sum >> 2) & 3
        carry_val = carry
        p = n - 1
        while p > 0:
            carry_val = (int_data[p] - _xxtea_mx(total_sum, carry_val, int_data[p - 1], p, e, key_ints)) & MASK32
            int_data[p] = carry_val
            p -= 1
        carry = (int_data[0] - _xxtea_mx(total_sum, carry_val, int_data[n - 1], 0, e, key_ints)) & MASK32
        int_data[0] = carry
        total_sum = (total_sum - DELTA) & MASK32
    return int_data

def der_decrypt(b64_str):
    try:
        data = base64.b64decode(b64_str.strip())
    except Exception:
        return None
    if len(data) == 0:
        return None
    key_bytes = KEY.encode("utf-8")[:16].ljust(16, b"\x00")
    key_ints = _to_int_array(key_bytes, False)
    data_ints = _to_int_array(data, False)
    if len(data_ints) < 2:
        return None
    dec_ints = _xxtea_decrypt(data_ints[:], key_ints)
    dec_bytes = _to_byte_array(dec_ints, True)
    if not dec_bytes:
        return None
    try:
        return dec_bytes.decode("utf-8")
    except Exception:
        return None

def b64_decode(s):
    s = re.sub(r"\s", "", s)
    return base64.b64decode(s + "=" * (-len(s) % 4))

def read_embedded_blob():
    z = zipfile.ZipFile(APK_PATH)
    base = z.read([n for n in z.namelist() if n.endswith("base.apk")][0])
    inner = zipfile.ZipFile(io.BytesIO(base))
    return inner.read(EMBEDDED_ASSET).decode().strip()

def save_output(path, config, source):
    final_json = { "CREDITS": "Decrypted By @Snpdark 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell" }
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
    print_c("Der Tunnel VPN Config Decryptor - By @SnapDark 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Fetching encrypted payload from Server...", C_BLUE)
    time.sleep(0.5)

    try:
        headers = {"User-Agent": "okhttp/4.9.0"}
        response = requests.get(CONFIG_URL, headers=headers, timeout=30)
        raw_data = response.text.strip()
    except Exception as e:
        print_c(f"[-] Failed to fetch config: {e}", C_RED)
        return

    print_c(f"[+] Encrypted payload downloaded ({len(raw_data)} chars)", C_GREEN)
    print("")

    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : lsparanoid getString (Sb.a)", C_CYAN)
    print_c(f"Key : {KEY}", C_CYAN)
    time.sleep(1)

    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : Custom Chained XXTEA (DELTA 0x9E5729B1)", C_CYAN)
    time.sleep(1)

    json_str = der_decrypt(raw_data)
    if json_str is None:
        print_c("[-] Complete decryption breach failure...", C_RED)
        return
    try:
        parsed = json.loads(json_str)
        print_c("[+] Layer 1 & 2 Successfully Breached..", C_GREEN)
    except Exception as e:
        print_c(f"[-] Failed to parse decrypted JSON: {e}", C_RED)
        return

    print("")
    print_c(f"[*] Version : {parsed.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Payloads : {len(parsed.get('Payloads', []))}", C_BLUE)
    print_c(f"[*] Free Servers : {len(parsed.get('Free_servers', []))} | Premium : {len(parsed.get('Premium_servers', []))} | Vip : {len(parsed.get('Vip_servers', []))} | Private : {len(parsed.get('Private_servers', []))}", C_BLUE)
    print("")

    save_output(OUTPUT_FILE, parsed, CONFIG_URL)

    print("")
    print_bar(C_CYAN)
    print_c(">>> EMBEDDED ASSET (assets/der.json) <<<", C_YELLOW)
    print_bar(C_CYAN)
    time.sleep(0.5)

    try:
        emb_b64 = read_embedded_blob()
        emb_str = der_decrypt(emb_b64)
        emb = json.loads(emb_str)
        print_c("[+] Embedded config Successfully Breached..", C_GREEN)
        print_c(f"[*] Version : {emb.get('Version', 'N/A')}", C_BLUE)
        print_c(f"[*] Payloads : {len(emb.get('Payloads', []))}", C_BLUE)
        print("")
        save_output(OUTPUT_EMBEDDED, emb, EMBEDDED_ASSET)
    except Exception as e:
        print_c(f"[-] Embedded decrypt failure: {e}", C_RED)
    print("")

if __name__ == "__main__":
    main()