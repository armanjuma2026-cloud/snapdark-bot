# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import base64
import shutil
import subprocess
import hashlib
import re

def check_dependencies():
    try:
        import requests
        from Crypto.Cipher import AES
    except ImportError:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + "[*] Required modules missing. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "pycryptodome", "-q"])

check_dependencies()
import requests
from Crypto.Cipher import AES

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

CONFIG_URL = "https://kohinurvipvpn.xyz/api/app?json=4c10fce1d9de234f3fcb"
OUTPUT_FILE = "/sdcard/VPNs/Apka Tunnel VPN ☠️.json"

BAES_PASSWORD = "MT_g1_146153854739a5c03a772ae4"
BAES_SALT = "MTsalt_48792b752bed685b83bf"
FIELD_KEY = "mt#21c311177e37"

CUSTOM_ALPHABET_B64 = "QUJDREVGR0hJSktMTU5PUA=="
CUSTOM_ALPHABET = base64.b64decode(CUSTOM_ALPHABET_B64).decode("utf-8")

SIG_PREFIX = "S1."
MAGIC = b"RBG1"
IV_LEN = 12
GCM_TAG_LEN = 16

DELTA = 0x9E3779B9
MASK32 = 0xFFFFFFFF

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

def sig_unwrap(raw_data):
    # SecureSig.unwrap: strip whitespace, drop "S1." + RSA signature envelope
    cleaned = re.sub(r'\s', '', raw_data)
    if not cleaned.startswith(SIG_PREFIX):
        return cleaned
    body = cleaned[len(SIG_PREFIX):]
    if "." not in body:
        raise ValueError("signed envelope missing payload separator")
    _signature, payload = body.split(".", 1)
    return payload

def baes_gen_user():
    return base64.b64encode(b"@technore24").decode() + "\n"

def baes_gen_key(password):
    return password.encode("utf-8").hex().upper()

def baes_gen_string(custom_encoded):
    result = bytearray()
    for i in range(0, len(custom_encoded) - 1, 2):
        high = CUSTOM_ALPHABET.index(custom_encoded[i])
        low = CUSTOM_ALPHABET.index(custom_encoded[i + 1])
        result.append(((high * 16) + low) & 0xFF)
    return result.decode("latin-1")

def baes_decrypt(password, custom_encoded):
    standard_b64 = baes_gen_string(custom_encoded)
    gen_user = baes_gen_user()
    gen_key = baes_gen_key(password)
    combined = BAES_SALT + gen_user + gen_key
    aes_key = hashlib.sha256(combined.encode("utf-8")).digest()

    blob = base64.b64decode(standard_b64)
    if len(blob) < len(MAGIC) + IV_LEN or blob[:len(MAGIC)] != MAGIC:
        raise ValueError("bad magic header")

    iv = blob[len(MAGIC):len(MAGIC) + IV_LEN]
    payload = blob[len(MAGIC) + IV_LEN:]
    cipher_bytes, tag = payload[:-GCM_TAG_LEN], payload[-GCM_TAG_LEN:]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    decrypted = cipher.decrypt_and_verify(cipher_bytes, tag)
    return decrypted.decode("utf-8")

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
    y = int_data[0]
    while total_sum != 0:
        e = (total_sum >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = int_data[p - 1]
            y = (int_data[p] - _xxtea_mx(total_sum, y, z, p, e, key_ints)) & MASK32
            int_data[p] = y
        z = int_data[n - 1]
        y = (int_data[0] - _xxtea_mx(total_sum, y, z, 0, e, key_ints)) & MASK32
        int_data[0] = y
        total_sum = (total_sum - DELTA) & MASK32
    return int_data

def tea_decrypt_field(b64_str, key_str=FIELD_KEY):
    if not b64_str or len(b64_str) < 4:
        return None

    # Strictly validate string as standard Base64 to prevent false positives
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', b64_str):
        return None

    try:
        data = base64.b64decode(b64_str, validate=True)
        if len(data) == 0:
            return None

        key_bytes = key_str.encode("utf-8")[:16].ljust(16, b"\x00")
        key_ints = _to_int_array(key_bytes, False)
        data_ints = _to_int_array(data, False)

        if len(data_ints) < 2:
            return None

        dec_ints = _xxtea_decrypt(data_ints[:], key_ints)
        dec_bytes = _to_byte_array(dec_ints, True)

        if dec_bytes:
            text = dec_bytes.decode("utf-8")
            if len(text) > 0:
                return text
        return None
    except Exception:
        return None

def main():
    print("")
    print_bar(C_CYAN)
    print_c("Apka Tunnel VPN Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Fetching encrypted payload from Endpoint...", C_BLUE)
    time.sleep(0.5)

    try:
        headers = {"User-Agent": "okhttp/4.9.0"}
        raw_data = ""
        for attempt in range(1, 6):
            try:
                response = requests.get(CONFIG_URL, headers=headers, timeout=30)
            except Exception as e:
                print_c(f"[-] Fetch attempt {attempt} network error: {e}", C_RED)
                time.sleep(10)
                continue
            body = response.text.strip()
            if response.status_code == 200 and body.startswith("S1."):
                raw_data = body
                break
            print_c(
                f"[!] Attempt {attempt}: HTTP {response.status_code} (server rate-limit), waiting 20 s...",
                C_YELLOW,
            )
            time.sleep(20)
        if not raw_data:
            print_c("[-] Server kept rate-limiting the app — try again a few minutes later.", C_RED)
            return
    except Exception as e:
        print_c(f"[-] Failed to fetch config: {e}", C_RED)
        return

    print_c(f"[+] Downloaded {len(raw_data)} characters successfully.", C_GREEN)
    time.sleep(0.5)

    print("")
    print_c(">>> STRIPPING SecureSig ENVELOPE <<<", C_YELLOW)
    print_c("Format : S1.<RSA-SHA256 signature>.<payload>", C_CYAN)
    time.sleep(0.5)

    try:
        payload_data = sig_unwrap(raw_data)
        print_c(f"[+] Signature envelope removed ({len(payload_data)} chars payload).", C_GREEN)
    except Exception as e:
        print_c(f"[-] Failed to unwrap signed payload: {e}", C_RED)
        return

    print("")
    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : BAES / AES-256-GCM (RBG1)", C_CYAN)
    time.sleep(1)

    try:
        json_str = baes_decrypt(BAES_PASSWORD, payload_data)
        print_c("[+] Layer 1 Successfully Breached via Primary Key...", C_GREEN)
    except Exception as e:
        print_c(f"[-] Complete decryption breach failure: {e}", C_RED)
        return

    try:
        config = json.loads(json_str)
    except Exception as e:
        print_c(f"[-] Failed to parse unsealed payload JSON: {e}", C_RED)
        return

    print("")
    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Target : Universal JSON Field Hunt (XXTEA)", C_CYAN)
    print_c(f"Key : {FIELD_KEY}", C_CYAN)
    time.sleep(1)

    success_count = 0

    def recursive_decrypt(node):
        nonlocal success_count
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if isinstance(v, str) and v:
                    # Heuristic to filter out standard strings (like ips or plain text)
                    if " " not in v and "{" not in v:
                        dec_v = tea_decrypt_field(v)
                        if dec_v is not None:
                            node[k] = dec_v
                            success_count += 1
                elif isinstance(v, (dict, list)):
                    recursive_decrypt(v)
        elif isinstance(node, list):
            for item in node:
                recursive_decrypt(item)

    # Initiate global search and destroy for Layer 2 encrypted fields
    recursive_decrypt(config)

    print_c("[+] Layer 2 Successfully Breached..", C_GREEN)
    print_c(f"[+] Decrypted {success_count} Fields Successfully...", C_GREEN)
    print("")

    final_json = { "CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell" }
    final_json.update(config)

    out_str = json.dumps(final_json, indent=4, ensure_ascii=False)
    
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: {OUTPUT_FILE}", C_GREEN)
    except PermissionError:
        print_c(f"[-] Permission denied for {OUTPUT_FILE}. Trying local dir...", C_RED)
        local_out = os.path.basename(OUTPUT_FILE)
        with open(local_out, 'w', encoding='utf-8') as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: ./{local_out}", C_GREEN)
    print("")

if __name__ == "__main__":
    main()