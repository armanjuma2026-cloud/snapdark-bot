# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import base64
import shutil
import subprocess
import re
import sqlite3
import hashlib

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

CREDITS = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell"}

PACKAGE = "com.smartiptunnel.vpn"
DATABASE_NAME = "system.Database"
DEFAULT_DB = f"/data/data/{PACKAGE}/databases/{DATABASE_NAME}"
OUTPUT_FILE = "/sdcard/VPNs/SmartIP Tunnel VPN ☠️.json"

# ---------------- Field cipher (noobdev AbstractC2924ki / Ai / IE0) ----------------
# Stored config fields are encoded as: base64( AES-256-CFB/NoPadding(plaintext) )
#   key = SHA-256( keystring )   (61 spaces + "'" + 12 spaces + "." + 8 spaces)
#   iv  = 0x4E6A2C8153D9B4A7903F685CA1EF2479
KEY_STRING = " " * 61 + "'" + " " * 12 + "." + " " * 8
AES_KEY = hashlib.sha256(KEY_STRING.encode("utf-8")).digest()
AES_IV = bytes([0x4E, 0x6A, 0x2C, 0x81, 0x53, 0xD9, 0xB4, 0xA7, 0x90, 0x3F, 0x68, 0x5C, 0xA1, 0xEF, 0x24, 0x79])

def check_dependencies():
    try:
        from Crypto.Cipher import AES
    except ImportError:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required module pycryptodome missing. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome", "-q"])
        from Crypto.Cipher import AES
    return AES

AES = check_dependencies()

_B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

def b64_decode(s):
    s = re.sub(r"\s", "", s)
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def _printable(pt):
    try:
        txt = pt.decode("utf-8")
    except Exception:
        return None
    if txt == "":
        return None
    for ch in txt:
        o = ord(ch)
        if o == 0 or o == 0x7F or (o < 32 and o not in (9, 10, 13)):
            return None
    return txt

def decrypt_field(s):
    if not _B64_RE.match(s) or len(s) < 4 or len(s) % 4 == 1:
        return None
    try:
        ct = b64_decode(s)
    except Exception:
        return None
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV, segment_size=128)
        pt = cipher.decrypt(ct)
    except Exception:
        return None
    return _printable(pt)

def recursive_decrypt(node, stats):
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str):
                pt = decrypt_field(v)
                if pt is not None:
                    node[k] = pt
                    stats[0] += 1
            elif isinstance(v, (dict, list)):
                recursive_decrypt(v, stats)
    elif isinstance(node, list):
        for x in node:
            recursive_decrypt(x, stats)
    return stats[0]

# ---------------- Data readers ----------------

def read_db(db_path):
    if not os.path.isfile(db_path):
        return None, f"database not found: {db_path}"
    with sqlite3.connect(db_path) as con:
        cur = con.execute("SELECT DATA FROM spkmoder_table WHERE ID = ?", (1,))
        row = cur.fetchone()
    if not row or not row[0]:
        return None, "spkmoder_table id=1 empty"
    return row[0], None

def extract_json_objects(raw):
    """Best-effort MMKV/xml cleanup: pull the largest balanced {...} JSON candidates."""
    found = []
    i = 0
    n = len(raw)
    while i < n:
        if raw[i] not in b"{[":
            i += 1
            continue
        depth = 0
        buf = bytearray()
        in_str = False
        esc = False
        j = i
        ok = False
        while j < n:
            c = raw[j]
            buf.append(c)
            if in_str:
                if esc:
                    esc = False
                elif c == 0x5c:
                    esc = True
                elif c == 0x22:
                    in_str = False
            else:
                if c == 0x22:
                    in_str = True
                elif c == 0x7b or c == 0x5b:
                    depth += 1
                elif c == 0x7d or c == 0x5d:
                    depth -= 1
                    if depth == 0:
                        ok = True
                        break
                elif c in (0x0d, 0x0a) and depth == 1:
                    break
            j += 1
        if ok:
            try:
                obj = json.loads(bytes(buf).decode("utf-8", "ignore"))
                if isinstance(obj, (dict, list)):
                    found.append(obj)
            except Exception:
                pass
        i = j + 1
    return found

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

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
    db_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB
    print("")
    print_bar(C_CYAN)
    print_c("SmartIP Tunnel VPN Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_c(f"Package: {PACKAGE}  |  DB: {DATABASE_NAME}", C_CYAN)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Reading on-device SQLite config (spkmoder_table)...", C_BLUE)
    raw, err = read_db(db_path)
    if raw is None:
        print_c(f"[-] DB read failure: {err}", C_RED)
        print_c("[-] Trying generic JSON blob scan on provided file(s)...", C_YELLOW)
        merged = {}
        for arg in sys.argv[1:]:
            if not os.path.isfile(arg):
                continue
            data = open(arg, "rb").read()
            for obj in extract_json_objects(data):
                merged.update(obj)
        if not merged:
            print_c("[-] Nothing decryptable found. Copy the app DB and retry:", C_RED)
            print_c(f"    {DEFAULT_DB}", C_RED)
            return
        parsed, db_label = merged, "MMKV/blob scan"
    else:
        try:
            parsed = json.loads(raw)
        except Exception as e:
            print_c(f"[-] spkmoder_table DATA is not valid JSON: {e}", C_RED)
            return
        db_label = "system.Database"

    print("")
    print_c(">>> INITIATING FIELD DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : AES-256-CFB (NoPadding), key = SHA-256(static string)", C_CYAN)
    print_c("Encoding  : base64 -> AES decrypt -> UTF-8  (per string field)", C_CYAN)
    time.sleep(1)

    stats = [0]
    recursive_decrypt(parsed, stats)
    print_c(f"[+] Decrypted string fields : {stats[0]}", C_GREEN)

    print("")
    servers = parsed.get("Servers", [])
    if isinstance(servers, list):
        print_c(f"[*] Servers : {len(servers)}", C_BLUE)
    print_c(f"[*] Source  : {db_label}", C_BLUE)
    print("")

    save_output(OUTPUT_FILE, parsed)
    print("")

if __name__ == "__main__":
    main()