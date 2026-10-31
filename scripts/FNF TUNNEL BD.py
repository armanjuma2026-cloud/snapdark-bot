# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import base64
import random
import string
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

REGISTER_URL = "https://arifbd.xyz/api/douser.php?deviceid="
OUTPUT_FILE = "/sdcard/VPNs/FNF TUNNEL BD ☠️.json"
APK_CANDIDATES = [
    "/sdcard/MT2/apks/FNF TUNNEL BD_PrinceBuild35.apks",
    "/storage/emulated/0/MT2/apks/FNF TUNNEL BD_PrinceBuild35.apks",
]
ASSET_GREMLIN = "assets/gremlin.json"
ASSET_PSI = "assets/server.psi"
ASSET_OVPN = "assets/prince.ovpn"

# ---- Layer keys ----
#  lsparanoid Deobfuscator$MHRTUNNELVPN$app  (seed splitmix64 / chunk pool 8191)
#  XXTEA (gremlin.json)   : delta 0x9E5729B1, key '...|...'  (AbstractC1312oi)
#  libputils pPutils      : XOR key "4%PdXch>fkP]" (obfuscateKey()), pkg gate = "dastan.prince.myvpnksa"
XXTEA_KEY = "...|..."
DELTA = 0x9E5729B1
MASK32 = 0xFFFFFFFF

PUTILS_KEY = b"4%PdXch>fkP]"
# server.psi layout:  ('a' half-nibble header) + hex( XOR( hex(server_list), PUTILS_KEY rotated-left-7 ) )
PUTILS_KEY_ROT = PUTILS_KEY[7:] + PUTILS_KEY[:7]

APP_PACKAGE = "dastan.prince.myvpnksa"
APP_UA = "okhttp/4.12.0"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

# ---------------- LAYER 2 : XXTEA (DELTA 0x9E5729B1, length header) ----------------

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

def prince_decrypt(b64_str):
    """gremlin.json: base64( XXTEA(json, '...|...') )"""
    try:
        data = base64.b64decode(re.sub(r"\s", "", b64_str.strip()))
    except Exception:
        return None
    if len(data) == 0:
        return None
    key_bytes = XXTEA_KEY.encode("utf-8")[:16].ljust(16, b"\x00")
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

# ---------------- LAYER 3 : libputils pDecrypt emulation ----------------

def _xor_bytes(data, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))

def putils_p_encrypt(plain_str):
    """pEncrypt(Context, s) = hex( XOR(s, '4%PdXch>fkP]') )  [pkg-gated in APK]"""
    return _xor_bytes(plain_str.encode("utf-8"), PUTILS_KEY).hex()

def putils_p_decrypt(hex_text, skip_lead=True):
    """pDecrypt(Context, s) = XOR( hexToBytes(s), key ). server.psi carries a 1-nibble
    ('a') header and the byte-phase between hex plane and key plane is half-shifted
    (key applied as PUTILS_KEY rotated left 7)."""
    t = re.sub(r"\s", "", hex_text)
    if len(t) % 2 != 0:
        t = t[1:]
    raw = bytes.fromhex(t)
    return _xor_bytes(raw, PUTILS_KEY_ROT)

def parse_psiphon_entries(plain_text):
    """psi payload: hex(server_list) where server_list = '\n'-joined hex(json entries)
    -> pDecrypt output is hex text -> hex-decode -> '{...}0 0 0 0 {...}' season format"""
    hex_body = re.sub(r"[^0-9a-fA-F]", "", plain_text)
    if len(hex_body) % 2:
        hex_body = hex_body[:-1]
    blob = bytes.fromhex(hex_body).decode("utf-8", "replace")
    objs = []
    depth, start = 0, -1
    for i, c in enumerate(blob):
        if c == "{":
            if depth <= 0:
                start = i
                depth = 1
            else:
                depth += 1
        elif c == "}":
            depth -= 1
            if depth <= 0 and start != -1:
                try:
                    objs.append(json.loads(blob[start:i + 1]))
                except Exception:
                    pass
                start = -1
                depth = 0
    return blob, objs

# ---------------- Asset loading ----------------

def read_assets():
    for apk in APK_CANDIDATES:
        if os.path.exists(apk):
            z = zipfile.ZipFile(apk)
            bases = [n for n in z.namelist() if n.endswith("base.apk")]
            inner = zipfile.ZipFile(io.BytesIO(z.read(bases[0])))
            gremlin = inner.read(ASSET_GREMLIN).decode()
            psi = inner.read(ASSET_PSI).decode()
            ovpn = inner.read(ASSET_OVPN).decode()
            src = apk
            break
    else:
        # local extracted fallback
        root = os.environ.get("FNF_ASSET_DIR", "base/assets")
        gremlin = open(os.path.join(root, "gremlin.json"), encoding="utf-8").read()
        psi = open(os.path.join(root, "server.psi"), encoding="utf-8").read()
        ovpn = open(os.path.join(root, "prince.ovpn"), encoding="utf-8").read()
        src = root
    return gremlin, psi, ovpn, src

def save_output(path, final):
    out_str = json.dumps(final, indent=1, ensure_ascii=False)

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
    print_c("FNF TUNNEL BD (Prince Build 35) Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    # ---- Live probe: device registration (douser.php) ----
    print_c("[*] Probing live registration API (arifbd.xyz)...", C_BLUE)
    device_plain = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(15))
    device_enc = putils_p_encrypt(device_plain)
    live_note = ""
    try:
        r = requests.get(REGISTER_URL + device_enc, headers={"User-Agent": APP_UA}, timeout=20)
        live_note = r.text.strip()
        print_c(f"[+] douser.php -> {live_note!r} (deviceid: {device_plain} / {device_enc})", C_GREEN)
        print_c(f"[*] deviceid cipher = hex( XOR( plain15, \"4%PdXch>fkP]\" ) ) - pkg-gated pEncrypt", C_CYAN)
    except Exception as e:
        print_c(f"[-] Live API unreachable: {e}", C_RED)
        live_note = ""
    print("")
    time.sleep(0.5)

    # ---- Embedded assets ----
    print_c("[*] Loading encrypted embedded assets from APK...", C_BLUE)
    try:
        gremlin, psi, ovpn, src = read_assets()
        print_c(f"[+] Assets loaded from: {src}", C_GREEN)
    except Exception as e:
        print_c(f"[-] Failed to load assets: {e}", C_RED)
        return
    print("")

    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : lsparanoid getString (Deobfuscator$MHRTUNNELVPN$app)", C_CYAN)
    print_c("Engine    : splitmix64-seeded LCG char pool, 5x8191 chunks", C_CYAN)
    time.sleep(0.8)
    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : XXTEA (DELTA 0x9E5729B1) - gremlin.json", C_CYAN)
    print_c(f"Key       : {XXTEA_KEY}", C_CYAN)
    time.sleep(0.8)
    print_c(">>> INITIATING LAYER 3 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : libputils pDecrypt (XOR 'obfuscateKey' + hex) - server.psi", C_CYAN)
    print_c(f"Key       : {PUTILS_KEY.decode()}   |   Package gate: {APP_PACKAGE}", C_CYAN)
    time.sleep(0.8)

    json_str = prince_decrypt(gremlin)
    if json_str is None:
        print_c("[-] gremlin.json decryption breach failure...", C_RED)
        return
    try:
        parsed = json.loads(json_str)
        print_c("[+] Layer 2 Successfully Breached.. (gremlin.json)", C_GREEN)
    except Exception as e:
        print_c(f"[-] Failed to parse decrypted JSON: {e}", C_RED)
        return

    psi_plain = putils_p_decrypt(psi).decode("utf-8", "replace")
    psi_blob, psiphon_servers = parse_psiphon_entries(psi_plain)
    if psiphon_servers:
        print_c(f"[+] Layer 3 Successfully Breached.. (server.psi -> {len(psiphon_servers)} Psiphon entries)", C_GREEN)
    else:
        print_c("[-] server.psi decoding produced no Psiphon entries...", C_RED)

    print("")
    print_c(f"[*] Version : {parsed.get('Version', 'N/A')}", C_BLUE)
    print_c(f"[*] Payloads : {len(parsed.get('Payloads', []))}", C_BLUE)
    print_c(f"[*] Free Servers : {len(parsed.get('Free_servers', []))} | Premium : {len(parsed.get('Premium_servers', []))} | Vip : {len(parsed.get('Vip_servers', []))} | Private : {len(parsed.get('Private_servers', []))}", C_BLUE)
    print_c(f"[*] Psiphon Servers : {len(psiphon_servers)}", C_BLUE)

    final = {
        "CREDITS": "Decrypted By @snapdark_decoder 🇧🇩 | Join channel: t.me/Jubairbro",
        "_source": "https://arifbd.xyz/api/douser.php (device register API) | config = embedded encrypted assets (gremlin.json / server.psi)",
    }
    final.update(parsed)
    final["Psiphon_servers"] = psiphon_servers
    final["prince.ovpn"] = ovpn
    final["App"] = {
        "package": APP_PACKAGE,
        "versionName": "PrinceBuild35",
        "versionCode": 35,
        "modes": ["ocsudp", "ocsxray", "ocssplit", "ocsshadow", "ocsv2ray", "ocspsiphon"],
    }
    final["API"] = {
        "register": REGISTER_URL,
        "deviceid_cipher": "hex( XOR( 15-char [a-z0-9], \"4%PdXch>fkP]\" ) )",
        "user_agent": APP_UA,
        "responses": ["Success! Created", "Success! Exists", "Success!"],
    }
    final["Notes"] = (
        "No live config endpoint - the full server list ships inside the APK. "
        "gremlin.json = base64(XXTEA(0x9E5729B1, '...|...')); server.psi = 'a' + hex(XOR(hex(psiphon server list), key rotated-left-7)); "
        " prince.ovpn is a template (remote 0.0.0.0 1194 placeholder) used for OVPN mode. "
        "Payloads with host/port 'Pulled' take values from the selected server at runtime. "
        "douser.php only registers/burns the random 15-char deviceid (pEncrypt)."
    )

    # JSON validity gate
    try:
        json.dumps(final, ensure_ascii=False)
    except Exception as e:
        print_c(f"[-] Output JSON invalid: {e}", C_RED)
        return

    save_output(OUTPUT_FILE, final)

    print("")
    print_bar(C_CYAN)
    print_c(">>> ALL LAYERS DECRYPTED - STAY CONNECTED <<<", C_YELLOW)
    print("")

if __name__ == "__main__":
    main()
