# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import base64
import re
import shutil
import subprocess

def check_dependencies():
    try:
        import requests
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256
    except ImportError:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + "[*] Required modules not found. Auto-installing requests & pycryptodome...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "pycryptodome", "-q"])
        import requests
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256

check_dependencies()
import requests
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

# ---- constants (all proven from smali + lib) ----
CONFIG_URL = "https://raw.githubusercontent.com/memoryvpn/6in1JsonFixBuild/refs/heads/main/webtunnel.json"
SOURCE = "wiJOarF55ouCQ26a3szIhgVa2eYq"                # lib .bss source
P_KEY = "7769"                                        # custom_hex_table(SOURCE)[:4], table "01234567890FIXDE"
AES_PASSWORD = ("fb" + SOURCE).encode()               # field PBKDF2 password
PBKDF2_ITERS = 1097                                   # rodata
XOR_KEY = b"FXWIJO"                                   # "FX" + SOURCE[:4].upper()
XOR_DELTA_BLOB = 0x2e0ba747                           # XXTEA delta
DEX_PREFIX = ""                                       # 549KB payload: strip(20) is the lib prefix
UUID_RE = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
M = 0xffffffff

OUTPUT_FILE = "/sdcard/VPNs/WEB TUNNEL VPN ☠️.json"

NHC_KEYS = {"NetworkHostConfig"}
NESTED_KEYS = {"V2rayMainID", "V2RayCertID"}
WIPE_KEYS = {"TrackPostExp"}

B64RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def print_c(text, color=""):
    print(f"{color}{text}{C_RESET}")


def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(color + ("═" * width) + C_RESET)


def vm_b64(s):
    s = "".join(s.split())
    s = s.replace("-", "+").replace("_", "/")
    s = s.split("=", 1)[0]
    s = re.sub(r"[^A-Za-z0-9+/]", "", s)
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def bytes_to_words(d, with_len):
    n = len(d)
    l = n >> 2 if n % 4 == 0 else (n >> 2) + 1
    a = [0] * (l + with_len)
    if with_len:
        a[l] = n & M
    for i in range(n):
        a[i >> 2] = (a[i >> 2] | (d[i] & 255) << ((i & 3) << 3)) & M
    return a


def words_to_bytes(a, with_len):
    L = len(a) << 2
    if with_len:
        q = a[-1] & M
        q = q - 0x100000000 if q & 0x80000000 else q
        if q < L - 7 or q > L - 4:
            return None
        L = q
    return bytes((a[i >> 2] >> ((i & 3) << 3)) & 255 for i in range(L))


def fit_key16(k):
    k = bytes(k)[:16]
    return k + b"\0" * (16 - len(k))


def xxtea_mx(s, y, z, p, e, k):
    return (((s ^ y) + (k[p & 3 ^ e] ^ z)) ^ (((z >> 5 ^ (y << 2 & M)) & M) + ((y >> 3 ^ (z << 4 & M)) & M))) & M


def xxtea_decrypt(d, k, delta):
    """Standard XXTEA block decrypt (PrimeV2rayMax family flavour)."""
    if not d:
        return b""
    v = bytes_to_words(d, 0)
    kk = bytes_to_words(fit_key16(k), 0)
    n = len(v)
    if n > 1:
        sm = ((6 + 52 // n) * delta) & M
        y = v[0]
        while sm:
            e = sm >> 2 & 3
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                y = (v[p] - xxtea_mx(sm, y, z, p, e, kk)) & M
                v[p] = y
            z = v[n - 1]
            v[0] = (v[0] - xxtea_mx(sm, y, z, 0, e, kk)) & M
            y = v[0]
            sm = (sm - delta) & M
    return words_to_bytes(v, 1)


def key_words(k):
    """Expand the short Caesar key into the 4-word XXTEA key."""
    b = k if isinstance(k, bytes) else k.encode()
    h = bytearray(b)
    while len(h) < 16:
        h += b
    return [int.from_bytes(h[i*4:(i+1)*4], "little") for i in range(4)]


def double_shift(s, i):
    return "".join(chr((ord(c) - i) % 65536) for c in s)


def has_ctrl(s):
    return any(ord(c) < 9 or (13 < ord(c) < 32) or ord(c) == 127 for c in s)


# ---- L1: strip + XXTEA + double Caesar ----
def outer_decrypt(text):
    c = "".join(text.split())
    c = c[20:]                                       # lib PbX strip prefix (20 chars)
    d = vm_b64(c)
    pt = xxtea_decrypt(d, P_KEY.encode(), XOR_DELTA_BLOB)
    if not pt:
        raise ValueError("xxtea failed")
    t = pt.decode("utf-8", "surrogatepass")
    t = double_shift(double_shift(t, int(P_KEY)), int(P_KEY))
    return t


# ---- L2 field crypto ----
def gcm_decrypt(b64, password=AES_PASSWORD, iterations=PBKDF2_ITERS):
    b = vm_b64("".join(b64.split()))
    if len(b) < 44:
        raise ValueError("short")
    key = PBKDF2(password, b[:16], 32, iterations, hmac_hash_module=SHA256)
    nonce = b[16:28]
    ct = b[28:-16]
    tag = b[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def rot18(c):
    """Family ROT18: +18 A-Z/a-z, +6 0-9."""
    o = ord(c)
    if 0x41 <= o <= 0x5A:
        return chr(((o - 0x2F) % 26) + 0x41)
    if 0x61 <= o <= 0x7A:
        return chr(((o - 0x4F) % 26) + 0x61)
    if 0x30 <= o <= 0x39:
        return chr(((o - 0x2A) % 10) + 0x30)
    return c


def xor_rot18(text, key=XOR_KEY):
    return "".join(rot18(chr(ord(c) ^ key[i % len(key)])) for i, c in enumerate(text))


decrypted_count = 0
wiped_count = 0


def nhc_dec_field(s):
    """NetworkHostConfig: per-field strip scan -> GCM -> XOR(FXWIJO) -> ROT18 -> host."""
    global decrypted_count, wiped_count
    c = "".join(s.split())
    for st in range(101):
        t = c[st:]
        if len(t) < 30:
            break
        try:
            r = gcm_decrypt(t)
        except Exception:
            continue
        x = xor_rot18(r.decode("utf-8", "surrogatepass"))
        if has_ctrl(x):
            wiped_count += 1
            return ""
        if x != s:
            decrypted_count += 1
        return x
    return s


def nested_gcm(text):
    return gcm_decrypt(text).decode("utf-8", "surrogatepass")


def is_uuid(s):
    return bool(re.fullmatch(UUID_RE, s))


def field_decrypt(k, s):
    global decrypted_count, wiped_count
    if not isinstance(s, str) or len(s) < 20 or " " in s or "{" in s:
        return s
    c = "".join(s.split())
    if not (len(c) >= 20 and B64RE.fullmatch(c)):
        return s
    if k in NHC_KEYS:
        return nhc_dec_field(s)
    try:
        t = gcm_decrypt(c).decode("utf-8", "surrogatepass")
    except Exception:
        return s
    if k in WIPE_KEYS:
        try:
            w = nested_gcm(t)
        except Exception:
            w = ""
        wiped_count += 1
        return ""
    if k in NESTED_KEYS:
        try:
            n = nested_gcm(t)
            if is_uuid(n) or n == "":
                decrypted_count += 1
                return n
        except Exception:
            pass
        try:
            n = nested_gcm(t.rstrip("=") + "=" * ((4 - len(t.rstrip("=")) % 4) % 4))
            if is_uuid(n):
                decrypted_count += 1
                return n
        except Exception:
            pass
        decrypted_count += 1
        return t
    if t != s:
        decrypted_count += 1
    return t


def deep_decrypt(o):
    if isinstance(o, dict):
        return {k: deep_decrypt(field_decrypt(k, v)) for k, v in o.items()}
    if isinstance(o, list):
        return [deep_decrypt(v) for v in o]
    return o


def fix_surrogates(s):
    return s.encode("utf-8", "surrogatepass").decode("utf-8", "replace")


def fix_surrogates_deep(o):
    if isinstance(o, str):
        return fix_surrogates(o)
    if isinstance(o, dict):
        return {k: fix_surrogates_deep(v) for k, v in o.items()}
    if isinstance(o, list):
        return [fix_surrogates_deep(v) for v in o]
    return o


def http_get(u):
    resp = requests.get(u, headers={"User-Agent": "Mozilla/5.0"}, timeout=45)
    return resp.text


def main():
    print("")
    print_bar(C_CYAN)
    print_c("WEB TUNNEL Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    src = sys.argv[1] if len(sys.argv) > 1 else CONFIG_URL
    if src.startswith("http"):
        print_c("[*] Fetching encrypted payload from server...", C_BLUE)
        time.sleep(0.5)
        try:
            raw = http_get(src)
        except Exception as e:
            print_c(f"[-] Failed to fetch config: {e}", C_RED)
            return
    else:
        with open(src, encoding="utf-8", errors="surrogatepass") as f:
            raw = f.read()

    print("")
    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : Strip(20) + XXTEA + Double Caesar", C_CYAN)
    print_c(f"Key p : {P_KEY}", C_CYAN)
    time.sleep(1)

    try:
        data = json.loads(outer_decrypt(raw))
    except Exception as e:
        print_c(f"[-] Decryption failed! The key or data might be incorrect. ({e})", C_RED)
        return

    print_c("[+] Layer 1 Successfully Breached...", C_GREEN)

    print("")
    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Pipeline : PBKDF2-SHA256 + AES-GCM (nested) + XOR/ROT18 NHC", C_CYAN)
    time.sleep(1)

    global decrypted_count, wiped_count
    decrypted_count = 0
    wiped_count = 0
    data = deep_decrypt(data)

    for s in data.get("Servers", []):
        u = s.get("V2rayMainID", "")
        t = s.get("ServerCloudFront", "")
        if u and t:
            t = t.replace("[fixkey]", u).replace("[fixid]", u)
            h = s.get("ServerIP", "") or s.get("ServerHTTP", "")
            if not h:
                m = re.search(r"host=([^&\[]+)", t) or re.search(r"sni=([^&\[]+)", t)
                if m:
                    h = m.group(1)
            if h:
                t = t.replace("[fixhost]", h)
            s["ServerCloudFront"] = t

    data = fix_surrogates_deep(data)

    print_c("[+] Layer 2 Successfully Breached..", C_GREEN)
    print_c(f"[+] Decrypted {decrypted_count} Fields Successfully...", C_GREEN)
    print_c(f"[+] Wiped {wiped_count} Dummy Fields...", C_GREEN)
    print_c(f"[+] {len(data.get('Servers', []))} Servers | {len(data.get('HTTPNetworks', []))} HTTPNetworks", C_GREEN)
    print("")

    final_json = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩"}
    final_json.update(data)

    out_str = json.dumps(final_json, indent=4, ensure_ascii=False)
    out_str = out_str.replace(
        '"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩",',
        '"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩",\n'
    )

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

    uri_file = OUTPUT_FILE.replace(".json", ".txt")
    lines = []
    for s in data.get("Servers", []):
        t = s.get("ServerCloudFront", "")
        if t and t.startswith("vless://"):
            lines.append("# " + s.get("Name", "server"))
            lines.append(t)
    try:
        with open(uri_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
        print_c(f"[★] Saved VLESS URI list to: {uri_file}", C_GREEN)
    except Exception:
        pass
    print("")


if __name__ == "__main__":
    main()
