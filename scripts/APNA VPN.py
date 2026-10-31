# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import shutil
import subprocess

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

OUTPUT_FILE = "/sdcard/VPNs/APNA VPN ☠️.json"
APK_CANDIDATES = [
    "/sdcard/MT2/apks/APNA VPN_3.9.apks",
    "/storage/emulated/0/MT2/apks/APNA VPN_3.9.apks",
]
ASSET_CONFIG = "assets/janu.json"

APP_NAME = "APNA VPN"
APP_PACKAGE = "my.teamapna.tunnel"
APP_UA = "my.teamapna.tunnel"

# ---- Layer keys ----
#  lsparanoid Deobfuscator$APNAVPN$app : splitmix64-style seed(), 16-bit LCG next(),
#    chunk pool 8191 chars, getCharAt(pos,next(state)), string len = high16 of first pool char.
#  XXTEA (janu.json) : delta 0x9E5729B1, chained-carry MX (Bm.a/Bm.b), LE words,
#    key '...|...' zero-padded to 16 bytes, tail word = plaintext length.
#  Base64 : standard alphabet (HZ.o), whole-file blob.
XXTEA_KEY = "...|..."
DELTA = 0x9E5729B1
MASK32 = 0xFFFFFFFF

CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/SnapDark"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}{C_RESET}")

# ---------------- LAYER 2 : XXTEA (delta 0x9E5729B1, chained-carry, length tail) ----------------

def _to_int_array(data, include_length):
    m = (len(data) + 3) // 4
    result = [0] * (m + 1) if include_length else [0] * m
    if include_length:
        result[m] = len(data)
    for i, b in enumerate(data):
        result[i // 4] |= (b & 0xFF) << ((i % 4) * 8)
    return result

def _to_byte_array(words, with_length):
    raw = b"".join((w & MASK32).to_bytes(4, "little") for w in words)
    if not with_length:
        return raw
    n = len(words)
    tail = int.from_bytes(raw[-4:], "little")
    if 4 * n - 7 <= tail <= 4 * n - 4:
        return raw[:tail]
    return None

def _mx(sum_, y, z, p, e, key):
    a = ((z & MASK32) >> 5) ^ ((y << 2) & MASK32)
    b = ((y & MASK32) >> 3) ^ ((z << 4) & MASK32)
    c = (sum_ ^ y) & MASK32
    d = (key[(p & 3) ^ e] ^ (z & MASK32)) & MASK32
    return ((a + b) ^ (c + d)) & MASK32

def xxtea_decrypt(data, key):
    if not data:
        return None
    v = _to_int_array(data, False)
    k = _to_int_array((key.encode() + b"\x00" * 16)[:16], False)
    n = len(v)
    if n < 2:
        return _to_byte_array(v, True)
    rounds = 52 // n + 6
    sum_ = (rounds * DELTA) & MASK32
    carry = v[0]
    e = (sum_ >> 2) & 3
    while sum_ != 0:
        for p in range(n - 1, 0, -1):
            carry = v[p] = (v[p] - _mx(sum_, carry, v[p - 1], p, e, k)) & MASK32
        carry = v[0] = (v[0] - _mx(sum_, carry, v[n - 1], 0, e, k)) & MASK32
        sum_ = (sum_ - DELTA) & MASK32
        e = (sum_ >> 2) & 3
    return _to_byte_array(v, True)

def decrypt_blob(payload_text, key=XXTEA_KEY):
    """The app's Bm.c wrapper: base64 -> XXTEA(chained-carry) -> UTF-8 text."""
    raw = base64_decode(payload_text)
    out = xxtea_decrypt(raw, key)
    if out is None:
        raise ValueError("XXTEA tail length invalid — wrong key/scheme")
    return out.decode("utf-8", "replace")

def base64_decode(text):
    import base64
    return base64.b64decode("".join(str(text).split()))

# ---------------- LAYER 1 : live updater first, embedded APK asset as fallback ----------------

def l2_field(value):
    """L2: top-level credential blobs use the SAME engine + key (lsparanoid-backed).
    e.g. 'zsqaS2Xni5AiP3Z/iFsBMg==' -> 'tanginaka'. Keep raw on any failure."""
    if not isinstance(value, str) or not (8 <= len(value) <= 512):
        return value
    if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value):
        return value
    try:
        return decrypt_blob(value)
    except Exception:
        return value

def load_embedded():
    import zipfile
    import io
    for apk_path in APK_CANDIDATES:
        if not os.path.exists(apk_path):
            continue
        try:
            label = apk_path
            if apk_path.endswith(".apks"):
                with zipfile.ZipFile(apk_path) as z:
                    base = zipfile.ZipFile(io.BytesIO(z.read("base.apk")))
                    if ASSET_CONFIG not in base.namelist():
                        continue
                    return base.read(ASSET_CONFIG), apk_path
            else:
                with zipfile.ZipFile(apk_path) as z:
                    if ASSET_CONFIG in z.namelist():
                        return z.read(ASSET_CONFIG), apk_path
        except Exception:
            continue
    return None, None

def main():
    print_bar(C_RED)
    print_c(f"{APP_NAME} — decryptor (my.teamapna.tunnel)", C_RED)
    print_c("By @SnapDark 🇧🇩 | t.me/SnapDark", C_CYAN)
    print_bar(C_RED)

    config = None
    source = None

    # Live updater (same XXTEA layer, Version field bumps with each push)
    try:
        print_c("[*] Fetching live updater ...", C_BLUE)
        link = "https://amtun.xyz/updater/c44cef4d43f71b0d45e01ae1dc7bd2"
        r = requests.get(link, timeout=60, headers={"User-Agent": APP_UA})
        r.raise_for_status()
        config = json.loads(decrypt_blob(r.text))
        source = link
        print_c(f"[+] LIVE OK — Version {config.get('Version')}", C_GREEN)
    except Exception as ex:
        print_c(f"[!] Live updater failed: {ex}", C_YELLOW)

    if config is None:
        data, apk_path = load_embedded()
        if data is None:
            print_c("[-] No embedded config found!", C_RED)
            return
        try:
            print_c("[*] Decrypting embedded config ...", C_BLUE)
            config = json.loads(decrypt_blob(data.decode("utf-8")))
            source = f"embedded {os.path.basename(apk_path)} {ASSET_CONFIG}"
            print_c(f"[+] Embedded OK — Version {config.get('Version')}", C_GREEN)
        except Exception as ex:
            print_c(f"[-] Embedded decrypt failed: {ex}", C_RED)
            return

    # ---- global account: like APNA SHIELD / FNF, per-server username/password ----
    # ---- are empty placeholders — the app injects the top-level account into ----
    # ---- every server at runtime. Fill them so the JSON shows what the app uses.
    glob_user = l2_field(config.get("Username"))
    glob_pass = l2_field(config.get("Password"))
    filled = 0
    for bucket in ("Premium_servers", "Vip_servers", "Private_servers", "Free_servers"):
        for srv in config.get(bucket) or []:
            if isinstance(srv, dict):
                if not srv.get("username"):
                    srv["username"] = glob_user
                    filled += 1
                if not srv.get("password"):
                    srv["password"] = glob_pass
                    filled += 1
    print_c(f"[*] global account {glob_user}/{glob_pass} injected into {filled} empty server cred fields", C_CYAN)

    out = {
        "CREDITS": CREDITS,
        "_source": f"{source} | XXTEA delta 0x9E5729B1 key '...|...' | lsparanoid Deobfuscator$APNAVPN$app",
        "_credentials_note": (f"app-wide global account — every server with empty creds uses "
                              f"Username={glob_user!r} / Password={glob_pass!r} (injected by the app at runtime; "
                              f"now filled into each server entry)."),
        "Premium_servers": config.get("Premium_servers", []),
        "Vip_servers": config.get("Vip_servers", []),
        "Private_servers": config.get("Private_servers", []),
        "Payloads": config.get("Payloads", []),
        "Free_servers": config.get("Free_servers", []),
        "Version": config.get("Version"),
        "Changelogs": config.get("Changelogs"),
        "Username": l2_field(config.get("Username")),
        "Password": l2_field(config.get("Password")),
        "UpdaterLink": config.get("UpdaterLink"),
        "App": {"name": APP_NAME, "package": APP_PACKAGE},
    }

    # JSON validity gate — never save invalid output
    try:
        json.dumps(out, ensure_ascii=False)
    except (TypeError, ValueError) as ex:
        print_c(f"[-] JSON validity gate failed: {ex}", C_RED)
        return

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print_c(f"[+] Saved: {OUTPUT_FILE}", C_GREEN)
    print_c(f"    servers: {len(out['Free_servers'])} free | {len(out['Payloads'])} payloads | version {out['Version']}", C_CYAN)
    print_bar(C_GREEN)

if __name__ == "__main__":
    main()
