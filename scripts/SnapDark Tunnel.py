# Python By @snapdark_decoder 🇧🇩
# SnapDark Tunnel - live-first decryptor (rebranded from DARK TUNNEL VPN stack)
import os
import sys
import json
import time
import base64
import shutil
import subprocess
import zipfile

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
import urllib3
urllib3.disable_warnings()
from Crypto.Cipher import AES

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

# Live endpoints probed in order (SnapDark rebrand first, proven DarkTunnel path as fallback)
CANDIDATE_URLS = [
    "https://dark.gandas.uk/SnapDark/Kabaka/zovu.json",
    "https://dark.gandas.uk/SnapDark/zovu.json",
    "https://dark.gandas.uk/DarkTunnel/Kabaka/zovu.json",   # proven working host path
    "https://dark.gandas.uk/DarkTunnel/zovu.json",
]
SOURCE_URL = None  # set when live fetch succeeds (goes into output _source)

APK_PATH = "/storage/emulated/0/MT2/apks/DARK TUNNEL VPN_DT 20.apks"
RAW_ENTRY = "res/raw/zovu.json"
OUTPUT_FILE = "/sdcard/VPNs/SnapDark Tunnel ☠️.json"
OUTPUT_EMBEDDED = "/sdcard/VPNs/SnapDark Tunnel (Embedded) ☠️.json"

GCM_KEY = bytes([65, 66, 67, 68, 69, 70, 71, 72, 73, 80, 81, 82, 83, 84, 85, 86,
                 97, 98, 99, 100, 101, 102, 103, 104, 105, 112, 113, 114, 115, 116, 117, 118])
CREDITS_TEXT = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/SnapDark"


def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")


def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(color + ("=" * width) + C_RESET)


def dark_decrypt(b64_text):
    raw = base64.b64decode(b64_text.strip() + "=" * (-len(b64_text.strip()) % 4))
    nonce, ct = raw[:12], raw[12:]
    c = AES.new(GCM_KEY, AES.MODE_GCM, nonce=nonce)
    pt = c.decrypt_and_verify(ct[:-16], ct[-16:])
    return json.loads(pt.decode("utf-8", errors="replace"))


def grab_embedded():
    with zipfile.ZipFile(APK_PATH) as z:
        names = z.namelist()
        base = next((n for n in names if n.endswith("base.apk")), None)
        if not base:
            return None
        tmp = "/data/data/com.termux/files/usr/tmp/snapdark_embedded_zovu.json"
        with z.open(base) as f, open(tmp, "wb") as out:
            out.write(f.read())
    with zipfile.ZipFile(tmp) as b:
        return b.read(RAW_ENTRY).decode("utf-8", errors="replace")


def save(path, config, tag, source):
    data = {"CREDITS": CREDITS_TEXT, "_note": tag}
    if source:
        data["_source"] = source
    data.update(config)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # JSON-validity gate
    payload = json.dumps(data, ensure_ascii=False, indent=4)
    json.loads(payload)
    with open(path, "w", encoding="utf-8") as f:
        f.write(payload)
    print_c(f"[+] Saved -> {path}", C_GREEN)


def main():
    print_bar(C_CYAN)
    print_c("SNAPDARK TUNNEL | Decrypter By @snapdark_decoder 🇧🇩", C_BLUE)
    print_bar(C_CYAN)

    live = None
    for url in CANDIDATE_URLS:
        try:
            print_c(f"[*] Live probe: {url}", C_YELLOW)
            r = requests.get(url, timeout=(15, 60), verify=False,
                             headers={"User-Agent": "okhttp/4.9.0"})
            if r.status_code == 200:
                live = dark_decrypt(r.text)
                SOURCE_URL = url
                print_c(f"[+] LIVE config v{live.get('version')} | UDPHYSTERIA {len(live.get('UDPHYSTERIA', []))} | SUPERDNS {len(live.get('SUPERDNS', []))} | DNSSERVER {len(live.get('DNSSERVER', []))}", C_GREEN)
                break
            else:
                print_c(f"[-] HTTP {r.status_code}", C_RED)
        except Exception as e:
            print_c(f"[-] Failed: {e}", C_RED)

    embedded = None
    try:
        print_c("[*] Reading embedded res/raw/zovu.json ...", C_YELLOW)
        emb = grab_embedded()
        if emb:
            embedded = dark_decrypt(emb)
            print_c(f"[+] Embedded config v{embedded.get('version')} | UDPHYSTERIA {len(embedded.get('UDPHYSTERIA', []))} | SUPERDNS {len(embedded.get('SUPERDNS', []))} | DNSSERVER {len(embedded.get('DNSSERVER', []))}", C_GREEN)
    except Exception as e:
        print_c(f"[!] Embedded failed: {e}", C_RED)

    if live:
        save(OUTPUT_FILE, live, f"live v{live.get('version')}", SOURCE_URL)
    if embedded:
        save(OUTPUT_EMBEDDED, embedded, f"embedded res/raw/zovu.json v{embedded.get('version')}", None)

    if not live and not embedded:
        print_c("[!] Nothing decrypted. Check network / APK path.", C_RED)
        sys.exit(1)

    print_bar(C_CYAN)
    print_c("Done. Keep configs free - Don't sell 🔥", C_GREEN)
    print_bar(C_CYAN)


if __name__ == "__main__":
    main()
