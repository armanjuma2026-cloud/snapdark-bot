# Python By @snapdark_decoder 🇧🇩
import os
import re
import sys
import json
import base64
import shutil
import struct
import hashlib
import argparse
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

CONFIG_URL = "https://config.jubairsensei.com/sensei_configs_2026_v2.enc"
SETTINGS_URL = "https://config.jubairsensei.com/sensei_app_settings.enc"
BASE_URL = "https://config.jubairsensei.com"
ADMIN_URL = "https://admin.jubairsensei.com"
OUTPUT_FILE = "/sdcard/VPNs/Sensei Tunnel VPN ☠️.json"
SETTINGS_FILE = "/sdcard/VPNs/Sensei Tunnel Settings ☠️.json"

LABEL_V1 = b"SenseiTunnel:JubairSensei:2026"
LABEL_V2 = "SenseiTunnel:JubairSensei:2026:v2"
LABEL_V3 = "sensei::cfg::v3::2026"
V2_KEY = hashlib.sha256(LABEL_V2.encode()).digest()
EXPECTED_CERT_SHA256 = "a9e40f078e9361d7114ac6e236402ed1e15c6ba031f9cd6c73f8e7855d7688b0"

UA = {"User-Agent": "SenseiTunnel/1.0"}
B64_RE = re.compile(r'^[A-Za-z0-9+/_=-]+$')


def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

def b64_decode(s):
    s = s.strip().rstrip('=')
    return base64.b64decode(s + '=' * (-len(s) % 4))

def gcm_open(key, blob):
    if len(blob) < 28:
        return None
    cipher = AES.new(key, AES.MODE_GCM, nonce=blob[:12])
    return cipher.decrypt_and_verify(blob[12:-16], blob[-16:])

def cert_key(cert_hex):
    return hashlib.sha256(f"{cert_hex}:{LABEL_V3}".encode()).digest()

def cert_hex_from_der(der):
    return hashlib.sha256(der).hexdigest()


def apk_cert_candidates(path):
    data = open(path, 'rb').read()
    out = []
    mf = re.search(rb'PK\x05\x06', data[-66000:]) if len(data) > 66000 else re.search(rb'PK\x05\x06', data)
    if mf:
        cd_off = struct.unpack_from('<I', data, len(data) - 66000 + mf.start() + 16)[0] if len(data) > 66000 else struct.unpack_from('<I', data, mf.start() + 16)[0]
    else:
        cd_off = 0
    magic = data.rfind(b'APK Sig Block 42')
    if magic != -1:
        block_size = struct.unpack_from('<Q', data, magic - 8)[0]
        pairs = data[magic - block_size:magic - 8]
        for m in re.finditer(rb'\x30\x82(.{2})', pairs, re.S):
            der = pairs[m.start():m.start() + 4 + struct.unpack('>H', m.group(1))[0]]
            if der not in out:
                out.append(der)
    for name, raw in _apk_v1_certs(data):
        for m in re.finditer(rb'\x30\x82(.{2})', raw, re.S):
            der = raw[m.start():m.start() + 4 + struct.unpack('>H', m.group(1))[0]]
            if der not in out:
                out.append(der)
    return out

def _apk_v1_certs(data):
    res = []
    import io
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        for n in zf.namelist():
            if n.startswith('META-INF/') and n.upper().endswith(('.RSA', '.DSA', '.EC')):
                res.append((n, zf.read(n)))
    except Exception:
        pass
    return res


class Dec:
    def __init__(self, apk_path=None):
        self.certs = [EXPECTED_CERT_SHA256]
        if apk_path and os.path.exists(apk_path):
            for der in apk_cert_candidates(apk_path):
                h = cert_hex_from_der(der)
                if h not in self.certs:
                    self.certs.append(h)

    def unwrap(self, text):
        t = text.strip()
        if t.startswith('sensei:v1:'):
            raw = b64_decode(t[len('sensei:v1:'):])
            k = LABEL_V1
            return bytes(b ^ k[i % len(k)] for i, b in enumerate(raw)).decode('utf-8')
        if t.startswith('sensei:v2:'):
            pt = gcm_open(V2_KEY, b64_decode(t[len('sensei:v2:'):]))
            if pt is None:
                raise RuntimeError("v2 GCM auth failed")
            return pt.decode('utf-8')
        if t.startswith('sensei:v3:'):
            blob = b64_decode(t[len('sensei:v3:'):])
            for ch in self.certs:
                try:
                    pt = gcm_open(cert_key(ch), blob)
                    if pt is not None:
                        return pt.decode('utf-8')
                except Exception:
                    continue
            raise RuntimeError("v3 GCM auth failed (cert key mismatch)")
        if t.startswith('sensei:v2p:'):
            raise RuntimeError("sensei:v2p: is a PIN-locked share; needs the sharer PIN")
        try:
            return json.loads(t)
        except Exception:
            raise RuntimeError("unknown envelope prefix")

def fetch(url):
    r = requests.get(url, headers=UA, timeout=30)
    r.raise_for_status()
    return r.text.strip(), url

def save_output(path, obj, source):
    final_json = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell"}
    if isinstance(obj, list):
        final_json["configs"] = obj
    else:
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
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--apk', default=None)
    ap.add_argument('--file', default=None)
    args, _ = ap.parse_known_args()

    print("")
    print_bar(C_CYAN)
    print_c("Sensei Tunnel Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    dec = Dec(args.apk)

    if args.file:
        text = open(args.file, encoding='utf-8').read().strip()
        config = json.loads(dec.unwrap(text))
        save_output(OUTPUT_FILE, config, args.file)
        return

    print_c("[*] Fetching live config feed (cert-bound v3)...", C_BLUE)
    try:
        enc, source = fetch(CONFIG_URL)
        config = json.loads(dec.unwrap(enc))
    except Exception as e:
        print_c(f"[-] Live config failed: {e}", C_RED)
        print_c("[*] Try: --apk \"/storage/emulated/0/MT2/apks/Sensei Tunnel_1.0.55.apk\" or --file <local.enc>", C_YELLOW)
        return

    print_c("[+] Config decrypted OK", C_GREEN)

    print("")
    print_c(">>> DECRYPTION SUMMARY <<<", C_YELLOW)
    print_c("v1 : XOR  key=SenseiTunnel:JubairSensei:2026", C_CYAN)
    print_c("v2 : AES-256-GCM  key=SHA256('SenseiTunnel:JubairSensei:2026:v2')", C_CYAN)
    print_c("v3 : AES-256-GCM  key=SHA256(certHex + ':sensei::cfg::v3::2026')", C_CYAN)
    print_c(f"Cert : {dec.certs[0]}", C_CYAN)
    print("")

    if isinstance(config, list):
        official = sum(1 for c in config if c.get('isOfficial'))
        protos = {}
        for c in config:
            p = c.get('protocol', '?')
            protos[p] = protos.get(p, 0) + 1
        print_c(f"[*] Configs         : {len(config)} ({official} official)", C_BLUE)
        print_c(f"[*] Protocols       : {', '.join(f'{k}:{v}' for k, v in sorted(protos.items()))}", C_BLUE)
        print_c(f"[*] Telegram        : @bd_loser", C_BLUE)
        print_c(f"[*] Admin panel     : {ADMIN_URL}", C_BLUE)
        print("")
        for c in config:
            auth = ''
            if c.get('username') or c.get('password'):
                auth = f" | {c.get('username','')}:{c.get('password','')}"
            tag = 'OFFICIAL' if c.get('isOfficial') else 'custom'
            print_c(f"    - {c.get('name','').strip()} [{tag}] {c.get('protocol','')}://{c.get('address','')}:{c.get('port','')}{auth}", C_CYAN)
    else:
        print_c(f"[*] Keys            : {', '.join(config.keys())}", C_BLUE)

    print("")
    print_c("[*] Fetching app settings bundle...", C_BLUE)
    try:
        enc, src2 = fetch(SETTINGS_URL)
        settings = json.loads(dec.unwrap(enc))
        st = settings.get('settings', {})
        print_c(f"[*] appLocked={st.get('appLocked')} forceUpdate={st.get('forceUpdate')} latest={st.get('latestVersion')} vers={st.get('vers')}", C_BLUE)
        save_output(SETTINGS_FILE, settings, src2)
    except Exception as e:
        print_c(f"[-] Settings fetch/decrypt failed: {e}", C_YELLOW)

    print("")
    save_output(OUTPUT_FILE, {"configs": config}, source)
    print("")

if __name__ == "__main__":
    main()
