# Python By @snapdark_decoder 🇧🇩
import os
import re
import io
import sys
import json
import time
import base64
import shutil
import zipfile
import subprocess

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        missing.append("cryptography")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + "[*] Required modules missing. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    import requests
    return requests

check_dependencies()
import requests

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

LIVE_URL = "https://strongteam.co/api/wolfcustom/newv1.txt"
OUTPUT_FILE = "/sdcard/VPNs/Wolf Custom VPN ☠️.json"
APK_CANDIDATES = [
    "/sdcard/MT2/apks/Wolf Custom VPN_v2.8.1.2.apks",
    "/storage/emulated/0/MT2/apks/Wolf Custom VPN_v2.8.1.2.apks",
]
ASSET_CONFIG = "assets/configfile.json"

# ---- Layer keys ----
# libgojni.so  ->  github.com/2dust/AndroidLibXrayLite.Decrypt
#   s = base64.StdEncoding.DecodeString(input)
#   NB = rsa? no -> aes.NewCipher([]byte("qkKG+glMDxozePe5/Kcm+ZLeba+jJIrF"))
#   g, _ = cipher.NewGCM(NB)
#   plaintext = g.Open(nil, s[:12], s[12:], nil)
# Hollow 32-byte rodata slice @ libgojni 0x363810 (hex literal via 0x6153F0)
MAIN_KEY = b"qkKG+glMDxozePe5/Kcm+ZLeba+jJIrF"

APP_UA = "okhttp/4.9.0"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

# ---------------- LAYER 1 : base64( IV12 || AES-256-GCM(ct||tag) ) ----------------

def wb64_decode(s):
    s = re.sub(r"\s", "", s)
    return base64.b64decode(s + "=" * (-len(s) % 4))

def wolf_decrypt(text):
    blob = wb64_decode(text)
    if len(blob) < 12:
        raise ValueError("blob too short")
    nonce = blob[:12]
    ct = blob[12:]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pt = AESGCM(MAIN_KEY).decrypt(nonce, ct, None)
    return pt

# ---------------- LAYER 2 : same GCM key, per-field ----------------

_B64_RE = re.compile(r'^[A-Za-z0-9+/]{36,}={0,2}$')

def _try_field_dec(b64):
    try:
        raw = wb64_decode(b64)
    except Exception:
        return None
    if len(raw) < 28:            # 12 IV + 16 tag minimum (+0..n ct bytes)
        return None
    try:
        pt = wolf_decrypt(b64)
        return pt.decode("utf-8")
    except Exception:
        return None

def recursive_l2(node, count=[0]):
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str) and _B64_RE.match(v):
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

# ---------------- embedded fallback ----------------

def load_embedded():
    last = None
    for apk_path in APK_CANDIDATES:
        try:
            with zipfile.ZipFile(apk_path) as z:
                names = z.namelist()
                base = None
                for n in names:
                    if n.endswith("base.apk"):
                        base = z.read(n)
                        break
                if base is None:
                    return None, apk_path
                with zipfile.ZipFile(io.BytesIO(base)) as inner:
                    if ASSET_CONFIG not in inner.namelist():
                        return None, apk_path
                    return inner.read(ASSET_CONFIG).decode("utf-8"), apk_path
        except Exception as e:
            last = e
            continue
    if last:
        print_c(f"[-] Embedded read failure: {last}", C_RED)
    return None, None

def save_output(path, config, source):
    final_json = {
        "CREDITS": "Decrypted By @snapdark_decoder 🇧🇩 | Join channel: t.me/Jubairbro",
        "_source": f"{source} | L1 = base64(IV12 || AES-256-GCM(ct||tag)) | libgojni.so AndroidLibXrayLite.Decrypt, rodata key @0x363810",
    }
    final_json.update(config)
    out_str = json.dumps(final_json, indent=4, ensure_ascii=False)

    # JSON validity gate
    try:
        json.loads(out_str)
    except Exception as e:
        print_c(f"[-] Output JSON invalid: {e}", C_RED)
        return

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: {path}", C_GREEN)
    except (PermissionError, OSError):
        print_c(f"[-] Permission denied for {path}. Trying local dir...", C_RED)
        local_out = os.path.basename(path)
        with open(local_out, "w", encoding="utf-8") as f:
            f.write(out_str)
        print_c(f"[★] Saved Decrypted Configuration to: ./{local_out}", C_GREEN)

def main():
    print("")
    print_bar(C_CYAN)
    print_c("Wolf Custom VPN Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Fetching encrypted live config from strongteam.co...", C_BLUE)
    time.sleep(0.5)

    live_failed = False
    try:
        response = requests.get(LIVE_URL, headers={"User-Agent": APP_UA}, timeout=(30, 300))
        response.raise_for_status()
        blob = response.text
        if len(blob) < 100000:
            raise ValueError("live payload suspiciously small")
        print_c(f"[+] Live encrypted payload ready ({len(blob)} chars b64)...", C_GREEN)
        source = LIVE_URL
    except Exception as e:
        live_failed = True
        print_c(f"[-] Live fetch failed ({e})", C_RED)
        print_c("[*] Falling back to embedded asset (assets/configfile.json)...", C_YELLOW)
        blob, apk_used = load_embedded()
        if blob is None:
            return
        print_c(f"[+] Embedded payload ready ({len(blob)} chars b64)...", C_GREEN)
        source = os.path.basename(apk_used or "") + " " + ASSET_CONFIG

    print("")
    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : AES-256-GCM  (nonce = blob[:12], no AAD)", C_CYAN)
    print_c("Key (rodata libgojni 0x363810) : 'qkKG+glMDxozePe5/Kcm+ZLeba+jJIrF'", C_CYAN)
    time.sleep(0.6)

    try:
        plain = wolf_decrypt(blob)
        parsed = json.loads(plain)
    except Exception as e:
        print_c(f"[-] Layer 1 breach failure: {e}", C_RED)
        return
    print_c(f"[*] Version : {parsed.get('Version', 'N/A')}", C_BLUE)

    print_c(">>> INITIATING LAYER 2 (per-field AES-256-GCM) <<<", C_YELLOW)
    print_c("Scope : Servers + Networks (ServerIPHost, OVPNUser/Pass, UDP_*, SlowDNS*, V2ray*, Payload, SNI, BugDNS, H2pass ...)", C_CYAN)
    n2 = recursive_l2(parsed)
    print_c(f"[+] Layer 1 Successfully Breached.. ({len(plain)} bytes of config JSON)", C_GREEN)
    print_c(f"[+] Layer 2 Successfully Breached.. per-field decryptions: {n2}", C_GREEN)

    servers = parsed.get('Servers', [])
    nets = parsed.get('Networks', [])
    print("")
    print_c(f"[*] Version   : {parsed.get('Version', 'N/A')} | Embedded shipped : 1.01", C_BLUE)
    print_c(f"[*] Release   : {parsed.get('ReleaseNotes', 'N/A')[:60]}", C_BLUE)
    print_c(f"[*] Servers   : {len(servers)}", C_BLUE)
    print_c(f"[*] Networks  : {len(nets)}", C_BLUE)
    print_c(f"[*] OVPN def  : user='{parsed.get('DefOVPNUser','')}' / pass='{parsed.get('DefOVPNPass','')}' | Hysteria '{parsed.get('HysteriaUser','')}' obfs '{parsed.get('HysteriaOBFS','')}'", C_BLUE)
    print("")

    tunnel_types = sorted({str(n.get("TunnelType", "")) for n in nets if n.get("TunnelType")})
    proto_modes = sorted({str(s0.get("ServerProtocol", "")) for s0 in servers if s0.get("ServerProtocol")})

    print_c(">>> BUILDING FINAL DELIVERABLE JSON <<<", C_YELLOW)

    final = {
        "CREDITS": "Decrypted By @snapdark_decoder 🇧🇩 | Join channel: t.me/Jubairbro",
        "_source": f"{source}",
    }
    final.update(parsed)
    final["App"] = {
        "package": "core.vpn3jx.xtreme",
        "versionName": "v2.8.1.2",
        "versionCode": 13,
        "core": "v2rayNG (libgojni) + sandok injector (com.vpn.sandok/ultrasshservice) + libuz (sing-box TUN)",
        "protocols": proto_modes,
        "tunnelTypes": tunnel_types,
    }
    final["Crypto"] = {
        "live_url": LIVE_URL,
        "layer1": "base64( IV12 || AES-256-GCM(ct||tag), no AAD )",
        "key": "qkKG+glMDxozePe5/Kcm+ZLeba+jJIrF  (32-byte rodata string, libgojni 0x363810)",
        "impl": "github.com/2dust/AndroidLibXrayLite.Decrypt exported as Java_libv2ray_Libv2ray_decrypt",
        "layer2": "every config field is again base64(IV12 || AES-256-GCM) with the SAME key - empty values are 28-byte IV+tag-only records",
        "user_agent": APP_UA,
    }
    final["Notes"] = (
        "Live config = https://strongteam.co/api/wolfcustom/newv1.txt (StrongVPNTeam host, same parent as PTI/SA). "
        "Servers[] defs per host: ServerIPHost/SSLPort/SSH_Port/OpenVPNTCP/UDPPort, OVPNUser/OVPNPass, "
        "UDP_obfs=chacha-obfs password, SlowDNSHost/Key, V2rayUUID/Protocol/Network/Host(path). "
        "Networks[] = 1900+ connection payloads (b64 headers, SNI/ProxyPort/TunnelType) built per server connection"
        " (TunnelType 'Http/Ws Proxy', 'SSL Direct', ...). isTimerOn+timetoadd = auto-update Server config by app timer."
    )

    save_output(OUTPUT_FILE, final, source)

    print("")
    print_bar(C_CYAN)
    print_c(">>> ALL LAYERS DECRYPTED - STAY CONNECTED <<<", C_YELLOW)
    print("")

if __name__ == "__main__":
    main()
