# Python By @SnapDark
import os
import sys
import json
import time
import base64
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

#  Target : Boltnet VPN v2.0.9 (com.bossapps.boltnetvpn, bossapps family, Bangladesh "noyakhali.today" hosts)
#  Live   : update.php  -> response.{tweaks,servers} = {version, data}
#           blob layers: data = b64( JSON{type,version,data: b64( AES-128-CBC ciphertext )} )
#           AES/CBC/NoPadding ; key = HEAP hex-decoded 16B ; IV = ASCII "15FB9FCEBD303ADD" (16 chars = 16 bytes)
#           (encryptor zero-pads plaintext to a multiple of 16 — app relies on NoPadding)
#  Keys   : TWEAK_KEY  = 6BD635FCC9E7F687D22D973D739DE133
#           SERVER_KEY = 97B2059BE742A6D28D398BE39F4BB9BC
#  Modes  : connection_mode 1 = tcp direct (proto tcp-client, remote host)
#           2 / 4 = local BugServer (payload + custom_sni bug) -> remote 127.0.0.1:bugport
#           6     = udpTunnel path (auth "user:md5(password):md5(imei)")
#           other = default proto udp-client
#  AUTH   : account.php?u=<plain>&p=<md5>&i=<md5(imei)> -> premium status — CODE-ONLY, NEVER CONTACTED
#           udpTunnel.setAuthStr("%s:%s:%s" % (user, md5(pw), md5(deviceId)))
#  ovpn   : assets/boltnet.ovpn template — "[proto]"/"[remote]" runtime-filled
#  House rule: CREDITS first + _source ; JSON-validity gate ; backup-before-replace ;
#              chmod 600 (FUSE may still show 660)

UPDATE_URL = "https://www.boltnetapp.com/api/update.php"
UA = "okhttp/4.9.0"
TWEAK_KEY = bytes.fromhex("6BD635FCC9E7F687D22D973D739DE133")
SERVER_KEY = bytes.fromhex("97B2059BE742A6D28D398BE39F4BB9BC")
ASCII_IV = "15FB9FCEBD303ADD"
OUTPUT_FILE = "/sdcard/VPNs/Boltnet VPN ☠️.json"
OUTPUT_TEXT = "/sdcard/VPNs/Boltnet VPN ☠️.txt"

MODE_NAMES = {
    1: "tcp direct",
    2: "bug server (payload/sni)",
    3: "default (proto udp-client)",
    4: "bug server (payload/sni)",
    6: "udp tunnel (auth user:md5(pw):md5(imei))",
}

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}{C_RESET}")

# ---------------- LAYER 1 : outer b64 -> JSON -> inner data ----------------

def peel(b64text):
    """response.<section>.data -> {type, version, data:<ENC b64>}"""
    return json.loads(base64.b64decode(b64text))

# ---------------- LAYER 2 : AES-128-CBC NoPadding ----------------

def aes_decrypt(enc_b64, key, iv=ASCII_IV):
    raw = base64.b64decode(enc_b64)
    pt = AES.new(key, AES.MODE_CBC, iv.encode()).decrypt(raw)
    # NoPadding: encoder zero-pads -> trailing NULs must go
    pt = pt.rstrip(b"\x00")
    text = pt.decode("utf-8", "replace")
    # strict JSON gate: parse once here so output failures are caught early
    obj, _end = json.JSONDecoder().raw_decode(text)
    return obj

def load_blob(section, version, data, key):
    obj = peel(data)
    items = aes_decrypt(obj["data"], key)
    return version, items

def main():
    t_start = time.monotonic()
    print_bar(C_CYAN)
    print_c("⚡ BOLTNET VPN — live resource decryptor ⚡", C_CYAN)
    print_bar(C_CYAN)
    print_c("Algorithm : AES-128-CBC NoPadding (hex key, ASCII IV)", C_CYAN)
    print_c("Source    : update.php (tweaks + servers blobs)", C_CYAN)
    print_c("AUTH      : account.php is code-only — never contacted", C_YELLOW)
    print_bar()

    r = requests.get(UPDATE_URL, headers={"User-Agent": UA}, timeout=45)
    r.raise_for_status()
    resp = r.json().get("response", {})
    tweak_v = resp.get("tweaks", {}).get("version", "?")
    server_v = resp.get("servers", {}).get("version", "?")
    print_c("[+] update.php 200 OK — tweaks v%s | servers v%s" % (tweak_v, server_v), C_GREEN)

    _, tweak_items = load_blob("tweaks", tweak_v, resp["tweaks"]["data"], TWEAK_KEY)
    _, server_items = load_blob("servers", server_v, resp["servers"]["data"], SERVER_KEY)
    tweaks = tweak_items.get("items", [])
    servers = server_items.get("items", [])
    print_c("[+] tweaks: %d items | servers: %d items" % (len(tweaks), len(servers)), C_GREEN)

    out_servers = []
    for it in servers:
        conf = it.get("conf", {})
        out_servers.append({
            "Name": it.get("name", ""),
            "Description": it.get("description", ""),
            "ServerHost": conf.get("server_host", "-1"),
            "AltServerHost": conf.get("alt_server_host", "-1"),
        })

    out_tweaks = []
    for it in tweaks:
        conf = it.get("conf", {})
        mode = conf.get("connection_mode")
        out_tweaks.append({
            "Name": it.get("name", ""),
            "Description": it.get("description", ""),
            "Tag": it.get("tag", ""),
            "Mode": mode,
            "ModeName": MODE_NAMES.get(mode, "other"),
            "ServerPort": conf.get("server_port", ""),
            "Payload": conf.get("payload", ""),
            "SNI": conf.get("custom_sni", ""),
            "SniPayload": conf.get("sni_payload", ""),
            "ProxyHost": conf.get("proxy_host", ""),
            "ProxyPort": conf.get("proxy_port", ""),
        })

    final_json = {
        "CREDITS": "Decrypted By @SnapDark 🇧🇩",
        "TELEGRAM": "https://t.me/bd_loser",
        "CHANNEL": "https://t.me/+GEautSR2nNphZWJl",
        "NOTE": "Free Config - Do not sell",
        "_source": {
            "app": "Boltnet VPN",
            "package": "com.bossapps.boltnetvpn",
            "apk_version": "2.0.9",
            "live_endpoint": UPDATE_URL,
            "auth_endpoint": "https://www.boltnetapp.com/api/account.php (CODE-ONLY, never contacted; u=plain p=md5(pw) i=md5(deviceId))",
            "crypto": "AES-128-CBC NoPadding; key hex-decoded; IV = ASCII '15FB9FCEBD303ADD'; outer b64(JSON{type,version,data:b64(ct)}); zero-pad",
            "tweak_key_hex": TWEAK_KEY.hex().upper(),
            "server_key_hex": SERVER_KEY.hex().upper(),
            "tweak_version": tweak_v,
            "servers_version": server_v,
            "connection_modes": MODE_NAMES,
            "ovpn_template": "assets/boltnet.ovpn ([proto]/[remote] runtime-filled; EasyRSA CA)",
            "native_LIBs": ["libhysteria.so (hy2)", "libovpncli.so (ics-openvpn)", "libtun2socks.so"],
            "user_agent": UA,
        },
        "Servers": out_servers,
        "Tweaks": out_tweaks,
    }

    # ---- JSON-validity gate ----
    try:
        parsed = json.loads(json.dumps(final_json, ensure_ascii=False))
    except Exception as e:
        print_bar("!")
        print_c("FATAL: output JSON invalid: %r" % (e,))
        sys.exit(5)
    if not parsed.get("Servers") and not parsed.get("Tweaks"):
        print_bar("!")
        print_c("FATAL: no Servers and no Tweaks decrypted")
        sys.exit(6)

    # ---- backup-before-replace (U5) ----
    if os.path.exists(OUTPUT_FILE):
        bak = OUTPUT_FILE + ".bak-" + time.strftime("%Y%m%d_%H%M%S")
        shutil.copy2(OUTPUT_FILE, bak)
        print_c("[*] existing output backed up -> %s" % bak)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(parsed, f, ensure_ascii=False, indent=1)
    try:
        os.chmod(OUTPUT_FILE, 0o600)
    except OSError:
        pass

    # ---- readable .txt ----
    lines = ["════ BOLTNET VPN ☠️ — @SnapDark 🇧🇩 ════",
             "tweaks v%s | servers v%s" % (tweak_v, server_v),
             ""]
    lines.append("──── SERVERS (%d) ────" % len(out_servers))
    for i, s in enumerate(out_servers, 1):
        lines.append("%02d. %-28s %-16s %s" % (i, s["Name"], s["Description"], s["ServerHost"]))
    lines.append("")
    lines.append("──── TWEAKS (%d) ────" % len(out_tweaks))
    for i, t in enumerate(out_tweaks, 1):
        lines.append("%02d. %s  [%s | %s]" % (i, t["Name"], t["Mode"], t["ModeName"]))
        lines.append("    desc  : %s" % t["Description"])
        lines.append("    port  : %s | SNI: %s | proxy: %s:%s" % (t["ServerPort"], t["SNI"] or "-", t["ProxyHost"] or "-", t["ProxyPort"] or "-"))
        if t["Payload"]:
            lines.append("    payload: %s" % t["Payload"])
        if t["SniPayload"]:
            lines.append("    sni_payload: %s" % t["SniPayload"])
    try:
        os.makedirs(os.path.dirname(OUTPUT_TEXT), exist_ok=True)
        with open(OUTPUT_TEXT, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print_c(f"[★] Saved Readable Config to: {OUTPUT_TEXT}", C_GREEN)
    except OSError as e:
        print_c(f"[!] .txt save failed (output JSON only): {e}", C_YELLOW)

    total = time.monotonic() - t_start
    print_bar()
    print_c("Tweaks: %d | Servers: %d" % (len(out_tweaks), len(out_servers)))
    print_c("output: %s (%d bytes)" % (OUTPUT_FILE, os.path.getsize(OUTPUT_FILE)))
    print_c("total elapsed: %.1fs" % total)
    print_bar()
    print_c("☠️  DONE — JSON validated  ☠️")
    print_bar()


if __name__ == "__main__":
    main()
