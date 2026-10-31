# Python By @SnapDark🇧🇩
import os
import sys
import json
import time
import base64
import shutil
import subprocess
import re

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

CONFIG_URL = "https://dsappx.com/bd_vpn_admin/v2ray_config_list/api.php"
OUTPUT_FILE = "/sdcard/VPNs/Bangladesh VPN ☠️.json"
OUTPUT_TEXT = "/sdcard/VPNs/Bangladesh VPN ☠️.txt"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

def b64pad(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))

def parse_endpoint(content):
    """vmess:// / vless:// / ss:// / trojan:// -> readable dict"""
    content = content.strip()
    scheme = content.split("://", 1)[0]
    rest = content.split("://", 1)[1]
    if scheme == "vmess":
        j = json.loads(b64pad(rest).decode("utf-8"))
        return {"type": "vmess", "add": j.get("add", ""), "port": j.get("port", ""),
                "id": j.get("id", ""), "ps": j.get("ps", ""), "net": j.get("net", ""),
                "tls": j.get("tls", ""), "path": j.get("path", ""), "sni": j.get("sni", ""),
                "ale": j.get("alpn", ""), "raw": content}
    if scheme == "vless":
        hostpart, qstr = (rest.split("?", 1) + [""])[:2]
        addr = hostpart.rsplit("@", 1)[0] if "@" in hostpart else "?"
        host = hostpart.rsplit("@", 1)[1] if "@" in hostpart else ""
        q = dict(p.split("=", 1) for p in qstr.split("&") if "=" in p)
        frg = host.split("#", 1)
        fs = q.get("fp", "")
        return {"type": "vless", "add": q.get("add", host), "id": addr, "port": q.get("port", ""),
                "ps": frg[1] if len(frg) > 1 else q.get("ps", ""), "net": q.get("type", "tcp"),
                "tls": q.get("security", ""), "path": q.get("path", ""), "sni": q.get("sni", ""),
                "ale": q.get("alpn", ""), "raw": content}
    return {"type": scheme, "raw": content}

def save_output(path, obj, source):
    final_json = {"CREDITS": "Decrypted By @SnapDark 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell"}
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
    print("")
    print_bar(C_CYAN)
    print_c("Bangladesh VPN Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    print_c("[*] Fetching encrypted payload from Server...", C_BLUE)
    time.sleep(0.5)

    try:
        response = requests.get(CONFIG_URL, headers={'User-Agent': 'okhttp/4.9.0'}, timeout=25)
        response.raise_for_status()
        rows = response.json()
    except Exception as e:
        print_c(f"[-] Failed to fetch config: {e}", C_RED)
        return

    print_c(f"[+] Encrypted payload downloaded ({len(rows)} servers)...", C_GREEN)
    print("")

    print_c(">>> INITIATING DECRYPTION <<<", C_YELLOW)
    print_c("Envelope : V2RayPanel PHP API (vmess:// / vless://)", C_CYAN)
    print_c("Decode : Base64 payload -> JSON param map -> readable config", C_CYAN)
    time.sleep(1)

    servers = []
    for e in rows:
        parsed = parse_endpoint(e.get("content", ""))
        parsed.update({
            "row_id": e.get("id"),
            "server_name": e.get("name"),
            "city": e.get("city_name"),
            "country": e.get("country_code"),
            "premium": e.get("is_premium"),
        })
        servers.append(parsed)

    vmess = [s for s in servers if s.get("type") == "vmess"]
    vless = [s for s in servers if s.get("type") == "vless"]
    other = [s for s in servers if s.get("type") not in ("vmess", "vless")]

    print_c("[+] Decryption Successfully Breached..", C_GREEN)
    print_c(f"[*] Total Servers : {len(servers)}", C_BLUE)
    print_c(f"[*] Vmess : {len(vmess)} | Vless : {len(vless)} | Other : {len(other)}", C_BLUE)
    print("")

    # human-readable text output
    lines = []
    for s in servers:
        title = f"[{s['country'].upper()}] {s.get('server_name')} - {s.get('city')}"
        lines.append(title)
        lines.append("=" * len(title))
        del s["raw"]
        lines.append(json.dumps(s, indent=2, ensure_ascii=False))
        lines.append("")
    txt = "\n".join(lines)

    try:
        os.makedirs(os.path.dirname(OUTPUT_TEXT), exist_ok=True)
        with open(OUTPUT_TEXT, 'w', encoding='utf-8') as f:
            f.write(txt)
        print_c(f"[★] Saved Readable Config to: {OUTPUT_TEXT}", C_GREEN)
    except (PermissionError, OSError):
        with open(os.path.basename(OUTPUT_TEXT), 'w', encoding='utf-8') as f:
            f.write(txt)
        print_c(f"[★] Saved Readable Config to: ./{os.path.basename(OUTPUT_TEXT)}", C_GREEN)

    save_output(OUTPUT_FILE, {"servers": servers}, CONFIG_URL)
    print("")

if __name__ == "__main__":
    main()