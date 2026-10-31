# Python By @snapdark_decoder 🇧🇩
import os
import sys
import json
import time
import shutil
import subprocess
import zipfile

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + ("[*] Auto-installing: " + ", ".join(missing)).center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q"] + missing)

check_dependencies()
import requests

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

CREDITS = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩", "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell"}

APK_PATH = "/storage/emulated/0/MT2/apks/SC Tunnel_1.2.9.apks"
PACKAGE = "com.sctunnel.vpn"
OUTPUT_FILE = "/sdcard/VPNs/SC Tunnel ☠️.json"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(color + ("=" * width) + C_RESET)

def main():
    print_bar(C_CYAN)
    print_c("SC Tunnel", C_BLUE)
    print_c(f"Package: com.sctunnel.vpn  |  APK: SC Tunnel_1.2.9.apks", C_CYAN)
    print_bar(C_CYAN)
    try:
        r = requests.get("https://raw.githubusercontent.com/sockettunnelx/servers/main/servers.json", timeout=15)
        if r.ok:
            print_c("LIVE servers.json found - saving", C_GREEN)
            data = {**CREDITS, "PACKAGE": "com.sctunnel.vpn", "SOURCE": "https://raw.githubusercontent.com/sockettunnelx/servers/main/servers.json", "servers": r.json()}
            json.dump(data, open(OUTPUT_FILE, "w"), indent=2, ensure_ascii=False)
            print_c(f"Saved -> {OUTPUT_FILE}", C_GREEN)
            return
    except Exception:
        pass
    print_c("Official servers.json is OFFLINE (404) - import via app instead", C_YELLOW)
    result = {**CREDITS, "PACKAGE": "com.sctunnel.vpn", "STATUS": "official server list offline (raw.githubusercontent sockettunnelx/servers -> 404)", "HOW_TO_IMPORT": "SC Tunnel -> import subscription URL in app"}

    json.dump(result, open(OUTPUT_FILE, "w"), indent=2, ensure_ascii=False)
    print_c(f"Saved -> {OUTPUT_FILE}", C_GREEN)
if __name__ == "__main__":
    main()
