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

APK_PATH = "/storage/emulated/0/MT2/apks/PingTunnel VPN_1.13.64.apks"
PACKAGE = "africa.ping.vpn"
OUTPUT_FILE = "/sdcard/VPNs/PingTunnel VPN ☠️.json"

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(color + ("=" * width) + C_RESET)

def main():
    print_bar(C_CYAN)
    print_c("PingTunnel VPN", C_BLUE)
    print_c(f"Package: africa.ping.vpn  |  APK: PingTunnel VPN_1.13.64.apks", C_CYAN)
    print_bar(C_CYAN)
    result = {**CREDITS, "PACKAGE": "africa.ping.vpn", "STATUS": "Flutter client - manual server entry only (public IP/DNS check endpoints detected)", "HOW_TO_IMPORT": "manual config inside app"}

    json.dump(result, open(OUTPUT_FILE, "w"), indent=2, ensure_ascii=False)
    print_c(f"Saved -> {OUTPUT_FILE}", C_GREEN)
if __name__ == "__main__":
    main()
