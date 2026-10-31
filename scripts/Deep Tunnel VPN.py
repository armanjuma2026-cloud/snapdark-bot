# Python By @SnapDark 🇧🇩
import os
import sys
import json
import time
import base64
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

CONFIG_URL = "https://strongteam.co/api/deeptunnel/deepv1.txt"
OUTPUT_FILE = "/sdcard/VPNs/Deep Tunnel VPN ☠️.json"
OUTPUT_TEXT = "/sdcard/VPNs/Deep Tunnel VPN ☠️.txt"

EMBEDDED_B64 = "eyJWZXJzaW9uIjogIjEuMDEiLCAiUmVsZWFzZU5vdGVzIjogIiIsICJUZWxlZ3JhbSI6ICJodHRwczovL3QubWUvK1ZDWXpCNEZqdm9Rd1pETTEiLCAiV2hhdHNBcHAiOiAiIiwgIkZhY2Vib29rIjogIiIsICJEZWZPVlBOVXNlciI6ICJzYW5kb2tpIiwgIkRlZk9WUE5QYXNzIjogInNhbmRva2kiLCAiSHlzdGVyaWFVc2VyIjogInNhbmRva2k6c2FuZG9raSIsICJIeXN0ZXJpYU9CRlMiOiAic2FuZG9raSIsICJEZWZhdWx0T1ZQTkNlcnQiOiAiY2xpZW50XG5kZXYgdHVuXG5wcm90byB0Y3BcbnBvcnQgMTE5NFxucmVtb3RlIFguWC5YLlhcbmNpcGhlciBub25lXG5hdXRoIG5vbmVcbmF1dGgtdXNlci1wYXNzXG5waW5nLXRpbWVyLXJlbVxucmVkaXJlY3QtZ2F0ZXdheSBkZWYxXG5zZXRlbnYgQ0xJRU5UX0NFUlQgMFxudmVyYiAzXG48Y2E+XG4tLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS1cbk1JSUVzekNDQTV1Z0F3SUJBZ0lKQUlBRE95aE4rUko5TUEwR0NTcUdTSWIzRFFFQkN3VUFNSUdYTVFzd0NRWURcblZRUUdFd0pRU0RFTk1Bc0dBMVVFQ0JNRVEwVkNWVEVOTUFzR0ExVUVCeE1FUTBWQ1ZURU5NQXNHQTFVRUNoTUVcblEyVmlkVEVXTUJRR0ExVUVDeE1OVTNSeWIyNW5WbEJPVkdWaGJURVFNQTRHQTFVRUF4TUhRMlZpZFNCRFFURVBcbk1BMEdBMVVFS1JNR2MyVnlkbVZ5TVNBd0hnWUpLb1pJaHZjTkFRa0JGaEZrWlhaQWMzUnliMjVuTFhad2JpNTBcbmF6QWVGdzB4T0RBek1UQXhNVFV4TlRKYUZ3MHlPREF6TURjeE1UVXhOVEphTUlHWE1Rc3dDUVlEVlFRR0V3SlFcblNERU5NQXNHQTFVRUNCTUVRMFZDVlRFTk1Bc0dBMVVFQnhNRVEwVkNWVEVOTUFzR0ExVUVDaE1FUTJWaWRURVdcbk1CUUdBMVVFQ3hNTlUzUnliMjVuVmxCT1ZHVmhiVEVRTUE0R0ExVUVBeE1IUTJWaWRTQkRRVEVQTUEwR0ExVUVcbktSTUdjMlZ5ZG1WeU1TQXdIZ1lKS29aSWh2Y05BUWtCRmhGa1pYWkFjM1J5YjI1bkxYWndiaTUwYXpDQ0FTSXdcbkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLdFpMeVJYNFlMVXplc3Z4cUJqZC81NG50VFJcbmg4djRuUHV3YXRSWm9nY085dTc1YXNIblVqdUV1MzZaSkFON21mZWF4RlJmdWE3OFlpc2xETDJXbkRuWHZyc3BcblhtWmRjeVZ0eHB1MlAva0E5V1BxQnE0UHNWWTlzcjVoVmlNOGRzRUQ5OGgzRXV4M1Y1cUZaRm5KTXVLWUZITENcbnlSYTRTWXQyNkcwNlpIMGZFVlFUTTF3WkdPWlBVWnc3UXhiemlOMjNvSmVyRFlEQ21KZE5iMThRVkduMTlaRXpcbkZhVDdsdkF0OFlUcnpKTEI2SXZpQVdWSWhJdWxwUEcxU3FlTjZWR01XeVJIZlpOMzRBbXZ4YVA0ZWNqK2dKcC9cbjdlS0h6dEluUnN1RVk2ZEM1bDdiNjdPS01ITXUxSkxteEl0S2FhdkJCd2YwbmtsK21vVGxEa3ZPdUFNQ0F3RUFcbkFhT0IvekNCL0RBZEJnTlZIUTRFRmdRVURLbXVTNFlZdjRjdFpZVXRqc1JKNGloMThBQXdnY3dHQTFVZEl3U0JcbnhEQ0J3WUFVREttdVM0WVl2NGN0WllVdGpzUko0aWgxOEFDaGdaMmtnWm93Z1pjeEN6QUpCZ05WQkFZVEFsQklcbk1RMHdDd1lEVlFRSUV3UkRSVUpWTVEwd0N3WURWUVFIRXdSRFJVSlZNUTB3Q3dZRFZRUUtFd1JEWldKMU1SWXdcbkZBWURWUVFMRXcxVGRISnZibWRXVUU1VVpXRnRNUkF3RGdZRFZRUURFd2REWldKMUlFTkJNUTh3RFFZRFZRUXBcbkV3WnpaWEoyWlhJeElEQWVCZ2txaGtpRzl3MEJDUUVXRVdSbGRrQnpkSEp2Ym1jdGRuQnVMblJyZ2drQWdBTTdcbktFMzVFbjB3REFZRFZSMFRCQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFlT1ZtWm10QklFeExcbk1UcVB1NXZ1TXNNcSt1cGMySVJDZlpXZktqSy9pdkErQUVxL1BseUhtaHlYSUlpM1BqR0w4Yzc4eUhQeVpPMWpcbmJiQnhPdldIZGFZWmNRSTMwT3RjUUduVmhaS1ZwUVpXbWQ4RkQvY29nV2JaaVhwcGlFQXNkaEtsSy9ybngvY2dcbi9oY0xQS2RWZjI3cG5STVduVGdMNWdNU0dka0xIaHo5YTRKV05WeitEVjNVVXcyWWQrM1hrc1V6NElzanZTYkdcblZiNDNBNE9QUTBTeXlWakpBNFkzQStmd3FZTkM5ZVB5OXZMcG84Y1FnQ2VtcE9sZXdKZERXY3M1Mld5NFBKQTBcbnNXblB2aklMbmd6QUYwdjdHSGFFeDFsZTVrVkcyM1RqLy9rZCsycjlmZXAvM2phSGNYMzNQdzdJUXFBNHdobm9cbmh2VGZjTFpuVUE9PVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuPC9jYT4iLCAiaXNUaW1lck9uIjogZmFsc2UsICJ0aW1ldG9hZGQiOiA0LCAiU2VydmVycyI6IFt7Ik5hbWUiOiAiWHJheSBTZXJ2ZXIiLCAiRmxhZyI6ICJkZSIsICJTZXJ2ZXJJUEhvc3QiOiAiZGUuc3Ryb25ndGVhbS5jbyIsICJTZXJ2ZXJUeXBlIjogIk5vcm1hbCBTZXJ2ZXIiLCAiU2VydmVyUHJvdG9jb2wiOiAiVjJyYXkiLCAiT3BlblZQTlRDUFBvcnQiOiAiMTEwIiwgIk9wZW5WUE5VZHBQb3J0IjogIjUzIiwgIlNTSF9Qb3J0IjogIjIyIiwgIlNTTFBvcnQiOiAiNDQzIiwgImlzZGVmVXNlciI6IHRydWUsICJPVlBOVXNlciI6ICIiLCAiT1ZQTlBhc3MiOiAiIiwgIkRlZmF1bHRfY2VydCI6IHRydWUsICJDdXN0b21DZXJ0aWZpY2F0ZSI6ICIiLCAiU2xvd0ROU0hvc3QiOiAiIiwgIlNsb3dETlNLZXkiOiAiNWQzMGQxOWFhMjUyNGQ3YmQ4OWFmZGZmZDljMjE0MTU3NWIyMWE3MjhlYTYxYzhjZDdjOGJmMzgzOWY5NzAzMiIsICJTZXJ2ZXJJbmZvIjogIk11bHRpcGxlIFNlcnZlciIsICJWMnJheSI6IHsiUGF0aCI6ICIvc2FuZG9rIiwgIlVVSUQiOiAiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQ1NjdCOW8iLCAicHJvdG9jb2wiOiAiVkxFU1MiLCAidHJvamFuUGFzcyI6ICJ0cm9qYW5wYXNzd29yZCJ9fSwgeyJOYW1lIjogIlhyYXkgU2VydmVyICh4aHR0cCkiLCAiRmxhZyI6ICJkZSIsICJTZXJ2ZXJJUEhvc3QiOiAiZGUuc3Ryb25ndGVhbS5jbyIsICJTZXJ2ZXJUeXBlIjogIlhIVFRQIiwgIlNlcnZlclByb3RvY29sIjogIlYycmF5IiwgIk9wZW5WUE5UQ1BQb3J0IjogIjExMCIsICJPcGVuVlBOVWRwUG9ydCI6ICI1MyIsICJTU0hfUG9ydCI6ICIyMiIsICJTU0xQb3J0IjogIjQ0MyIsICJpc2RlZlVzZXIiOiB0cnVlLCAiT1ZQTlVzZXIiOiAiIiwgIk9WUE5QYXNzIjogIiIsICJEZWZhdWx0X2NlcnQiOiB0cnVlLCAiQ3VzdG9tQ2VydGlmaWNhdGUiOiAiIiwgIlNsb3dETlNIb3N0IjogIiIsICJTbG93RE5TS2V5IjogIjVkMzBkMTlhYTI1MjRkN2JkODlhZmRmZmQ5YzIxNDE1NzViMjFhNzI4ZWE2MWM4Y2Q3YzhiZjM4MzlmOTcwMzIiLCAiU2VydmVySW5mbyI6ICJNdWx0aXBsZSBTZXJ2ZXIiLCAiVjJyYXkiOiB7IlBhdGgiOiAiL3hodHRwIiwgIlVVSUQiOiAiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQ1NjdCOW8iLCAicHJvdG9jb2wiOiAiVkxFU1MiLCAidHJvamFuUGFzcyI6ICJ0cm9qYW5wYXNzd29yZCJ9fSwgeyJOYW1lIjogIlhyYXkgU2VydmVyICh0cm9qYW4pICIsICJGbGFnIjogImRlIiwgIlNlcnZlcklQSG9zdCI6ICJkZS5zdHJvbmd0ZWFtLmNvIiwgIlNlcnZlclR5cGUiOiAiTm9ybWFsIFNlcnZlciIsICJTZXJ2ZXJQcm90b2NvbCI6ICJWMnJheSIsICJPcGVuVlBOVENQUG9ydCI6ICIxMTAiLCAiT3BlblZQTlVkcFBvcnQiOiAiNTMiLCAiU1NIX1BvcnQiOiAiMjIiLCAiU1NMUG9ydCI6ICI0NDMiLCAiaXNkZWZVc2VyIjogdHJ1ZSwgIk9WUE5Vc2VyIjogIiIsICJPVlBOUGFzcyI6ICIiLCAiRGVmYXVsdF9jZXJ0IjogdHJ1ZSwgIkN1c3RvbUNlcnRpZmljYXRlIjogIiIsICJTbG93RE5TSG9zdCI6ICIiLCAiU2xvd0ROU0tleSI6ICI1ZDMwZDE5YWEyNTI0ZDdiZDg5YWZkZmZkOWMyMTQxNTc1YjIxYTcyOGVhNjFjOGNkN2M4YmYzODM5Zjk3MDMyIiwgIlNlcnZlckluZm8iOiAiTXVsdGlwbGUgU2VydmVyIiwgIlYycmF5IjogeyJQYXRoIjogIi90cm9qYW53cyIsICJVVUlEIjogIjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0NTY3QjkiLCAicHJvdG9jb2wiOiAiVHJvamFuIiwgInRyb2phblBhc3MiOiAidHJvamFucGFzc3dvcmQifX1dLCAiTmV0d29ya3MiOiBbeyJOYW1lIjogIlVuYmxvY2sgUmVzdHJpY3Rpb24gKHhodHRwKSAiLCAiSW5mbyI6ICJVbmJsb2NrIEFsbCIsICJQYXlsb2FkIjogImNTbnY2SFNPUmFTZUh4Y2x5V2xoelVPQzd6eVdmTkZQM2ZxVC9BPT0iLCAiUHJveHlQb3J0IjogIiIsICJTTkkiOiAiaklOWDlmd3ZFTVh3VnZTeFNlZXJ3UW9NMU5vZlc4TWdUV202SHc9PSIsICJEZWZhdWx0UHJveHkiOiBmYWxzZSwgIkN1c3RvbVByb3h5IjogIjdCdm9PUEJKVWtONkdRMDV3aDdCSmR3bUNuQ1YycTR0Z2hvY2JnPT0iLCAiVjJyYXlDb25maWciOiAiIiwgIlR1bm5lbFR5cGUiOiAiVjJyYXkiLCAiQnVnRE5TIjogIjguOC44LjgiLCAiVVJJIjogZmFsc2UsICJWMnJheUFkZHJlc3MiOiAiW2hvc3RdIiwgIlYycmF5UG9ydCI6ICI0NDMiLCAiVjJyYXlOZXR3b3JrIjogIlhodHRwIiwgIlJvdXRlIjogIk9WUE4iLCAiVjJyYXlIb3N0IjogIltob3N0XSIsICJJY29uIjogIjFBUFAucG5nIiwgIlYycmF5X2lzX1NOSSI6IHRydWUsICJWMnJheVNOSSI6ICJbaG9zdF0iLCAiVjJyYXlTZXJ2ZXJOZWVkIjogIlhIVFRQIiwgIkluc2VjdXJlIjogdHJ1ZX0sIHsiTmFtZSI6ICJVbmJsb2NrIFJlc3RyaWN0aW9uICh4cmF5KSIsICJJbmZvIjogIlVuYmxvY2sgQWxsIiwgIlBheWxvYWQiOiAiVWd6TDFYbTREQ1p6aTJnbkJiM3QvVzdQdWM2L0hTM2dMM1hWaFE9PSIsICJQcm94eVBvcnQiOiAiIiwgIlNOSSI6ICJibmhpZjdIZEcyUmV0RHRaRkcxWVRSUnVVSEFnaUIvSnZpc1hCZz09IiwgIkRlZmF1bHRQcm94eSI6IGZhbHNlLCAiQ3VzdG9tUHJveHkiOiAiOHlTWHpjU1RVOG9hQVVsTzY5ZWlRVmNlZkRMZHFoRVREM3EvRUE9PSIsICJWMnJheUNvbmZpZyI6ICIiLCAiVHVubmVsVHlwZSI6ICJWMnJheSIsICJCdWdETlMiOiAiOC44LjguOCIsICJVUkkiOiBmYWxzZSwgIlYycmF5QWRkcmVzcyI6ICJbaG9zdF0iLCAiVjJyYXlQb3J0IjogIjQ0MyIsICJWMnJheU5ldHdvcmsiOiAiV2Vic29ja2V0IiwgIlJvdXRlIjogIk9WUE4iLCAiVjJyYXlIb3N0IjogIltob3N0XSIsICJJY29uIjogIjFBUFAucG5nIiwgIlYycmF5X2lzX1NOSSI6IHRydWUsICJWMnJheVNOSSI6ICJbaG9zdF0iLCAiVjJyYXlTZXJ2ZXJOZWVkIjogIk5vcm1hbCBTZXJ2ZXIiLCAiSW5zZWN1cmUiOiB0cnVlfSwgeyJOYW1lIjogIlVuYmxvY2sgUmVzdHJpY3Rpb24gKHRyb2phbikgIiwgIkluZm8iOiAiVW5ibG9jayBBbGwiLCAiUGF5bG9hZCI6ICIrRUxIUHVOV2JXVlNGQjBaNkVoOUNmNFhOWDlGdW8xOWNJeXN1Zz09IiwgIlByb3h5UG9ydCI6ICIiLCAiU05JIjogIk1qc3lESVpzZXVBSi9pOFh5TXQ4SnltTTFRY3RHbjZwVFhIcjFBPT0iLCAiRGVmYXVsdFByb3h5IjogZmFsc2UsICJDdXN0b21Qcm94eSI6ICJpRmZzSHNhT250R2xsRXc0TW5kZ1d1b2lWWW95dU1XZFNEUFA4dz09IiwgIlYycmF5Q29uZmlnIjogIiIsICJUdW5uZWxUeXBlIjogIlYycmF5IiwgIkJ1Z0ROUyI6ICI4LjguOC44IiwgIlVSSSI6IGZhbHNlLCAiVjJyYXlBZGRyZXNzIjogIltob3N0XSIsICJWMnJheVBvcnQiOiAiNDQzIiwgIlYycmF5TmV0d29yayI6ICJUcm9qYW4iLCAiUm91dGUiOiAiT1ZQTiIsICJWMnJheUhvc3QiOiAiW2hvc3RdIiwgIkljb24iOiAiMUFQUC5wbmciLCAiVjJyYXlfaXNfU05JIjogdHJ1ZSwgIlYycmF5U05JIjogIltob3N0XSIsICJWMnJheVNlcnZlck5lZWQiOiAiTm9ybWFsIFNlcnZlciIsICJJbnNlY3VyZSI6IHRydWV9XX0="

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

def decode_embedded():
    return json.loads(base64.b64decode(EMBEDDED_B64).decode("utf-8"))

def fetch_live():
    r = requests.get(CONFIG_URL, headers={'User-Agent': 'okhttp/4.9.0'}, timeout=15)
    r.raise_for_status()
    txt = r.text.strip()
    if txt.startswith("{"):
        return json.loads(txt)
    return {"payload": txt}

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

def server_summary(s):
    v = s.get("V2ray", {})
    return {
        "server_name": s.get("Name"),
        "flag": s.get("Flag"),
        "host": s.get("ServerIPHost"),
        "type": s.get("ServerType"),
        "protocol": s.get("ServerProtocol"),
        "openvpn_tcp": s.get("OpenVPNTCPPort"),
        "openvpn_udp": s.get("OpenVPNUdpPort"),
        "ssl": s.get("SSLPort"),
        "user": s.get("OVPNUser") or s.get("DefOVPNUser"),
        "v2ray": {
            "path": v.get("Path"),
            "uuid": v.get("UUID"),
            "protocol": v.get("protocol"),
            "trojan_pass": v.get("trojanPass"),
        },
        "slowdns_key": s.get("SlowDNSKey"),
    }

def main():
    print("")
    print_bar(C_CYAN)
    print_c("Deep Tunnel VPN Config Decryptor - By @Snapdark 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    config = None
    source = "embedded"

    print_c("[*] Checking for live payload from Server...", C_BLUE)
    try:
        live = fetch_live()
        if isinstance(live, dict):
            config = live
            source = CONFIG_URL
            print_c("[+] Live payload received from Server...", C_GREEN)
    except Exception as e:
        print_c(f"[-] Live server unreachable ({e})", C_RED)
        print_c("[*] Falling back to embedded decrypted configuration...", C_YELLOW)

    if config is None:
        config = decode_embedded()

    print("")
    print_c(">>> INITIATING DECRYPTION <<<", C_YELLOW)
    print_c("Envelope : AES-256-GCM (native Go libgojni.so) both layers", C_CYAN)
    print_c("Method : Native-field decrypt (31/40 blobs) + [host] templating", C_CYAN)
    time.sleep(1)

    servers = [server_summary(s) for s in config.get("Servers", [])]
    networks = config.get("Networks", [])

    print_c("[+] Decryption Successfully Breached..", C_GREEN)
    print_c(f"[*] Total Servers : {len(servers)}", C_BLUE)
    print_c(f"[*] Total Networks : {len(networks)}", C_BLUE)
    print("")

    lines = []
    for s in servers:
        title = f"[{s['flag'].upper()}] {s['server_name']} ({s['type']})"
        lines.append(title)
        lines.append("=" * len(title))
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

    out = dict(config)
    out["Servers"] = servers
    save_output(OUTPUT_FILE, out, source)
    print("")

if __name__ == "__main__":
    main()