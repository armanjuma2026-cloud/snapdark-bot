#!/usr/bin/env python3
# Python By @snapdark_decoder 🇧🇩
# ─────────────────────────────────────────────────────────────────────────────
#  BONDHU VIP (masterbuild / dev.masterbuild.bondhuvip) Config Decryptor
#  House rule: CREDITS first + _source ; JSON-validity gate ; backup-before-replace ;
#  fetch config endpoint only (auth/kill endpoints are code-only, never contacted).
#
#  Chain : HTTP body = CUSTOM-HEX in alphabet "123456abcdefplko" (lsparanoid pool const)
#        -> ASCII b64 text -> AES-256-CBC (key = SHA256( b64("salman@#1&\u00a3")+"\\n"
#        + HEX("963456") + HEX("fferty") + HEX("wsdfgh") ), IV = 0x00*16)
#        [t6/g.java via wrapper I2.b.i]
#  L2 field ladder (I2/b.smali wrappers):
#      j(v2->CloudAlgo) : b64 -> AES-256-CBC(SHA256("abab1212"+SALT), IV 4259af51ffbd026862ceda1100e94401)
#                         -> b64 -> AES-256-CBC(SHA256("v2crypt"), IV 0)            [Payload/Config]
#      s(XrayHost)      : j-input x : b64 -> AES-256-CBC(SHA256("cloudcorepass"), IV "encryptionIntVec")
#                         -> hex-decode -> AES-256-CBC(SHA256(HEX("mastercryptpassword2password3")),"IV 0123456789012345")
#      t(XrayID)        : x -> b64 -> AES-128-ECB(SHA1("pass1pass2pass3")[:16])
#      x                : b64 -> AES-256-CBC(SHA256("cloudcorepass"), IV "encryptionIntVec")
#      i(fields)        : same salman chain (Squid / SNIHost inner blobs)
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import json
import time
import shutil
import base64
import hashlib
import subprocess

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa
    except ImportError:
        missing.append("cryptography")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required modules {missing} not found. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    import requests
    return requests

requests = check_dependencies()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

C_RED = '\033[91m'; C_GREEN = '\033[92m'; C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'; C_CYAN = '\033[96m'; C_RESET = '\033[0m'

URL = "https://mkvpn.xyz/api/app?json=e116335ac2d7a0126e66"
UA = "okhttp/4.9.0"
OUTPUT_FILE = "/sdcard/VPNs/BONDHU VIP ☠️.json"
OUTPUT_TEXT = "/sdcard/VPNs/BONDHU VIP ☠️.txt"
CACHE_FILE = "/sdcard/VPNs/.bondhu_payload_cache.hex"

# ---- BONDHU VIP key material (lsparanoid pool, Deobfuscator$BONDHUVIP$app) ----
ALPHA = "123456abcdefplko"
IDX = {c: n for n, c in enumerate(ALPHA)}
SALT = "d68a1c8a0a8b8710f7c771065165867fc8e73b50ee6809a7e9f53873b38e3e0d"
IV_V = bytes.fromhex("4259af51ffbd026862ceda1100e94401")
KM_SALMAN = (base64.b64encode("salman@#1&\u00a3".encode("utf-8")) + b"\n"
             + "963456".encode().hex().upper().encode()
             + "fferty".encode().hex().upper().encode()
             + "wsdfgh".encode().hex().upper().encode())
KEY_SALMAN = hashlib.sha256(KM_SALMAN).digest()          # t6.g.a (I2.b.i)
KEY_ABAB   = hashlib.sha256(("abab1212" + SALT).encode()).digest()   # l6.c (I2.b.v)
KEY_V2     = hashlib.sha256(b"v2crypt").digest()          # CloudAlgo l6.d (I2.b.j)
KEY_CLOUD  = hashlib.sha256(b"cloudcorepass").digest()   # I2.b.x
KEY_MC  = hashlib.sha256("mastercryptpassword2password3".encode().hex().upper().encode()).digest()  # I2.b.s
KEY_P123   = hashlib.sha1(b"pass1pass2pass3").digest()[:16]           # I2.b.t (AES-128-ECB)
IV_MC = b"0123456789012345"
IV_XC = b"encryptionIntVec"


def _d(KEY, iv, data):
    d = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def _de(KEY, iv, data):
    return _un(_d(KEY, iv, data)).decode("utf-8", "replace")


def _un(pt):
    u = PKCS7(128).unpadder()
    return u.update(pt) + u.finalize()


def _b64(s):
    if isinstance(s, str):
        s = s.replace("\n", "").strip().encode()
    return base64.b64decode(s + b"=" * (-len(s) % 4))


def wrap_i(hexstr):
    """I2.b.i -> t6.g.a: custom-hex -> ASCII b64 -> AES-256-CBC(salman km). zero IV."""
    raw = bytes((IDX[hexstr[i]] * 16 + IDX[hexstr[i + 1]]) for i in range(0, len(hexstr) - 1, 2))
    return _de(KEY_SALMAN, b"\x00" * 16, _b64(raw.decode()))


def wrap_v(ct):
    """I2.b.v -> l6.c: b64 -> AES-256-CBC(abab1212+salt, IV 4259...)."""
    return _de(KEY_ABAB, IV_V, _b64(ct))


def wrap_j(ct):
    """I2.b.j -> v -> CloudAlgo(v2crypt, IV 0).  Returns '' like the app on failure."""
    try:
        return _de(KEY_V2, b"\x00" * 16, _b64(wrap_v(ct)))
    except Exception:
        return ""


def wrap_x(ct):
    """I2.b.x: b64 -> AES-256-CBC(cloudcorepass, IV 'encryptionIntVec')."""
    return _de(KEY_CLOUD, IV_XC, _b64(ct))


def wrap_s(ct):
    """I2.b.s: x -> hex-decode -> AES-256-CBC(mastercrypt-hex key, IV '0123456789012345')."""
    return _de(KEY_MC, IV_MC, bytes.fromhex(wrap_x(ct)))


def wrap_t(ct):
    """I2.b.t: x -> b64 -> AES-128-ECB(pass1pass2pass3 sha1(:16))."""
    d = Cipher(algorithms.AES(KEY_P123), modes.ECB()).decryptor()
    return _un(d.update(_b64(wrap_x(ct)))).decode("utf-8", "replace")


def clean_payload(pttext):
    """Server-side payload blobs carry a 21-byte head the app itself receives
    (transmitted-IV slot + 5 junk bytes): cut at the first printable run."""
    b = pttext.encode("utf-8", "surrogatepass")
    run = 0; start = 0
    for n_, c in enumerate(b):
        if 32 <= c < 127:
            if run == 0:
                start = n_
            run += 1
            if run >= 12:
                break
        else:
            run = 0
    if start >= 12:
        return b[start:].decode("utf-8", "replace")
    return pttext


def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")


def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}{C_RESET}")


def fetch_payload():
    """Live fetch; falls back to the last cached raw payload on failure."""
    try:
        r = requests.get(URL, headers={'User-Agent': UA}, timeout=30)
        r.raise_for_status()
        with open(CACHE_FILE, "w") as f:
            f.write(r.text)
        return r.text.strip(), "live"
    except Exception as e:
        print_c(f"[-] Live fetch failed ({e})", C_YELLOW)
        print_c("[*] Falling back to cached payload...", C_BLUE)
        with open(CACHE_FILE) as f:
            return f.read().strip(), "cache"


def main():
    t_start = time.monotonic()
    print("")
    print_bar(C_CYAN)
    print_c("BONDHU VIP Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    body_hex, source = fetch_payload()
    print_c(f"[+] Encrypted payload ready ({len(body_hex)} chars, source={source})...", C_GREEN)

    print("")
    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : custom-hex (123456abcdefplko) -> b64 -> AES-256-CBC", C_CYAN)
    print_c("            key = SHA256(b64('salman@#1&£')+'\\n'+HEX('963456',fferty,wsdfgh)) IV 0", C_CYAN)

    try:
        cfg = json.loads(wrap_i(body_hex))
    except Exception as e:
        print_c(f"[-] Layer 1 failure: body is not JSON ({e})", C_RED)
        return
    n_srv = len(cfg.get("Servers", []))
    n_net = len(cfg.get("Networks", []))
    n_ssl = len(cfg.get("SSLNetworks", []))
    print_c(f"[+] Layer 1 breached : JSON body ({len(json.dumps(cfg))} B), {n_srv} servers, {n_net} networks", C_GREEN)

    print("")
    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : wrapper ladder i / j / s / t / x (see header)", C_CYAN)
    print_c(f"Scope     : Networks ({n_net}) inner fields + ProxySettings.Squid + SNIHost", C_CYAN)

    out_nets = []
    for n in cfg.get("Networks", []):
        no = {k: n.get(k) for k in ("Name", "NetworkIcon", "SNIHost", "V2ray_Mode", "Xray_Secure", "Info",
              "UDPMode", "isCustomConfig", "Protocol", "TunnelType", "FrontQuery", "BackQuery",
              "Priority", "ServerHostDNS", "V2rayMode")}
        for fld, fn in (("Payload", wrap_j), ("XrayHost", wrap_s), ("SNIHost", wrap_i)):
            v = n.get(fld, "")
            if not v:
                continue
            try:
                dec = fn(v)
                if fld == "Payload":
                    if dec:
                        no[fld] = clean_payload(dec)
                    else:
                        no[fld] = None   # in-app the wrapper also fails on this blob
                else:
                    no[fld] = dec
            except Exception:
                pass
        ps = n.get("ProxySettings")
        if isinstance(ps, dict) and ps.get("Squid"):
            try:
                no["ProxySettings"] = {"Squid": wrap_i(ps["Squid"]), "Port": ps.get("Port", "")}
            except Exception:
                pass
        out_nets.append(no)

    out_srvs = []
    for s in cfg.get("Servers", []):
        out_srvs.append({k: s.get(k) for k in ("Name", "Info", "Flag", "Protocol", "ServerIPHost",
             "ServerCloudFrontHost", "ServerHTTPHost", "Server_Xray_Secure", "Server_V2ray_Mode",
             "CustomOVPNCert", "UseDefaultServers", "ServerEntry", "Nameserver", "PublicKey",
             "Username", "Password", "Category", "ServerPort", "SSLPort", "DropbearPort")})

    print_c("[+] Layer 2 Successfully Breached..", C_GREEN)

    # ---- JSON-validity gate ----
    try:
        final = json.loads(json.dumps({
            "CREDITS": "Decrypted By @snapdark_decoder 🇧🇩",
            "TELEGRAM": "https://t.me/bd_loser",
            "CHANNEL": "https://t.me/+GEautSR2nNphZWJl",
            "NOTE": "Free Config - Do not sell",
            "_source": source,
            "Version": cfg.get("Version"),
            "Date": cfg.get("Date"),
            "Notice": cfg.get("Notice"),
            "AccountApi_CODE_ONLY": cfg.get("AccountApi"),
            "_notes": ("Server Config/XrayID blobs are placeholder-empty (server j/ECB decrypt "
                       "yields ''); network Payload blobs carry a 21-byte head "
                       "(16B IV slot + 5B junk) - readable body cut automatically; "
                       "Account endpoint is CODE-ONLY, never contacted."),
            "Servers": out_srvs,
            "Networks": out_nets,
        }, ensure_ascii=False))
        if not final.get("Networks"):
            raise ValueError("no networks decrypted")
    except Exception as e:
        print_bar("!")
        print_c(f"FATAL: output JSON invalid: {e!r}", C_RED)
        sys.exit(5)

    # ---- backup-before-replace ----
    if os.path.exists(OUTPUT_FILE):
        bak = OUTPUT_FILE + ".bak-" + time.strftime("%Y%m%d_%H%M%S")
        shutil.copy2(OUTPUT_FILE, bak)
        print_c(f"[*] existing output backed up -> {bak}", C_YELLOW)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=1)
    try:
        os.chmod(OUTPUT_FILE, 0o600)
    except OSError:
        pass
    print_c(f"[★] Saved Decrypted Configuration to: {OUTPUT_FILE}", C_GREEN)

    # ---- readable .txt ----
    lines = ["════ BONDHU VIP ☠️ — @SnapDark 🇧🇩 ════",
             f"version v{final.get('Version', 'N/A')} | servers {n_srv} | networks {n_net} | ssl {n_ssl}",
             f"date : {final.get('Date', 'N/A')}",
             ""]
    lines.append("──── SERVERS ────")
    for i, s in enumerate(final.get("Servers", []), 1):
        lines.append("%02d. %-30s proto=%s [%s]" % (i, s.get("Name", "?"), s.get("Protocol", "-"), s.get("Category", "-")))
        lines.append("    host : %s | ports tcp=%s ssl=%s dropbear=%s" % (
            s.get("ServerIPHost", "-"), s.get("ServerPort", "-"),
            s.get("SSLPort", "-"), s.get("DropbearPort", "-")))
    lines.append("")
    lines.append("──── NETWORKS ────")
    for i, t in enumerate(final.get("Networks", []), 1):
        lines.append("%02d. %s  [mode %s | tunnel %s | proto %s]" % (
            i, t.get("Name", "?"), t.get("V2rayMode", "-"), t.get("TunnelType", "-"), t.get("Protocol", "-")))
        if t.get("Info"):
            lines.append("    info   : %s" % t["Info"])
        if t.get("XrayHost"):
            lines.append("    xhost  : %s" % t["XrayHost"])
        if t.get("SNIHost"):
            lines.append("    sni    : %s" % t["SNIHost"])
        if t.get("ProxySettings"):
            lines.append("    proxy  : %s:%s" % (t["ProxySettings"].get("Squid", "[Default]"), t["ProxySettings"].get("Port", "-")))
        if t.get("Payload"):
            lines.append("    payload: %s" % t["Payload"])
        lines.append("")
    if final.get("Notice"):
        lines.append("──── NOTICE ────")
        lines.append(str(final["Notice"]))
    lines.append("")
    lines.append("account api (code-only, never contacted) : %s" % final.get("AccountApi_CODE_ONLY", "-"))
    with open(OUTPUT_TEXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print_c(f"[★] Saved readable summary to: {OUTPUT_TEXT}", C_GREEN)

    secs = round(time.monotonic() - t_start, 1)
    print("")
    print_c(f"Done in {secs}s", C_GREEN)
    print("")


if __name__ == "__main__":
    main()
