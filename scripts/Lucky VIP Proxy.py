#!/usr/bin/env python3
# Python By @snapdark_decoder 🇧🇩
# ─────────────────────────────────────────────────────────────────────────────
#  Lucky VIP Proxy (dev.lucky.vipproxy / sa-sandok family) Cloud Config
#  Decryptor  v1.10.11.1 (versionCode 53)
#  House rule: CREDITS first + _source ; JSON-validity gate ; backup-before-replace ;
#  cache fallback ; fetch config endpoint only (auth/updater endpoints code-only).
#
#  Source : POST https://strongteam.co/api/luckyvip/
#           body: hash=xsandokUpdatex  (content-type application/x-www-form-urlencoded)
#           -> AndroidLibXrayLite.CU() inside libgojni.so  (builds url.Values{"hash":
#              "xsandokUpdatex"}, http.NewRequestWithContext POST, Client.do)
#           No GET suffix file exists for this build (family .txt pattern NOT used).
#
#  ENVELOPE (live server reply)                       [AndroidLibXrayLite.decrypt @0x1012360]
#      INPUT (b64 text) -> base64 DecodeString
#      -> blob : salt[16] | nonce[12] | ct | tag[16]   (min raw len 28 checked natively)
#      -> ARGON2ID deriveKey(mode=2) : salt=blob[:16], t=3, m=8192 KiB, p=1, keylen=32, v=19
#         password (rodata @0x35ecb0, 28 B) = "LuckyVIPProxyP@ssword2026!II"
#      -> AES-256-GCM Open(nonce=blob[16:28], ct=blob[28:], aad=blob[:16])
#
#  EMBEDDED FALLBACK (assets/configfile.json in APK, JSON v3.94)
#                                                        [AndroidLibXrayLite.DO @0x1012c90]
#      same chain but password (rodata @0x35b53b, 26 B) = "LuckyVIPProxyP@ssword2026!"
#
#  FIELDS (every per-field blob: Servers + Networks)  [Hometab.Companion.a -> Libv2ray.do_]
#      same as DO path: argon2id(26 B password, per-blob salt) + AES-256-GCM, aad=salt
#      44-byte blobs (salt+nonce+empty tag) are empty placeholders -> decrypt to ""
#
#  libgojni.so sha16 3d994273f2e154c6  ·  pclntab f1ffffff  ·  TEXT base 0x523450
# ─────────────────────────────────────────────────────────────────────────────
import os
import io
import re
import sys
import json
import time
import shutil
import base64
import zipfile
import subprocess

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # noqa
    except ImportError:
        missing.append("cryptography")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required modules {missing} not found. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    import requests
    return requests

requests = check_dependencies()
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- argon2 resolver: prefer argon2-cffi bindings, else cryptography rust Argon2id ----
try:
    from argon2.low_level import hash_secret_raw, Type as ArgonType
    _ARGON_BACKEND = "argon2-cffi"
except ImportError:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:
        Argon2id = None

    class ArgonType:
        ID = "argon2id"
        I = "argon2i"
        D = "argon2d"

    def hash_secret_raw(secret, salt, time_cost, memory_cost, parallelism, hash_len,
                        type=ArgonType.ID, version=19):
        if Argon2id is None:
            raise RuntimeError("no argon2 backend available")
        if type != ArgonType.ID or version != 19 or parallelism != 1:
            raise ValueError("unsupported argon2 params (family requires Argon2id v19 p=1)")
        return Argon2id(salt=bytes(salt), length=hash_len, iterations=time_cost,
                        lanes=parallelism, memory_cost=memory_cost).derive(bytes(secret))
    _ARGON_BACKEND = "cryptography(rust)"

C_RED = '\033[91m'; C_GREEN = '\033[92m'; C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'; C_CYAN = '\033[96m'; C_RESET = '\033[0m'

URL = "https://strongteam.co/api/luckyvip/"
POST_BODY = "hash=xsandokUpdatex"          # AndroidLibXrayLite.CU form secret (x…x sentinels)
APK_PATH = "/storage/emulated/0/MT2/apks/Lucky VIP Proxy_v1.10.11.1.apks"
EMBEDDED_ASSET = "assets/configfile.json"
OUTPUT_FILE = "/sdcard/VPNs/Lucky VIP Proxy ☠️.json"
OUTPUT_TEXT = "/sdcard/VPNs/Lucky VIP Proxy ☠️.txt"
CACHE_FILE = "/sdcard/VPNs/.lucky_cloud_cache.b64"

PW_FIELD = "LuckyVIPProxyP@ssword2026!"      # 26 B @0x35b53b : DO (embedded + all fields)
PW_LIVE  = "LuckyVIPProxyP@ssword2026!II"   # 28 B @0x35ecb0 : decrypt (live envelope)

_B64_RE = re.compile(r'^[A-Za-z0-9+/]{44,}={0,2}$')
_KEY_CACHE = {}


def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")


def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}{C_RESET}")


def b64d(s):
    if isinstance(s, str):
        s = re.sub(r"\s", "", s).encode()
    return base64.b64decode(s + b"=" * (-len(s) % 4))


def sa_argon_key(pw_b, salt):
    return hash_secret_raw(secret=pw_b, salt=salt, time_cost=3, memory_cost=8192,
                           parallelism=1, hash_len=32, type=ArgonType.ID, version=19)


def _key_for(pw_b, salt):
    """argon2id key cache ; parallel derivation is pre-warmed for bulk fields."""
    bucket = _KEY_CACHE.setdefault(pw_b, {})
    if salt not in bucket:
        bucket[salt] = sa_argon_key(pw_b, salt)
    return bucket[salt]


def _pw_keys(order):
    return [(PW_FIELD if k == 0 else PW_LIVE).encode() for k in order]


def sa_decrypt_blob(blob, key_order=(0, 1)):
    """Envelope Open: salt16 | nonce12 | ct | tag16, aad = salt (SA-sandok recipe)."""
    if len(blob) < 44:
        raise ValueError("blob too short")
    last = None
    for pw_b in _pw_keys(key_order):
        try:
            cipher = AESGCM(_key_for(pw_b, blob[:16]))
            return cipher.decrypt(blob[16:28], blob[28:], blob[:16])
        except Exception as e:
            last = e
    raise last


# ------------------------------------------------------------ pre-warm pool ---
def _pool_boost(salts, pw_b):
    """Bulk-derive argon2 keys for a whole pw attempt across all CPUs.

    Uses multiprocessing when >1 core ; falls back silently to sequential."""
    bucket = _KEY_CACHE.setdefault(pw_b, {})
    todo = [s for s in salts if s not in bucket]
    if not todo:
        return 0
    cores = max(1, (os.cpu_count() or 1))
    if cores > 1 and len(todo) > 64:
        try:
            import multiprocessing as mp
            def _work(s):
                return s, sa_argon_key(pw_b, s)
            done = 0
            with mp.Pool(min(cores, 4)) as pool:
                for s, k in pool.imap_unordered(_work, todo, chunksize=8):
                    bucket[s] = k
                    done += 1
                    if done % 256 == 0 or done == len(todo):
                        pct = done * 100 // len(todo)
                        bar = '#' * (pct // 5)
                        print(f"\r\033[96m    argon2id {pct}% ({done}/{len(todo)}) {bar}\033[0m",
                              end='', flush=True)
            print("")
            return done
        except Exception:
            pass
    for i, s in enumerate(todo, 1):
        bucket[s] = sa_argon_key(pw_b, s)
        if i % 64 == 0 or i == len(todo):
            pct = i * 100 // len(todo)
            print(f"\r\033[96m    argon2id {pct}% ({i}/{len(todo)})\033[0m", end='', flush=True)
    print("")
    return len(todo)


# ------------------------------------------------------------ embedded asset ---
def read_embedded_blob():
    """Extract assets/configfile.json (b64) from the Lucky VIP Proxy apk(.apks)."""
    z = zipfile.ZipFile(APK_PATH)
    names = z.namelist()
    inner = z
    if "base.apk" in names:
        inner = zipfile.ZipFile(io.BytesIO(z.read("base.apk")))
        names = inner.namelist()
    if EMBEDDED_ASSET in names:
        return b64d(inner.read(EMBEDDED_ASSET).decode().strip())
    raise FileNotFoundError(f"{EMBEDDED_ASSET} not found in APK")


# ------------------------------------------------------------ recursive fields ---
def collect_salts(node, out):
    if isinstance(node, dict):
        for v in node.values():
            _c(v, out)
    elif isinstance(node, list):
        for x in node:
            _c(x, out)
    return out


def _c(v, out):
    if isinstance(v, dict):
        for x in v.values():
            _c(x, out)
    elif isinstance(v, list):
        for x in v:
            _c(x, out)
    elif isinstance(v, str) and len(v) >= 60 and _B64_RE.match(v):
        try:
            b = b64d(v)
        except Exception:
            return
        if len(b) >= 44:
            out.add(b[:16])


def decrypt_field(b64val):
    """Per-field DO blob: pw FIELD first (all field blobs), LIVE as fallback."""
    try:
        raw = b64d(b64val)
    except Exception:
        return None
    if len(raw) < 44:
        return None
    for pw_b in _pw_keys((0, 1)):
        try:
            cipher = AESGCM(_key_for(pw_b, raw[:16]))
            pt = cipher.decrypt(raw[16:28], raw[28:], raw[:16])
            return pt.decode('utf-8', errors='strict')
        except Exception:
            continue
    return None


def recursive_l2(node, count=[0]):
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str) and _B64_RE.match(v) and len(v) >= 44:
                d = decrypt_field(v)
                if d is not None:
                    node[k] = d
                    count[0] += 1
            elif isinstance(v, (dict, list)):
                recursive_l2(v, count)
    elif isinstance(node, list):
        for x in node:
            recursive_l2(x, count)
    return count[0]


# ------------------------------------------------------------ fetch ---
def fetch_payload():
    """Live POST (exactly what AndroidLibXrayLite.CU sends); cache + embedded fallbacks."""
    try:
        r = requests.post(URL, data=POST_BODY,
                          headers={'Content-Type': 'application/x-www-form-urlencoded',
                                   'User-Agent': 'Go-http-client/1.1'},
                          timeout=30)
        r.raise_for_status()
        txt = r.text.strip()
        b = b64d(txt)                                  # sanity: must be a b64 blob
        if len(b) < 28:
            raise ValueError(f"live body too small ({len(b)} B)")
        try:
            with open(CACHE_FILE, "w") as f:
                f.write(txt)
        except OSError:
            pass
        return txt, "live"
    except Exception as e:
        print_c(f"[-] Live POST failed ({e})", C_YELLOW)
        try:
            with open(CACHE_FILE) as f:
                txt = f.read().strip()
            print_c("[*] Falling back to cached cloud payload...", C_BLUE)
            return txt, "cache"
        except OSError:
            pass
        try:
            blob = read_embedded_blob()
            print_c("[*] Falling back to embedded assets/configfile.json...", C_BLUE)
            return blob, "embedded"
        except Exception as e2:
            print_c(f"[-] Embedded read failure: {e2}", C_RED)
            return None, None


def main():
    global _ARGON_BACKEND
    t_start = time.monotonic()
    print("")
    print_bar(C_CYAN)
    print_c("Lucky VIP Proxy Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    print_c(f"[+] argon2 backend: {_ARGON_BACKEND} (Argon2id t=3 m=8192 p=1 v19)", C_BLUE)

    body, source = fetch_payload()
    if body is None:
        return
    print_c(f"[+] Encrypted payload ready ({len(body)} chars, source={source})...", C_GREEN)
    print("")
    print_c(">>> INITIATING LAYER 1 DECRYPTION (envelope) <<<", C_YELLOW)
    if source == "embedded":
        print_c("Algorithm : argon2id(26 B pw @0x35b53b) + AES-256-GCM aad=salt   [DO path]", C_CYAN)
        key_order = (0, 1)
    else:
        print_c("Algorithm : argon2id(28 B pw @0x35ecb0) + AES-256-GCM aad=salt [CU/decrypt]", C_CYAN)
        key_order = (1, 0)
    try:
        json_str = sa_decrypt_blob(b64d(body), key_order=key_order)
        parsed = json.loads(json_str)
    except Exception as e:
        print_c(f"[-] Envelope breach failure: {e}", C_RED)
        return
    n_srv = len(parsed.get('Servers', []))
    n_net = len(parsed.get('Networks', []))
    print_c(f"[+] Envelope breached : JSON ({len(json_str)} B) "
            f"v{parsed.get('Version')} | {n_srv} servers | {n_net} networks", C_GREEN)
    print_c(f"[*] Notes : {str(parsed.get('ReleaseNotes', '-'))[:80]!r}", C_BLUE)
    print("")

    print_c(">>> INITIATING LAYER 2 DECRYPTION (per-field blobs) <<<", C_YELLOW)
    print_c("Algorithm : argon2id(26 B pw, per-blob salt) + AES-256-GCM aad=salt  [DO]", C_CYAN)
    print_c("Scope     : Servers + Networks (hosts, credentials, SNI, Payload, V2ray*, ...)", C_CYAN)

    salts = collect_salts(parsed, set())
    n_der = sum(1 for _ in salts)
    print_c(f"[*] Pre-warming argon2id key schedule for {n_der} unique salts...", C_BLUE)
    _pool_boost(salts, PW_FIELD.encode())

    n2 = recursive_l2(parsed)
    print_c(f"[+] Layer 2 complete : {n2} fields decrypted (incl. empty placeholders)", C_GREEN)

    # ---- JSON-validity gate ----
    try:
        if source == "embedded":
            src = f"{APK_PATH}#{EMBEDDED_ASSET}"
        elif source == "cache":
            src = URL + " (cache fallback)"
        else:
            src = URL
        final = json.loads(json.dumps({
            "CREDITS": "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro",
            "_source": src,
            "_fetch": source,
            "Version": parsed.get("Version"),
            "ReleaseNotes": parsed.get("ReleaseNotes"),
            "DefOVPNUser": parsed.get("DefOVPNUser"),
            "DefOVPNPass": parsed.get("DefOVPNPass"),
            "HysteriaUser": parsed.get("HysteriaUser"),
            "HysteriaOBFS": parsed.get("HysteriaOBFS"),
            "DefaultOVPNCert": parsed.get("DefaultOVPNCert"),
            "isTimerOn": parsed.get("isTimerOn"),
            "timetoadd": parsed.get("timetoadd"),
            "_notes": ("Envelope(live) = b64 -> argon2id(28B pw, salt=blob[:16], t=3, "
                       "m=8192, p=1, v19) -> AES-256-GCM open(nonce=blob[16:28], "
                       "aad=blob[:16]); envelope(embedded v3.94) and ALL per-field blobs "
                       "use the 26B password instead (DO path). Updater/auth endpoints "
                       "are CODE-ONLY, never contacted."),
            "Servers": parsed.get("Servers", []),
            "Networks": parsed.get("Networks", []),
        }, ensure_ascii=False))
        if not final.get("Servers") or not final.get("Networks"):
            raise ValueError("no servers/networks decrypted")
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
    lines = ["════ Lucky VIP Proxy ☠️ — @SnapDark 🇧🇩 ════",
             f"version v{final.get('Version', 'N/A')} | servers {n_srv} | networks {n_net}",
             f"notes : {str(final.get('ReleaseNotes', '-'))[:100]}",
             ""]
    lines.append("──── SERVERS ────")
    for i, s in enumerate(final.get("Servers", []), 1):
        lines.append("%02d. %-34s [%s] proto=%s | type=%s" % (
            i, str(s.get("Name", "?")), s.get("Flag", "-"),
            s.get("ServerProtocol", "-"), s.get("ServerType", "-")))
        lines.append("    host : %s | tcp=%s udp=%s ssh=%s ssl=%s" % (
            s.get("ServerIPHost", "-"), s.get("OpenVPNTCPPort", "-"),
            s.get("OpenVPNUdpPort", "-"), s.get("SSH_Port", "-"), s.get("SSLPort", "-")))
        if s.get("OVPNUser") or s.get("OVPNPass"):
            lines.append("    ovpn : %s / %s" % (s.get("OVPNUser", "-"), s.get("OVPNPass", "-")))
        if s.get("V2rayUUID"):
            lines.append("    uuid : %s | v2host %s" % (s.get("V2rayUUID", "-"), s.get("V2rayPath", "-")))
        if s.get("SlowDNSHost"):
            lines.append("    sdns : %s | %s" % (s.get("SlowDNSHost", "-"), s.get("SlowDNSKey", "-")))
    lines.append("")
    lines.append("──── NETWORKS ────")
    for i, t in enumerate(final.get("Networks", []), 1):
        lines.append("%02d. %s  [tunnel %s | route %s]" % (
            i, str(t.get("Name", "?")), t.get("TunnelType", "-"), t.get("Route", "-")))
        if t.get("Info"):
            lines.append("    info : %s" % t["Info"])
        if t.get("SNI"):
            lines.append("    sni  : %s" % str(t["SNI"])[:120])
        if t.get("Payload"):
            lines.append("    payl : %s" % str(t["Payload"])[:120])
        if t.get("V2rayHost"):
            lines.append("    v2h  : %s | %s:%s" % (
                str(t.get("V2rayHost", "-"))[:100], t.get("V2rayAddress", "-"),
                t.get("V2rayPort", "-")))
        if t.get("BugDNS"):
            lines.append("    dns  : %s" % t["BugDNS"])
        lines.append("")
    lines.append("connections : telegram %s | whatsapp %s" % (
        parsed.get("Telegram", "-"), parsed.get("WhatsApp", "-")))
    lines.append("")
    with open(OUTPUT_TEXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print_c(f"[★] Saved readable summary to: {OUTPUT_TEXT}", C_GREEN)

    if os.path.exists(CACHE_FILE):
        print_c(f"[*] Cloud payload cached -> {CACHE_FILE}", C_BLUE)

    secs = round(time.monotonic() - t_start, 1)
    print("")
    print_c(f"Done in {secs}s", C_GREEN)
    print("")


if __name__ == "__main__":
    main()
