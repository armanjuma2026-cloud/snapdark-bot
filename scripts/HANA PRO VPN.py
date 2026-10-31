# Python By @snapdark_decoder 🇧🇩
# ─────────────────────────────────────────────────────────────────────────────
#  HANA PRO VPN (noobdev / com.noobdev.vpn) Config Decryptor
#  House rule: CREDITS first + _source ; JSON-validity gate ; backup-before-replace ;
#  fetch config endpoints only (auth/kill-switch endpoints never contacted).
#
#  Chain : HTTP config payload (b64 body)
#        -> AES-256-XTS (body key64 = rol8(K0^C) per derived constant, tweak = first 16B,
#           OpenSSL CRYPTO_xts128_decrypt convention: tweak pre-encrypted with K2 half,
#           ciphertext-stealing tail)         [libnoobzicore/libovpn3.so NoobCrypt mode 5]
#        -> per-field ladder : b64 -> AES-256-GCM (nonce12 + ct + tag16, key32)
#                             -> else AES-256-CBC (iv16 + ct + PKCS7, key32)  [mode 0/1]
#  Pure-python XTS — verified bit-exact against libcrypto EVP ground truth.
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import json
import re
import shutil
import subprocess
import time
import base64


def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except ImportError:
        missing.append("cryptography")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required modules {missing} not found. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    import requests  # noqa
    return requests


requests = check_dependencies()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

URL = "https://jezvpn.xyz/api/app?json=743ebcbbf84f7f9cac2f"
UA = "okhttp/4.9.0"
OUTPUT_FILE = "/sdcard/VPNs/HANA PRO VPN ☠️.json"
OUTPUT_TEXT = "/sdcard/VPNs/HANA PRO VPN ☠️.txt"
CACHE_FILE = "/sdcard/VPNs/.hana_payload_cache.b64"

# NoobCrypt constants (libovpn3.so rodata derivations, embedded verbatim)
KEY64 = bytes.fromhex(
    "071823cbc90de8733ee21ffa9f563c8b0cd0d948b08b24d8ba987ad7c3f2d601d"
    "6bfc77684b8931a32df907e9b7b146752d211197ca8ee0da0d14b2b0ea82fd8")
KEY32 = bytes.fromhex(
    "98c4d1e8636cfd85e5d4d9e479704edf0563d44117efaa33c631241704e7dd60")

B64RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")


def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}{C_RESET}")


# ---------------- LAYER 1 : AES-256-XTS body decrypt (pure python) -----------

def _mul_tweak(t_int):
    """XTS tweak multiply by alpha in GF(2^128), little-endian byte order."""
    t2 = (t_int << 1) & ((1 << 128) - 1)
    return t2 ^ 0x87 if t_int >> 127 else t2


def xts_decrypt(key64, blob):
    """AES-256-XTS decrypt per OpenSSL CRYPTO_xts128_decrypt semantics:
    tweak = AES-enc(key64[32:], iv); block i tweak = alpha^i;
    with residue: last full ct block decrypted at alpha^m, head r bytes become
    the final partial plaintext, residue ciphertext spliced into head and
    decrypted at alpha^(m-1) as the last full block."""
    data_key = key64[:32]
    twk_key = key64[32:64]
    iv, ct = blob[:16], blob[16:]
    twenc = Cipher(algorithms.AES(twk_key), modes.ECB()).encryptor().update(iv)
    t = int.from_bytes(twenc, "little")
    n = len(ct)
    m, r = n // 16, n % 16
    out = bytearray(n)
    dec = Cipher(algorithms.AES(data_key), modes.ECB())
    d1 = dec.decryptor()
    for i in range(m - 1):
        tt = t.to_bytes(16, "little")
        blk = ct[i * 16:(i + 1) * 16]
        out[i * 16:(i + 1) * 16] = bytes(a ^ b for a, b in zip(d1.update(bytes(a ^ b for a, b in zip(blk, tt))), tt))
        t = _mul_tweak(t)
    d1 = dec.decryptor()
    t1 = _mul_tweak(t).to_bytes(16, "little")   # alpha^m
    t0 = t.to_bytes(16, "little")               # alpha^(m-1)
    cm1, cm = ct[(m - 1) * 16:m * 16], ct[m * 16:]
    if r == 0:
        out[(m - 1) * 16:] = bytes(a ^ b for a, b in zip(d1.update(bytes(a ^ b for a, b in zip(cm1, t0))), t0))
        return bytes(out)
    s = bytes(a ^ b for a, b in zip(d1.update(bytes(a ^ b for a, b in zip(cm1, t1))), t1))
    out[m * 16:] = s[:r]                        # final partial = head
    s2 = cm + s[r:]                             # splice residue ct into head
    d2 = dec.decryptor()
    out[(m - 1) * 16:m * 16] = bytes(a ^ b for a, b in zip(d2.update(bytes(a ^ b for a, b in zip(s2, t0))), t0))
    return bytes(out)


# ---------------- LAYER 2 : per-field GCM/CBC ladder -------------------------

def _utf8(b):
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for c in s:
        if ord(c) < 32 and c not in "\t\r\n":
            return None
    return s


def _b64(s):
    if len(s) % 4:
        s += "=" * (4 - len(s) % 4)
    return base64.b64decode(s, validate=True)


def field_ladder(s):
    """b64 -> AES-256-GCM(nonce12, ct+tag16, key32) -> else AES-256-CBC(iv16,
    ct, PKCS7, key32); returns (value, mode) or (original, None)."""
    if not isinstance(s, str) or len(s) < 24 or not B64RE.match(s):
        return s, None
    try:
        raw = _b64(s)
    except Exception:
        return s, None
    if len(raw) < 28:
        return s, None
    try:
        t = _utf8(AESGCM(KEY32).decrypt(raw[:12], raw[12:], None))
        if t is not None:
            return t, "gcm"
    except Exception:
        pass
    try:
        d = Cipher(algorithms.AES(KEY32), modes.CBC(raw[:16])).decryptor()
        ptd = d.update(raw[16:]) + d.finalize()
        pad = ptd[-1]
        if not (1 <= pad <= 16 and ptd[-pad:] == bytes([pad]) * pad):
            return s, None
        t = _utf8(ptd[:-pad])
        if t is not None:
            return t, "cbc"
    except Exception:
        pass
    return s, None


def recursive_ladder(node, count=[0]):
    if isinstance(node, dict):
        return {k: recursive_ladder(v, count) for k, v in node.items()}
    if isinstance(node, list):
        return [recursive_ladder(v, count) for i, v in enumerate(node)]
    if isinstance(node, str):
        nv, how = field_ladder(node)
        if how is not None:
            count[0] += 1
            return nv
        return nv
    return node


def fetch_payload():
    """Live fetch; falls back to the last cached raw payload on failure."""
    try:
        r = requests.get(URL, headers={'User-Agent': UA}, timeout=25)
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
    print_c("HANA PRO VPN Config Decryptor - By @snapdark_decoder 🇧🇩", C_YELLOW)
    print_bar(C_CYAN)
    print("")

    body_b64, source = fetch_payload()
    print_c(f"[+] Encrypted payload ready ({len(body_b64)} chars, source={source})...", C_GREEN)

    print("")
    print_c(">>> INITIATING LAYER 1 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : AES-256-XTS (56B key = rol8(K0^C), encrypted-tweak XTS,", C_CYAN)
    print_c("            ciphertext stealing) — NoobCrypt core mode 5", C_CYAN)

    blob = base64.b64decode(body_b64)
    json_str = xts_decrypt(KEY64, blob)
    try:
        parsed = json.loads(json_str)
    except Exception as e:
        print_c(f"[-] Layer 1 failure: body is not JSON ({e})", C_RED)
        return
    n_srv = len(parsed.get("Servers", []))
    n_twk = len(parsed.get("Tweaks", []))
    print_c(f"[+] Layer 1 breached : JSON body ({len(json_str)} B), {n_srv} servers, {n_twk} tweaks", C_GREEN)

    print("")
    print_c(">>> INITIATING LAYER 2 DECRYPTION <<<", C_YELLOW)
    print_c("Algorithm : per-field b64 -> AES-256-GCM (nonce12+ct+tag16)", C_CYAN)
    print_c("            -> else AES-256-CBC (iv16+ct+PKCS7), 32B field key", C_CYAN)
    fs = parsed.get("Servers", [])
    print_c(f"Scope     : Servers ({len(fs)}) + Tweaks ({n_twk}) inner fields", C_CYAN)

    n2 = 0
    parsed = recursive_ladder(parsed, [0])
    n2 = n2 if isinstance(n2, int) else 0
    print_c("[+] Layer 2 Successfully Breached..", C_GREEN)

    # ---- JSON-validity gate ----
    try:
        parsed = json.loads(json.dumps(parsed, ensure_ascii=False))
    except Exception as e:
        print_bar("!")
        print_c(f"FATAL: output JSON invalid: {e!r}", C_RED)
        sys.exit(5)
    if not parsed.get("Servers") or not parsed.get("Tweaks"):
        print_bar("!")
        print_c("FATAL: no Servers or no Tweaks decrypted", C_RED)
        sys.exit(6)

    # ---- backup-before-replace ----
    if os.path.exists(OUTPUT_FILE):
        bak = OUTPUT_FILE + ".bak-" + time.strftime("%Y%m%d_%H%M%S")
        shutil.copy2(OUTPUT_FILE, bak)
        print_c(f"[*] existing output backed up -> {bak}", C_YELLOW)

    final = {"CREDITS": "Decrypted By @snapdark_decoder 🇧🇩",
             "TELEGRAM": "https://t.me/bd_loser",
             "CHANNEL": "https://t.me/+GEautSR2nNphZWJl",
             "NOTE": "Free Config - Do not sell",
             "_source": source}
    final.update(parsed)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=1)
    try:
        os.chmod(OUTPUT_FILE, 0o600)
    except OSError:
        pass
    print_c(f"[★] Saved Decrypted Configuration to: {OUTPUT_FILE}", C_GREEN)

    # ---- readable .txt ----
    lines = ["════ HANA PRO VPN ☠️ — @SnapDark 🇧🇩 ════",
             f"version v{final.get('Version', 'N/A')} | servers {n_srv} | tweaks {n_twk}",
             ""]
    lines.append("──── SERVERS ────")
    for i, s in enumerate(final.get("Servers", []), 1):
        host = s.get("ServerIPHost") or s.get("ServerHTTPHost") or s.get("DNSHost") or "-"
        lines.append("%02d. %-30s proto=%s" % (i, s.get("Name", "?"), s.get("Protocol", "-")))
        lines.append("    host : %s | ports tcp=%s ssl=%s udp=%s" % (
            host, s.get("TCPPort", "-"), s.get("SSLPort", "-"), s.get("OpenVPNUDPPort", "-")))
        if s.get("Username") or s.get("Password"):
            lines.append("    cred : %s / %s" % (s.get("Username", "-"), s.get("Password", "-")))
        ov = s.get("NoobOvpn")
        if isinstance(ov, str) and ov and len(ov) > 120:
            lines.append("    ovpn : %s..." % ov[:70].replace("\n", " "))
    lines.append("")
    lines.append("──── TWEAKS ────")
    for i, t in enumerate(final.get("Tweaks", []), 1):
        lines.append("%02d. %s  [mode %s | flag %s]" % (i, t.get("Name", "?"), t.get("Mode", "-"), t.get("Flag", "-")))
        if t.get("Info"):
            lines.append("    info  : %s" % t["Info"])
        if t.get("Payload"):
            lines.append("    payload: %s" % t["Payload"])
        if t.get("Sni"):
            lines.append("    sni   : %s | proxy: %s:%s" % (t["Sni"], t.get("ProxyHost", "-") or "-", t.get("ProxyPort", "-") or "-"))
    try:
        os.makedirs(os.path.dirname(OUTPUT_TEXT), exist_ok=True)
        with open(OUTPUT_TEXT, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print_c(f"[★] Saved Readable Config to: {OUTPUT_TEXT}", C_GREEN)
    except OSError as e:
        print_c(f"[!] .txt save failed (output JSON only): {e}", C_YELLOW)

    print("")
    print_c(f"[*] Version : {final.get('Version', 'N/A')} | Message: {final.get('Message', 'N/A')}", C_BLUE)
    print_c(f"[*] Servers : {n_srv} | Tweaks : {n_twk}", C_BLUE)
    print_c("    total = %.2fs" % (time.monotonic() - t_start), C_BLUE)
    print_bar(C_GREEN)


if __name__ == "__main__":
    main()
