#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================================================
  Jas Tunnel (v1.0, noob.jastunnel.app) — full config decryptor
====================================================================================================
  CREDITS
  -------
  * Cracked by: SKILL: vpn-decryptor-suite (OpenCode agent session, 2026-10-29)
  * Credits : z3ro (Arman) / SenseiTunnel — authorized local APK analysis
  * Target  : /storage/emulated/0/MT2/apks/Jas Tunnel_1.0.apks (sha256 d1716d5b38496c…)
  * Family  : noobdev-noobcrypt — libovpn3.so NoobCrypt (com.noobdev.vpn.utils.preference.NoobCrypt)
  * Pipeline: b64 body -> AES-256-XTS-256 (NoobCrypt mode 5; key64 = per-byte ROL6(K0_block ^ C_block)
              with libovpn3 rodata K0@0x21db30 ^ C@0x1c2000/0x1c21c0/0x1c2aa0/0x1c2ab0)
              -> OpenSSL CRYPTO_xts128_decrypt convention (tweak pre-encrypted with K2 half,
              ciphertext-stealing tail)                [pure-Python, bit-exact vs libcrypto EVP]
              -> field ladder: per-field b64 -> AES-256-GCM(nonce12|ct||tag) else AES-256-CBC(iv16|PKCS7)
              key32 = A32@0x21d820 ^ (C@0x1c2b80[:16] || C@0x1c2860[:16])
  * LCG strings: muddy-style new C3325q30(new long[]{-…}) with java.util.Random.nextLong
              sign-extension ((long)(int)hi<<32)+(int)lo
  * Config  : https://jastunnel.xyz/api/app?json=ae5122d99cfab755fad6   (live GET, b64 body)
              Shared noobdev updater https://jezvpn.xyz/api/app?json=d154dff4627f2474cf87 +
              pastebin.com/raw/XrVPE3mj — code-only references, NEVER contacted by this script.
  * Output  : /sdcard/VPNs/Jas Tunnel ☠️.json  (full decrypted config, valid JSON gate)
              /sdcard/VPNs/Jas Tunnel ☠️.txt   (human-readable summary)
  * Run     : python3 -P "Jas Tunnel.py"    (for internet; without -P net may be unavailable,
              a cached payload at /sdcard/VPNs/.jas_payload_cache.b64 is used as fallback)
  * Safety  : JSON validity gate + backup-before-replace on existing outputs.
====================================================================================================
"""
import os, sys, json, time, base64

# ---------------- CREDITS banner (first output) ----------------
def _banner():
    bar = "═" * 100
    print(bar)
    print("  Jas Tunnel (noobdev) — NoobCrypt AES-256-XTS + GCM/CBC field ladder decryptor")
    print("  Credits: z3ro (Arman) / SenseiTunnel — crack: vpn-decryptor-suite 2026-10-29")
    print(bar)

APP_NAME  = "Jas Tunnel"
OUT_JSON  = "/sdcard/VPNs/Jas Tunnel ☠️.json"
OUT_TXT   = "/sdcard/VPNs/Jas Tunnel ☠️.txt"
CACHE_B64 = "/sdcard/VPNs/.jas_payload_cache.b64"
ENDPOINT  = "https://jastunnel.xyz/api/app?json=ae5122d99cfab755fad6"

# NoobCrypt native constants (libovpn3.so, Jas Tunnel build 8522256 B)
KEY64 = bytes.fromhex("7bb4ae738e9963145ef92b33fed5cf93a3cdb80e0c4acc2e9a1f97aae560a725b5344d423ce4c96f91440aac5a2d855c6e75ef369aa6380a8b9e67e24eed9ad3")
KEY32 = bytes.fromhex("d65c9af6bc0c6e441dc9553de03ed567cc95b3aa1b136ed8a7b3d41556c9ee85")

G64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def check_dependencies():
    """House pattern: verify required deps; auto-install reasonable ones."""
    try:
        from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)  # noqa: F401
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except ImportError:
        print("[*] 'cryptography' missing — attempting pip install ...")
        os.system(sys.executable + " -m pip install --no-input cryptography")
        try:
            from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)  # noqa: F401
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
            return True
        except ImportError:
            print("[!] cryptography unavailable — cannot continue.")
            return False


def print_c(text, color=""):
    print(color + text + "\x1b[0m" if color else text)


C_CYAN, C_GREEN, C_RED, C_YEL = "\x1b[36m", "\x1b[32m", "\x1b[31m", "\x1b[33m"


# ---------------- LAYER 1 : body XTS (pure python, bit-exact vs EVP) ----------------
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
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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


# ---------------- LAYER 2 : per-field GCM/CBC ladder ----------------
def _utf8(b):
    """Emoji-tolerant UTF-8 gate: strict decode + no control chars < 32 (tab/cr/lf allowed)."""
    try:
        s = b.decode("utf-8")
    except Exception:
        return None
    clean = s.replace("\t", "").replace("\r", "").replace("\n", "")
    if any(ord(c) < 32 for c in clean):
        return None
    return s


def field_ladder(s):
    """Per-field b64 -> [nonce12][ct||tag] GCM else [iv16][ct+PKCS7] CBC; key32."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(s) < 24 or set(s) - G64:
        return None
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None
    if len(raw) >= 28:
        try:
            pt = AESGCM(KEY32).decrypt(raw[:12], raw[12:], None)
            v = _utf8(pt)                                   # ct||tag concatenated
            if v is not None:
                return v
        except Exception:
            pass
    if len(raw) >= 18 and (len(raw) - 16) % 16 == 0:
        try:
            d = Cipher(algorithms.AES(KEY32), modes.CBC(raw[:16])).decryptor()
            padded = d.update(raw[16:]) + d.finalize()
            pad = padded[-1] if padded else 0
            pt = padded[:-pad] if 1 <= pad <= 16 and padded.endswith(bytes([pad]) * pad) else padded
            v = _utf8(pt)
            if v is not None:
                return v
        except Exception:
            pass
    return None


def recursive_ladder(node, count=None):
    if count is None:
        count = [0]
    if isinstance(node, dict):
        for k in list(node.keys()):
            v = node[k]
            if isinstance(v, (dict, list)):
                recursive_ladder(v, count)
            elif isinstance(v, str):
                r = field_ladder(v)
                if r is not None:
                    node[k] = r
                    count[0] += 1
    elif isinstance(node, list):
        for i in range(len(node)):
            v = node[i]
            if isinstance(v, (dict, list)):
                recursive_ladder(v, count)
            elif isinstance(v, str):
                r = field_ladder(v)
                if r is not None:
                    node[i] = r
                    count[0] += 1
    return count[0]


# ---------------- payload fetch (with cache fallback) ----------------
def fetch_payload():
    try:
        import urllib.request as req
        r = req.Request(ENDPOINT, headers={"User-Agent": "okhttp/3.12.0"})
        with req.urlopen(r, timeout=60) as f:
            body = f.read()
        print_c("[*] fetched live config: %d B" % len(body), C_CYAN)
        base64.b64decode(body)          # sanity
        open(CACHE_B64, "w").write(body.decode("ascii", "ignore"))
        print_c("[*] cached body -> %s" % CACHE_B64, C_CYAN)
        return body
    except Exception as e:
        print_c("[!] live fetch failed (%s) — using cache fallback" % e, C_YEL)
        if os.path.exists(CACHE_B64):
            return open(CACHE_B64, "rb").read()
        raise SystemExit("[X] no cache payload available; run once with network")


def make_txt(data):
    L = []
    L.append("════════════════════════════════════════════════════════════")
    L.append("  %s — decrypted config   (generated by 'Jas Tunnel.py')" % APP_NAME)
    L.append("  Credits: z3ro (Arman) / SenseiTunnel — vpn-decryptor-suite")
    L.append("════════════════════════════════════════════════════════════")
    L.append("")
    L.append("Family     : noobdev-noobcrypt (NoobCrypt mode5 XTS + GCM/CBC ladder)")
    L.append("Endpoint   : %s" % ENDPOINT)
    L.append("Version    : %s" % data.get("Version"))
    L.append("defTime    : %s | unlimited: %s | showAds: %s" % (data.get("defTime"), data.get("unlimited"), data.get("showAds")))
    L.append("Updater    : %s  (code-only, never contacted)" % data.get("updater"))
    L.append("")
    sv = data.get("Servers") or []
    L.append("Servers (%d):" % len(sv))
    for i, s in enumerate(sv):
        L.append("  [%d] %s" % (i, s.get("Name")))
        L.append("      host=%s  tcp=%s ssl=%s udp=%s dropbear=%s" % (
            s.get("ServerIPHost"), s.get("TCPPort"), s.get("SSLPort"),
            s.get("OpenVPNUDPPort"), s.get("DropBear")))
        if s.get("ServerHTTPHost"):
            L.append("      http=%s" % s.get("ServerHTTPHost"))
        L.append("      user=%s pass=%s flag=%s proto=%s" % (
            s.get("Username"), s.get("Password"), s.get("Flag"), s.get("Protocol")))
        if s.get("useCustomOvpnCert") and s.get("OpenVPNCertificate"):
            L.append("      custom ovpn config embedded (cipher none)")
        udp = s.get("UDP") or {}
        if udp:
            L.append("      udp: obfs=%s mode=%s ports=%s" % (udp.get("UDPObfs"), udp.get("UDPMode"), udp.get("UDPOpenPort")))
    tw = data.get("Tweaks") or []
    L.append("")
    L.append("Tweaks (%d) — first 12:" % len(tw))
    for i, t in enumerate(tw[:12]):
        L.append("  [T%d] id=%s" % (i, t.get("TweakId")))
        L.append("      %s" % t.get("Name"))
        info = t.get("Info")
        if info:
            L.append("      %s" % info[:110])
    if len(tw) > 12:
        L.append("  ... (%d more in JSON)" % (len(tw) - 12))
    L.append("")
    L.append("Full config JSON: %s" % OUT_JSON)
    return "\n".join(L)


def main():
    print_c("            Jas Tunnel decryptor — NoobCrypt core (mode 5 XTS +", C_CYAN)
    print_c("            GCM/CBC field ladder) — pure-python XTS bit-exact", C_CYAN)
    t0 = time.time()
    blob_b64 = fetch_payload()
    blob = base64.b64decode(blob_b64)
    print_c("[*] body blob: %d B (tweak16 + ct)" % len(blob), C_CYAN)
    pt = xts_decrypt(KEY64, blob)
    try:
        data = json.loads(pt.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("not a dict")
    except Exception as e:
        print_c("[X] JSON validity gate FAILED after XTS: %s" % e, C_RED)
        raise SystemExit(1)
    print_c("[+] XTS ok — JSON gate passed (top keys: %d)" % len(data.keys()), C_GREEN)
    n = recursive_ladder(data)
    print_c("[+] field ladder: %d fields decrypted" % n, C_GREEN)
    os.makedirs("/sdcard/VPNs", exist_ok=True)
    # backup-before-replace (house pattern)
    for out in (OUT_JSON, OUT_TXT):
        if os.path.exists(out):
            b = out + ".bak-" + time.strftime("%Y%m%d_%H%M%S")
            os.replace(out, b)
            print_c("[*] backup: %s" % b, C_YEL)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    with open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write(make_txt(data))
    print_c("[+] wrote %s" % OUT_JSON, C_GREEN)
    print_c("[+] wrote %s" % OUT_TXT, C_GREEN)
    print_c("[✓] done in %.2f s — Jas Tunnel config unlocked" % (time.time() - t0), C_GREEN)


if __name__ == "__main__":
    _banner()
    if not check_dependencies():
        raise SystemExit(2)
    main()
