#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  BD PRO VPN ☠️  —  com.bdprovpn.app (v1.4) config decryptor
#  Cipher : XxTeaBase64 (chained-carry XXTEA, DELTA 0x948553D4, LE words)
#  Key    : 4x nested b64 "V2tWa1YyRnRSa2hPV0ZwcVlsWldOVlJyVFhkUVVUMDk="
#           -> "technore24-" + suffix, fixKey pad/trunc 16B
#           envelope (Utils.decryptMain) suffix "mm&oa"  -> technore24-mm&oa
#           L2 fields (VPNUtil.decrypt)   suffix "dee!is" -> technore24-dee!i
#  Ground truth: jadx XxTeaBase64.java (toIntArray LE, tail word = pt len
#  validated N*4-7..N*4-4, ct has NO len word) + JDK round-trip of app code
#  House rule: CREDITS first + _source ; JSON-validity gate ; live-first
# ============================================================================
import base64
import json
import os
import re
import shutil
import sys
import time
import urllib.request

CONFIG_URL = "https://24tunnel.xyz/api/files/app?json=d33c7ba0c14caba0be74"
OUT_PATH = "/sdcard/VPNs/BD PRO VPN ☠️.json"
CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"

KEY_B64_NESTED = "V2tWa1YyRnRSa2hPV0ZwcVlsWldOVlJyVFhkUVVUMDk="
SUFFIX_ENVELOPE = "mm&oa"    # Utils.decryptMain
SUFFIX_L2 = "dee!is"         # VPNUtil.decrypt
DELTA = 0x948553D4           # Java getDelta() = -1803201580
MASK32 = 0xFFFFFFFF
CREDITS_FIRST = True

B64_CAND = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
HEXY = re.compile(r"^[0-9a-fA-F]{32,}$")


def print_bar(ch="="):
    print(ch * shutil.get_terminal_size().columns)


def print_c(msg=""):
    print(msg.center(shutil.get_terminal_size().columns))


def check_dependencies():
    # pure-stdlib cipher; nothing to install
    pass


def b64d(s):
    s = s.strip()
    return base64.b64decode(s + "=" * ((-len(s)) % 4))


def derive_key(suffix):
    k = KEY_B64_NESTED
    for _ in range(4):            # 4x nested base64 -> "technore24-"
        k = b64d(k).decode("latin1")
    raw = (k + suffix).encode("utf-8")
    return raw[:16] if len(raw) >= 16 else raw.ljust(16, b"\x00")


def mx(s, y, z, p, e, ki):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((s ^ y) + (ki[(p & 3) ^ e] ^ z))) & MASK32


def to_int_array(b):
    if len(b) % 4:
        b = b + b"\x00" * (4 - len(b) % 4)
    return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]


def xxtea_decrypt(ct, key_words):
    v = to_int_array(ct)
    n = len(v)
    if n < 2:
        return None
    rnd = 52 // n + 6
    s = (rnd * DELTA) & MASK32
    carry = v[0]
    while s:
        e = (s >> 2) & 3
        cv = carry
        p = n - 1
        while p > 0:
            cv = (v[p] - mx(s, cv, v[p - 1], p, e, key_words)) & MASK32
            v[p] = cv
            p -= 1
        carry = (v[0] - mx(s, cv, v[n - 1], 0, e, key_words)) & MASK32
        v[0] = carry
        s = (s - DELTA) & MASK32
    ln = v[-1]
    N = n * 4
    if not (N - 7 <= ln <= N - 4):     # toByteArray(..., true) window
        return None
    out = b"".join(x.to_bytes(4, "little") for x in v)
    return out[:ln]


def decrypt_blob(b64_text, key16):
    try:
        raw = b64d(b64_text)
    except Exception:
        return None
    if not raw:
        return None
    pt = xxtea_decrypt(raw, to_int_array(key16))
    if pt is None:
        return None
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        return None


def looks_like_blob(s):
    if not isinstance(s, str):
        return False
    L = len(s)
    if L < 12 or L > 8192 or L % 4 == 1:
        return False
    if not B64_CAND.match(s):
        return False
    if s.startswith(("{", "[")) or "://" in s or " " in s:
        return False
    if HEXY.match(s):
        return False
    return True


def usable_pt(t):
    if t is None or t == "":
        return t is not None          # empty plaintext is a valid L2 result
    if "\ufffd" in t:
        return False
    printable = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\n\r\t") / len(t)
    return printable > 0.85


def l2_walk(node, key16, stats):
    if isinstance(node, dict):
        for k, v in node.items():
            node[k] = l2_walk(v, key16, stats)
        return node
    if isinstance(node, list):
        for i, v in enumerate(node):
            node[i] = l2_walk(v, key16, stats)
        return node
    if looks_like_blob(node):
        stats["candidates"] += 1
        t = decrypt_blob(node, key16)
        if usable_pt(t):
            stats["decrypted"] += 1
            return t
        stats["residual"] += 1
    return node


def fetch(url, timeout=40):
    req = urllib.request.Request(url, headers={"User-Agent": "okhttp/4.12.0"})
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
        code = getattr(r, "status", 200)
    print_c("[%.1fs] fetch HTTP=%s size=%d" % (time.monotonic() - t0, code, len(body)))
    return body.decode("utf-8", "replace")


def main():
    check_dependencies()
    print_bar()
    print_c("☠️  BD PRO VPN  —  com.bdprovpn.app  XxTeaBase64 decryptor  ☠️")
    print_bar()
    t_start = time.monotonic()
    embedded_path = None
    if "--embedded" in sys.argv:
        embedded_path = sys.argv[sys.argv.index("--embedded") + 1]

    blob_text = None
    source = None
    t0 = time.monotonic()
    try:
        blob_text = fetch(CONFIG_URL)
        source = CONFIG_URL
    except Exception as e:
        print_c("[!] live fetch failed: %r" % (e,))
    print_c("[%.1fs] stage fetch" % (time.monotonic() - t0))

    if blob_text is None and embedded_path and os.path.exists(embedded_path):
        blob_text = open(embedded_path, encoding="utf-8").read()
        source = "embedded:" + embedded_path
        print_c("[*] using embedded fallback res/raw/servers.js")

    if blob_text is None:
        print_bar("!")
        print_c("FATAL: no config blob (live fetch failed, no --embedded given)")
        print_bar("!")
        sys.exit(2)

    t0 = time.monotonic()
    plain = decrypt_blob(blob_text, derive_key(SUFFIX_ENVELOPE))
    print_c("[%.1fs] stage L1 envelope decrypt" % (time.monotonic() - t0))
    if plain is None:
        print_bar("!")
        print_c("FATAL: L1 decrypt failed (tail-length check) — wrong format?")
        print_bar("!")
        sys.exit(3)

    try:
        cfg = json.loads(plain)
    except Exception as e:
        print_bar("!")
        print_c("FATAL: L1 plaintext is not JSON: %r" % (e,))
        sys.exit(4)

    t0 = time.monotonic()
    stats = {"candidates": 0, "decrypted": 0, "residual": 0}
    cfg = l2_walk(cfg, derive_key(SUFFIX_L2), stats)
    print_c("[%.1fs] stage L2 field walk: %d candidates, %d decrypted, %d residual"
            % (time.monotonic() - t0, stats["candidates"], stats["decrypted"], stats["residual"]))

    out = {}
    out["CREDITS"] = CREDITS
    out["_source"] = source
    out["_app"] = "BD PRO VPN"
    out["_package"] = "com.bdprovpn.app"
    out["_protocol"] = "v2rayNG-stack (OpenVPN + V2Ray/Hysteria2 UDP)"
    out["_formats"] = ["XxTeaBase64-envelope", "XXTEA-L2-fields"]
    out["_extraction"] = "XxTeaBase64 chained XXTEA (DELTA 0x948553D4, key technore24-mm&oa / -dee!i)"
    out["_analyzed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    out["_l2_stats"] = stats
    for k, v in cfg.items():
        out[k] = v

    # ---- validation gate (Stage 6) ----
    try:
        parsed = json.loads(json.dumps(out, ensure_ascii=False))
    except Exception as e:
        print_bar("!")
        print_c("FATAL: output JSON invalid: %r" % (e,))
        sys.exit(5)
    n_servers = len(parsed.get("Servers", []))
    n_networks = len(parsed.get("Networks", []))
    if n_servers == 0 and n_networks == 0:
        print_bar("!")
        print_c("FATAL: no Servers and no Networks in decrypted config")
        sys.exit(6)

    # ---- backup-before-replace (U5) ----
    if os.path.exists(OUT_PATH):
        bak = OUT_PATH + ".bak-" + time.strftime("%Y%m%d_%H%M%S")
        shutil.copy2(OUT_PATH, bak)
        print_c("[*] existing output backed up -> %s" % bak)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(parsed, f, ensure_ascii=False, indent=1)
    try:
        os.chmod(OUT_PATH, 0o600)
    except OSError:
        pass

    total = time.monotonic() - t_start
    print_bar()
    print_c("Version: %s | Servers: %d | Networks: %d | L2 residual: %d"
            % (parsed.get("Version", "?"), n_servers, n_networks, stats["residual"]))
    print_c("output: %s (%d bytes)" % (OUT_PATH, os.path.getsize(OUT_PATH)))
    print_c("total elapsed: %.1fs" % total)
    print_bar()
    print_c("☠️  DONE — JSON validated  ☠️")
    print_bar()


if __name__ == "__main__":
    main()
