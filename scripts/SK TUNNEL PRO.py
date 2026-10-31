#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  SK TUNNEL PRO ☠️  —  com.jhoelsoft.thunderv3s (16kb-page-size) decryptor
#  L1 : AES-256-CBC / PKCS7, key = SHA-256("sk1987"), IV = 16x00,
#       input = standard base64 (whitespace stripped before decode)
#  L2 : 26-glyph hex substitution on decrypted values (replace chain from
#       ActivityUi: 1-9,0,a-p). No-op on strings that carry no glyphs.
#  Ground truth: jadx 1.5.6 + panda912 Muddy deobfuscation of
#       c_11 (conf / data_url / ex_api_url), UtilsKey, VPNUtil, ActivityUi
#  Live : https://sksuperpower.xyz/api/app?json=bdefca7cdee64430c490 (HTTP 200)
#  Dead : https://myprotectionservices.com/uploads/json/8e8987d108922a1ce74a.json
#         (HTTP 404 — stale c_11 data_url)
#  NOT contacted: https://pastebin.com/raw/LDEnpzU2 (dev kill-switch gate),
#                 https://sksuperpower.xyz/api/shoh9uunga/auth (account auth)
#  House rule: CREDITS first + _source ; JSON-validity gate ; live-first ;
#              backup-before-replace ; chmod 600 (FUSE may still show 660)
# ============================================================================
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.request

CONFIG_URL = "https://sksuperpower.xyz/api/app?json=bdefca7cdee64430c490"
OUT_PATH = "/sdcard/VPNs/SK TUNNEL PRO ☠️.json"
CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"
KEY_STR = "sk1987"                                          # UtilsKey.key (Muddy)
AES_KEY = hashlib.sha256(KEY_STR.encode("utf-8")).digest()  # generateKey(): SHA-256
IV = b"\x00" * 16                                           # AESHelper: fixed zero IV

# glyph -> hex char (ActivityUi replace chain, 26 pairs; injected below)
GLYPH = {'大': '1', '女': '2', '듽': '3', 'く': '4', '듌': '5', '中': '6', '들': '7', '山': '8', '땀': '9', '天': '0', '둣': 'a', '딸': 'b', '딨': 'c', '땬': 'd', '二': 'e', '小': 'f', '与': 'g', '主': 'h', '没': 'i', '日': 'j', '当': 'k', '就': 'l', '国': 'm', '为': 'n', '的': 'o', '畫': 'p'}

B64_CAND = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
HEXY = re.compile(r"^[0-9a-fA-F]{32,}$")


def check_dependencies():
    global AES
    try:
        from Crypto.Cipher import AES as _AES
    except ImportError:
        print("FATAL: pycryptodome missing — pkg install python-cryptodome")
        sys.exit(10)
    AES = _AES


def print_bar(ch="="):
    print(ch * shutil.get_terminal_size().columns)


def print_c(msg=""):
    print(msg.center(shutil.get_terminal_size().columns))


def b64d(s):
    s = "".join(s.split())          # VPNUtil.decrypt strips ' ' and '\n'
    return base64.b64decode(s + "=" * ((-len(s)) % 4))


def aes_dec(blob):
    """Strict AES-256-CBC decrypt; returns str or None (bad pad / not UTF-8)."""
    try:
        data = b64d(blob)
    except Exception:
        return None
    if not data or len(data) % 16:
        return None
    try:
        pt = AES.new(AES_KEY, AES.MODE_CBC, IV).decrypt(data)
    except Exception:
        return None
    padn = pt[-1]
    if not (1 <= padn <= 16 and pt[-padn:] == bytes([padn]) * padn):
        return None
    pt = pt[:-padn]
    try:
        return pt.decode("utf-8")   # strict: rejects random bytes
    except UnicodeDecodeError:
        return None


def glyph_fix(s):
    for g, a in GLYPH.items():
        if g in s:
            s = s.replace(g, a)
    return s


def has_ctrl(t):
    return any(ord(c) < 32 and c not in "\n\r\t" for c in t)


def looks_like_blob(s):
    if not isinstance(s, str):
        return False
    L = len(s)
    if L < 16 or L > 8192 or L % 4 == 1:
        return False
    if not B64_CAND.match(s):
        return False
    if s.startswith(("{", "[")) or "://" in s or " " in s:
        return False
    if HEXY.match(s):
        return False
    return True


def l2_walk(node, stats):
    if isinstance(node, dict):
        for k, v in node.items():
            node[k] = l2_walk(v, stats)
        return node
    if isinstance(node, list):
        for i, v in enumerate(node):
            node[i] = l2_walk(v, stats)
        return node
    if looks_like_blob(node):
        stats["candidates"] += 1
        t = aes_dec(node)
        if t is not None and not has_ctrl(t):
            stats["decrypted"] += 1
            return glyph_fix(t)     # only decrypted values get the glyph chain
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
    print_c("☠️  SK TUNNEL PRO  —  com.jhoelsoft.thunderv3s  AES+glyph decryptor  ☠️")
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
        print_c("[*] using embedded fallback (c_11 conf dump)")

    if blob_text is None:
        print_bar("!")
        print_c("FATAL: no config blob (live fetch failed, no --embedded given)")
        print_bar("!")
        sys.exit(2)

    t0 = time.monotonic()
    plain = aes_dec(blob_text)
    print_c("[%.1fs] stage L1 AES decrypt" % (time.monotonic() - t0))
    if plain is None:
        print_bar("!")
        print_c("FATAL: L1 decrypt failed (bad padding / not UTF-8)")
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
    cfg = l2_walk(cfg, stats)
    print_c("[%.1fs] stage L2 field walk: %d candidates, %d decrypted, %d residual"
            % (time.monotonic() - t0, stats["candidates"], stats["decrypted"], stats["residual"]))

    out = {}
    out["CREDITS"] = CREDITS
    out["_source"] = source
    out["_app"] = "SK TUNNEL PRO"
    out["_package"] = "com.jhoelsoft.thunderv3s"
    out["_protocol"] = ("SSH suite (Direct/Proxy/SSL, SSL-RP, SlowDNS) + OpenVPN "
                        "+ v2ray + Hysteria2 + WireGuard + OpenConnect")
    out["_formats"] = ["AES-256-CBC-PKCS7(SHA256(sk1987),IV=0)", "glyph-hex-26"]
    out["_extraction"] = ("Muddy deobfuscation -> sk1987 -> AES-CBC -> "
                          "ActivityUi glyph chain")
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
    if stats["residual"]:
        print_c("[!] residual blobs: %d (inspect before use)" % stats["residual"])

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
