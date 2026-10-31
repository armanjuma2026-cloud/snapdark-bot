#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MNR TUNNEL PLUS 3.4 (com.mnrultra.app) — config decryptor / server dumper
=========================================================================
L1 : superscript glyph text (16-symbol substitution alphabet taken from a
     Base64 literal inside LE5/a) -> hex nibble pairs -> ASCII base64
L2 : Base64 -> AES-256-CBC/PKCS7, key = SHA-256(hexUpper("devpro")), IV = 0
L3 : every config field is itself glyph text again, but with the *invisible*
     alphabet U+2000..U+200F -> base64 -> AES-256-CBC, key = SHA-256(hexUpper(K))
     where K = "❤️🧑‍💻Bøbõ⁰⁰!!" (recovered by emulating LK3/f.toString in the dex)

Live  : https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/plusfast
Output: /sdcard/VPNs/MNR TUNNEL PLUS VPN ☠️.json + .txt

Usage:
    python3 "MNR TUNNEL PLUS.py"                 # live
    python3 "MNR TUNNEL PLUS.py" --file <blob>   # local glyph blob / json
    python3 "MNR TUNNEL PLUS.py" --apk <.apk|.apks>   # embedded asset config
"""
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.request
import zipfile

CONFIG_URL = "https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/plusfast"
APP_URL = "https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/plusfastapp"

# LE5/a <clinit> : Base64.decode("wrnCssKz4oG04oG14oG24oG34oG44oG54oGwwrcs4oC9OifigLI=")
OUTER_ALPHABET = "\u00b9\u00b2\u00b3\u2074\u2075\u2076\u2077\u2078\u2079\u2070\u00b7,\u203d:'\u2032"
# LG4/f(2).toString()
FIELD_ALPHABET = "".join(chr(0x2000 + i) for i in range(16))
# LK3/f(2).toString()  ->  ❤️🧑‍💻Bøbõ⁰⁰!!
FIELD_SECRET = "\u2764\ufe0f\U0001f9d1\u200d\U0001f4bbB\u00f8b\u00f5\u2070\u2070!!"
OUTER_SECRET = "devpro"

HEX = "0123456789ABCDEF"
MASK = 0xFFFFFFFF

OUT_JSON = "/sdcard/VPNs/MNR TUNNEL PLUS VPN ☠️.json"
OUT_TXT = "/sdcard/VPNs/MNR TUNNEL PLUS VPN ☠️.txt"
CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"
UAS = ["okhttp/4.9.0", "okhttp/3.12.0", "Mozilla/5.0 (Linux; Android 13)"]


# ----------------------------------------------------------------------------- ui
def term_w(default=78):
    try:
        return max(60, min(96, shutil.get_terminal_size((default, 24)).columns))
    except Exception:
        return default


def print_c(text, ch="="):
    w = term_w()
    print(ch * w)
    for line in str(text).splitlines():
        print(line.center(w))
    print(ch * w)


def print_bar(text, ch="-"):
    print(ch * term_w())
    print(" " + str(text))
    print(ch * term_w())


# ------------------------------------------------------------------------- AES-256
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_INV = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV[_v] = _i
INV = bytes(_INV)
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return r & 0xff


_M9 = bytes(_mul(i, 9) for i in range(256))
_M11 = bytes(_mul(i, 11) for i in range(256))
_M13 = bytes(_mul(i, 13) for i in range(256))
_M14 = bytes(_mul(i, 14) for i in range(256))


def _pack(a, b, c, d):
    return (a << 24) | (b << 16) | (c << 8) | d


TD0 = [_pack(_M14[INV[x]], _M9[INV[x]], _M13[INV[x]], _M11[INV[x]]) for x in range(256)]
TD1 = [_pack(_M11[INV[x]], _M14[INV[x]], _M9[INV[x]], _M13[INV[x]]) for x in range(256)]
TD2 = [_pack(_M13[INV[x]], _M11[INV[x]], _M14[INV[x]], _M9[INV[x]]) for x in range(256)]
TD3 = [_pack(_M9[INV[x]], _M13[INV[x]], _M11[INV[x]], _M14[INV[x]]) for x in range(256)]


def _expand(key):
    """Key schedule -> equivalent-inverse-cipher round keys (InvMixColumns applied)."""
    nk = len(key) // 4
    nr = nk + 6
    w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = ((t << 8) & MASK) | (t >> 24)
            t = ((_SBOX[t >> 24] << 24) | (_SBOX[(t >> 16) & 0xff] << 16) |
                 (_SBOX[(t >> 8) & 0xff] << 8) | _SBOX[t & 0xff])
            t ^= RCON[i // nk - 1] << 24
        elif nk > 6 and i % nk == 4:
            t = ((_SBOX[t >> 24] << 24) | (_SBOX[(t >> 16) & 0xff] << 16) |
                 (_SBOX[(t >> 8) & 0xff] << 8) | _SBOX[t & 0xff])
        w.append(w[i - nk] ^ t)
    dw = [0] * (4 * (nr + 1))
    for c in range(4):
        dw[c] = w[c]
    for c in range(4 * nr, 4 * nr + 4):
        dw[c] = w[c]
    for r in range(1, nr):
        for c in range(4):
            x = w[4 * r + c]
            a0, a1, a2, a3 = (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
            dw[4 * r + c] = _pack(_M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3],
                                  _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3],
                                  _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3],
                                  _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3])
    return dw, nr


def aes_cbc_decrypt(data, key, iv=None, unpad=True):
    """Pure-python AES-CBC decryption (T-table, ~10 MB/s) — no third-party deps."""
    if iv is None:
        iv = bytes(16)
    w, nr = _expand(key)
    out = bytearray(len(data))
    prev = iv
    d0, d1, d2, d3, inv = TD0, TD1, TD2, TD3, INV
    for base in range(0, len(data) - len(data) % 16, 16):
        c = data[base:base + 16]
        s = [int.from_bytes(c[0:4], "big"), int.from_bytes(c[4:8], "big"),
             int.from_bytes(c[8:12], "big"), int.from_bytes(c[12:16], "big")]
        rk = 4 * nr
        s = [s[0] ^ w[rk], s[1] ^ w[rk + 1], s[2] ^ w[rk + 2], s[3] ^ w[rk + 3]]
        for r in range(nr - 1, 0, -1):
            rk = 4 * r
            a, b_, cc, d = s
            s = [d0[a >> 24] ^ d1[(d >> 16) & 0xff] ^ d2[(cc >> 8) & 0xff] ^ d3[b_ & 0xff] ^ w[rk],
                 d0[b_ >> 24] ^ d1[(a >> 16) & 0xff] ^ d2[(d >> 8) & 0xff] ^ d3[cc & 0xff] ^ w[rk + 1],
                 d0[cc >> 24] ^ d1[(b_ >> 16) & 0xff] ^ d2[(a >> 8) & 0xff] ^ d3[d & 0xff] ^ w[rk + 2],
                 d0[d >> 24] ^ d1[(cc >> 16) & 0xff] ^ d2[(b_ >> 8) & 0xff] ^ d3[a & 0xff] ^ w[rk + 3]]
        a, b_, cc, d = s
        t0 = ((inv[a >> 24] << 24) | (inv[(d >> 16) & 0xff] << 16) |
              (inv[(cc >> 8) & 0xff] << 8) | inv[b_ & 0xff]) ^ w[0]
        t1 = ((inv[b_ >> 24] << 24) | (inv[(a >> 16) & 0xff] << 16) |
              (inv[(d >> 8) & 0xff] << 8) | inv[cc & 0xff]) ^ w[1]
        t2 = ((inv[cc >> 24] << 24) | (inv[(b_ >> 16) & 0xff] << 16) |
              (inv[(a >> 8) & 0xff] << 8) | inv[d & 0xff]) ^ w[2]
        t3 = ((inv[d >> 24] << 24) | (inv[(cc >> 16) & 0xff] << 16) |
              (inv[(b_ >> 8) & 0xff] << 8) | inv[a & 0xff]) ^ w[3]
        pt = bytes([t0 >> 24, (t0 >> 16) & 0xff, (t0 >> 8) & 0xff, t0 & 0xff,
                    t1 >> 24, (t1 >> 16) & 0xff, (t1 >> 8) & 0xff, t1 & 0xff,
                    t2 >> 24, (t2 >> 16) & 0xff, (t2 >> 8) & 0xff, t2 & 0xff,
                    t3 >> 24, (t3 >> 16) & 0xff, (t3 >> 8) & 0xff, t3 & 0xff])
        out[base:base + 16] = bytes(x ^ y for x, y in zip(pt, prev))
        prev = c
    if unpad and out:
        p = out[-1]
        if 1 <= p <= 16 and out[-p:] == bytes([p]) * p:
            del out[-p:]
    return bytes(out)


def _hex_upper(raw):
    return "".join(HEX[c >> 4] + HEX[c & 0x0f] for c in raw)


def derive_key(secret):
    """LE5/a.a(String) + SHA-256 -> AES key."""
    return hashlib.sha256(_hex_upper(secret.encode("utf-8")).encode("ascii")).digest()


KEY_OUTER = derive_key(OUTER_SECRET)
KEY_FIELD = derive_key(FIELD_SECRET)


# ------------------------------------------------------------------------- glyphs
def glyph_decode(text, alphabet):
    """16 glyph chars -> nibble pairs -> bytes (the common L1/L3 front-end)."""
    keep = [c for c in text if c in alphabet]
    if len(keep) < 2 or len(keep) % 2:
        raise ValueError("glyph payload has %d valid symbols" % len(keep))
    return bytes((alphabet.index(keep[i]) << 4) | alphabet.index(keep[i + 1])
                 for i in range(0, len(keep), 2))


def b64d(raw):
    s = raw.decode("ascii")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def decrypt_config(text):
    """L1 + L2 -> parsed JSON."""
    b64 = glyph_decode(text, OUTER_ALPHABET)
    ct = b64d(b64)
    if not ct or len(ct) % 16:
        raise ValueError("ciphertext length %d is not a multiple of 16" % len(ct))
    pt = aes_cbc_decrypt(ct, KEY_OUTER, bytes(16))
    return json.loads(pt.decode("utf-8")), len(ct)


_GLYPH_SET = set(FIELD_ALPHABET)


def field(value):
    """L3 per-field blob. Returns None if the string is not a field ciphertext."""
    if not isinstance(value, str) or len(value) < 2:
        return None
    if len(value) % 2 or any(c not in _GLYPH_SET for c in value):
        return None
    try:
        ct = b64d(glyph_decode(value, FIELD_ALPHABET))
        if not ct or len(ct) % 16:
            return None
        txt = aes_cbc_decrypt(ct, KEY_FIELD, bytes(16)).decode("utf-8")
        if any(ord(c) < 32 and c not in "\r\n\t" for c in txt):
            return None
        return txt
    except Exception:                 # noqa: BLE001
        return None


def decrypt_fields(obj):
    """Decrypt every L3 blob in place (recursive). Returns count."""
    n = 0

    def rec(o):
        nonlocal n
        if isinstance(o, dict):
            for k in list(o):
                if isinstance(o[k], str):
                    r = field(o[k])
                    if r is not None:
                        o[k] = r
                        n += 1
                else:
                    rec(o[k])
        elif isinstance(o, list):
            for i, v in enumerate(o):
                if isinstance(v, str):
                    r = field(v)
                    if r is not None:
                        o[i] = r
                        n += 1
                else:
                    rec(v)

    rec(obj)
    return n


def residual(obj):
    out = []

    def rec(o, path=""):
        if isinstance(o, dict):
            for k, v in o.items():
                rec(v, path + "." + k if path else k)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                rec(v, "%s[%d]" % (path, i))
        elif isinstance(o, str) and field(o) is not None:
            out.append(path)

    rec(obj)
    return out


# --------------------------------------------------------------------------- fetch
def fetch(url, timeout=45):
    err = None
    for ua in UAS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                if r.status == 200 and len(body) > 512:
                    return body.decode("utf-8", "replace"), ua
        except Exception as exc:      # noqa: BLE001
            err = exc
    raise RuntimeError("fetch failed for %s (%s)" % (url, err))


def app_version(url=APP_URL):
    for ua in UAS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=20) as r:
                j = json.loads(r.read().decode("utf-8", "replace"))
            return "%s (code %s)" % (j.get("versionName"), j.get("versionCode"))
        except Exception:             # noqa: BLE001
            continue
    return "?"


# ---------------------------------------------------------------------------- apk
def config_from_apk(path):
    """Pull assets/config/config.json out of an .apk or .apks bundle."""
    if path.lower().endswith(".apks"):
        with zipfile.ZipFile(path) as outer:
            for name in outer.namelist():
                if not name.lower().endswith(".apk"):
                    continue
                try:
                    with outer.open(name) as fh:
                        data = fh.read()
                except Exception:     # noqa: BLE001
                    continue
                got = _asset_from_apk_bytes(data)
                if got:
                    return got
        raise RuntimeError("assets/config/config.json not found in %s" % path)
    with open(path, "rb") as fh:
        got = _asset_from_apk_bytes(fh.read())
    if not got:
        raise RuntimeError("assets/config/config.json not found in %s" % path)
    return got


def _asset_from_apk_bytes(data):
    import io
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:                 # noqa: BLE001
        return None
    for name in zf.namelist():
        if name.replace("\\", "/").lower().endswith("assets/config/config.json"):
            return zf.read(name).decode("utf-8", "replace")
    return None


# -------------------------------------------------------------------------- output
def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def _short(s, n=110):
    s = (s or "").replace("\r", "").replace("\n", " | ")
    return s if len(s) <= n else s[:n - 1] + "…"


def write_txt(path, doc):
    L = ["MNR TUNNEL PLUS 3.4 — decrypted config", CREDITS,
         "source : %s" % doc["_source"],
         "app    : %s   config version: %s" % (doc.get("_app_version"), doc.get("Version")),
         "servers: %d    networks: %d    L3 fields: %d    residual: %d"
         % (len(doc["Servers"]), len(doc["Networks"]), doc["_l3_fields"],
            doc["_residual"]), ""]
    if doc.get("ReleaseNotes"):
        L.append("ReleaseNotes: %s" % _short(doc["ReleaseNotes"], 240))
        L.append("")
    L.append("Servers (%d):" % len(doc["Servers"]))
    for s in doc["Servers"]:
        L.append("[%s] %s" % (s.get("FLAG"), s.get("Name")))
        L.append("    host: %s   port: %s   creds: %s / %s"
                 % (s.get("ServerIP"), s.get("ServerPort"), s.get("ServerUser"),
                    s.get("ServerPass")))
        if s.get("Auth_Str"):
            L.append("    auth: %s   obfs: %s" % (s.get("Auth_Str"), s.get("Obfs_Str")))
        if s.get("UdpIP"):
            L.append("    udp: %s   xudp: %s   id: %s"
                     % (s.get("UdpIP"), s.get("XudpPort"), s.get("MnrServerId")))
        if s.get("serverNameKey"):
            L.append("    sni: %s" % s.get("serverNameKey"))
        if s.get("chaveKey"):
            L.append("    key: %s" % s.get("chaveKey"))
        if s.get("v2rayurl"):
            for u in str(s.get("v2rayurl")).split("~"):
                L.append("    v2ray: %s" % _short(u, 150))
        L.append("")
    L.append("Networks (%d):" % len(doc["Networks"]))
    for n in doc["Networks"]:
        kind = next((k for k in ("isSSL", "isInject", "isv2ray", "wsProxyPayload",
                                 "SlowDns", "isMnrDns", "isUdp") if n.get(k)), "-")
        L.append("  - %-13s [%s] %s" % (kind, n.get("FLAG"), n.get("Name")))
        bits = []
        if n.get("Payload"):
            bits.append("payload=" + _short(n.get("Payload"), 80))
        if n.get("SNI"):
            bits.append("sni=" + str(n.get("SNI")))
        if n.get("dnsKey"):
            bits.append("dnsKey=" + _short(n.get("dnsKey"), 60))
        if n.get("ProxyIP"):
            bits.append("proxy=%s:%s" % (n.get("ProxyIP"), n.get("ProxyPort")))
        if bits:
            L.append("      " + "  ".join(bits))
        extra = []
        if n.get("MNR_MODE") is not None:
            extra.append("mnr_mode=%s" % n.get("MNR_MODE"))
        if n.get("XudpMode"):
            extra.append("xudp=%s" % n.get("XudpMode"))
        if n.get("DNS_RESOLVER_MANUAL"):
            extra.append("dns=%s" % _short(n.get("DNS_RESOLVER_MANUAL"), 60))
        if n.get("MTU"):
            extra.append("mtu=%s" % n.get("MTU"))
        if extra:
            L.append("      " + "  ".join(extra))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


# ---------------------------------------------------------------------------- main
def main():
    t0 = time.time()
    print_c("MNR TUNNEL PLUS 3.4  —  CONFIG DECRYPTOR\n"
            "glyph(16) → base64 → AES-256-CBC · L1+L3 · key 'devpro' / field-secret")
    cfg = None
    src = ""
    raw_len = 0
    local = apk = None
    for i, a in enumerate(sys.argv):
        if a == "--file" and i + 1 < len(sys.argv):
            local = sys.argv[i + 1]
        if a == "--apk" and i + 1 < len(sys.argv):
            apk = sys.argv[i + 1]

    if local:
        print("[*] local file: %s" % local)
        text = open(local, encoding="utf-8", errors="replace").read()
        src = "file:" + os.path.basename(local)
        if text.lstrip().startswith("{"):
            cfg = json.loads(text)
            raw_len = len(text)
        else:
            cfg, raw_len = decrypt_config(text)
    elif apk:
        print("[*] apk: %s" % apk)
        text = config_from_apk(apk)
        cfg, raw_len = decrypt_config(text)
        src = "apk:" + os.path.basename(apk)
        print("    ok %d glyph chars" % len(text))
    else:
        print("[*] live: %s" % CONFIG_URL)
        text, ua = fetch(CONFIG_URL)
        cfg, raw_len = decrypt_config(text)
        src = CONFIG_URL
        print("    ok %d chars (UA %s)" % (len(text), ua))

    av = app_version() if not apk else "3.4 (bundled)"
    print("[*] app %s · config v%s · %d servers · %d networks"
          % (av, cfg.get("Version"), len(cfg.get("Servers") or []),
             len(cfg.get("Networks") or [])))

    n = decrypt_fields(cfg)
    left = residual(cfg)
    print("[*] L3 fields decrypted: %d   residual: %d" % (n, len(left)))
    if left:
        print("    %s" % left[:8])

    doc = {
        "CREDITS": CREDITS,
        "_source": src,
        "_family": "mnr-ultra / com.mnrultra.app",
        "_cipher": ("glyph16→hex→base64→AES-256-CBC/PKCS7 key=SHA256(hexUpper('devpro')) IV=0; "
                    "L3 fields: invisible-glyph16→base64→AES-256-CBC key=SHA256(hexUpper(K)) IV=0"),
        "_app_version": av,
        "_raw_ct_len": raw_len,
        "_l3_fields": n,
        "_residual": len(left),
    }
    doc.update({k: v for k, v in cfg.items()})
    doc["_summary"] = {
        "servers": len(cfg.get("Servers") or []),
        "networks": len(cfg.get("Networks") or []),
        "l3_fields": n,
        "residual": len(left),
        "release_notes_len": len(cfg.get("ReleaseNotes") or ""),
    }
    write_json(OUT_JSON, doc)
    write_txt(OUT_TXT, doc)

    print_bar("RESULT  v%s · %d servers · %d networks · %d L3 fields · %d residual"
              % (cfg.get("Version"), len(cfg.get("Servers") or []),
                 len(cfg.get("Networks") or []), n, len(left)))
    print("JSON: %s (%d KB)" % (OUT_JSON, os.path.getsize(OUT_JSON) // 1024))
    print("TXT : %s" % OUT_TXT)
    print("done in %.2fs" % (time.time() - t0))


if __name__ == "__main__":
    main()
