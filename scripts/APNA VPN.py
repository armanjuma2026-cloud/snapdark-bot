#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APNA VPN 3.9 (my.teamapna.tunnel) — config decryptor / server dumper
===================================================================
Family  : prince-ocs (same chained-carry XXTEA engine as Der Tunnel / APNA Tunnel Lite / FNF)
L1      : base64 -> XXTEA (DELTA 0x9E5729B1, LE words, carry-chain, tail = plaintext len) -> JSON
L2      : per-field blobs (Username / Password) = SAME engine + SAME key -> "tanginaka"
Key     : '...|...'  (7 bytes, zero-padded to 16)
Live    : https://amtun.xyz/updater/c44cef4d43f71b0d45e01ae1dc7bd2   (UA-locked: 403 without a UA)
Embedded: assets/janu.json inside base.apk of the .apks   (fallback, v289)
Output  : /sdcard/VPNs/APNA VPN ☠️.json  +  .txt

Usage:
    python3 "APNA VPN.py"                 # live first, embedded fallback
    python3 "APNA VPN.py" --apk FILE.apks # force embedded
    python3 "APNA VPN.py" --out-dir DIR --basename name   # custom output (bot/server)
"""
import base64
import json
import os
import re
import shutil
import struct
import sys
import time
import urllib.request
import zipfile

CONFIG_URL = "https://amtun.xyz/updater/c44cef4d43f71b0d45e01ae1dc7bd2"
ALT_URLS = [
    "https://paperonboard.com/updater/3c3c4c58d864ca394da16656b4d0c4",
]
APK_DEFAULT = "/storage/emulated/0/MT2/apks/APNA VPN_3.9.apks"

KEY = b"...|..."
DELTA = 0x9E5729B1
MASK = 0xFFFFFFFF

OUT_DIR = os.environ.get("APNA_OUT_DIR", "/sdcard/VPNs")
OUT_BASE = os.environ.get("APNA_OUT_BASE", "APNA VPN ☠️")

CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"
UAS = ["okhttp/3.12.0", "okhttp/4.9.0", "okhttp/4.12.0", "Mozilla/5.0 (Linux; Android 13)"]

B64_RE = re.compile(r"^[A-Za-z0-9+/]{11,}={0,2}$")


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
    w = term_w()
    print(ch * w)
    print(" " + str(text))
    print(ch * w)


# --------------------------------------------------------------------------- xxtea
def _mx(s, y, z, p, e, k):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & MASK


def xxtea_decrypt(data, key=KEY):
    """prince-family chained-carry XXTEA. data = raw bytes (LE words, no len word)."""
    if len(data) < 8:
        return None
    v = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    k = list(struct.unpack("<4I", key.ljust(16, b"\0")[:16]))
    n = len(v)
    rounds = 52 // n + 6
    s = (rounds * DELTA) & MASK
    carry = v[0]
    while s:
        e = (s >> 2) & 3
        cv = carry
        p = n - 1
        while p > 0:
            cv = (v[p] - _mx(s, cv, v[p - 1], p, e, k)) & MASK
            v[p] = cv
            p -= 1
        carry = (v[0] - _mx(s, cv, v[n - 1], 0, e, k)) & MASK
        v[0] = carry
        s = (s - DELTA) & MASK
    out = b"".join(x.to_bytes(4, "little") for x in v)
    # last word = plaintext length, valid window N*4-7 .. N*4-4
    tail = int.from_bytes(out[-4:], "little")
    if not (len(out) - 7 <= tail <= len(out) - 4):
        return None
    return out[:tail]


def b64d(s):
    s = "".join(s.split())
    return base64.b64decode(s + "=" * (-len(s) % 4))


def decrypt_config(text):
    """base64 -> XXTEA -> JSON (whole config file)."""
    raw = b64d(text)
    plain = xxtea_decrypt(raw)
    if plain is None:
        raise ValueError("XXTEA length gate failed (wrong key/delta or corrupted blob)")
    return json.loads(plain.decode("utf-8")), len(raw)


def l2_field(value):
    """Per-field blob decrypt (Username/Password ...). Returns None if not a blob."""
    if not isinstance(value, str) or not B64_RE.match(value):
        return None
    try:
        raw = b64d(value)
        if len(raw) < 8:
            return None
        plain = xxtea_decrypt(raw)
        if plain is None:
            return None
        txt = plain.decode("utf-8")
        return txt.rstrip("\x00")
    except Exception:
        return None


# --------------------------------------------------------------------------- fetch
def fetch(url, timeout=45):
    err = None
    for ua in UAS:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": ua,
                "Accept": "*/*",
                "Connection": "close",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                if r.status == 200 and len(body) > 512:
                    return body.decode("utf-8", "replace"), ua
        except Exception as exc:      # noqa: BLE001
            err = exc
    raise RuntimeError("fetch failed for %s (%s)" % (url, err))


# ------------------------------------------------------------------------ embedded
def load_embedded(apk_path):
    with zipfile.ZipFile(apk_path) as apks:
        names = apks.namelist()
        inner = "base.apk" if "base.apk" in names else next(
            (n for n in names if n.endswith(".apk")), None)
        if inner is None:
            raise RuntimeError("no base.apk inside %s" % apk_path)
        blob = apks.read(inner)
    import io
    with zipfile.ZipFile(io.BytesIO(blob)) as base:
        text = base.read("assets/janu.json").decode("utf-8", "replace")
    return decrypt_config(text)[0], "embedded:" + apk_path


# ------------------------------------------------------------------------ output
def walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, path + "." + k if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, "%s[%d]" % (path, i))
    elif isinstance(obj, str):
        yield path, obj


def decrypt_l2(obj):
    """Decrypt every L2 blob in place; returns list of decrypted paths."""
    done = []

    def rec(o, path):
        if isinstance(o, dict):
            for k in list(o):
                p = path + "." + k if path else k
                if isinstance(o[k], str):
                    r = l2_field(o[k])
                    if r is not None:
                        o[k] = r
                        done.append(p)
                else:
                    rec(o[k], p)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                p = "%s[%d]" % (path, i)
                if isinstance(v, str):
                    r = l2_field(v)
                    if r is not None:
                        o[i] = r
                        done.append(p)
                else:
                    rec(v, p)

    rec(obj, "")
    return done


def merge_servers(cfg):
    out = []
    for key, tag in (("Free_servers", "FREE"), ("Premium_servers", "PREMIUM"),
                     ("Vip_servers", "VIP"), ("Private_servers", "PRIVATE")):
        for s in cfg.get(key) or []:
            s = dict(s)
            s["_tier"] = tag
            out.append(s)
    return out


def build_doc(cfg, source, raw_len):
    servers = merge_servers(cfg)
    return {
        "CREDITS": CREDITS,
        "_source": source,
        "_family": "prince-ocs / my.teamapna.tunnel",
        "_cipher": "XXTEA chained-carry DELTA 0x9E5729B1 key '...|...' (L1 base64 blob + L2 per-field)",
        "_raw_b64_len": raw_len,
        "Version": cfg.get("Version"),
        "Changelogs": cfg.get("Changelogs"),
        "UpdaterLink": cfg.get("UpdaterLink"),
        "Username": cfg.get("Username"),
        "Password": cfg.get("Password"),
        "Free_servers": cfg.get("Free_servers") or [],
        "Premium_servers": cfg.get("Premium_servers") or [],
        "Vip_servers": cfg.get("Vip_servers") or [],
        "Private_servers": cfg.get("Private_servers") or [],
        "Payloads": cfg.get("Payloads") or [],
        "_summary": {
            "servers": len(servers),
            "free": len(cfg.get("Free_servers") or []),
            "premium": len(cfg.get("Premium_servers") or []),
            "vip": len(cfg.get("Vip_servers") or []),
            "private": len(cfg.get("Private_servers") or []),
            "payloads": len(cfg.get("Payloads") or []),
            "categories": sorted({s.get("category") for s in servers if s.get("category")}),
        },
    }


def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def write_txt(path, doc):
    L = []
    L.append("APNA VPN 3.9 — decrypted config")
    L.append(CREDITS)
    L.append("source : %s" % doc["_source"])
    L.append("version: %s    servers: %d    payloads: %d"
             % (doc.get("Version"), doc["_summary"]["servers"], doc["_summary"]["payloads"]))
    L.append("creds  : %s / %s" % (doc.get("Username"), doc.get("Password")))
    L.append("")
    for s in merge_servers(doc):
        hosts = [h for h in (s.get("server_host") or "").split(";") if h]
        L.append("[%s] %s  (%s)" % (s["_tier"], s.get("server_name", "?"), s.get("category", "?")))
        L.append("    hosts(%d): %s%s" % (len(hosts), ", ".join(hosts[:6]),
                                          " ..." if len(hosts) > 6 else ""))
        ports = {k: s.get(k) for k in ("server_port", "server_udp_port", "ssl_port", "squid_port")
                 if s.get(k)}
        if ports:
            L.append("    ports: " + "  ".join("%s=%s" % kv for kv in ports.items()))
    L.append("")
    cats = {}
    for p in doc["Payloads"]:
        cats.setdefault(p.get("category"), []).append(p)
    L.append("Payloads by category (%d total):" % len(doc["Payloads"]))
    for c in sorted(cats, key=lambda x: str(x)):
        L.append("  %-12s %d" % (c, len(cats[c])))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------- main
def _arg(flag, default=None):
    for i, a in enumerate(sys.argv):
        if a == flag and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


def main():
    t0 = time.time()
    print_c("APNA VPN 3.9  —  CONFIG DECRYPTOR\nprince-ocs  ·  XXTEA 0x9E5729B1  ·  key '...|...'")

    cfg = src = None
    raw_len = 0
    force_apk = "--apk" in sys.argv
    apk = _arg("--apk")
    out_dir = _arg("--out-dir", OUT_DIR)
    out_base = _arg("--basename", OUT_BASE)
    out_json = os.path.join(out_dir, out_base + ".json")
    out_txt = os.path.join(out_dir, out_base + ".txt")
    if not force_apk:
        for url in [CONFIG_URL] + ALT_URLS:
            try:
                print("\n[*] live fetch: %s" % url)
                text, ua = fetch(url)
                cfg, raw_len = decrypt_config(text)
                src = url
                print("    ok  %s  (%d chars, UA %s)" % (url, len(text), ua))
                break
            except Exception as exc:      # noqa: BLE001
                print("    fail %s" % exc)

    if cfg is None:
        path = apk or APK_DEFAULT
        print("\n[*] embedded fallback: %s" % path)
        cfg, src = load_embedded(path)

    print("[*] version %s  ·  %d servers  ·  %d payloads"
          % (cfg.get("Version"), len(merge_servers(cfg)), len(cfg.get("Payloads") or [])))

    done = decrypt_l2(cfg)
    print("[*] L2 fields decrypted: %d %s" % (len(done), done if len(done) <= 6 else ""))

    doc = build_doc(cfg, src, raw_len)
    blob_left = [p for p, v in walk(cfg) if isinstance(v, str) and B64_RE.match(v) and l2_field(v)]
    print("[*] residual L2 blobs: %d" % len(blob_left))

    write_json(out_json, doc)
    write_txt(out_txt, doc)

    s = doc["_summary"]
    print_bar("RESULT  v%s · %d servers (free %d) · %d payloads · %s"
              % (doc.get("Version"), s["servers"], s["free"], s["payloads"], ",".join(s["categories"])))
    print("JSON : %s (%d KB)" % (out_json, os.path.getsize(out_json) // 1024))
    print("TXT  : %s" % out_txt)
    print("creds: %s / %s" % (doc.get("Username"), doc.get("Password")))
    print("done in %.2fs" % (time.time() - t0))


if __name__ == "__main__":
    main()
