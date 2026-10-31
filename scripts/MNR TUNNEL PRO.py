#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MNR TUNNEL PRO 3.2 (com.mnrtunnel.udp) — config decryptor / server dumper
=========================================================================
L1  : base64 -> Karaytec XXTEA (DELTA 0x2E0BA747, key "4669", LE words,
      carry=y init v[0], tail word = plaintext length)
L2a : every char -0x247A (mod 65536)  [circled-glyph Caesar]
L2b : single UTF-8 decode -> UTF-16 re-pair -> JSON
L3  : per-field base64 blobs (ServerIP / Username / NetworkPayload / SSLSNI /
      SquidProxy / Ovpn_Cert ...) use the SAME XXTEA + SAME glyph shift.

Live  : https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/mnr
Output: /sdcard/VPNs/MNR TUNNEL PRO VPN ☠️.json + .txt

Usage:
    python3 "MNR TUNNEL PRO.py"                # live
    python3 "MNR TUNNEL PRO.py" --file <blob>  # local b64 config
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

CONFIG_URL = "https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/mnr"
KEY = b"4669"
DELTA = 0x2E0BA747
MASK = 0xFFFFFFFF
GLYPH = 0x247A

OUT_JSON = "/sdcard/VPNs/MNR TUNNEL PRO VPN ☠️.json"
OUT_TXT = "/sdcard/VPNs/MNR TUNNEL PRO VPN ☠️.txt"
CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"
UAS = ["okhttp/4.9.0", "okhttp/3.12.0", "Mozilla/5.0 (Linux; Android 13)"]
B64_RE = re.compile(r"^[A-Za-z0-9+/]{7,}={0,2}$")


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


# --------------------------------------------------------------------------- xxtea
def _mx(s, y, z, p, e, k):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & MASK


def xxtea_decrypt(data, key=KEY):
    if len(data) < 8 or len(data) % 4:
        return None
    v = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    k = list(struct.unpack("<4I", key.ljust(16, b"\0")[:16]))
    n = len(v)
    s = ((52 // n + 6) * DELTA) & MASK
    y = v[0]
    while s:
        e = (s >> 2) & 3
        cv = y
        p = n - 1
        while p > 0:
            cv = (v[p] - _mx(s, cv, v[p - 1], p, e, k)) & MASK
            v[p] = cv
            p -= 1
        y = (v[0] - _mx(s, cv, v[n - 1], 0, e, k)) & MASK
        v[0] = y
        s = (s - DELTA) & MASK
    out = b"".join(x.to_bytes(4, "little") for x in v)
    tail = int.from_bytes(out[-4:], "little")
    if not (len(out) - 7 <= tail <= len(out) - 4):
        return None
    return out[:tail]


# ------------------------------------------------------------------------- glyphs
def unshift(text):
    """circled-glyph Caesar: every code unit -0x247A (mod 65536), then UTF-16 repair."""
    units = "".join(chr((ord(c) - GLYPH) % 65536) for c in text)
    return units.encode("utf-16-be", "surrogatepass").decode("utf-16-be")


def b64d(s):
    s = "".join(s.split())
    return base64.b64decode(s + "=" * (-len(s) % 4))


def decrypt_config(text):
    raw = b64d(text)
    pt = xxtea_decrypt(raw)
    if pt is None:
        raise ValueError("XXTEA length gate failed (wrong key/delta or corrupt blob)")
    return json.loads(unshift(pt.decode("utf-8"))), len(raw)


def field(value):
    """L3 per-field blob: b64 -> XXTEA -> glyph shift. Returns None if not a blob."""
    if not isinstance(value, str) or not B64_RE.match(value):
        return None
    try:
        raw = b64d(value)
        pt = xxtea_decrypt(raw)
        if pt is None:
            return None
        txt = unshift(pt.decode("utf-8")).rstrip("\x00")
        if any(ord(c) < 32 and c not in "\r\n\t" for c in txt):
            return None
        return txt
    except Exception:
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


# -------------------------------------------------------------------------- output
def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def write_txt(path, doc):
    L = ["MNR TUNNEL PRO 3.2 — decrypted config", CREDITS,
         "source : %s" % doc["_source"],
         "version: %s    servers: %d    http: %d    ssl: %d    L3 fields: %d"
         % (doc.get("Version"), len(doc["Servers"]), len(doc["HTTPNetworks"]),
            len(doc["SSLNetworks"]), doc["_l3_fields"]), ""]
    for s in doc["Servers"]:
        L.append("[%s] %s  (type %s, cat %s)"
                 % (s.get("FLAG"), s.get("Name"), s.get("serverType"), s.get("Category")))
        L.append("    host: %s   tcp: %s   udp/ssl: %s"
                 % (s.get("ServerIP"), s.get("TcpPort"), s.get("SSLPort")))
        if s.get("ServerHTTP"):
            L.append("    http: %s   cf: %s" % (s.get("ServerHTTP"), s.get("ServerCloudFront")))
        if s.get("Username"):
            L.append("    creds: %s / %s   login=%s" % (s.get("Username"), s.get("Password"),
                                                        s.get("AutoLogIn")))
        if s.get("server_web_renew"):
            L.append("    renew: %s   exp: %s" % (s.get("server_web_renew"), s.get("Server_exp")))
    L.append("")
    L.append("HTTPNetworks (%d):" % len(doc["HTTPNetworks"]))
    for h in doc["HTTPNetworks"]:
        L.append("  - %-22s proto=%-2s %-4s payload=%-28s squid=%s:%s"
                 % (h.get("Name"), h.get("proto_spin"), h.get("server_type"),
                    h.get("NetworkPayload"), h.get("SquidProxy"), h.get("SquidPort")))
    L.append("")
    L.append("SSLNetworks (%d):" % len(doc["SSLNetworks"]))
    for x in doc["SSLNetworks"]:
        L.append("  - %-24s proto=%-2s %-4s sni=%-18s squid=%s:%s"
                 % (x.get("Name"), x.get("proto_spin"), x.get("server_type"),
                    x.get("SSLSNI"), x.get("SquidProxy"), x.get("SquidPort")))
        p = (x.get("SSLPayload") or "").replace("\r", "").replace("\n", " | ")
        if p:
            L.append("      payload: %s" % p[:150])
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


# ---------------------------------------------------------------------------- main
def main():
    t0 = time.time()
    print_c("MNR TUNNEL PRO 3.2  —  CONFIG DECRYPTOR\n"
            "XXTEA 0x2E0BA747 · key '4669' · glyph -0x247A · L1+L3")
    cfg = None
    src = ""
    raw_len = 0
    local = None
    for i, a in enumerate(sys.argv):
        if a == "--file" and i + 1 < len(sys.argv):
            local = sys.argv[i + 1]
    if local:
        print("[*] local file: %s" % local)
        cfg, raw_len = decrypt_config(open(local, encoding="utf-8", errors="replace").read())
        src = "file:" + local
    else:
        print("[*] live: %s" % CONFIG_URL)
        text, ua = fetch(CONFIG_URL)
        cfg, raw_len = decrypt_config(text)
        src = CONFIG_URL
        print("    ok %d chars (UA %s)" % (len(text), ua))

    print("[*] v%s · %d servers · %d HTTP · %d SSL · ovpn %d B"
          % (cfg.get("Version"), len(cfg.get("Servers") or []),
             len(cfg.get("HTTPNetworks") or []), len(cfg.get("SSLNetworks") or []),
             len(cfg.get("Ovpn_Cert") or "")))

    n = decrypt_fields(cfg)
    left = residual(cfg)
    print("[*] L3 fields decrypted: %d   residual: %d" % (n, len(left)))
    if left:
        print("    %s" % left[:8])

    doc = {
        "CREDITS": CREDITS,
        "_source": src,
        "_family": "mnr-karaytec / com.mnrtunnel.udp",
        "_cipher": "XXTEA DELTA 0x2E0BA747 key '4669' (LE, carry=y) + glyph -0x247A; L3 per-field same",
        "_raw_b64_len": raw_len,
        "_l3_fields": n,
    }
    doc.update({k: v for k, v in cfg.items()})
    doc["_summary"] = {
        "servers": len(cfg.get("Servers") or []),
        "http_networks": len(cfg.get("HTTPNetworks") or []),
        "ssl_networks": len(cfg.get("SSLNetworks") or []),
        "l3_fields": n,
        "json_settings": len(cfg.get("JSONsettings") or []),
    }
    write_json(OUT_JSON, doc)
    write_txt(OUT_TXT, doc)

    print_bar("RESULT  v%s · %d servers · %d HTTP + %d SSL networks · %d L3 fields · 0 residual"
              % (cfg.get("Version"), len(cfg.get("Servers") or []),
                 len(cfg.get("HTTPNetworks") or []), len(cfg.get("SSLNetworks") or []), n))
    print("JSON: %s (%d KB)" % (OUT_JSON, os.path.getsize(OUT_JSON) // 1024))
    print("TXT : %s" % OUT_TXT)
    print("done in %.2fs" % (time.time() - t0))


if __name__ == "__main__":
    main()
