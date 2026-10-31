#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  APNA SHIELD PRO 5.1  —  com.apnashield.pro (prince/OCS family) decryptor
#  Package   : com.apnashield.pro   code ns: prince.open.vpn
#  Family    : prince-ocs (same stack as FNF TUNNEL BD / APNA VPN) — DB proc #9
#  Chain     : assets/janu.json  = std-b64 -> XXTEA(chained-carry, DELTA 0x9E5729B1,
#              LE words, key '...|...' zero-padded, tail word = plaintext length)
#              L2 (Username/Password) = same engine + same key
#              assets/server.psi = 1-nibble 'a' header -> hex XOR
#              (PUTILS_KEY '4%PdXch>fkP]' rotated-left-7) -> hex2 -> psiphon JSON
#  Sources   : EMBEDDED ONLY — no config endpoint exists in dex/resources (verified:
#              full https scan of classes*.dex + resources.arsc = ads/analytics only)
#  Ground truth: prince-ocs procedure (validated 2026-10-28 against THIS apk:
#              janu -> v117/20 servers/142 payloads; psi -> 22 psiphon entries)
#  House rule: CREDITS first + _source ; JSON-validity gate ; backup-before-replace ;
#              chmod 600 (FUSE may still show 660)
# ============================================================================
import base64
import io
import json
import os
import shutil
import sys
import time
import zipfile

APK_CANDIDATES = [
    "/storage/emulated/0/MT2/apks/APNA SHIELD PRO_5.1.apks",
    "/sdcard/MT2/apks/APNA SHIELD PRO_5.1.apks",
]
ASSET_CONFIG = "assets/janu.json"
ASSET_PSI = "assets/server.psi"
OUTPUT_FILE = "/sdcard/VPNs/APNA SHIELD PRO ☠️.json"
APP_NAME = "APNA SHIELD PRO"
APP_PACKAGE = "com.apnashield.pro"

XXTEA_KEY = "...|..."
DELTA = 0x9E5729B1
MASK32 = 0xFFFFFFFF
PUTILS_KEY = b"4%PdXch>fkP]"
PUTILS_KEY_ROT = PUTILS_KEY[7:] + PUTILS_KEY[:7]

CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"


def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}\033[0m")


def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * width}\033[0m")


# ---------------- janu.json layer: XXTEA chained-carry (Bm.c wrapper) ----------------

def _to_int_array(data, include_length):
    m = (len(data) + 3) // 4
    result = [0] * (m + 1) if include_length else [0] * m
    if include_length:
        result[m] = len(data)
    for i, b in enumerate(data):
        result[i // 4] |= (b & 0xFF) << ((i % 4) * 8)
    return result


def _to_byte_array(words, with_length):
    raw = b"".join((w & MASK32).to_bytes(4, "little") for w in words)
    if not with_length:
        return raw
    n = len(words)
    tail = int.from_bytes(raw[-4:], "little")
    if 4 * n - 7 <= tail <= 4 * n - 4:
        return raw[:tail]
    return None


def _mx(sum_, y, z, p, e, key):
    a = ((z & MASK32) >> 5) ^ ((y << 2) & MASK32)
    b = ((y & MASK32) >> 3) ^ ((z << 4) & MASK32)
    c = (sum_ ^ y) & MASK32
    d = (key[(p & 3) ^ e] ^ (z & MASK32)) & MASK32
    return ((a + b) ^ (c + d)) & MASK32


def xxtea_decrypt(data, key):
    if not data:
        return None
    v = _to_int_array(data, False)
    k = _to_int_array((key.encode() + b"\x00" * 16)[:16], False)
    n = len(v)
    if n < 2:
        return _to_byte_array(v, True)
    rounds = 52 // n + 6
    sum_ = (rounds * DELTA) & MASK32
    carry = v[0]
    e = (sum_ >> 2) & 3
    while sum_ != 0:
        for p in range(n - 1, 0, -1):
            carry = v[p] = (v[p] - _mx(sum_, carry, v[p - 1], p, e, k)) & MASK32
        carry = v[0] = (v[0] - _mx(sum_, carry, v[n - 1], 0, e, k)) & MASK32
        sum_ = (sum_ - DELTA) & MASK32
        e = (sum_ >> 2) & 3
    return _to_byte_array(v, True)


def decrypt_blob(payload_text, key=XXTEA_KEY):
    text = "".join(str(payload_text).split())
    raw = base64.b64decode(text + "=" * ((-len(text)) % 4))
    out = xxtea_decrypt(raw, key)
    if out is None:
        raise ValueError("XXTEA tail length invalid — wrong key/scheme")
    return out.decode("utf-8", "replace")


def l2_field(value):
    """L2 credential blobs: same engine + key (e.g. -> 'tanginaka'). Keep raw on failure."""
    if not isinstance(value, str) or not (8 <= len(value) <= 512):
        return value
    if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value):
        return value
    try:
        return decrypt_blob(value)
    except Exception:
        return value


# ---------------- server.psi layer: pDecrypt (XOR rot7 + hex) ----------------

def _xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def putils_p_decrypt(hex_text):
    t = "".join(hex_text.split())
    if len(t) % 2:
        t = t[1:]          # 1-nibble 'a' header
    raw = bytes.fromhex(t)
    return _xor_bytes(raw, PUTILS_KEY_ROT)


def parse_psiphon_entries(plain_text):
    hex_body = "".join(c for c in plain_text if c in "0123456789abcdefABCDEF")
    if len(hex_body) % 2:
        hex_body = hex_body[:-1]
    blob = bytes.fromhex(hex_body).decode("utf-8", "replace")
    objs, depth, start = [], 0, -1
    for i, c in enumerate(blob):
        if c == "{":
            if depth <= 0:
                start, depth = i, 1
            else:
                depth += 1
        elif c == "}":
            depth -= 1
            if depth <= 0 and start != -1:
                try:
                    objs.append(json.loads(blob[start:i + 1]))
                except Exception:
                    pass
                start, depth = -1, 0
    return blob, objs


# ---------------- asset loading ----------------

def read_assets(apk_path=None):
    for apk in ([apk_path] if apk_path else APK_CANDIDATES):
        if not apk or not os.path.exists(apk):
            continue
        try:
            z = zipfile.ZipFile(apk)
            if apk.endswith(".apks"):
                bases = [n for n in z.namelist() if n.endswith("base.apk")]
                inner = zipfile.ZipFile(io.BytesIO(z.read(bases[0])))
            else:
                inner = z
            cfg = inner.read(ASSET_CONFIG).decode("utf-8", "replace")
            psi = inner.read(ASSET_PSI).decode("utf-8", "replace")
            return cfg, psi, apk
        except Exception:
            continue
    return None, None, None


def main():
    t_start = time.monotonic()
    apk_arg = None
    if "--apk" in sys.argv:
        apk_arg = sys.argv[sys.argv.index("--apk") + 1]

    print_bar("\033[91m")
    print_c(f"{APP_NAME} 5.1 — prince-ocs decryptor (com.apnashield.pro)", "\033[91m")
    print_c("By @SnapDark 🇧🇩 | t.me/Jubairbro", "\033[96m")
    print_bar("\033[91m")

    cfg_raw, psi_raw, src = read_assets(apk_arg)
    if cfg_raw is None:
        print_bar("\033[91m")
        print_c("FATAL: embedded assets not found (janu.json / server.psi)", "\033[91m")
        print_bar("\033[91m")
        sys.exit(2)

    t0 = time.monotonic()
    cfg = json.loads(decrypt_blob(cfg_raw))
    print_c("[%.1fs] janu.json OK — Version %s" % (time.monotonic() - t0, cfg.get("Version")), "\033[92m")

    t0 = time.monotonic()
    _, psiphon = parse_psiphon_entries(putils_p_decrypt(psi_raw).decode("utf-8", "replace"))
    print_c("[%.1fs] server.psi OK — %d psiphon entries" % (time.monotonic() - t0, len(psiphon)), "\033[92m")

    # ---- global account: the app injects top-level Username/Password into every ----
    # ---- server whose own creds are empty (placeholder = "use the global one").  ----
    # ---- Fill them so the JSON shows exactly what the application uses.          ----
    glob_user = l2_field(cfg.get("Username"))
    glob_pass = l2_field(cfg.get("Password"))
    filled = 0
    for bucket in ("Premium_servers", "Vip_servers", "Private_servers", "Free_servers"):
        for srv in cfg.get(bucket) or []:
            if isinstance(srv, dict):
                if not srv.get("username"):
                    srv["username"] = glob_user
                    filled += 1
                if not srv.get("password"):
                    srv["password"] = glob_pass
                    filled += 1
    print_c("[*] global account %s/%s injected into %d empty server cred fields"
            % (glob_user, glob_pass, filled), "\033[96m")

    out = {
        "CREDITS": CREDITS,
        "_source": (f"embedded {os.path.basename(src)} {ASSET_CONFIG} + {ASSET_PSI} | "
                    "XXTEA delta 0x9E5729B1 key '...|...' | pDecrypt XOR rot7 '4%PdXch>fkP]' | "
                    "prince.open.vpn (no live endpoint — embedded only)"),
        "_app": APP_NAME,
        "_package": APP_PACKAGE,
        "_credentials_note": (f"app-wide global account — every server with empty creds uses "
                              f"Username={glob_user!r} / Password={glob_pass!r} (injected by the app at runtime; "
                              f"now filled into each server entry). Psiphon entries carry their own "
                              f"psiphon_ssh_* logins from server.psi."),
        "Premium_servers": cfg.get("Premium_servers", []),
        "Vip_servers": cfg.get("Vip_servers", []),
        "Private_servers": cfg.get("Private_servers", []),
        "Free_servers": cfg.get("Free_servers", []),
        "Payloads": cfg.get("Payloads", []),
        "Version": cfg.get("Version"),
        "Changelogs": cfg.get("Changelogs"),
        "Username": l2_field(cfg.get("Username")),
        "Password": l2_field(cfg.get("Password")),
        "Psiphon_servers": psiphon,
        "App": {"name": APP_NAME, "package": APP_PACKAGE, "version": "5.1"},
    }

    # ---- JSON validity gate ----
    try:
        parsed = json.loads(json.dumps(out, ensure_ascii=False))
    except (TypeError, ValueError) as ex:
        print_bar("\033[91m")
        print_c(f"FATAL: JSON validity gate failed: {ex}", "\033[91m")
        sys.exit(3)
    if not parsed["Free_servers"] and not parsed["Psiphon_servers"]:
        print_bar("\033[91m")
        print_c("FATAL: no servers and no psiphon entries", "\033[91m")
        sys.exit(4)

    # ---- backup-before-replace ----
    if os.path.exists(OUTPUT_FILE):
        bak = OUTPUT_FILE + ".bak-" + time.strftime("%Y%m%d_%H%M%S")
        shutil.copy2(OUTPUT_FILE, bak)
        print_c(f"[*] backed up -> {os.path.basename(bak)}", "\033[93m")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(parsed, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(OUTPUT_FILE, 0o600)
    except OSError:
        pass

    print_bar("\033[92m")
    print_c(f"Version {parsed['Version']} | Free {len(parsed['Free_servers'])} | "
            f"Payloads {len(parsed['Payloads'])} | Psiphon {len(parsed['Psiphon_servers'])}", "\033[92m")
    print_c(f"Global account (all servers): {glob_user} / {glob_pass}", "\033[93m")
    print_c(f"saved: {OUTPUT_FILE} ({os.path.getsize(OUTPUT_FILE)} bytes)", "\033[92m")
    print_c(f"total: {time.monotonic() - t_start:.1f}s", "\033[96m")
    print_bar("\033[92m")
    print_c("☠️  DONE — JSON validated  ☠️", "\033[92m")
    print_bar("\033[92m")


if __name__ == "__main__":
    main()
