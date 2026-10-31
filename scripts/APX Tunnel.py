# Python By @SnapDark 🇧🇩
# APX Tunnel VPN - Live Config Decryptor (full server + network unlock)
# Cracked: update.js envelope (AES-128-CBC + RenzXXTEA + Caesar-2),
#          fields: mode0/1/2 (Threefish-256-CTR via native lib, HKDF, PBKDF2)

import os, sys, re, json, base64, glob, ctypes, zipfile, struct, hashlib, hmac, tempfile, unicodedata, shutil
from urllib.request import urlopen, Request

def install(pkg):
    os.system(f"{sys.executable} -m pip install {pkg} -q")
try:
    from Crypto.Cipher import AES
except ImportError:
    install("pycryptodome")
    from Crypto.Cipher import AES

def print_c(text, color="w"):
    colors = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "b": "\033[94m",
              "m": "\033[95m", "c": "\033[96m", "w": "\033[0m"}
    print(colors.get(color, "") + text + "\033[0m")

CREDITS = "Decrypted By @SnapDark 🇧🇩"
URL = "https://raw.githubusercontent.com/Techbuy6/APX-Tunnel-VPN/refs/heads/main/update.js"
KEY32 = bytes.fromhex("9cdeeb9c7cbd64930445474c1acdb9f1f370863466d55ccda0b9d07dfa83f991")
import re as _re
_BB = _re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")
RAW_LOCKED = False  # True -> replace unreadable values with placeholder
FIXED_SALT = bytes.fromhex("8cc8577f1a4c5ca5b681a45da9bee9785034724c7a30375a39d4661e16de31dc")
CONST_IV = bytes.fromhex("b667089d11e619d6b930641e74c51dbe")
M = 0xffffffff
SHA16 = hashlib.sha256(KEY32).digest()[:16]
HK16 = hkdf = None

def hkdf_sha256(ikm, salt, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""; t = b""; c = 1
    while len(out) < length:
        t = hmac.new(prk, t + bytes([c]), hashlib.sha256).digest()
        out += t; c += 1
    return out[:length]

HK16 = hkdf_sha256(KEY32, FIXED_SALT[:16], 16)
DK32 = hashlib.pbkdf2_hmac("sha256", KEY32, FIXED_SALT, 100000, 32)

def unpad7(b):
    if b:
        p = b[-1]
        if 1 <= p <= 16 and b[-p:] == bytes([p]) * p:
            return b[:-p]
    return b

def xxtea_dec(data, key):
    if len(data) < 8 or len(data) % 4:
        return None
    n = len(data) // 4
    v = [int.from_bytes(data[i * 4:i * 4 + 4], "little") for i in range(n)]
    k = [int.from_bytes(key[i * 4:i * 4 + 4], "little") for i in range(4)]
    D = 0x7A56D3E1
    r = 6 + 52 // n
    s = (r * D) & M
    u = lambda x: x & M
    for _ in range(r):
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            y = v[p + 1] if p + 1 < n else v[0]
            z = v[p - 1]
            mx = u(u(u(z >> 5) ^ u(y << 2)) + u(u(z << 4) ^ u(y >> 3))) ^ u(u(s ^ y) + u(k[e ^ (p & 3)] ^ z))
            v[p] = u(v[p] - mx)
        y = v[1]; z = v[n - 1]
        mx = u(u(u(z >> 5) ^ u(y << 2)) + u(u(z << 4) ^ u(y >> 3))) ^ u(u(s ^ y) + u(k[e] ^ z))
        v[0] = u(v[0] - mx)
        s = u(s - D)
    ln = v[-1]
    out = b"".join(x.to_bytes(4, "little") for x in v)[:-4]
    return out[:ln] if 0 < ln <= len(out) else None

def aes128_cbc(data, key, iv):
    if not data or len(data) % 16:
        return None
    try:
        return unpad7(AES.new(key, AES.MODE_CBC, iv).decrypt(data))
    except Exception:
        return None

# ---------- native threefish (extracted from the app itself) ----------
def find_lib():
    cache = "/data/data/com.termux/files/usr/tmp/libovpn3_apx.so"
    if os.path.exists(cache):
        return cache
    for pre in ("/data/data/com.termux/files/usr/tmp/apxlib/libovpn3.so",):
        if os.path.exists(pre):
            try:
                shutil.copyfile(pre, cache)
            except Exception:
                pass
            return pre
    pats = ["/storage/emulated/0/MT2/apks/APX*Tunnel*", "/sdcard/VPNs/APX*",
            "/storage/emulated/0/MT2/apks/*APX*"]
    for pat in pats:
        for a in glob.glob(pat):
            try:
                z = zipfile.ZipFile(a)
                names = z.namelist()
                so = "lib/arm64-v8a/libovpn3.so"
                if so in names:
                    open(cache, "wb").write(z.read(so))
                    return cache
                for sp in names:
                    if sp.startswith("split_config.arm64"):
                        import io
                        s = zipfile.ZipFile(io.BytesIO(z.read(sp)))
                        if so in s.namelist():
                            open(cache, "wb").write(s.read(so))
                            return cache
            except Exception:
                pass
    return None

class Native:
    def __init__(self):
        p = find_lib()
        if not p:
            raise RuntimeError("APX apk not found (needed for Threefish-256)")
        self.lib = ctypes.CDLL(p)
        c = ctypes
        self.lib.threefishSetKey.argtypes = [c.c_void_p, c.c_int, c.c_void_p, c.c_void_p]
        self.lib.threefishDecryptBlockWords.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p]
        self.lib.getHKDF32BitKey.argtypes = [c.c_char_p, c.c_size_t, c.c_void_p]
        hk = c.create_string_buffer(64)
        self.lib.getHKDF32BitKey(KEY32, 32, hk)
        self.hk32 = c.create_string_buffer(hk.raw[:32], 32)
        dk = c.create_string_buffer(64)
        self.lib.getPBKDF232BitKey(KEY32, 32, dk)
        self.dk32 = dk.raw[:32]
        h16 = c.create_string_buffer(64)
        self.lib._Z15generateHKDFKeyPKhmPh(KEY32, 32, h16)
        self.hk16 = h16.raw[:16]
        self.xx = self.lib.xxtea_decrypt
        self.xx.restype = c.c_void_p
        self.xx.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p,
                            c.POINTER(c.c_size_t)]

    def nxx(self, data, key):
        if not data or len(data) % 4:
            return None
        k = ctypes.create_string_buffer(key, 32)
        ol = ctypes.c_size_t(0)
        p = self.xx(data, len(data), ctypes.cast(k, ctypes.c_void_p), ctypes.byref(ol))
        if not p or not ol.value:
            return None
        return ctypes.string_at(p, ol.value)

    def tf_ctr(self, data):
        n = len(data)
        buf = ctypes.create_string_buffer(data + b"\0" * 16, n + 16)
        out = ctypes.create_string_buffer(n + 16)
        ctx = ctypes.create_string_buffer(8192)
        cp = ctypes.c_void_p
        for i in range((n + 31) // 32):
            tw = ctypes.create_string_buffer(struct.pack("<QQ", i, 0), 16)
            self.lib.threefishSetKey(cp(ctypes.addressof(ctx)), 256, cp(ctypes.addressof(self.hk32)), cp(ctypes.addressof(tw)))
            self.lib.threefishDecryptBlockWords(cp(ctypes.addressof(ctx)),
                cp(ctypes.addressof(buf) + i * 32), cp(ctypes.addressof(out) + i * 32))
        return out.raw

NAT = None

def printable(v):
    if not v:
        return False
    ok = 0
    for c in v:
        if 32 <= c < 127 or c >= 0x80:
            ok += 1
    return ok >= len(v) * 0.95 and b"\0" not in v

def printable_txt(s):
    if not s:
        return False
    for c in s:
        o = ord(c)
        if o in (9, 10, 13):
            continue
        if 32 <= o < 127:
            continue
        if unicodedata.category(c) in ("Cc", "Cs", "Co", "Cn", "Zl", "Zp") or c == "\ufffd":
            return False
    return True

def dec_mode0(b):
    pt = aes128_cbc(b, SHA16, CONST_IV)
    if pt is None:
        return None
    x = xxtea_dec(pt, SHA16)
    if x is None:
        return None
    out = bytes((c - 2) % 256 for c in x)
    return out if printable(out) else None

def dec_mode1(b):
    t = NAT.tf_ctr(b)
    n = len(b)
    for cand in (t[:n].rstrip(b"\0"), t[:n - (n % 16)], t.rstrip(b"\0")):
        if len(cand) % 16:
            continue
        pt = aes128_cbc(cand, HK16, CONST_IV)
        if pt is not None and printable(pt):
            return pt
    return None

def dec_mode2(b):
    dk = NAT.dk32 if NAT else DK32
    x = xxtea_dec(b, dk)
    if x is None or len(x) < 32 or len(x) % 16:
        return None
    pt = aes128_cbc(x[16:], dk, x[:16])
    return pt if pt is not None and printable(pt) else None

def dec_multi(b):
    dk = NAT.dk32 if NAT else DK32
    h16 = NAT.hk16 if NAT else HK16
    D = b + b"\0" * ((-len(b)) % 16)
    keys = [SHA16, dk, KEY32, h16 + b"\0" * 16, hashlib.md5(b"APX").digest(),
            NAT.hk32.raw if NAT else b""]
    ivs = [CONST_IV, b[:16], bytes(16), dk[:16]]
    for key in keys:
        if not key:
            continue
        for iv in ivs + [key[:16]]:
            try:
                a = AES.new(key, AES.MODE_CBC, iv).decrypt(D[:len(D) // 16 * 16])
            except Exception:
                continue
            a = unpad7(a).rstrip(b"\0")
            for post in (a, bytes((c - 2) % 256 for c in a)):
                try:
                    t = post.decode("utf-8")
                    if printable_txt(t):
                        return post
                except Exception:
                    pass
                x = NAT.nxx(post, key) if NAT else None
                if x is None and key in (SHA16, dk):
                    x = xxtea_dec(post, key)
                if not x:
                    continue
                for v in (x, unpad7(x).rstrip(b"\0"),
                          bytes((c - 2) % 256 for c in unpad7(x).rstrip(b"\0"))):
                    try:
                        t = v.decode("utf-8")
                        if printable_txt(t):
                            return v
                    except Exception:
                        pass
                    if len(v) >= 32:
                        for iv2 in (v[:16], key[:16], CONST_IV):
                            try:
                                pt = unpad7(AES.new(key, AES.MODE_CBC, iv2).decrypt(
                                    v[16:len(v) // 16 * 16])).rstrip(b"\0")
                            except Exception:
                                continue
                            try:
                                t = pt.decode("utf-8")
                                if printable_txt(t):
                                    return pt
                            except Exception:
                                pass
    if NAT:
        for key in keys:
            if not key:
                continue
            x = NAT.nxx(D, key)
            if not x:
                continue
            for v in (x, unpad7(x).rstrip(b"\0"),
                      bytes((c - 2) % 256 for c in x),
                      bytes((c - 2) % 256 for c in unpad7(x).rstrip(b"\0"))):
                if len(v) < 32:
                    continue
                for iv2 in (v[:16], key[:16], CONST_IV, bytes(16)):
                    for kl in (16, 32):
                        try:
                            pt = unpad7(AES.new(key[:kl], AES.MODE_CBC, iv2).decrypt(
                                v[16:len(v) // 16 * 16])).rstrip(b"\0")
                        except Exception:
                            continue
                        try:
                            t = pt.decode("utf-8")
                            if printable_txt(t):
                                return pt
                        except Exception:
                            pass
    return None

def field(s):
    if not isinstance(s, str) or len(s) < 16:
        return s
    try:
        b = base64.b64decode(s, validate=True)
    except Exception:
        return s
    if len(b) < 16:
        return s
    for fn in (dec_mode0, dec_mode1, dec_mode2, dec_multi):
        try:
            v = fn(b)
        except Exception:
            v = None
        if v is not None:
            try:
                t = v.decode("utf-8")
                if printable_txt(t):
                    return t
            except Exception:
                pass
    return s

def walk(o):
    if isinstance(o, dict):
        return {k: walk(v) for k, v in o.items()}
    if isinstance(o, list):
        return [walk(v) for v in o]
    if isinstance(o, str):
        if o.startswith("{") and "'" in o:
            try:
                return walk(ast_parse(o))
            except Exception:
                pass
        return field(o)
    return o

import ast
def ast_parse(s):
    return ast.literal_eval(s)

def main():
    global NAT
    print_c("=" * 60, "c")
    print_c("   APX TUNNEL VPN - FULL CONFIG DECRYPTOR", "y")
    print_c("   " + CREDITS, "g")
    print_c("=" * 60, "c")
    print_c("[*] Fetching live config...", "b")
    req = Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    raw = urlopen(req, timeout=30).read()
    data = base64.b64decode(raw)
    pt = aes128_cbc(data, SHA16, CONST_IV)
    if pt is None:
        print_c("[!] Envelope AES failed", "r"); return
    x = xxtea_dec(pt, SHA16)
    if x is None:
        print_c("[!] Envelope XXTEA failed", "r"); return
    cfg = bytes((c - 2) % 256 for c in x).decode("utf-8")
    j = json.loads(cfg)
    print_c(f"[+] Version : {j.get('Version')}", "g")
    print_c(f"[+] Servers : {len(j.get('Servers', []))}", "g")
    print_c(f"[+] Networks: {len(j.get('Networks', []))}", "g")
    print_c("[*] Loading native Threefish-256 from app...", "b")
    try:
        NAT = Native()
    except Exception as e:
        NAT = None
        print_c(f"[!] Native lib unavailable ({e}) - server fields partial", "y")
    print_c("[*] Decrypting fields...", "b")
    out = walk(j)
    still = []
    def _w(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(v, str) and _BB.match(v):
                    still.append((x, k, v))
                else:
                    _w(v)
        elif isinstance(x, list):
            for i, v in enumerate(x):
                if isinstance(v, str) and _BB.match(v):
                    still.append((x, i, v))
                else:
                    _w(v)
    _w(out)
    if RAW_LOCKED:
        for obj, k, v in still:
            obj[k] = "LOCKED (publisher corrupt entry)"
    elif still:
        out["locked_fields"] = [str(v)[:24] + "..." for *_, v in still]
    for srv in out.get("Servers", []):
        print_c(f"  ☠ {srv.get('Name')} | {str(srv.get('ServerIPHost'))[:40]}", "c")
    if isinstance(out.get("Notes"), str) and out["Notes"].strip():
        print_c(f"[] Notes: {out['Notes']}", "m")
    for d in ("/sdcard/VPNs", tempfile.gettempdir()):
        try:
            os.makedirs(d, exist_ok=True)
            fp = os.path.join(d, "APX Tunnel VPN \u2620\ufe0f.json")
            out = {"CREDITS": CREDITS, "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell", **out}
            json.dump(out, open(fp, "w"), indent=2, ensure_ascii=False)
            print_c(f"[+] Saved: {fp}", "g")
            break
        except Exception:
            continue
    print_c("[+] " + CREDITS, "y")

if __name__ == "__main__":
    main()
