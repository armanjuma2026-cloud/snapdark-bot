#!/usr/bin/env python3
# NOYPI VPN.py — com.noypi.vpn (v1.8) decryptor  |  @SnapDark 🇧🇩
# Family: renz (NOYPI / renzbarbz config chain) — libovpn3.so ground truth
# Constants @ .rodata: KEY32@0x203c30  IV16@0x203c50  BLOB16(hkdf salt)@0x203c10  SALT32@0x203c9c
#   (BLOB16 == first 16B of SALT32)
#
# OUTER CONFIG (RenzUtils mode 1 = "string chain"), proven empirically:
#   b64 -> AES-128-CBC(key=SHA256(KEY32)[:16], iv=IV16) -> modified-XXTEA(key words=SHA256(KEY32))
#          -> trim to length word v[n-1] -> every byte -2 -> JSON
#   XXTEA = canonical btea algebra with DELTA D1=0x7A56D3E1, sum+0x85A92C1F per round,
#   rounds=6+52//n; verified native==python 2056/2056 (single-round oracle patched1.so).
#
# L2 FIELD DECRYPTION (auto-detected per base64 field):
#   mode1: AES128(SHA256(KEY32)[:16],IV16) -> xxtea(SHA256(KEY32)) -> len-trim -> -2   [Name, ports, UUID...]
#   mode2: b64 -> xxtea(key=PBKDF2-HMAC-SHA256(KEY32, SALT32, 100000)[:16])
#          -> AES-256-CBC(key=PBKDF2 32B, IV=first 16B of xxtea out) -> PKCS7          [Username/Password]
#   mode0: b64 -> MODIFIED Threefish-256 (HKDF32 key, per 32B LE-u64 block) -> NUL-trim
#          -> AES-128-CBC(key=HKDF16, iv=IV16) -> PKCS7                                [hosts, vless URL]
#   Modified Threefish-256 (decoded from threefishEncrypt/DecryptBlockWords, byte-exact vs native):
#     * rotation table = 8 rows cycling mod 8: [14,16],[52,57],[23,40],[5,37],[25,33],[46,12],[58,22],[32,32]
#     * mix: y0=a+b; y1=(a+b)^rol(b,r);  perm [0,3,2,1];  72 rounds, subkeys at d%4==0 + final
#     * subkey i: v0+=k[i%5];  v1+=k[(i+1)%5]+t[i%3];  v2+=k[(i+2)%5]+t[(i+1)%3];
#       v3+=k[(i+3)%5]+i    <-- literal group index, NO tweak word (renz deviation from Skein)
#     * parity k[4]=C240^k0^k1^k2^k3, C240=0x1BD11BDAA9FC1A22; tweak t=(0,0), t2=t0^t1
#   HKDF = HKDF-SHA256 only extract+first-expand-block (native EVP_KDF: digest/salt/key, no info)
#   PBKDF2 = PBKDF2-HMAC-SHA256(pass=KEY32, salt=SALT32, iters=100000, dklen=32)
#            (getPBKDF232BitKey @0x3a91fc: PKCS5_PBKDF2_HMAC 0x186A0 iters)
# Live: update.js @ Civ3snipher/NOYPI-VPN-PRO raw (Authorization: Bearer PAT header required)
# Out:  /sdcard/VPNs/NOYPI VPN VPN ☠️.json  (CREDITS-first house rule)
#
# RESTORED 2026-11-01 from template (~/noypi/noypi_main.py) after another senseitunnel trim:
# BLOB64 snapshot re-extracted from surviving .pyc — verified byte-equal to the live curl blob.
# v2.8 flow: argv file -> live PAT fetch (GitHub/GitLab via fetch_private_raw) -> embedded snapshot.
import base64, hashlib, hmac, json, os, re, struct, io, sys

CREDITS  = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"
CONFIG_URL = "https://raw.githubusercontent.com/Civ3snipher/NEW-VIP-SNIPHER-PRO-3/refs/heads/main/update.json"
PAT      = "Bearer " + bytes([0x67, 0x68, 0x70, 0x5f, 0x33, 0x43, 0x43, 0x44, 0x64, 0x52, 0x41, 0x50, 0x37, 0x31, 0x6c, 0x42, 0x7a, 0x58, 0x63, 0x5a, 0x69, 0x36, 0x67, 0x61, 0x5a, 0x7a, 0x49, 0x79, 0x76, 0x79, 0x62, 0x52, 0x62, 0x55, 0x30, 0x30, 0x6c, 0x49, 0x4c, 0x44]).decode("ascii") + ""
OUT_JSON = "/sdcard/VPNs/NOYPI VPN VPN ☠️.json"
OUT_TXT  = "/sdcard/VPNs/NOYPI VPN VPN ☠️.txt"

KEY32  = bytes.fromhex("1fea453c1c20a9366214bf96b64a26f1b76e32660d02ab66a1ddc878936186b1")
IV16   = bytes.fromhex("82aa46e488644f9f3af6b61b69d214cd")
BLOB16 = bytes.fromhex("c9c5fd1cace2fe51e213935313b2f03b")
SALT32 = bytes.fromhex("c9c5fd1cace2fe51e213935313b2f03ba055190f23b4aced90c36cf3cb43d291")

M32       = 0xFFFFFFFF
D1        = 0x7A56D3E1              # modified DELTA (D1*6 mod 2^32 == 0xDE08F746)
INC       = 0x85A92C1F              # -D1 mod 2^32
SHAKEY    = hashlib.sha256(KEY32).digest()
AES1KEY   = SHAKEY[:16]             # mode-1 AES-128 key
PBK       = hashlib.pbkdf2_hmac("sha256", KEY32, SALT32, 100000, dklen=32)  # mode-2 key
M64       = 0xFFFFFFFFFFFFFFFF
C240      = 0x1BD11BDAA9FC1A22
R8        = [[14,16],[52,57],[23,40],[5,37],[25,33],[46,12],[58,22],[32,32]]

def hkdf(salt, ikm, L):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < L:
        t = hmac.new(prk, t + b"\x01", hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:L]

TFKEY   = list(struct.unpack("<4Q", hkdf(SALT32, KEY32, 32)))   # mode-0 threefish key
AES0KEY = hkdf(BLOB16, KEY32, 16)                               # mode-0 aes key
TWEAK   = (0, 0)                                                # native calls with tweak=0

def rol64(x, n): return ((x << n) | (x >> (64 - n))) & M64_ if n else x
M64_ = M64
def ror64(x, n): return ((x >> n) | (x << (64 - n))) & M64_ if n else x

# ---------------- modified-XXTEA (renz family, canonical-body btea) ----------------
def xxtea_words_dec(data, key16):
    n = len(data) // 4
    if n < 2: return None
    v = list(struct.unpack("<%dI" % n, data))
    k = list(struct.unpack("<4I", key16[:16]))
    rounds = 6 + 52 // n
    s = (rounds * D1) & M32
    y_init = v[0]
    while s != 0:
        e = (s >> 2) & 3
        y = y_init
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ ((z << 4) & M32))) ^
                  ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & M32
            y = v[p] = (v[p] - mx) & M32
        z = v[n - 1]
        mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ ((z << 4) & M32))) ^
              ((s ^ y) + (k[e] ^ z))) & M32
        y_init = v[0] = (v[0] - mx) & M32
        s = (s + INC) & M32
    out = struct.pack("<%dI" % n, *v)
    lw = struct.unpack("<I", out[n*4-4:n*4])[0]
    if 0 < lw <= n*4 - 4:
        return out[:lw]
    return None

# ---------------- modified Threefish-256 (renz) ----------------
def tf_dec_words(words4):
    v = list(words4)
    k = list(TFKEY) + [C240 ^ TFKEY[0] ^ TFKEY[1] ^ TFKEY[2] ^ TFKEY[3]]
    t3 = [TWEAK[0], TWEAK[1], (TWEAK[0] ^ TWEAK[1]) & M64]
    def isub(i):
        v[0] = (v[0] - k[i % 5]) & M64
        v[1] = (v[1] - k[(i+1) % 5] - t3[i % 3]) & M64
        v[2] = (v[2] - k[(i+2) % 5] - t3[(i+1) % 3]) & M64
        v[3] = (v[3] - k[(i+3) % 5] - i) & M64      # literal i (renz deviation)
    isub(18)
    for d in range(71, -1, -1):
        v = [v[0], v[3], v[2], v[1]]
        r = R8[d % 8]
        for lo, hi, rr in ((0, 1, r[0]), (2, 3, r[1])):
            b = ror64(v[hi] ^ v[lo], rr)
            a = (v[lo] - b) & M64
            v[lo], v[hi] = a, b
        if d % 4 == 0:
            isub(d // 4)
    return v

# ---------------- chains ----------------
def aes_cbc(key, iv, data):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

def pkcs7(b):
    pad = b[-1]
    if 1 <= pad <= 16 and b[len(b)-pad:] == bytes([pad]) * pad:
        return b[:len(b)-pad]
    return None

def shift2(b): return bytes((x - 2) & M32 for x in b)

def chain_mode1(raw):
    """AES128 -> xxtea -> len-trim -> -2"""
    if len(raw) % 16: return None
    t = pkcs7(aes_cbc(AES1KEY, IV16, raw))
    if not t: return None
    x = xxtea_words_dec(t, SHAKEY)
    if not x: return None
    return shift2(x)

def chain_mode2(raw):
    """xxtea(PBKDF2[:16]) -> AES256(iv=xxtea-out first 16B)"""
    if len(raw) % 4 or len(raw) < 8: return None
    x = xxtea_words_dec(raw, PBK[:16])
    if not x or len(x) <= 16: return None
    return pkcs7(aes_cbc(PBK, x[:16], x[16:]))

def chain_mode0(raw):
    """threefish-256 per 32B block -> NUL-trim -> AES128"""
    out = bytearray()
    for bi in range((len(raw) + 31) // 32):
        blk = raw[bi*32:(bi+1)*32].ljust(32, b"\x00")
        out += struct.pack("<4Q", *tf_dec_words(struct.unpack("<4Q", blk)))
    t = bytes(out[:len(raw)])
    while t and t[-1] == 0: t = t[:-1]
    if not t or len(t) % 16: return None
    return pkcs7(aes_cbc(AES0KEY, IV16, t))

def printable(b):
    if not b: return False
    try: s = b.decode("utf-8")
    except UnicodeDecodeError: return False
    return all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s)

def dec_field(s):
    sv = s.strip()
    if len(sv) < 8 or len(sv) % 4 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in sv):
        return None
    try: raw = base64.b64decode(sv)
    except Exception: return None
    if len(raw) < 4: return None
    for ch in (chain_mode1, chain_mode2, chain_mode0):
        try: out = ch(raw)
        except Exception: continue
        if out and printable(out):
            return out.decode("utf-8")
    return None

def l2_walk(o, n):
    if isinstance(o, dict):
        for k in o: o[k] = l2_walk(o[k], n)
        return o
    if isinstance(o, list):
        return [l2_walk(v, n) for v in o]
    if isinstance(o, str):
        t = dec_field(o)
        if t is not None:
            n[0] += 1
            return t
    return o

# ---------- private-config fetch helper (GitHub/GitLab PAT-gated raw) — house flow v2.8 ----------
def fetch_private_raw(url, headers=None, timeout=90):
    """GitHub : raw.githubusercontent.com/<owner>/<repo>/<branch>/<file> + 'Authorization: Bearer <PAT>'
       GitLab : gitlab.com/<owner>/<repo>/-/raw/<branch>/<file> + 'PRIVATE-TOKEN: <token>'"""
    import urllib.request
    req = urllib.request.Request(url, headers=dict(headers or {}))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def load_blob():
    """argv file first (offline), live-first (PAT), embedded fallback."""
    if len(sys.argv) > 1:
        txt = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
        m = re.search(r"[A-Za-z0-9+/=]{1000,}", txt)
        b64 = re.sub(r"\s+", "", m.group(0)) if m else re.sub(r"\s+", "", txt)
        raw = base64.b64decode(b64)
        print("local %s: %d B (%d raw)" % (sys.argv[1], len(txt), len(raw)))
        return raw, "local:" + sys.argv[1]
    try:
        data = fetch_private_raw(CONFIG_URL, {"Authorization": PAT})
        txt = data.decode("utf-8", "replace")
        m = re.search(r"[A-Za-z0-9+/=]{1000,}", txt)
        b64 = re.sub(r"\s+", "", m.group(0)) if m else re.sub(r"\s+", "", txt)
        raw = base64.b64decode(b64)
        if len(raw) > 1000:
            print("live HTTP 200, %d B (%d raw)" % (len(data), len(raw)))
            return raw, CONFIG_URL
    except Exception as e:
        print("live fail (%s) -> embedded fallback" % e)
    return base64.b64decode(BLOB64), "embedded:update.js"

BLOB64 = "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"

def main():
    raw, source = load_blob()
    if len(raw) % 16: raise SystemExit("outer blob not 16-aligned (%d)" % len(raw))
    t = aes_cbc(AES1KEY, IV16, raw)
    pad = t[-1]
    if not (1 <= pad <= 16 and t[len(t)-pad:] == bytes([pad])*pad):
        raise SystemExit("outer pkcs7 fail pad=%d" % pad)
    t = t[:len(t)-pad]
    x = xxtea_words_dec(t, SHAKEY)
    if not x: raise SystemExit("outer xxtea len-word fail")
    d = json.loads(shift2(x).decode("utf-8"))
    n = [0]
    d = l2_walk(d, n)
    doc = {"CREDITS": CREDITS, "_source": source}
    doc.update(d)
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    with io.open(OUT_TXT, "w", encoding="utf-8") as f:
        srv = d.get("Servers") or []
        f.write(CREDITS + "\nsource: " + source + "\nVersion: " + str(d.get("Version")) + "\n")
        f.write("creds: %s / %s\nservers: %d\nfields decrypted: %d\n\n" %
                (d.get("Username"), d.get("Password"), len(srv), n[0]))
        for s in srv:
            f.write("- %s [%s] flag=%s tcp=%s ssl=%s\n" % (s.get("Name"), s.get("Subname"),
                    s.get("flag"), s.get("OpenVPNTCPPort"), s.get("OpenVPNSSLPort")))
            v2 = s.get("V2Ray") or {}
            if v2:
                f.write("  host: %s\n  path: %s\n  uuid: %s\n" % (v2.get("V2RayHost"), v2.get("PATH"), v2.get("UUID")))
        nets = d.get("Networks") or []
        for nt in nets:
            f.write("net: %s info=%s tls=%s squid=%s\n" % (nt.get("Name"), nt.get("Info"),
                    nt.get("TLSVersion"), (nt.get("ProxySettings") or {}).get("Squid")))
    print("L2 fields: %d | servers %d" % (n[0], len(srv)))
    print("OUT:", OUT_JSON)

if __name__ == "__main__":
    main()
