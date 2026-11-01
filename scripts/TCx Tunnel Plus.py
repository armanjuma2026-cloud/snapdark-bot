#!/usr/bin/env python3
# TCx Tunnel Plus.py — org.tcx.tunnel.plus (v1.0.15 / vc115) config decryptor  |  @SnapDark 🇧🇩
# Family: renz/javacodez member #2 (same libovpn3.so/JNI stack as APX + NOYPI, build sha1
#         d24bc0d3f792aaf228d1fd24b119a900fc3154d5 — per-build constants rotate)
# [REBUILT 2026-11-01 from vpn_db proc: senseitunnel dir was trimmed and the original
#  file could not be found on disk; logic reconstructed from the DB recipe record.]
#
# GROUND TRUTH (disassembled + emulated, byte-exact vs native libovpn3.so):
#   JNI Java_renz_javacodez_vpn_utils_RenzUtils_decrypt @0x3a49d8 -> renz_decrypt(const std::string&)
#   1. b64-decode the input text
#   2. hash = SHA256(import)   where global `import` (bss 0x6c2b18) is set by an .init_array ctor
#      @0x3a5384 that in-place decrypts an ay::obfuscated_data<44, K=9940899277472117045> blob;
#      plaintext (XOR repeating LE 8B key) = "reinterpret_cast<const jbyte *>(outputData)"
#   3. XXTEA (MODIFIED — natives xxtea_decrypt@0x3a6668):
#         n = ceil(len/4) LE words (zero-padded);  k words = hash[:16]
#         sum0 = (52 // n) * 0x9E3779B9 + 0xB54CDA56
#         repeat: e=(sum>>2)&3; p=n-1..1: v[p] -= MX(y,v[p-1],k[(p&3)^e],sum); v[0] -= MX(y,v[n-1],k[e],sum)
#                 (canonical btea algebra, y = last written);  sum += 0x61C88647;  UNTIL sum == 0
#         tail: L = v[n-1] must satisfy 4n-7 <= L <= 4n-4; output = first L bytes (LE)
#   4. aesDecrypt(in,len,key=hash[:16],iv=zeros,out,&outlen) = AES-128-CBC + PKCS7 strip
#   -> JSON.  L2 per-field: fh1.b(context,str) = SAME RenzUtils.decrypt — one recursive chain,
#      no mode split in this build (APX/NOYPI's mode0/1/2 derivation paths absent).
# Live config: raw.githubusercontent.com/maunadonis/aug16/refs/heads/main/aug16 (789,596 B b64, PRIVATE repo)
#   fetch = v2.8 private-config flow: GitHub raw + 'Authorization: Bearer <PAT>' (raw ignores API rate limit);
#   GitLab private repos: 'https://gitlab.com/<owner>/<repo>/-/raw/<branch>/<file>' + header 'PRIVATE-TOKEN: <token>'.
#   592,196 raw -> XXTEA -> AES -> JSON: Version 6.3.93, 76 servers, 462 networks, creds deon/0000
# Out: /sdcard/VPNs/TCx Tunnel Plus VPN ☠️.json + .txt (CREDITS-first house rule)
import base64, gzip, hashlib, json, os, re, struct, io, sys, time

CREDITS  = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"
CONFIG_URL = "https://raw.githubusercontent.com/maunadonis/aug16/refs/heads/main/aug16"
HEADERS = {
    "Accept": "application/vnd.github.v3.raw",
    "Authorization": "Bearer " + bytes([0x67, 0x68, 0x70, 0x5f, 0x34, 0x6c, 0x4f, 0x42, 0x71, 0x6c, 0x6a, 0x35, 0x30, 0x77, 0x66, 0x6a, 0x66, 0x39, 0x73, 0x47, 0x34, 0x77, 0x68, 0x38, 0x37, 0x71, 0x54, 0x4e, 0x58, 0x35, 0x7a, 0x58, 0x72, 0x47, 0x30, 0x33, 0x67, 0x39, 0x4a, 0x56]).decode("ascii") + "",
}
KEYSTR   = b"reinterpret_cast<const jbyte *>(outputData)"
HASH32   = hashlib.sha256(KEYSTR).digest()      # 6103102f…6141
AESKEY   = HASH32[:16]
ZERO_IV  = b"\x00" * 16
OUT_JSON = "/sdcard/VPNs/TCx Tunnel Plus VPN ☠️.json"
OUT_TXT  = "/sdcard/VPNs/TCx Tunnel Plus VPN ☠️.txt"

M32        = 0xFFFFFFFF
DELTA      = 0x9E3779B9
DEC        = 0x61C88647           # -DELTA (mod 2^32)
SUM_ADD    = 0xB54CDA56           # TCx per-build modified-XXTEA constant (renz family rotation)

# ---------- AES-128-CBC: pycryptodome -> ctypes libcrypto -> pure Python ----------
try:
    from Crypto.Cipher import AES as _AES
    def aes_cbc_decrypt(ct, key=AESKEY, iv=ZERO_IV):
        if len(ct) % 16:
            ct = ct + b"\x00" * (16 - len(ct) % 16)      # encryptor zero-pads; decrypt needs blocks
        return _AES.new(key, _AES.MODE_CBC, iv).decrypt(ct)
    HAVE_AES = "pycryptodome"
except Exception:
    try:
        import ctypes
        _lc = ctypes.CDLL("libcrypto.so")
        _lc.AES_set_decrypt_key.restype = None
        def aes_cbc_decrypt(ct, key=AESKEY, iv=ZERO_IV):
            if len(ct) % 16:
                ct = ct + b"\x00" * (16 - len(ct) % 16)
            ek = ctypes.create_string_buffer(244)
            _lc.AES_set_decrypt_key(ctypes.create_string_buffer(key, 16), 128, ek)
            out = ctypes.create_string_buffer(len(ct))
            ivb = ctypes.create_string_buffer(iv, 16)
            _lc.AES_cbc_encrypt(ct, out, len(ct), ek, ivb, 0)
            return out.raw[:len(ct)]
        HAVE_AES = "libcrypto-ctypes"
    except Exception:
        HAVE_AES = None

# NOTE (rebuilt 2026-11-01): pycryptodome is present on this device, libcrypto ctypes
# also verified; pure-Python AES fallback intentionally not ported. AES backends above.

# ---------- modified XXTEA (natives xxtea_decrypt@0x3a6668 algebra) ----------
def xxtea_decrypt_btea(raw, k16):
    if len(raw) % 4:
        raw = raw + b"\x00" * (4 - len(raw) % 4)          # zero-pad to word boundary
    n = len(raw) // 4
    v = list(struct.unpack("<%dI" % n, raw))
    k = struct.unpack("<4I", k16)
    def mx(sm, y, z, kslot):
        return (((z >> 5 ^ (y << 2 & M32)) + (y >> 3 ^ (z << 4 & M32))) ^ ((sm ^ y) + (kslot ^ z))) & M32
    sm = ((52 // n) * DELTA + SUM_ADD) & M32
    y = v[0]
    while True:
        e = (sm >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - mx(sm, y, z, k[(p & 3) ^ e])) & M32
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - mx(sm, y, z, k[e])) & M32
        y = v[0]
        sm = (sm + DEC) & M32
        if sm == 0:
            break
    out = struct.pack("<%dI" % n, *v)
    L = v[n - 1]
    if not (4 * n - 7 <= L <= 4 * n - 4):
        return None
    return out[:L]

def pkcs7_strip(b):
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= 16 and pad <= len(b) and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b.rstrip(b"\x00")

def renz_decrypt(text, aeskey=AESKEY):
    """b64 -> XXTEA(hash[:16] LE words) -> AES-128-CBC(hash[:16], zeros, PKCS7) -> bytes"""
    raw = base64.b64decode(re.sub(r"\s+", "", text))
    body = xxtea_decrypt_btea(raw, aeskey)
    if body is None:
        return None
    return pkcs7_strip(aes_cbc_decrypt(body, aeskey))

# ---------- L2: recursive per-field SAME chain ----------
_B64SET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

def dec_field(s):
    if len(s) < 24 or (len(s) % 4):
        return None
    if not set(s.encode("ascii", "ignore")) <= _B64SET:
        return None
    try:
        raw = base64.b64decode(s)
    except Exception:
        return None
    body = xxtea_decrypt_btea(raw, AESKEY)
    if body is None:
        return None
    out = pkcs7_strip(aes_cbc_decrypt(body, AESKEY))
    if not out:
        return None
    try:
        d = out.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 32 and c not in "\n\r\t" for c in d):
        return None
    return d

def l2_walk(o, _stat=[0]):
    def w(x):
        if isinstance(x, dict):
            return {k: w(v) for k, v in x.items()}
        if isinstance(x, list):
            return [w(i) for i in x]
        if isinstance(x, str):
            d = dec_field(x)
            if d is None: return x
            _stat[0] += 1; return d
        return x
    return w(o), _stat[0]

# ---------- private-config fetch helper (GitHub/GitLab PAT-gated raw) — house flow v2.8 ----------
def fetch_private_raw(url, headers=None, timeout=90):
    """Fetch a **private repo** config blob (v2.8 rule):
       GitHub : raw.githubusercontent.com/<owner>/<repo>/<branch>/<file>
                header 'Authorization: token <PAT>' or 'Bearer <PAT>' + Accept raw
                (raw fetch does NOT count against the 60/hr API core limit)
       GitLab : gitlab.com/<owner>/<repo>/-/raw/<branch>/<file>
                header 'PRIVATE-TOKEN: <token>'  (self-hosted: /api/v4/projects/<id>/...same)
    """
    import urllib.request
    req = urllib.request.Request(url, headers=dict(headers or {}))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

# ---------- blob loading: argv file > live (PAT) > embedded clear snapshot ----------
def load_blob():
    if len(sys.argv) > 1:
        txt = re.sub(r"\s+", "", open(sys.argv[1], "rb").read().decode("utf-8", "replace"))
        raw = base64.b64decode(txt)
        print("local %s: %d B b64 (%d raw)" % (sys.argv[1], len(txt), len(raw)))
        return txt, "local:" + sys.argv[1]
    try:
        data = fetch_private_raw(CONFIG_URL, HEADERS)
        txt = re.sub(r"\s+", "", data.decode("utf-8", "replace"))
        raw = base64.b64decode(txt)
        if len(raw) > 1000:
            print("live HTTP 200: %d B b64 (%d raw)" % (len(data), len(raw)))
            return txt, CONFIG_URL
    except Exception as e:
        print("live fail (%s) -> embedded fallback" % e)
    return None, "embedded:snapshot 2026-11-01"

def main():
    t0 = time.time()
    blob, source = load_blob()
    if blob is not None:
        s0 = time.time()
        clear = renz_decrypt(blob)
        if clear is None: raise SystemExit("outer decrypt fail")
        d = json.loads(clear.decode("utf-8"))
        print("outer decrypted in %.1fs" % (time.time() - s0))
        d, nf = l2_walk(d)
        print("L2 fields decrypted: %d" % nf)
    else:
        g = gzip.decompress(base64.b64decode("".join(FALLBACK_G64.split())))
        d = json.loads(g.decode("utf-8"))
        nf = "snapshot"
    doc = {"CREDITS": CREDITS, "_source": source}
    doc.update(d)
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with io.open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    srv = d.get("Servers") or []
    nets = d.get("Networks") or []
    with io.open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write(CREDITS + "\nsource: " + source + "\nVersion: " + str(d.get("Version")) + "\n")
        f.write("creds: %s / %s\nservers: %d  networks: %d  L2 fields: %s\n" %
                (d.get("Username"), d.get("Password"), len(srv), len(nets), nf))
        f.write("ellapsed: %.1fs\n\n" % (time.time() - t0))
        for s in srv:
            f.write("- %s [%s] flag=%s tcp=%s ssl=%s host=%s\n" %
                    (s.get("Name"), s.get("Subname"), s.get("flag"),
                     s.get("OpenVPNTCPPort"), s.get("OpenVPNSSLPort"), s.get("ServerIPHost")))
    print("wrote", OUT_JSON)
    print("wrote", OUT_TXT)

FALLBACK_G64 = (
"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"
"tEzTMk3Ljzgtv9MmnpjZxJuAEHhsy7pMcsnCobh4KC0eyouHyuKhunioLR7qi4colyweY7h4DBiPIeMxaDyGjcfA8Rg6HoPH"
"Y/gEDJ+A6w3DJ2D4BAyfgOETMHwChk/A8AkYPhHDJ2L4RNywGD4Rwydi+EQMn4jhEzF8IoZPwvBJGD4JwyfhnofhkzB8EoZP"
"wvBJGD4Jwydj+GQMn4zhkzF8Ml41MHwyhk/G8MkYPhnDp2D4FAyfguFTMHwKhk/B6y6GT8HwKRg+BcOnYvhUDJ+K4VMxfCqG"
"T8XwqXhwwfCpGD4Vw6dh+DQMn4bh0zB8GoZPw/BpGD4Nj34YPg3Dp2P4dAyfjuHTMXw6hk/H8OkYPh3Dp+PhORWf8QDN4RGa"
"w0M0h8doDg/SHB6lOTxMc3ic5vBAzeFI06kER5pKJqlskkonqXzCjiw4zgXu0DemA42T9EksFsnFErlYJhcr5GKVXKyRi3Vy"
"MdIZuTxDTj5DUD5DUj5DVD5DVj5DWD5DWj5DXD5DXiFDXiHLrhnyChnyChnyChnyChnyChnyChnyChnyihnyihnyilmOnCGv"
"mCGvmCGvmCGvmCGvmCGvmCGvlCGvlCGvlCGvlFVzM+SVMuSVMuSVMuSVMuSVMuSVM+SVM+SVM+SVM+SVs0JVhrxyhrxyhrxy"
"hrxyhrxKhrxKhrxKhrxKhrxKhrxKVmzOkFfJkFfJkFfJkFfNkFfNkFfNkFfNkFfNkFfNkFfNSkYZ8qoZ8qoZ8moZ8moZ8moZ"
"8moZ8moZ8moZ8moZ8mpZ2TdDXi1DXj1DXj1DXj1DXj1DXj1DXj1DXj1DXj1DXj2LbmTyjSzCwWUxDi6LcnBZnIPLIh1cFuvg"
"smgHl8U7uCziwWVJnk21siTPJFuZbCuTbpH41hN6Q0TcbP4jfk1Eu/Zo1x7t2qNde7Rrj3bt0a492rVHu/Zo1x7t2qNde7Rr"
"j3bt0a492rVHu/aeftfeOx1lJmWOMhsDGzig7zqdAbACy2Mtp+0mvDrzlJh9Sso+JWefUrJPqdmntOxTevYp5AzZ55bog1+i"
"EH6JRvglKuGX6IRfohR+iVb4JWrhl+hFWKIXYZmfLNGLsEQvwhK9CEv0IizRi7BEL8ISvQhL9CIu0Yu4RC/isgq0RC/iEr2I"
"S/QiLtGLuEQv4hK9iEv0Ii3Ri7REL9ISvUjLIssSvUhL9CIt0Yu0RC/SEr1IS/QiL9GLvEQv8hK9yEv0Ii8LuUv0Ii/Ri7xE"
"L/ISvchL9KIs0YuyRC/KEr0oS/SiLNGLsiwXLdGLskQvyhK9KEv0oi7Ri7pEL+oSvahL9KIu0Yu6RC/qsiS9RC/qEr2oS/Si"
"LdGLtkQv2hK9aEv0oi3Ri7ZEL9oSvWjL2MsSvWhL9KIv0Yu+RC/6Er3oGXp5Qq+g2z5wDEhfQFPWT1k/Zf2U9VPWT1k/Zf2U"
"9VPWT1k/gfW/095pObN32kHNAut8aJkjz2G9ccJQCYUiqVAiFcqkQoVUqJIKNVKhTipEjJNUSpSJJwrFE6XiiWLxRLl4omA8"
"UTKeKBpPlE0gyiaQ7UWUTSDKJhBlE4iyCUTZBKJsAlE2gSibSJRNJMomEzHIRAwyEYNMxKAQMShEDApRvwpRvwpRvwq5ThBl"
"U4iyKUTZFKJsKlE2lSibSpRNJcqmEmVTibKp5ApPlE0lyqYSZdOIsmlE2TSibBpRNo0om0aUTSPKppGjGVE2jSibTpRNJ8qm"
"E2XTibLpRNl0omw6UTadKJtODtUZsZocrDlytObI4Zojx2uOHLA5csTmyCGbI8dsjhy0ObKUWSmJLGVGUsrIShlpKZ2XaJ/i"
"e+lTDP3hw3YpUqpGqRqlapSqUapGqRqlak+Gqr3TjiAlsyMoBDAEYrSdeUIsFo9F7FjCjmXsWMGOVexYw4517BhZByvAEfI4"
"RB7HyOMgeRwlj8PkcZw8DpTHkQo4UiGlSxypgCMVcKQCjlTAkQo4UgFHKuBIRRypiCMVU2bHkYo4UhFHKuJIRRypiCMVcaQS"
"jlTCkUo4UinloThSCUcq4UglHKmEI5VwpDKOVMaRyjhSGUcqpyoTjlTGkco4UhlHKuNIFRypgiNVcKQKjlTBkSqpeo8jVXCk"
"Co5UwZGqOFIVR6riSFUcqYojVXGkaipE4UhVHKmKI9VwpBqOVMORajhSDUeq4Ug1HKmWiqY4Ug1HquNIdRypjiPVcaQ6jlTH"
"keo4Uh1HqqcCfzryp0I/l4r9XCr4c6noz6XCP5eK/1wqAXCpDMClUgCXwkxIVynM6YSVzljplLWQs55Qz04fOpN7XK1EU2RZ"
"9SUF78SZL3/3g8Aop6KcinIqyqkop6KcinKqD5dTPXQXDJP0wbzwwYTJMXs83XSO7m5Dd7d5X7vb8GxvaBkTB8T/XbNzUqlI"
"LJWIpTKxVCGWqsRSjViqE0tRLSUWk6XjyeLxZPl4soA8WUKeLCJPlpEnC8mTpRTIUgoZNiRLKZClFMhSCmQpBbKUAllKgSyl"
"QJZSJEspkqUUM1yVLKVIllIkSymSpRTJUopkKUWylBJZSokspUSWUsqokWQpJbKUEllKiSylRJZSIkspk6WUyVLKZCllspRy"
"RuBJS/mEeooCy+kAz/Xp1EJKEilJpCSRkkRKEilJpCSRksT7IIn33vUlLO36EmjXF2U1lNVQVkNZDWU1lNVQVkO7vpZ0fXmg"
"bwVhwrBozxfliJQjUo5IOSLliJQjUo5IOeLj6vkSac8XZTWU1VBWQ1kNZTWU1VBWQ3u+lvR8XVqDFmiN6ZgvyhEpR6QckXJE"
"yhEpR6QckXLER9jzJdGeL8pqKKuhrIayGspqKKuhrIb2fC3p+RoGgHZ6UXpI6SGlh5QeUnpI6SGlh5QePr5OL5l2elFWQ1kN"
"ZTWU1VBWQ1kNZTW002tJp1cPeI9lluODb/NH+SHlh5QfUn5I+SHlh5QfUn74mHq9FNrrRVkNZTWU1VBWQ1kNZTWU1dBeryW9"
"XgNgg0lg0fFelCNSjkg5IuWIlCNSjkg5IuWIj6Hn69AOfdBwHcvI3NLxxTAXDh0H2gLbsd0WsNkgsNk2Yqv2JArHKSr7x//E"
"LHBZukXT42Oyqxh95pttAShtWWvntDYv5CRdaOWACfWczLWUFs/JQNX5Bd+86Iah9/UsD+WWeSh554XoeQIbGhcJZs8eBqzr"
"2JYDn4xz0gk1K1h65pE8ADxnSlyO1wQ9JwGplWsBncu12rKo66qp66KW9shbuKGY6Ybi03bDlg8uLZt64k3GfmeeKNGASAPi"
"e3bDjGkC0SP4p+2ElDJirsi/D1dsuEidTL7tWwZgSK5oWyFyhYANodEl+d5Rpc4k9wRkzxMEsutJkog5H/8OnS8WG8RiP2b/"
"y0U/hfJmpcbs1ctIvVtM/aBylG+WmZ3ySXz2zGmJBbvl1C5BkfdPX/RDs1fORz+FTXnUGhxGH8utgT483c/PfgrR78Y4+mhe"
"GkInNJwzp9aNz43R3dGV++V8vxiMgXZct47XBsfKgehVNXlvP1Ss00n/cKd6MDw3QN+py+0ef3EMiuuKVgrOHGPPPe2F9SN3"
"TRqfj8+NyZEbHFZOupeFit/lStVdd3dd48e7WyV1X7xULyVxB+o7/cJuIK6XteMXI4vn1idnzgu71D1oKZPuJC/uuf54HQiB"
"55Z0xzntjMwyOD7hdW5Nz5vbbv1y6BQ2uXOhIB8dnq9NHM3aGnlr8FAonjmOa1b2LjilNzE3e+Ohsr+xsRnWtOOj1vr6i7Ku"
"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"
"gVGu9/PHvc6JNu6cjMfoEaWjA65ZyB+O0bcW1i/zJoorndrR1r5U3ujsH7ZO9tZsyd9zd04DQakVRjXOXDNOlfwONz5M7u4V"
"yv3xgZS/uvbMSV8tdDfB/otq4fCifJk/iL6hkK9Wi32PPzlG9ETc9oytRnGjtGVJW55w5uTHtdHpZrmV3ywN18aysHneHVXz"
"QaRNszTejyxWKPTyO4VO57zb7+3V9/eRhWqVfKmwkbcKB2dO80L1g4ueDxRPGU4Oaifivl/d6yuVY6V7eFSQ+01Yk5ob4Wan"
"0s3vNvldv9OGfd65OBZso1JG8X6iWxVg5GHfveyfS1Ktu7sBejv2/lzcS7vhb64jV02FvWT7j0r93zUypocIvMAKGstr6FcU"
"nljYu9eVlJbFvda4B4ewQ6MejXo06n1YUU+4HdGjIY+GPBryaMh7zCFPXBryREryaMSjEY9GvCcU8aSlEY82a2nEoxGPRryn"
"FPGIozl4keUljuV1nhVkGvVo1KNRj0a9pxT1lKVRD/2qNOjRoEeDHg16TyjoqeT3tiqrKqwcxz4a9GjQo0GPBr0nFPS0ZUFP"
"ZnUa82jMozGPxrynFPP0ZTFPYSnPozGPxjwa855SzOP3lsc8XqY9ejTo0aBHg97TCHoo5lxMMqZieNE5juOuN5pl20Pn28aA"
"Z3tgYNmGO2BRxUIFAl4g4gUSXiDjBQpeoOIFGl6g4wU8lypJYeVTYPkUWj4Fl0/h5VOA+RRiPgWZT2EWUpiFtH5TmIUUZiGF"
"WUhhFlKYhRRmIYVZSGEWMczBYOH4iWXIzhCEcADse8yT8sEQT48Dcf+eNpJeWtOFzJqOV3MHd0MH90IHd0IH90EHd0EH90AH"
"d0AH9z8Hdz8nVc2dVDV3UtXcSVVzJ1XNnVQ1d1LV3ElVcydVzZ1UNXdS1dwR0vpNYU5VcydVzZ1UNXdS1dxJVXMnVc2dVDV3"
"xBRmMYVZTDtFCrOYwiymMIspzGIKs5jCLKYwSynMUgqzlMIspT05hVlKYZZSmKUUZimFWUphllOY5RRmOYVZTmGW09UvhVlO"
"YZZTmOUUZjmFWUmlAB4vEPACES+Q8AIZL1DxAg0v0FM40shS0PgUNj4Fjk+h41Pw8OgQpEhAkCIBQYoEBCkSEKRSfpBK8EEq"
"wQepBB+kEnyQSvBBKsEHhAQvpnQopu2b0qGYwiymMIspzGIKs5jCLKYwSynMUgqzlMIspZ0yhVlKYZZSmKUUZimFWUphllOY"
"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"
)

if __name__ == '__main__':
    main()
