#!/usr/bin/env python3
# Python By @snapdark_decoder 🇧🇩
# ─────────────────────────────────────────────────────────────────────────────
#  7NET VPN (xyz.sevennetvpn.org, renz/javacodez APX-family) Cloud Config Decryptor  v1.0
#  House rule: CREDITS first + _source ; JSON-validity gate ;
#  OUTPUT = ☠️.json ONLY (user rule 2026-10-30: no .txt / no cache / no .bak extras ;
#  deliverable .py lives in /sdcard/senseitunnel, outputs in /sdcard/VPNs) ;
#  fetch config endpoint only (auth/updater endpoints are code-only, never contacted).
#
#  Source : https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js
#           (Volley StringRequest in SEVENNETVPNMain startup; URL = pp.a(-0x369eaaccb7e0))
#
#  MODE 0 (whole envelope + fields Name, Subname, flag, ports, TLSVersion, Info, net Name ...)
#      b64 -> AES-128-CBC(key = SHA256(PASSKEY32)[:16], IV = CONST_IV) PKCS7
#      -> XXTEA decrypt (DELTA 0x7A56D3E1, key = SHA256(PASSKEY32)[:16],
#         rounds = 6 + 52//n, plaintext length in last word) -> per-byte (b-2)&0xff
#
#  MODE 1 (decryptSpecial @0x4c0edc: ServerIPHost, SNIHost, Payload, ...)
#      b64 -> Threefish-256 decrypt per 32B block, key = HK32, tweak = (block_index, 0)
#      [pure-python byte-exact port of threefishDecrypt256 @0x4c75f8 - no .so needed]
#      -> strip trailing 0x00 -> zero-pad to 16 -> AES-128-CBC(HK16, CONST_IV) PKCS7
#
#  MODE 2 (decryptSensitive @0x4c167c: top-level Username / Password)
#      b64 -> XXTEA (DELTA 0x7A56D3E1, key = DK32[:16]) -> AES-256-CBC(DK32, IV = out[:16])
#      -> PKCS7 unpad        (DK32 = getPBKDF232BitKey)
#
#  Key material (libovpn3.so build sha16 1cbe5ce9f3de6256, .rodata):
#      PASSKEY32   @0x27e338   deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b
#      CONST_IV    @0x27e358   2d2f3112a271edbba9a41ad58a3a99bf
#      FIXED_SALT  @0x27e318   70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55
#                  @0x27e3cc   (second copy; HK16 uses FIXED_SALT[:16], HK32 full salt)
#      HK16 = HKDF-SHA256(ikm=PASSKEY32, salt=FIXED_SALT[:16], L=16) = e50acb6fd8d056b159bbf414c4acd908
#      HK32 = HKDF-SHA256(ikm=PASSKEY32, salt=FIXED_SALT,      L=32) = a8fe4b23f5ad67851d981cca6522d6b2f2bdca67e739751c3b5ad68552fb8311
#      DK32 = PBKDF2-HMAC-SHA256(PASSKEY32, FIXED_SALT, 100000, 32)
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import json
import shutil
import base64
import hashlib
import struct
import subprocess

def check_dependencies():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa
    except ImportError:
        missing.append("cryptography")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required modules {missing} not found. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    import requests
    return requests

requests = check_dependencies()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

C_RED = '\033[91m'; C_GREEN = '\033[92m'; C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'; C_CYAN = '\033[96m'; C_RESET = '\033[0m'

URL = "https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js"
OUTPUT_FILE = "/sdcard/VPNs/7NET VPN ☠️.json"
CREDITS = "Decrypted By @SnapDark 🇧🇩 | Join channel: t.me/Jubairbro"

# ---- 7NET VPN key material (libovpn3.so v5.6.0 .rodata, all extracted statically) ----
PASSKEY32  = bytes.fromhex("deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b")  # @0x27e338
CONST_IV   = bytes.fromhex("2d2f3112a271edbba9a41ad58a3a99bf")   # @0x27e358
FIXED_SALT = bytes.fromhex("70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55")  # @0x27e318
KEY16 = hashlib.sha256(PASSKEY32).digest()[:16]     # mode-0 AES + XXTEA key

def _hkdf(ikm, salt, L):
    prk = hashlib.sha256  # placeholder replaced below
    import hmac as _h
    prk = _h.new(salt, ikm, hashlib.sha256).digest()
    okm = b""; t = b""; i = 1
    while len(okm) < L:
        t = _h.new(prk, t + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:L]

HK16  = _hkdf(PASSKEY32, FIXED_SALT[:16], 16)   # generateHKDFKey
HK32  = _hkdf(PASSKEY32, FIXED_SALT, 32)        # getHKDF32BitKey (tail-jump to generateHKDF32BitKey)
DK32  = hashlib.pbkdf2_hmac("sha256", PASSKEY32, FIXED_SALT, 100000, 32)  # getPBKDF232BitKey

M32 = 0xffffffff
XXTEA_DELTA = 0x7A56D3E1

MODE1_KEYS = {"ServerIPHost", "SNIHost", "Payload", "V2RayHost", "PATH", "CustomV2RAYConfig"}


# ---------------------------------------------------------------- helpers ---
def _d(key, iv, data, mode=modes.CBC):
    dec = Cipher(algorithms.AES(key), mode(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _un(pt):
    u = PKCS7(128).unpadder()
    return u.update(pt) + u.finalize()


def b64d(s):
    if isinstance(s, str):
        s = s.replace("\n", "").strip().encode()
    return base64.b64decode(s + b"=" * (-len(s) % 4))


def xxtea_dec(data, key16):
    """libovpn3 xxtea_decrypt: DELTA 0x7A56D3E1, rounds = 6 + 52/n, sum descends by DELTA.
    Length embedded in the last word (validated 4n-7 <= len <= 4n-4)."""
    if len(data) < 8 or len(data) % 4:
        return None
    n = len(data) // 4
    if n < 2:
        return None
    v = [int.from_bytes(data[i*4:i*4+4], "little") for i in range(n)]
    k = [int.from_bytes(key16[i*4:i*4+4], "little") for i in range(4)]
    D, u = XXTEA_DELTA, (lambda x: x & M32)
    s = ((6 + 52 // n) * D) & M32
    for _ in range(6 + 52 // n):
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            y = v[p+1] if p + 1 < n else v[0]
            z = v[p-1]
            mx = u(u(u(z >> 5) ^ u(y << 2)) + u(u(z << 4) ^ u(y >> 3))) ^ u(u(s ^ y) + u(k[e ^ (p & 3)] ^ z))
            v[p] = u(v[p] - mx)
        y, z = v[1], v[n - 1]
        mx = u(u(u(z >> 5) ^ u(y << 2)) + u(u(z << 4) ^ u(y >> 3))) ^ u(u(s ^ y) + u(k[e] ^ z))
        v[0] = u(v[0] - mx)
        s = u(s - D)
    ln = v[-1]
    if not (4*n - 7 <= ln <= 4*n - 4):
        return None
    return b"".join(x.to_bytes(4, "little") for x in v)[:ln]


# -------- Threefish-256 decrypt: byte-exact port of threefishDecrypt256 @0x4c75f8 --------
TF_B85 = "1poj54*&oF4gdfE0RR915C8xG1poj52><{93IG5A000002mk;81poj52mk;83jhEB00000AOHXW1poj50{{R31ONa400000kN^Mx1poj53;+NC5dZ)H0RR9100000000004gdfE4gdfE3IG5A00000000004gdfE4gdfE000005&!@I0RR914FCWD0{{R33jhEB000000RR915C8xG1ONa42><{9000000RR916aWAK1ONa43jhEB00000000003;+NC3;+NC2mk;800000000005dZ)H5dZ)H4FCWD00000000004*&oF4*&oF5C8xG000000ssI24gdfE3;+NC4gdfE000000ssI25dZ)H4*&oF5dZ)H000000{{R34gdfE4gdfE00000AOHXW0{{R35dZ)H5dZ)H00000AOHXW000003;+NC3;+NC4gdfE00000000004*&oF4*&oF5dZ)H000000ssI25dZ)H5dZ)H3;+NC000000ssI24gdfE4*&oF4gdfE000000{{R35dZ)H5dZ)H00000IsgCw0{{R34gdfE4gdfE00000761SM000003;+NC3;+NC5dZ)H00000000000RR914*&oF4gdfE000000ssI24gdfE4gdfE3;+NC000000ssI24*&oF0RR915dZ)H000000{{R34gdfE4gdfE00000E&u=k0{{R35dZ)H4*&oF000003;+NC1^@s64*&oF00000000007ytkO1^@s6000000000000000pa1{>000001poj53;+NC4gdfE00000000000RR910RR915dZ)H000000ssI23;+NC5dZ)H1poj5000000ssI24gdfE0RR914gdfE00000000000RR910RR914FCWD000000{{R35dZ)H3;+NC0000082|tP0{{R34gdfE4gdfE00000ApigX0RR913;+NC000002mk;800000000001poj51poj54*&oF00000000001^@s65dZ)H3;+NC00000000000RR910RR914gdfE00000000004gdfE4gdfE2><{900000000005dZ)H1poj55dZ)H00000000004gdfE4gdfE000005dZ)H0ssI21poj50RR911^@s6000000ssI24gdfE4gdfE5dZ)H000000{{R31poj51poj500000B>(^b0{{R34gdfE4gdfE000001poj5000000RR910RR911poj500000000005dZ)H5dZ)H4gdfE000000ssI24gdfE0RR914gdfE000000ssI21poj51poj55dZ)H000000{{R34gdfE4gdfE00000C;$Ke0{{R31poj51poj5000007XSbN000000RR910RR914gdfE00000000005dZ)H5dZ)H1poj5000000ssI21poj50RR911poj5000000ssI24gdfE4gdfE5dZ)H000000{{R31poj51poj500000IRF3v0{{R34gdfE4gdfE00000Gynhq000000RR910RR911poj500000000005dZ)H5dZ)H4gdfE000000ssI24gdfE0RR914gdfE00000000000RR910RR913;+NC000000ssI21poj51poj55dZ)H000000{{R31^@s64gdfE000005C8xG0RR914gdfE1ONa44*&oF000000{{R31poj51poj5000004gdfE000005dZ)H5dZ)H3IG5A00000000000RR910RR911^@s600000000001^@s61^@s63jhEB00000000005dZ)H5dZ)H1poj500000000001poj51poj54gdfE00000000001^@s61^@s6000005C8xG0ssI21^@s61^@s65dZ)H000000ssI21poj50RR911poj5000000{{R31^@s61^@s600000AOHXW0{{R31poj51poj500000AOHXW000005dZ)H5dZ)H1^@s600000000000RR910RR911poj5000000ssI21poj51poj55dZ)H000000ssI21^@s60RR911^@s6000000{{R31poj51poj500000IsgCw0{{R31^@s61^@s600000761SM000005dZ)H5dZ)H1poj500000000000RR910RR911^@s6000000ssI21^@s61^@s65dZ)H000000ssI21poj50RR911poj5000000{{R31^@s61^@s600000E&u=k0{{R31poj51poj5000003;+NC000002LJ#75dZ)H1^@s600000000000RR910RR911poj5000000ssI25dZ)H1poj52LJ#7000000ssI21poj50RR911^@s600000000000RR910RR914gdfE000000{{R31^@s65dZ)H0000082|tP0{{R31poj51poj500000ApigX0RR915dZ)H0{{R33IG5A00000000002LJ#72LJ#72><{900000000006951J1^@s65dZ)H00000000000RR910RR911poj500000000001poj51poj52mk;800000000001^@s62LJ#71^@s600000000001poj51poj5000004*&oF0ssI22LJ#70RR916951J000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000B>(^b0RR916951J000002><{9000000{{R31poj51poj5000001poj5000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj5000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj500000C;$Ke0{{R32LJ#72LJ#7000007XSbN000000RR910RR911poj500000000001^@s61^@s62LJ#7000000ssI22LJ#70RR912LJ#7000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000IRF3v0{{R31poj51poj500000Gynhq000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj500000000000RR910RR915dZ)H000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj5000005C8xG000001^@s61^@s63jhEB000000{{R32LJ#72LJ#7000004gdfE000000RR910RR911poj500000000001poj51poj54*&oF00000000001^@s61^@s62LJ#700000000002LJ#72LJ#76951J00000000001poj51poj5000004gdfE0ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000AOHXW0{{R32LJ#72LJ#700000AOHXW000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj5000000{{R32LJ#72LJ#700000IsgCw0{{R31poj51poj500000761SM000001^@s61^@s62LJ#700000000000RR910RR911poj5000000ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000E&u=k0{{R32LJ#72LJ#7000003;+NC000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj500000000000RR910RR916951J000000{{R32LJ#72LJ#70000082|tP0{{R31poj51poj500000ApigX000001^@s61^@s62mk;800000000006951J2LJ#76aWAK00000000000RR910RR911poj500000000001poj51poj53IG5A00000000001^@s61^@s62LJ#700000000001poj51poj5000004FCWD0ssI22LJ#70RR916951J000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000B>(^b0RR916951J0{{R32mk;8000000{{R31poj51poj5000001poj5000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj5000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj500000C;$Ke0{{R32LJ#72LJ#7000007XSbN000000RR910RR911poj500000000001^@s61^@s62LJ#7000000ssI22LJ#70RR912LJ#7000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000IRF3v0{{R31poj51poj500000Gynhq000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj500000000000RR910RR916aWAK000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj5000005C8xG000001^@s61^@s64*&oF000000{{R32LJ#72LJ#7000004gdfE0RR916aWAK000004*&oF00000000000RR910RR911poj500000000001poj51poj52><{900000000001^@s61^@s62LJ#700000000002LJ#72LJ#76951J00000000001poj51poj5000003;+NC0ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000AOHXW0{{R32LJ#72LJ#700000AOHXW000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj5000000{{R32LJ#72LJ#700000IsgCw0{{R31poj51poj500000761SM000001^@s61^@s62LJ#700000000000RR910RR911poj5000000ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000E&u=k0{{R32LJ#72LJ#7000003;+NC000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj500000000000RR910RR916951J000000{{R32LJ#72LJ#70000082|tP0{{R31poj51poj500000ApigX000001^@s61^@s63IG5A00000000006951J2LJ#76aWAK00000000000RR910RR911poj500000000001poj51poj53jhEB00000000001^@s61^@s62LJ#700000000001poj51poj5000003jhEB0ssI22LJ#70RR916951J000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000B>(^b0RR916951J1ONa43IG5A000000{{R31poj51poj5000001poj50RR911ONa41ONa42mk;800000000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj5000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj500000C;$Ke0{{R32LJ#72LJ#7000007XSbN000000RR910RR911poj500000000001^@s61^@s62LJ#7000000ssI22LJ#70RR912LJ#7000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000IRF3v0{{R31poj51poj500000Gynhq000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj500000000000RR910RR916aWAK000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj5000005C8xG000001^@s61^@s62><{9000000{{R32LJ#72LJ#7000004gdfE0RR916aWAK0{{R32><{9000000RR910{{R30{{R34*&oF00000000000RR910RR911poj500000000001poj51poj52mk;800000000001^@s61^@s62LJ#700000000002LJ#72LJ#76951J00000000001poj51poj5000003IG5A0ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000AOHXW0{{R32LJ#72LJ#700000AOHXW000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj5000000{{R32LJ#72LJ#700000IsgCw0{{R31poj51poj500000761SM000001^@s61^@s62LJ#700000000000RR910RR911poj5000000ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000E&u=k0{{R32LJ#72LJ#7000003;+NC000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj500000000000RR910RR916951J000000{{R32LJ#72LJ#70000082|tP0{{R31poj51poj500000ApigX000001^@s61^@s63jhEB00000000006951J2LJ#76aWAK00000000000RR910RR911poj500000000001poj51poj54*&oF00000000001^@s61^@s62LJ#700000000001poj51poj5000002><{90ssI22LJ#70RR916951J000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000B>(^b0RR916951J000003jhEB000000{{R31poj51poj5000001poj50RR9100000000003IG5A00000000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj5000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj500000C;$Ke0{{R32LJ#72LJ#7000007XSbN000000RR910RR911poj500000000001^@s61^@s62LJ#7000000ssI22LJ#70RR912LJ#7000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000IRF3v0{{R31poj51poj500000Gynhq000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj500000000000RR910RR916aWAK000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj5000005C8xG000001^@s61^@s62mk;8000000{{R32LJ#72LJ#7000004gdfE000000RR910RR911poj500000000001poj51poj53IG5A00000000001^@s61^@s62LJ#700000000002LJ#72LJ#76951J00000000001poj51poj5000002mk;80ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000AOHXW0{{R32LJ#72LJ#700000AOHXW000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj5000000{{R32LJ#72LJ#700000IsgCw0{{R31poj51poj500000761SM000001^@s61^@s62LJ#700000000000RR910RR911poj5000000ssI21poj51poj51^@s6000000ssI22LJ#70RR912LJ#7000000{{R31poj51poj500000E&u=k0{{R32LJ#72LJ#7000003;+NC000001^@s61^@s61poj500000000000RR910RR912LJ#7000000ssI22LJ#72LJ#71^@s6000000ssI21poj50RR911poj500000000000RR910RR916951J000000{{R32LJ#72LJ#70000082|tP0{{R31poj51poj500000ApigX000001^@s61^@s64*&oF00000000006951J2LJ#71ONa400000000000RR910RR911poj500000000001poj51poj52><{900000000001^@s61^@s62LJ#700000000001poj51poj5000002LJ#70ssI22LJ#70RR916951J000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000B>(^b0{{R31poj51poj5000001poj5000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj5000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj500000C;$Ke0{{R32LJ#72LJ#7000007XSbN000000RR910RR911poj500000000001^@s61^@s62LJ#7000000ssI22LJ#70RR912LJ#7000000ssI21poj51poj51^@s6000000{{R32LJ#72LJ#700000IRF3v0{{R31poj51poj500000Gynhq000000RR910RR912LJ#700000000001^@s61^@s61poj5000000ssI21poj50RR911poj500000000000RR910RR911ONa4000000ssI22LJ#72LJ#71^@s6000000{{R31poj51poj5000005C8xG000001^@s61^@s63IG5A000000{{R31ONa42LJ#7000004gdfE000000RR910RR911poj500000000001poj51poj53jhEB00000000001^@s61^@s61ONa400000000001ONa41ONa40{{R300000000001poj51poj5000001^@s60ssI21poj51poj51^@s6000000ssI21ONa40RR911ONa4000000{{R31poj51poj500000AOHXW0{{R31ONa41ONa400000AOHXW000001^@s61^@s61poj500000000000RR910RR911ONa4000000ssI21ONa41ONa41^@s6000000ssI21poj50RR911poj5000000{{R31ONa41ONa400000IsgCw0{{R31poj51poj500000761SM000001^@s61^@s61ONa400000000000RR910RR911poj5000000ssI21poj51poj51^@s6000000ssI21ONa40RR911ONa4000000{{R31poj51poj500000E&u=k0{{R31ONa41ONa4000003;+NC000001^@s61^@s61poj500000000000RR910RR911ONa4000000ssI21ONa41ONa41^@s6000000ssI21poj50RR911poj500000000000RR910RR910{{R3000000{{R31ONa41ONa40000082|tP0{{R31poj51poj500000ApigX000001^@s61^@s62><{900000000000{{R31ONa40000000000000000RR910RR911poj500000000001poj51poj52mk;800000000001ONa41^@s61ONa400000000001poj51poj5000001poj50ssI20{{R30RR910{{R3000000ssI21poj51poj51ONa4000000{{R30{{R30{{R300000B>(^b0{{R31poj51poj5000001poj5000000RR910RR910{{R300000000001ONa41ONa41poj5000000ssI21poj50RR911poj5000000ssI20{{R30{{R31ONa4000000{{R31poj51poj500000C;$Ke0{{R30{{R30{{R3000007XSbN000000RR910RR911poj500000000001ONa41ONa40{{R3000000ssI20{{R30RR910{{R3000000ssI21poj51poj51ONa4000000{{R30{{R30{{R300000IRF3v0{{R31poj51poj500000Gynhq000000RR910RR910{{R300000000001ONa41ONa41poj5000000ssI21poj50RR911poj50000000000000000RR9100000000000ssI20{{R30{{R31ONa4000000{{R31poj51poj5000005C8xG0{{R30RR910{{R3000004gdfE000000{{R31ONa43jhEB000001ONa43jhEB3jhEB0000000000000001ONa41poj54*&oF000000000000000000001poj500000000000{{R30{{R30RR9100000000000RR910RR915C8xG00000000001ONa41ONa4000001ONa40ssI21ONa41ONa40{{R3000000ssI20RR91000000RR91000000{{R31ONa41ONa400000AOHXW0{{R30RR910RR9100000AOHXW000000{{R30{{R31ONa4000000000000000000000RR91000000ssI20RR910RR910{{R3000000ssI21ONa4000001ONa4000000{{R30RR910RR9100000IsgCw0{{R31ONa41ONa400000761SM000000{{R30{{R30RR91000000000000000000001ONa4000000ssI21ONa41ONa40{{R3000000ssI20RR91000000RR91000000{{R31ONa41ONa400000E&u=k0{{R30RR910RR91000003;+NC000000{{R30{{R31ONa4000000000000000000000RR91000000ssI20RR910RR910{{R3000000ssI21ONa4000001ONa400000000005C8xG000005C8xG000000{{R30RR910RR910000082|tP0{{R31ONa41ONa400000ApigX000000{{R30{{R32mk;80000000000000000RR914FCWD00000000005C8xG5C8xG1ONa400000000001ONa41ONa43IG5A00000000000RR910{{R30RR9100000000000{{R31ONa4000000{{R30ssI2000005C8xG00000000000ssI20{{R30{{R30RR91000000{{R3000000000000000B>(^b0{{R30{{R30{{R3000001poj5000005C8xG5C8xG0000000000000000RR910RR910{{R3000000ssI20{{R35C8xG0{{R3000000ssI200000000000RR91000000{{R30{{R30{{R300000C;$Ke0{{R30000000000000007XSbN000005C8xG5C8xG0{{R300000000000RR910RR9100000000000ssI2000005C8xG00000000000ssI20{{R30{{R30RR91000000{{R3000000000000000IRF3v0{{R30{{R30{{R300000Gynhq000005C8xG5C8xG0000000000000000RR910RR910{{R3000000ssI20{{R35C8xG0{{R300000000004FCWD5C8xG4FCWD000000ssI200000000000RR91000000{{R30{{R30{{R3000005C8xG000004*&oF0RR914*&oF000000{{R35C8xG00000000004gdfE00000000000{{R32><{900000000004FCWD4FCWD0{{R300000000004*&oF4*&oF5C8xG00000000005C8xG5C8xG3;+NC00000000000000000000000000ssI20ssI200000000004*&oF000000ssI25C8xG4FCWD5C8xG000000{{R3000000000000000AOHXW0{{R35C8xG5C8xG00000AOHXW000004*&oF4*&oF0000000000000004FCWD4FCWD5C8xG000000ssI25C8xG5C8xG4*&oF000000ssI2000004FCWD00000000000{{R35C8xG5C8xG00000IsgCw0{{R3000000000000000761SM000004*&oF4*&oF5C8xG00000000004FCWD4FCWD00000000000ssI200000000004*&oF000000ssI25C8xG4FCWD5C8xG000000{{R3000000000000000E&u=k0{{R35C8xG5C8xG000003;+NC000004*&oF4*&oF0000000000000004FCWD4FCWD5C8xG000000ssI25C8xG5C8xG4*&oF000000ssI2000004FCWD0000000000000003IG5A4*&oF3IG5A000000{{R35C8xG5C8xG0000082|tP0{{R3000000000000000ApigX000003;+NC4FCWD3;+NC00000000003IG5A3IG5A5C8xG000000RR913jhEB000003jhEB00000000004FCWD5C8xG4gdfE00000000003;+NC3;+NC00000000000ssI23jhEB3jhEB3IG5A000000ssI24FCWD3;+NC4FCWD000000{{R33jhEB3jhEB000001poj50{{R34FCWD4FCWD00000B>(^b000003IG5A3IG5A3jhEB00000000003;+NC3;+NC4FCWD000000ssI24FCWD4FCWD3IG5A000000ssI23jhEB3;+NC3jhEB000000{{R34FCWD4FCWD000007XSbN0{{R33jhEB3jhEB00000C;$Ke000003IG5A3IG5A4FCWD00000000003;+NC3;+NC3jhEB000000ssI23jhEB3jhEB3IG5A000000ssI24FCWD3;+NC4FCWD000000{{R33jhEB3jhEB00000Gynhq0{{R34FCWD4FCWD00000IRF3v000003IG5A3IG5A3jhEB000000ssI24*&oF4FCWD3IG5A00000000003;+NC3;+NC4FCWD00000000002><{93IG5A2><{9000000{{R34FCWD4*&oF000004gdfE0ssI23IG5A3;+NC3jhEB00000000003jhEB3;+NC4gdfE000000{{R33IG5A3IG5A000005C8xG000002><{92><{94FCWD00000000003;+NC4FCWD5dZ)H000002LJ#72><{93;+NC0ssI200000000002><{93jhEB3IG5A00000000002mk;83IG5A2mk;8000002LJ#72><{92mk;80ssI25C8xG"

TF_DECODED = [t for t in struct.iter_unpack("<5i", base64.b85decode(TF_B85))]


def tf256_dec_block(d32, key32, blk_i):
    """ctx (from threefishSetKey): [keylen=0x100, k0..k3, C240^k0..k3, t0, t1, t0^t1];
    SetKey is called per block with tweak = (block_index, 0)."""
    k4 = struct.unpack("<4Q", key32)
    fold = (0x1BD11BDAA9FC1A22 ^ k4[0] ^ k4[1] ^ k4[2] ^ k4[3]) & (1 << 64) - 1
    mem = {0: 0x100, 8: k4[0], 16: k4[1], 24: k4[2], 32: k4[3], 40: fold,
           0x90: blk_i & (1 << 64) - 1, 0x98: 0, 0xa0: blk_i & (1 << 64) - 1}
    DB = 0x10000; OB = 0x30000
    for i, w in enumerate(struct.unpack("<4Q", d32.ljust(32, b"\x00"))):
        mem[DB + 8*i] = w
    R = [0]*32
    R[1] = DB; R[2] = OB
    M = (1 << 64) - 1
    for mn, a, b, c, imm in TF_DECODED:
        if mn == 5:                                   # ldp
            base = R[c] + imm
            R[a] = mem.get(base, 0); R[b] = mem.get(base + 8, 0)
        elif mn == 6:                                 # ldr
            R[a] = mem.get(R[c] + imm, 0)
        elif mn == 7:                                 # stp
            base = R[c] + imm
            mem[base] = R[a]; mem[base + 8] = R[b]
        else:
            if mn in (0, 1, 2):                       # sub / add / eor
                v1 = R[b]
                v2 = imm if imm else R[c]
                v = v1 - v2 if mn == 0 else (v1 + v2 if mn == 1 else v1 ^ v2)
                R[a] = v & M
            elif mn == 3:                             # ror R[b] by imm
                n = imm % 64
                R[a] = ((R[b] >> n) | (R[b] << (64 - n))) & M if n else R[b]
            elif mn == 4:                             # mvn
                R[a] = (~R[b]) & M
            else:
                break
            if a == 31: R[31] = 0                     # xzr never holds a value
    return struct.pack("<4Q", *(mem[OB + 8*i] for i in range(4)))


def tf256_dec(data, key32):
    """Threefish-256 layer: per-32B block, tweak = (block_index, 0)."""
    out = bytearray()
    for i in range((len(data) + 31) // 32):
        out += tf256_dec_block(data[i*32:(i+1)*32], key32, i)
    return bytes(out[:len(data)])


# ---------------------------------------------------------------- modes ---
def mode0(s):
    """RenzUtils.decrypt(.., 0): body + field-level envelope chain."""
    try:
        b = b64d(s)
    except Exception:
        return None
    if len(b) < 16 or len(b) % 16:
        return None
    try:
        raw = _un(_d(KEY16, CONST_IV, b))
    except Exception:
        return None
    o = xxtea_dec(raw, KEY16)
    if o is None:
        return None
    return bytes((x - 2) & 0xff for x in o)


def mode1(s):
    """decryptSpecial: Threefish-256 -> AES-128-CBC(HK16)."""
    try:
        d = b64d(s)
    except Exception:
        return None
    if not d:
        return None
    T = tf256_dec(d, HK32).rstrip(b"\x00")
    if not T:
        return None
    T += b"\x00" * ((16 - len(T) % 16) % 16)
    try:
        return _un(_d(HK16, CONST_IV, T))
    except Exception:
        return None


def mode2(s):
    """decryptSensitive: XXTEA(DK32[:16]) -> AES-256(DK32, IV=out[:16])."""
    try:
        raw = b64d(s)
    except Exception:
        return None
    o = xxtea_dec(raw, DK32[:16])
    if o is None or len(o) < 32:
        return None
    try:
        return _un(_d(DK32, o[:16], o[16:]))
    except Exception:
        return None


def valid(txt):
    if not txt:
        return False
    try:
        t = txt.decode("utf-8")
    except UnicodeDecodeError:
        return False
    for c in t:
        o = ord(c)
        if (o < 32 and not c.isspace() and c != "\r" and c != "\n") or 0x7f <= o < 0xa0:
            return False
    return True


def decrypt_field(s):
    """Try-chain per field: mode0 -> mode1 -> mode2 (strict validity check)."""
    if not isinstance(s, str) or not s.strip():
        return s
    for fn in (mode0, mode1, mode2):
        r = fn(s)
        if valid(r):
            return r.decode("utf-8")
    return s.strip()


def walk(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                out[k] = walk(v)
            elif isinstance(v, str):
                out[k] = decrypt_field(v)
            else:
                out[k] = v
        return out
    if isinstance(obj, list):
        return [walk(x) for x in obj]
    return obj


# ------------------------------------------------------------------ main ---
def fetch(fallback=True):
    try:
        r = requests.get(URL, headers={"User-Agent": "okhttp/4.12.0"}, timeout=30)
        body = r.text.strip()
        if body:
            return body, "network"
    except Exception:
        pass
    return None, None


def strip_escapes(s):
    """Unescape JSON string values that carry escaped slashes from earlier tooling."""
    return s.replace("\\/", "/") if isinstance(s, str) else s


def save(out):
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        json.dumps(out)                                  # JSON-validity gate
        open(OUTPUT_FILE, "w", encoding="utf-8").write(
            json.dumps(out, ensure_ascii=False, indent=2))
        return True
    except Exception:
        return False


def main():
    print(C_BLUE + "─" * 74 + C_RESET)
    print(C_CYAN + "  7NET VPN Cloud Config Decryptor  v1.0".center(74) + C_RESET)
    print(C_CYAN + "  by @snapdark_decoder".center(74) + C_RESET)
    print(C_BLUE + "─" * 74 + C_RESET)
    body, src = fetch()
    if not body:
        print(C_RED + "[!] Fetch failed and no cache available." + C_RESET)
        sys.exit(1)
    print(C_GREEN + f"[+] Config body: {len(body)} bytes ({src})" + C_RESET)
    doc = mode0(body)
    if not doc or not valid(doc):
        print(C_RED + "[!] Mode-0 envelope decryption failed." + C_RESET)
        sys.exit(1)
    data = json.loads(doc)
    print(C_GREEN + f"[+] Envelope decrypted: Version {data.get('Version')} | "
          f"{len(data.get('Servers', []))} servers, {len(data.get('Networks', []))} networks" + C_RESET)

    # unescape string values, then per-field decrypt (modes 0/1/2 try-chain)
    data = json.loads(json.dumps(data).replace("\\/", "/"))
    full = walk(data)
    out = {"CREDITS": CREDITS, "_source": URL}
    out.update(full)

    # nothing inside must remain base64-encrypted; untouched means already-plaintext
    if json.dumps(out, ensure_ascii=False, indent=2) and save(out):
        print(C_GREEN + f"[+] Saved: {OUTPUT_FILE}" + C_RESET)
    else:
        print(C_RED + "[!] Save failed (JSON validity gate)." + C_RESET)
        sys.exit(1)
    print(C_BLUE + "─" * 74 + C_RESET)
    sv = out.get("Servers", [])
    if sv:
        print(C_CYAN + "  Server overview (first 8):" + C_RESET)
        for s in sv[:8]:
            nm = s.get("Name", "?"); ip = s.get("ServerIPHost", "?")
            print(f"   • {nm}  →  {ip}   [{s.get('flag', '?').upper() if isinstance(s.get('flag'), str) else '?'}]")


if __name__ == "__main__":
    main()
