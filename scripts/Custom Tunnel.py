# Python By @SnapDark🇧🇩
import os
import sys
import json
import base64
import re
import glob
import shutil
import hashlib
import hmac
import subprocess

def check_dependencies():
    missing = []
    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing.append("pycryptodome")
    if missing:
        width = shutil.get_terminal_size((80, 20)).columns
        print("\033[93m" + f"[*] Required modules {missing} not found. Auto-installing...".center(width) + "\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing + ["-q"])
    from Crypto.Cipher import AES
    return AES

AES = check_dependencies()

C_RED = '\033[91m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

OUTPUT_FILE = "/sdcard/VPNs/Custom Tunnel VPN ☠️.json"
CREDITS = "Decrypted By @Snapdark 🇧🇩"
APK_PATH = "/storage/emulated/0/MT2/apks/Custom Tunnel_17.0.0.apks"
DEFAULT_CTUN = "/storage/emulated/0/Download/Custom tunnel/x.ctun"

SEC32 = b'SEoToNOoUJ^wSMm\x7fUULDEEPWEU[JX_A\xdd'
MASTER = b'SENTINEL_TUNNEL_CONFIG_KEY_V1_20'
FALLBACK = b'ST-CTUN-SIG-FB-1'
KNOWN_CERTS = [bytes.fromhex('de30c9df502085e217b2eacfc2d05bbae39f9dac521d4c9011c87a27b26f2ad0')]

def print_c(text, color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{text.center(width)}{C_RESET}")

def print_bar(color=""):
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"{color}{'━' * (width)}{C_RESET}")

# ---------------- LAYER 1 : S2 container (NativeCrypto.deobfuscate) ----------------

def blkrev(b):
    out = bytearray(b)
    n, i = len(out), 0
    while i < n:
        j = i + 16
        if j < n:
            out[i:j] = out[i:j][::-1]
        i += 32
    return bytes(out)

def deobfuscate(data, key):
    rev = blkrev(data)
    return bytes(rev[i] ^ key[i % len(key)] for i in range(len(rev)))

def unpack_ctun(raw):
    if raw[:2] == b'S2':
        plain = deobfuscate(raw[2:], SEC32)
        if not plain.startswith(b'STCF'):
            raise ValueError("native S2 container check failed")
    else:
        plain = deobfuscate(raw, MASTER)
        if not plain.startswith(b'STCF'):
            raise ValueError("legacy container check failed")
    return json.loads(plain[5:].decode('utf-8'))

# ---------------- LAYER 2 : EncryptedConfigData (HMAC + AES-GCM) ----------------

def b64d(s):
    s = re.sub(r"\s", "", s or "")
    return base64.b64decode(s + "=" * (-len(s) % 4))

def decrypt_config_data(ecd, cert_hashes):
    iv, dt, hm = b64d(ecd['iv']), b64d(ecd['data']), b64d(ecd['hmac'])
    salt = b64d(ecd.get('keySalt', ''))
    scheme = int(ecd.get('scheme', 1))
    cands = []
    if scheme >= 2:
        for c in cert_hashes:
            cands.append(('native cert-sha256', hashlib.sha256(SEC32 + c + salt).digest()))
        cands.append(('legacy master', hashlib.sha256(MASTER + salt).digest()))
    else:
        cands.append(('legacy master', hashlib.sha256(MASTER + salt).digest()))
        for c in cert_hashes:
            cands.append(('native cert-sha256', hashlib.sha256(SEC32 + c + salt).digest()))
    for name, key in cands:
        if hmac.compare_digest(hmac.new(key, iv + dt, hashlib.sha256).digest(), hm):
            pt = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(dt[:-16], dt[-16:])
            return json.loads(pt.decode('utf-8')), name
    raise ValueError("key derivation failed (wrong signing cert / salt?)")

# ---------------- APK signing cert -> SHA-256 ----------------

def apk_cert_hash(apk):
    real = apk
    try:
        import zipfile
        if zipfile.is_zipfile(apk):
            with zipfile.ZipFile(apk) as z:
                names = z.namelist()
                if not any(n == 'AndroidManifest.xml' for n in names):
                    bases = [n for n in names if n.endswith('.apk') and 'base' in n] or [n for n in names if n.endswith('.apk')]
                    if bases:
                        tmp = "/data/data/com.termux/files/usr/tmp/_ctun_base.apk"
                        with open(tmp, 'wb') as f:
                            f.write(z.read(bases[0]))
                        real = tmp
    except Exception:
        pass
    try:
        out = subprocess.run(["apksigner", "verify", "--print-certs", real],
                             capture_output=True, text=True, timeout=120).stdout
        m = re.search(r'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})', out)
        if m:
            return bytes.fromhex(m.group(1))
    except Exception:
        pass
    return None

def gather_cert_hashes(apk_arg):
    certs = list(KNOWN_CERTS)
    if FALLBACK not in certs:
        certs.append(FALLBACK)
    if apk_arg and os.path.exists(apk_arg):
        h = apk_cert_hash(apk_arg)
        if h and h not in certs:
            certs.insert(0, h)
            print_c(f"[*] APK cert SHA-256: {h.hex()}", C_CYAN)
    else:
        auto = APK_PATH if os.path.exists(APK_PATH) else None
        if auto:
            h = apk_cert_hash(auto)
            if h and h not in certs:
                certs.insert(0, h)
                print_c(f"[*] APK cert SHA-256: {h.hex()}", C_CYAN)
    return certs

# ---------------- main ----------------

def find_ctun(args):
    if args:
        return args
    hits = []
    for pat in [DEFAULT_CTUN, "/storage/emulated/0/Download/*.ctun",
                "/storage/emulated/0/Download/*/*.ctun", "/sdcard/VPNs/*.ctun"]:
        hits += glob.glob(pat)
    return hits[0] if hits else None

def main():
    print_bar(C_RED)
    print_c("CUSTOM TUNNEL  ❰  Config Unlocker  ❱", C_RED)
    print_c("Python By @Snapdark 🇧🇩", C_CYAN)
    print_bar(C_RED)

    apk_arg = None
    files = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("--apk", "-a") and i + 1 < len(args):
            apk_arg = args[i + 1]; i += 2
        else:
            files.append(args[i]); i += 1

    ctun_files = find_ctun(files)
    if not ctun_files:
        print_c("[!] No .ctun file found. Usage: python3 'Custom Tunnel.py' [file.ctun] [--apk app.apk]", C_YELLOW)
        sys.exit(1)
    if isinstance(ctun_files, str):
        ctun_files = [ctun_files]

    certs = gather_cert_hashes(apk_arg)
    print_c(f"[*] CTUN files: {len(ctun_files)}", C_CYAN)

    results = {}
    for path in ctun_files:
        print_c(f"\n[*] Opening: {os.path.basename(path)}", C_YELLOW)
        try:
            raw = open(path, 'rb').read()
            exp = unpack_ctun(raw)
            sign = exp.get('appSignature', '?')
            cfg = exp.get('configData') or {}
            print_c(f"[*] appSignature: {sign}", C_CYAN)
            plain, how = decrypt_config_data(cfg, certs)
            print_c(f"[+] Unlocked via: {how}", C_GREEN)
            for k, v in plain.items():
                print_c(f"    {k:<15}: {v}", C_GREEN)
            results[os.path.basename(path)] = {**plain}
        except Exception as e:
            print_c(f"[-] Failed: {e}", C_RED)

    if results:
        out = {"CREDITS": CREDITS, "TELEGRAM": "https://t.me/bd_loser", "CHANNEL": "https://t.me/+GEautSR2nNphZWJl", "NOTE": "Free Config - Do not sell"}
        out.update(results)
        os.makedirs("/sdcard/VPNs", exist_ok=True)
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print_bar(C_GREEN)
        print_c(f"[+] Saved -> {OUTPUT_FILE}", C_GREEN)
        print_bar(C_GREEN)
    else:
        print_c("[!] Nothing decrypted", C_RED)

if __name__ == "__main__":
    main()
