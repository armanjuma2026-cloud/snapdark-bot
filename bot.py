#!/usr/bin/env python3
"""Long-polling Telegram bot for @SnapDarkBot (stdlib only).

Public: menu with VPN sections (needs an active subscription).
Admin (owner only): /admin -> edit section texts + give/remove/extend subscriptions.
Data: content.json (section texts), subs.json (subscriptions).
"""

import html
import http.server
import json
import os
import re
import secrets
import shutil
import fcntl
import concurrent.futures
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_builtin_print = print


def print(*args, **kwargs):  # timestamp every log line
    _builtin_print(time.strftime("%H:%M:%S"), *args, **kwargs)


API = "https://api.telegram.org/bot{token}/{method}"
HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, "token.txt")
CONTENT_FILE = os.path.join(HERE, "content.json")
SUBS_FILE = os.path.join(HERE, "subs.json")
ADMINS_FILE = os.path.join(HERE, "admins.json")
PRICES_FILE = os.path.join(HERE, "prices.json")
COOLDOWN_FILE = os.path.join(HERE, "cooldowns.json")

# ---------------------------------------------------------------- config
OWNER_ID = int(os.environ.get("SNAPDARK_OWNER_ID", "5576391405"))
ADMIN_USERNAME = "@snapdark_decoder"
ADMIN_URL = "https://t.me/snapdark_decoder"

MINUTE = 60
DAY = 86400

PLANS = [
    ("🧪 Test — 30 minutes", "test", 30 * MINUTE),
    ("1️⃣ 1 Month", "1m", 30 * DAY),
    ("2️⃣ 2 Months", "2m", 60 * DAY),
    ("3️⃣ 3 Months", "3m", 90 * DAY),
    ("4️⃣ 4 Months", "4m", 120 * DAY),
    ("5️⃣ 5 Months", "5m", 150 * DAY),
    ("6️⃣ 6 Months", "6m", 180 * DAY),
    ("📅 1 Year", "12m", 365 * DAY),
]
PLAN_SECONDS = {key: secs for _, key, secs in PLANS}
PLAN_NAME = {key: label.split(" ", 1)[1] for label, key, _ in PLANS}

SCRIPTS_DIR = os.path.join(HERE, "scripts")
SENSEI_DIR = "/storage/emulated/0/senseitunnel"
COOLDOWN_SECONDS = 8 * 3600  # same VPN again only after 8 hours


def slug(name):
    out = []
    for ch in name.lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-")


def discover_vpns():
    """Every decryptor script shipped in the repo becomes a button."""
    base = SCRIPTS_DIR if os.path.isdir(SCRIPTS_DIR) else SENSEI_DIR
    apps = []
    if os.path.isdir(base):
        for fn in sorted(os.listdir(base), key=str.lower):
            if fn.endswith(".py") and not fn.startswith("_"):
                name = fn[:-3]
                apps.append({"key": slug(name), "name": name, "script": fn})
    return apps


VPNS = discover_vpns()
VPN_BY_KEY = {v["key"]: v for v in VPNS}
RUNNING = set()  # uids currently generating a config

MENU = [
    ("📁 All VPN List", "all_vpn"),
    ("👨‍💻 Developer List", "developer"),
    ("💎 Paid VPN List", "paid"),
    ("🆓 Free VPN List", "free"),
    ("☎️ Help Line", "help_line"),
    ("📅 Subscription", "subscription"),
    ("⏳ Expire Date", "expire"),
    ("🆕 New Apps Decode", "decode"),
]
LABELS = {data: label.split(" ", 1)[1] for label, data in MENU}

DEFAULTS = {
    "all_vpn": "<b>📁 All VPN List</b>\n\nTODO: add your full VPN app list here.",
    "offline_list": "<b>🚫 Offline VPN List</b>",
    "developer": "<b>👨‍💻 Developer List</b>\n\nTODO: add developer names / channels here.",
    "paid": "<b>💎 Paid VPN List</b>\n\nTODO: add paid VPN apps here.",
    "free": "<b>🆓 Free VPN List</b>\n\nTODO: add free VPN apps here.",
    "help_line": (
        "<b>☎️ Help Line</b>\n\n"
        f"Admin: {ADMIN_USERNAME}\n"
        "Reply time: usually within a few hours."
    ),
    "subscription": (
        "<b>📅 Subscription</b>\n\n"
        "Plans:\n"
        "• Test — 30 minutes\n"
        "• 1, 2, 3, 4, 5, 6 months\n"
        "• 1 year\n\n"
        f"Contact the admin to activate: {ADMIN_USERNAME}"
    ),
    "expire": "<b>⏳ Expire Date</b>\n\nYour subscription details will be shown here.",
    "decode": "<b>🆕 New Apps Decode</b>\n\nTODO: add the newest decoded apps here (name + link).",
}
# ------------------------------------------------------------- end config


def load_token() -> str:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if token:
        return token
    with open(TOKEN_FILE, "r", encoding="utf-8") as fh:
        return fh.read().strip()


TOKEN = load_token()


def _load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            print(f"[warn] {path}: {exc}", flush=True)
    return default


def _save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


TEXTS = dict(DEFAULTS)
TEXTS.update(_load_json(CONTENT_FILE, {}))
if not os.path.isfile(SUBS_FILE):
    _bootstrap = os.path.join(HERE, "bootstrap_subs.json")
    if os.path.isfile(_bootstrap):
        shutil.copy(_bootstrap, SUBS_FILE)
        print("[boot] subs initialised from bootstrap_subs.json", flush=True)

SUBS = {int(k): v for k, v in _load_json(SUBS_FILE, {}).items()}
COOLDOWNS = _load_json(COOLDOWN_FILE, {})

ADMINS = [int(x) for x in _load_json(ADMINS_FILE, [])]
DEFAULT_PRICES = {
    "test": "Free",
    "1m": "150 BDT",
    "2m": "280 BDT",
    "3m": "400 BDT",
    "4m": "500 BDT",
    "5m": "600 BDT",
    "6m": "700 BDT",
    "12m": "1200 BDT",
}
PRICES = _load_json(PRICES_FILE, {}) or dict(DEFAULT_PRICES)

PENDING_EDIT = {}  # admin uid -> section key
PENDING_SUB = {}   # admin uid -> {"action": ..., "plan": ...}
PENDING_ACCEPT = {}  # admin uid -> user id whose token was just entered

EX_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4)  # keeps taps responsive

HELP_MODE = set()   # user ids currently chatting directly with the admin
RELAY_MAP = {}      # admin chat message_id -> user id (to route admin replies)


def save_content():
    _save_json(CONTENT_FILE, TEXTS)


def save_subs():
    _save_json(SUBS_FILE, {str(k): v for k, v in SUBS.items()})


def save_admins():
    _save_json(ADMINS_FILE, ADMINS)


def save_prices():
    _save_json(PRICES_FILE, PRICES)


def save_cooldowns():
    _save_json(COOLDOWN_FILE, COOLDOWNS)


def _sdcard_ok():
    probe = os.path.join("/sdcard/VPNs", ".probe")
    try:
        os.makedirs("/sdcard/VPNs", exist_ok=True)
        open(probe, "w").close()
        os.remove(probe)
        return True
    except OSError:
        return False


WRITE_OK = _sdcard_ok()
OUTPUT_ROOT = "/sdcard/VPNs" if WRITE_OK else os.path.join(HERE, "output")
os.makedirs(OUTPUT_ROOT, exist_ok=True)


def prepare_scripts():
    """On servers without /sdcard, patch script copies to write under OUTPUT_ROOT."""
    os.makedirs(OUTPUT_ROOT, exist_ok=True)
    if WRITE_OK:
        return SCRIPTS_DIR
    patched = os.path.join(HERE, "scripts_out")
    os.makedirs(patched, exist_ok=True)
    for fn in os.listdir(SCRIPTS_DIR):
        if not fn.endswith(".py"):
            continue
        src_path = os.path.join(SCRIPTS_DIR, fn)
        text = open(src_path, encoding="utf-8", errors="replace").read()
        if "/sdcard/VPNs" in text:
            text = text.replace('"/sdcard/VPNs', f'"{OUTPUT_ROOT}').replace("/sdcard/VPNs", OUTPUT_ROOT)
        open(os.path.join(patched, fn), "w").write(text)
    print(f"[env] /sdcard unavailable -> outputs go to {OUTPUT_ROOT}", flush=True)
    return patched


RUN_BASE = prepare_scripts()


def script_path(name):
    """Run the prepared copy (cloud-safe), fall back to repo + phone folder."""
    for base in (RUN_BASE, SCRIPTS_DIR, SENSEI_DIR):
        path = os.path.join(base, name)
        if os.path.exists(path):
            return path, base
    return None, None


def cooldown_left(user_id, key):
    last = COOLDOWNS.get(str(user_id), {}).get(key)
    if not last:
        return 0
    left = COOLDOWN_SECONDS - (time.time() - last)
    return int(max(0, left))


def mark_cooldown(user_id, key):
    COOLDOWNS.setdefault(str(user_id), {})[key] = time.time()
    save_cooldowns()


_CONTENT_MTIME = 0.0


def reload_content():
    """Pick up manual edits of content.json without restarting."""
    global _CONTENT_MTIME
    try:
        mtime = os.stat(CONTENT_FILE).st_mtime_ns
    except OSError:
        return
    if mtime == _CONTENT_MTIME:
        return
    _CONTENT_MTIME = mtime
    fresh = dict(DEFAULTS)
    fresh.update(_load_json(CONTENT_FILE, {}))
    TEXTS.clear()
    TEXTS.update(fresh)


# ------------------------------------------------------------- utilities
_TG_TLS = threading.local()  # one persistent HTTPS connection per thread
LAST_TG_ERROR = ""           # last Telegram-side error description


def _tg_conn():
    conn = getattr(_TG_TLS, "conn", None)
    if conn is None:
        conn = http.client.HTTPSConnection("api.telegram.org", timeout=40)
        _TG_TLS.conn = conn
    return conn


def call(method: str, **params):
    """POST to the Bot API over a keep-alive connection (TLS handshake once)."""
    body = urllib.parse.urlencode(params)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    for attempt in (1, 2):
        try:
            conn = _tg_conn()
            conn.request("POST", f"/bot{TOKEN}/{method}", body=body, headers=headers)
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode() or "{}")
            if not payload.get("ok"):
                global LAST_TG_ERROR
                LAST_TG_ERROR = str(payload.get("description") or "")
                print(f"[warn] {method}: {LAST_TG_ERROR}", flush=True)
                return None
            return payload.get("result")
        except Exception as exc:
            try:
                _tg_conn().close()
            except Exception:
                pass
            _TG_TLS.conn = None
            if attempt == 2:
                print(f"[warn] {method}: {exc}", flush=True)
                return None
            time.sleep(0.5)


def send(chat_id, text, markup=None):
    params = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if markup is not None:
        params["reply_markup"] = json.dumps(markup)
    ok = call("sendMessage", **params)
    if ok is None:  # bad HTML -> plain text fallback
        params.pop("parse_mode", None)
        ok = call("sendMessage", **params)
    print(f"[send] {chat_id}: {'ok' if ok else 'failed'}", flush=True)
    return ok


def send_document(chat_id, path, caption=None):
    """Upload a file with multipart/form-data using stdlib only."""
    boundary = "----snapdark" + secrets.token_hex(8)
    chunks = []

    def field(name, value):
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )

    field("chat_id", chat_id)
    if caption:
        field("caption", caption)
        field("parse_mode", "HTML")
    filename = os.path.basename(path)
    chunks.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{filename}"\r\n'
        "Content-Type: application/json\r\n\r\n".encode()
    )
    with open(path, "rb") as fh:
        chunks.append(fh.read())
    chunks.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(chunks)

    path_url = f"/bot{TOKEN}/sendDocument"
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    payload = None
    for attempt in range(1, 4):
        try:
            conn = _tg_conn()
            conn.request("POST", path_url, body=body, headers=headers)
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode() or "{}")
            break
        except Exception as exc:
            print(f"[warn] sendDocument attempt {attempt}: {exc}", flush=True)
            try:
                _tg_conn().close()
            except Exception:
                pass
            _TG_TLS.conn = None
            time.sleep(1.5 * attempt)
    if payload is None:
        return None
    if not payload.get("ok"):
        print(f"[warn] sendDocument: {payload.get('description')}", flush=True)
        return None
    print(f"[doc] {chat_id}: {filename} ({os.path.getsize(path)} B)", flush=True)
    return payload.get("result")


OFFLINE_APPS = [
    # (name, reason shown to users)  -- apps that cannot build a config now
    ("WebTunnelMax", "Server keys rotated — fix in progress"),
    ("Apka Tunnel", "New encrypted format — fix in progress"),
    ("APNA SHIELD PRO", "Missing app bundle — fix in progress"),
    ("Vip Snipher Pro", "Missing source URL — fix in progress"),
    ("CloudV2ray", "Server host currently down"),
    ("Great Tunnel", "Under maintenance"),
    ("Lucky VIP Proxy", "Under maintenance"),
    ("MM Tunnel", "Under maintenance"),
    ("PTI Tunnel Pro", "Under maintenance"),
    ("SA Tunnel", "Under maintenance"),
    ("Solid Tunnel", "Under maintenance"),
    ("VLX Tunnel", "Under maintenance"),
    ("Custom Tunnel", "Under maintenance"),
    ("FNF Tunnel BD", "Under maintenance"),
    ("Http Custom", "Under maintenance"),
    ("IPTunnel", "Under maintenance"),
    ("PDirect", "Under maintenance"),
    ("Proxy", "Under maintenance"),
    ("PStunnel", "Under maintenance"),
    ("SmartIP Tunnel", "Under maintenance"),
    ("SnapDarkTunnel Backup", "Under maintenance"),
]


def offline_keyboard():
    rows, row = [], []
    for name, _why in OFFLINE_APPS:
        row.append({"text": "🔴 " + name, "callback_data": "off:" + slug(name)})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "⬅️ Menu", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


def vpn_keyboard():
    def norm(s):
        return "".join(ch.lower() for ch in s if ch.isalnum())
    offline_keys = {slug(n) for n, _w in OFFLINE_APPS} | {norm(n) for n, _w in OFFLINE_APPS}
    rows, row = [], []
    shown = 0
    for v in VPNS:
        if v["key"] in offline_keys or norm(v["name"]) in offline_keys:  # only ACTIVE apps in the All VPN List
        # skip offline apps
            continue
        shown += 1
        row.append({"text": "📡 " + v["name"], "callback_data": "vpn:" + v["key"]})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": f"🚫 Offline VPN List ({len(OFFLINE_APPS)})", "callback_data": "offline_list"}])
    rows.append([{"text": "⬅️ Menu", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


JSON_DIRS = (OUTPUT_ROOT, "/sdcard/VPNs", "/sdcard", HERE, os.path.expanduser("~"))
CACHE_DIR = os.path.join(HERE, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)
REFRESHING = set()  # keys currently being rebuilt in background


def cached_path(key):
    p = os.path.join(CACHE_DIR, key + ".json")
    return p if os.path.isfile(p) and os.path.getsize(p) > 32 else None


def cache_store(key, path):
    try:
        data = open(path, "rb").read()
        with open(os.path.join(CACHE_DIR, key + ".json"), "wb") as fh:
            fh.write(data)
        return True
    except OSError as exc:
        print(f"[cache] store {key}: {exc}", flush=True)
        return False


def snapshot_json(extra_dirs=()):
    """(path -> (mtime, size)) for every JSON we could confuse with a fresh build."""
    seen = {}
    for d in (*JSON_DIRS, *extra_dirs):
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for fn in entries:
            if not fn.lower().endswith(".json"):
                continue
            p = os.path.join(d, fn)
            try:
                seen[p] = (os.path.getmtime(p), os.path.getsize(p))
            except OSError:
                pass
    return seen


def newest_json(started, seen, extra_dirs=()):
    """Only accept a JSON that is NEW or CHANGED since the snapshot (no stale files)."""
    best, best_m = None, 0
    for d in (*JSON_DIRS, *extra_dirs):
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for fn in entries:
            if not fn.lower().endswith(".json"):
                continue
            p = os.path.join(d, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_size <= 32 or st.st_mtime < started:
                continue
            if seen.get(p) == (st.st_mtime, st.st_size):
                continue  # untouched file from an earlier run
            if st.st_mtime > best_m:
                best, best_m = p, st.st_mtime
    return best


def refresh_build(key):
    """Rebuild an app silently in the background and refresh the cache."""
    if key in REFRESHING:
        return
    REFRESHING.add(key)
    try:
        spec = VPN_BY_KEY.get(key)
        if not spec:
            return
        script, base = script_path(spec["script"])
        if not script:
            return
        seen = snapshot_json((base,))
        started = time.time() - 1
        try:
            proc = subprocess.run(
                [sys.executable, script],
                cwd=base,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=120,
            )
        except Exception as exc:
            print(f"[refresh] {key} error: {exc}", flush=True)
            return
        out = newest_json(started, seen, (base,)) if proc.returncode == 0 else None
        if out:
            cache_store(key, out)
            print(f"[refresh] {key} cache updated ({os.path.getsize(out)//1024} KB)", flush=True)
        else:
            print(f"[refresh] {key} no fresh json (rc={proc.returncode})", flush=True)
    finally:
        REFRESHING.discard(key)


def build_vpn(chat_id, key):
    """Run the decryptor script and send the JSON it produced."""
    spec = VPN_BY_KEY.get(key)
    if not spec:
        send(chat_id, "Unknown app.", vpn_keyboard())
        return
    if chat_id in RUNNING:
        send(chat_id, "⏳ Still building the previous config, please wait.")
        return
    admin = is_admin(chat_id)
    left = 0 if admin else cooldown_left(chat_id, key)
    if left > 0:
        send(
            chat_id,
            f"⏳ <b>{spec['name']}</b> is on cooldown.\n\n"
            f"Available again in <b>{fmt_left(left)}</b>.\n"
            "You can request any other app right now.",
            vpn_keyboard(),
        )
        print(f"[cool] {chat_id} {key} left={left}s", flush=True)
        return
    cached = cached_path(key)
    if cached:
        sent = send_document(
            chat_id,
            cached,
            f"✅ <b>{spec['name']}</b> config (latest saved build)\n"
            f"📦 {os.path.getsize(cached)/1024:.0f} KB\n"
            "♻️ A fresh build is generating in the background.",
        )
        if sent and not admin:
            mark_cooldown(chat_id, key)
        if key not in REFRESHING:
            threading.Thread(target=refresh_build, args=(key,), daemon=True).start()
        return
    if key in REFRESHING:
        send(chat_id, f"⏳ <b>{spec['name']}</b> fresh build is already running — the new "
             "JSON arrives automatically a moment early.", vpn_keyboard())
        return
    RUNNING.add(chat_id)
    try:
        send(chat_id, f"⏳ Building <b>{spec['name']}</b> live config…\nThis can take up to a minute.")
        script, base = script_path(spec["script"])
        reason = ""
        seen = snapshot_json((base,))
        started = time.time() - 1
        ok = False
        if script:
            try:
                proc = subprocess.run(
                    [sys.executable, script],
                    cwd=base,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    timeout=120,
                )
                out_txt = (proc.stdout or b"").decode(errors="replace").strip().splitlines()[-2:]
                err_txt = (proc.stderr or b"").decode(errors="replace").strip().splitlines()[-2:]
                print(f"[vpn] {key} rc={proc.returncode} {' | '.join(out_txt)}", flush=True)
                for e in err_txt:
                    print(f"[vpn-err] {key} {e}", flush=True)
                reason = (err_txt or out_txt or [""])[-1]
                ok = proc.returncode == 0
            except Exception as exc:
                print(f"[vpn] {key} error: {exc}", flush=True)
        else:
            print(f"[vpn] {key} script missing", flush=True)

        out = newest_json(started, seen, (base,)) if ok else None
        if out:
            cache_store(key, out)
            size = os.path.getsize(out)
            sent = send_document(
                chat_id,
                out,
                f"✅ <b>{spec['name']}</b> live config\n"
                f"🕒 {time.strftime('%Y-%m-%d %H:%M')}\n📦 {size/1024:.0f} KB\n"
                f"⏳ Next refresh in 8h",
            )
            if sent and not admin:
                mark_cooldown(chat_id, key)
        else:
            cached = cached_path(key)
            if cached:
                send_document(
                    chat_id,
                    cached,
                    f"♻️ <b>{spec['name']}</b> — latest saved build\n"
                    "(live rebuild failed this time; file below is from the last success)",
                )
                if not admin:
                    mark_cooldown(chat_id, key)
                return
            msg = (
                f"❌ <b>{spec['name']}</b>: could not build the config right now.\n"
                "The app may be offline or the script needs updating."
            )
            if admin and reason:
                clean = re.sub(r"\\x1b\\[[0-9;]*m", "", reason).strip()[:180]
                msg += f"\n\n<code>{html.escape(clean)}</code>"
            send(chat_id, msg, vpn_keyboard())
    finally:
        RUNNING.discard(chat_id)


def edit(chat_id, message_id, text, markup=None):
    params = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
    }
    if markup is not None:
        params["reply_markup"] = json.dumps(markup)
    if call("editMessageText", **params) is None:
        if "not modified" in LAST_TG_ERROR:
            return  # same content, nothing to change
        params.pop("parse_mode", None)
        if call("editMessageText", **params) is None:
            if "not modified" in LAST_TG_ERROR:
                return
            send(chat_id, text, markup)


def is_owner(user_id) -> bool:
    return user_id == OWNER_ID


def is_admin(user_id) -> bool:
    return is_owner(user_id) or user_id in ADMINS


TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def gen_token() -> str:
    pick = lambda: "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(4))
    return f"SK-{pick()}-{pick()}"


def ensure_user(user_id) -> dict:
    """Every user gets one token the first time they touch the bot."""
    entry = SUBS.get(user_id)
    if entry is None:
        entry = {"token": gen_token(), "exp": 0, "plan": None, "created": time.time()}
        SUBS[user_id] = entry
        save_subs()
        print(f"[join] {user_id} token {entry['token']}", flush=True)
    elif not entry.get("token"):
        entry["token"] = gen_token()
        save_subs()
        print(f"[token] {user_id} -> {entry['token']}", flush=True)
    return entry


def parse_token_arg(text):
    for chunk in text.split():
        c = chunk.strip().strip(",;<>")
        if c and not c.isdigit() and not c.startswith("/") and len(c) >= 4:
            return c.upper()
    return None


def fmt_left(seconds: float) -> str:
    seconds = int(seconds)
    if seconds <= 0:
        return "expired"
    days, rem = divmod(seconds, DAY)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def sub_expiry(user_id):
    entry = SUBS.get(user_id)
    return entry.get("exp", 0) if entry else 0


def has_access(user_id) -> bool:
    if is_owner(user_id):
        return True
    return sub_expiry(user_id) > time.time()


def access_denied(chat_id):
    send(
        chat_id,
        "⛔️ <b>Subscription required</b>\n\n"
        "Your subscription is not active or has expired.\n"
        f"Please contact the admin to activate: {ADMIN_USERNAME}\n\n"
        f'<a href="{ADMIN_URL}">Open admin chat</a>',
        {"inline_keyboard": [[{"text": "💬 Admin Contact", "url": ADMIN_URL}]]},
    )


# ------------------------------------------------------------- keyboards
def main_keyboard(user_id=None):
    rows, row = [], []
    for label, data in MENU:
        row.append({"text": label, "callback_data": data})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "🔑 My Token", "callback_data": "mytoken"}])
    if user_id is not None and is_admin(user_id):
        rows.append([{"text": "🛠 Admin Panel", "callback_data": "adm:panel"}])
    rows.append([{"text": "💬 Admin Contact", "url": ADMIN_URL}])
    return {"inline_keyboard": rows}


def back_keyboard():
    return {"inline_keyboard": [[{"text": "⬅️ Back to Menu", "callback_data": "menu"}]]}


def section_back_keyboard():
    return {
        "inline_keyboard": [
            [
                {"text": "⬅️ Menu", "callback_data": "menu"},
                {"text": "⏳ My Expire Date", "callback_data": "expire"},
            ]
        ]
    }


def admin_keyboard():
    rows, row = [], []
    for label, data in MENU:
        row.append({"text": "📝 " + label.split(" ", 1)[1], "callback_data": "adm:edit:" + data})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append(
        [
            {"text": "🔔 New Users", "callback_data": "adm:joins"},
            {"text": "🗓 Subscriptions", "callback_data": "adm:subs"},
        ]
    )
    rows.append(
        [
            {"text": "🔑 Tokens", "callback_data": "adm:tokens"},
            {"text": "📣 Broadcast", "callback_data": "adm:cast"},
        ]
    )
    rows.append(
        [
            {"text": "💰 Prices", "callback_data": "adm:prices"},
            {"text": "👤 Admins", "callback_data": "adm:admins"},
        ]
    )
    rows.append(
        [
            {"text": "♻️ Cooldowns", "callback_data": "adm:cool"},
            {"text": "📊 Stats", "callback_data": "adm:stats"},
        ]
    )
    rows.append(
        [
            {"text": "👁 Preview Menu", "callback_data": "menu"},
            {"text": "✖️ Close", "callback_data": "adm:close"},
        ]
    )
    return {"inline_keyboard": rows}


def plans_keyboard(prefix="adm:plan:"):
    rows, row = [], []
    for label, key, _ in PLANS:
        row.append({"text": label, "callback_data": prefix + key})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "⬅️ Back", "callback_data": "adm:subs"}])
    return {"inline_keyboard": rows}


def subs_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "➕ Give / Extend", "callback_data": "adm:subs:add"}],
            [{"text": "➖ Remove", "callback_data": "adm:subs:del"}],
            [
                {"text": "🔍 Check user", "callback_data": "adm:subs:check"},
                {"text": "📋 Active list", "callback_data": "adm:subs:list"},
            ],
            [{"text": "⬅️ Back", "callback_data": "adm:panel"}],
        ]
    }


def prices_keyboard():
    rows, row = [], []
    for label, key, _ in PLANS:
        row.append({"text": label, "callback_data": "adm:price:" + key})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "⬅️ Back", "callback_data": "adm:panel"}])
    return {"inline_keyboard": rows}


def admins_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "📋 List admins", "callback_data": "adm:adm:list"}],
            [{"text": "➕ Add admin", "callback_data": "adm:adm:add"}],
            [{"text": "➖ Remove admin", "callback_data": "adm:adm:del"}],
            [{"text": "⬅️ Back", "callback_data": "adm:panel"}],
        ]
    }


def tokens_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "✅ Accept token", "callback_data": "adm:tok:accept"}],
            [{"text": "👥 New users (no subscription)", "callback_data": "adm:tok:newlist"}],
            [{"text": "➕ Create token by user id", "callback_data": "adm:tok:add"}],
            [{"text": "🗑 Remove token", "callback_data": "adm:tok:del"}],
            [{"text": "📋 List tokens", "callback_data": "adm:tok:list"}],
            [{"text": "⬅️ Back", "callback_data": "adm:panel"}],
        ]
    }


WELCOME = "👋 <b>Welcome to SnapDark</b>\n\nChoose an option from the menu below 👇"
ADMIN_PANEL = (
    "🛠 <b>Admin Panel</b>\n\n"
    "📝 buttons <b>edit the text</b> of a section (they do not show it).\n"
    "Tap 👁 Preview Menu to see what users see."
)
SUB_PANEL = "🗓 <b>Subscriptions</b>\n\nAdd, extend, remove or check any user."
TOKEN_PANEL = (
    "🔑 <b>Tokens</b>\n\n"
    "Tokens are created <b>automatically</b> — nothing to create here.\n\n"
    "✅ <b>Accept token</b> — the user sends you their token, you paste it here; "
    "the bot finds the user and shows the subscription plans. Pick a plan and "
    "their access is activated instantly.\n\n"
    "👥 <b>New users</b> — users who started the bot but have no subscription; "
    "tap a user to create a fresh token.\n"
    "➕ <b>Create token by user id</b> — make/replace a token for any id "
    "(send <code>id</code> or <code>id MY-TOKEN</code>).\n"
    "🗑 <b>Remove token</b> — block a user's token.\n"
    "📋 <b>List tokens</b> — every user id, token and status."
)
PRICE_PANEL = "💰 <b>Prices</b>\n\nTap a plan and send its price text."
ADMINS_PANEL = "👤 <b>Admins</b>\n\nExtra admin ids (owner always has access)."


# --------------------------------------------------------------- users
def user_status_text(user_id) -> str:
    exp = sub_expiry(user_id)
    entry = SUBS.get(user_id, {})
    plan = entry.get("plan", "-")
    if exp <= 0:
        return f"<b>{user_id}</b>: no subscription"
    state = "active ✅" if exp > time.time() else "expired ⛔️"
    left = fmt_left(exp - time.time())
    return (
        f"<b>{user_id}</b>: {state}\n"
        f"Plan: {PLAN_NAME.get(plan, plan)}\n"
        f"Expires: {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))} ({left} left)"
    )


def apply_plan(user_id, plan, extend=True):
    now = time.time()
    seconds = PLAN_SECONDS[plan]
    current = sub_expiry(user_id) if extend else 0
    base = max(now, current)
    entry = SUBS.get(user_id)
    if entry is None:
        entry = {"token": gen_token(), "created": now}
        SUBS[user_id] = entry
    # keep the token/created fields — only the plan part changes
    entry.update({"plan": plan, "exp": base + seconds, "started": now, "updated": now})
    if not entry.get("token"):
        entry["token"] = gen_token()
    save_subs()
    print(f"[admin] {user_id} -> {plan}, exp {SUBS[user_id]['exp']}", flush=True)
    return SUBS[user_id]["exp"]


def expire_watcher():
    """Log subscriptions that just ran out (access itself is time-based)."""
    while True:
        time.sleep(60)
        now = time.time()
        for uid, entry in list(SUBS.items()):
            exp = entry.get("exp", 0)
            if exp and exp < now and not entry.get("expired_logged"):
                entry["expired_logged"] = True
                save_subs()
                print(f"[expire] {uid} ({entry.get('plan')})", flush=True)


# ------------------------------------------------------------ handlers
def extract_user_id(msg, text):
    if msg.get("reply_to_message"):
        u = (msg["reply_to_message"].get("from") or {}).get("id")
        if u:
            return u
    if msg.get("forward_from"):
        return msg["forward_from"].get("id")
    origin = msg.get("forward_origin") or {}
    if (origin.get("sender_user") or {}).get("id"):
        return origin["sender_user"]["id"]
    for chunk in "".join(ch if ch.isdigit() or ch == " " else " " for ch in text).split():
        if len(chunk) >= 5:
            return int(chunk)
    return None


def handle_message(msg):
    reload_content()
    chat_id = msg["chat"]["id"]
    user = msg.get("from") or {}
    user_id = user.get("id")
    text = (msg.get("text") or "").strip()
    user_msg_id = msg.get("message_id", 0)
    name = html.escape(user.get("first_name") or "there")

    # --- admin editing a section text
    if user_id in PENDING_EDIT:
        if text.startswith("/cancel"):
            PENDING_EDIT.pop(user_id, None)
            send(chat_id, "❎ Edit cancelled.", admin_keyboard())
            return
        key = PENDING_EDIT.pop(user_id)
        TEXTS[key] = text
        save_content()
        print(f"[admin] {user_id} edited {key}", flush=True)
        send(chat_id, f"✅ <b>{LABELS[key]}</b> updated.\n\nPreview:\n{text}", admin_keyboard())
        return

    # --- admin reply routing (Help Line): reply to a support header -> delivered to user
    reply_id = (msg.get("reply_to_message") or {}).get("message_id", 0)
    if user_id == OWNER_ID and reply_id in RELAY_MAP:
        target_user = RELAY_MAP[reply_id]
        ok = call(
            "copyMessage",
            chat_id=target_user,
            from_chat_id=chat_id,
            message_id=user_msg_id,
        )
        if ok:
            RELAY_MAP.pop(reply_id, None)
            RELAY_MAP[ok["message_id"]] = target_user
            send(chat_id, f"✅ Delivered to <code>{target_user}</code>.")
            print(f"[help] admin -> {target_user} delivered", flush=True)
        else:
            send(chat_id, "⚠️ Could not deliver (user may have blocked the bot).")
        return

    # --- admin giving / removing / checking a subscription
    if user_id in PENDING_SUB:
        state = PENDING_SUB[user_id]
        action = state.get("action")
        if text.startswith("/cancel"):
            PENDING_SUB.pop(user_id, None)
            send(chat_id, "❎ Cancelled.", admin_keyboard())
            return
        if action == "broadcast":
            PENDING_SUB.pop(user_id, None)
            targets = sorted(SUBS.keys())
            sent = failed = 0
            for uid in targets:
                if uid == user_id:
                    continue
                if send(uid, text, back_keyboard()):
                    sent += 1
                else:
                    failed += 1
                time.sleep(0.05)
            print(f"[cast] {user_id}: {sent} ok, {failed} failed", flush=True)
            send(chat_id, f"📣 Broadcast done.\n✅ {sent} delivered\n⚠️ {failed} failed", admin_keyboard())
            return
        if action == "price":
            plan = state.get("plan")
            PENDING_SUB.pop(user_id, None)
            if plan not in PLAN_SECONDS:
                send(chat_id, "⚠️ Plan lost, try again.", prices_keyboard())
                return
            PRICES[plan] = text
            save_prices()
            print(f"[price] {plan} = {text}", flush=True)
            send(chat_id, f"✅ Price for <b>{PLAN_NAME[plan]}</b> set to <b>{text}</b>.", prices_keyboard())
            return
        target = extract_user_id(msg, text)
        if target is None:
            send(
                chat_id,
                "⚠️ Send a numeric user id, or reply to / forward a message from that user.",
                subs_keyboard(),
            )
            return
        PENDING_SUB.pop(user_id, None)
        if action == "cool_reset":
            PENDING_SUB.pop(user_id, None)
            cleared = len(COOLDOWNS.pop(str(target), {}) or {})
            save_cooldowns()
            print(f"[cool] {user_id} reset {target} ({cleared})", flush=True)
            send(
                chat_id,
                f"♻️ Cooldowns reset for <b>{target}</b> ({cleared} entries cleared).",
                admin_keyboard(),
            )
            return
        if action in ("admin_add", "admin_del"):
            if not is_owner(user_id):
                send(chat_id, "⛔️ Only the owner can manage admins.", admin_keyboard())
                return
            if action == "admin_add":
                if target == OWNER_ID or target in ADMINS:
                    send(chat_id, f"ℹ️ {target} is already an admin.", admins_keyboard())
                else:
                    ADMINS.append(target)
                    save_admins()
                    print(f"[admin] {user_id} added admin {target}", flush=True)
                    send(chat_id, f"✅ <b>{target}</b> is now an admin.", admins_keyboard())
                    send(target, "🛠 You are now an admin. Use /admin to open the panel.")
            else:
                if target in ADMINS:
                    ADMINS.remove(target)
                    save_admins()
                    print(f"[admin] {user_id} removed admin {target}", flush=True)
                    send(chat_id, f"✅ <b>{target}</b> removed from admins.", admins_keyboard())
                else:
                    send(chat_id, f"ℹ️ {target} is not an admin.", admins_keyboard())
            return
        if action == "tok_accept":
            PENDING_SUB.pop(user_id, None)
            wanted = text.strip().strip("<>,;").upper()
            target = next(
                (uid for uid, e in SUBS.items() if (e.get("token") or "").upper() == wanted),
                None,
            )
            if not target:
                send(
                    chat_id,
                    f"⚠️ No user has the token <code>{html.escape(wanted[:40])}</code>.\n\n"
                    "Check the token and tap ✅ Accept token again.",
                    tokens_keyboard(),
                )
                return
            PENDING_SUB.pop(user_id, None)
            PENDING_ACCEPT[user_id] = target
            exp = sub_expiry(target)
            status = (
                "✅ active until " + time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
                if exp > time.time()
                else "⛔️ no active subscription"
            )
            send(
                chat_id,
                f"🔎 <b>Token found</b>\n\n"
                f"👤 User: <code>{target}</code>\n"
                f"🔑 Token: <code>{wanted}</code>\n"
                f"📊 Status: {status}\n\n"
                "Accept this user?",
                {
                    "inline_keyboard": [[
                        {"text": "✅ Accept", "callback_data": "adm:tok:ok"},
                        {"text": "❌ Reject", "callback_data": "adm:tok:no"},
                    ]]
                },
            )
            return
        if action in ("tok_add", "tok_del"):
            if action == "tok_del":
                entry = SUBS.get(target)
                if not entry:
                    send(chat_id, f"ℹ️ {target} has no token.", tokens_keyboard())
                else:
                    entry["token"] = None
                    save_subs()
                    print(f"[token] {user_id} removed token of {target}", flush=True)
                    send(chat_id, f"🗑 Token removed for <b>{target}</b>.", tokens_keyboard())
                    send(target, "⛔️ Your token was removed by the admin. Contact " + ADMIN_USERNAME)
                return
            entry = SUBS.get(target)
            custom = parse_token_arg(text)
            if entry is None:
                entry = {"exp": 0, "plan": None, "created": time.time()}
                SUBS[target] = entry
            entry["token"] = custom if custom else gen_token()
            save_subs()
            print(f"[token] {user_id} set {target} -> {entry['token']}", flush=True)
            send(
                chat_id,
                f"🔑 Token for <b>{target}</b>: <code>{entry['token']}</code>",
                tokens_keyboard(),
            )
            delivered = send(
                target,
                f"🔑 Your token: <code>{entry['token']}</code>\n\n"
                f"Send it to {ADMIN_USERNAME} to activate your subscription.",
            )
            if not delivered:
                send(
                    chat_id,
                    f"⚠️ Token for <b>{target}</b> is created, but the user never "
                    "pressed /start, so Telegram blocked the message. Send it manually.",
                    tokens_keyboard(),
                )
            return
        if action == "remove":
            if SUBS.pop(target, None) is None:
                send(chat_id, f"ℹ️ {target} has no subscription.", subs_keyboard())
            else:
                save_subs()
                print(f"[admin] {user_id} removed {target}", flush=True)
                send(chat_id, f"🗑 Subscription removed for <b>{target}</b>.", subs_keyboard())
                send(target, "⛔️ Your subscription has been removed by the admin.")
            return
        if action == "check":
            send(chat_id, "🔍 " + user_status_text(target), subs_keyboard())
            return
        if action == "give":
            plan = state.get("plan")
            if plan not in PLAN_SECONDS:
                send(chat_id, "⚠️ Plan lost, please start again.", subs_keyboard())
                return
            exp = apply_plan(target, plan)
            left = fmt_left(exp - time.time())
            send(
                chat_id,
                f"✅ <b>{PLAN_NAME[plan]}</b> activated for <b>{target}</b>.\n"
                f"Expires: {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))} ({left} left)",
                subs_keyboard(),
            )
            send(
                target,
                "✅ <b>Subscription activated</b>\n\n"
                f"Plan: <b>{PLAN_NAME[plan]}</b>\n"
                f"Expires: {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}\n"
                f"Remaining: <b>{left}</b>\n\nUse /start to open the menu.",
            )
            return
        return

    if text.startswith("/start"):
        entry = ensure_user(user_id)
        entry["name"] = (user.get("first_name") or "") + (
            (" @" + user["username"]) if user.get("username") else ""
        )
        save_subs()
        fresh = time.time() - entry.get("created", 0) < 5
        token_line = f"🔑 Your token: <code>{entry['token']}</code>"
        if fresh:
            send(
                OWNER_ID,
                "🆕 <b>New user request</b>\n\n"
                f"👤 Name: {html.escape(entry['name'] or str(user_id))}\n"
                f"🪪 ID: <code>{user_id}</code>\n"
                f"🔑 Token: <code>{entry['token']}</code>\n\n"
                "Accept them: Admin Panel → 🔔 New Users or ✅ Accept token.",
            )
        if has_access(user_id):
            left = "owner" if is_owner(user_id) else fmt_left(sub_expiry(user_id) - time.time())
            send(
                chat_id,
                f"{WELCOME}\n\nHi <b>{name}</b>!\n{token_line}\nAccess: <b>{left}</b>",
                main_keyboard(user_id),
            )
        else:
            send(
                chat_id,
                f"👋 Hi <b>{name}</b>!\n\n{token_line}\n\n"
                "⛔️ <b>No active subscription</b>\n"
                f"Send this token to the admin to activate: {ADMIN_USERNAME}",
                {"inline_keyboard": [[{"text": "💬 Admin Contact", "url": ADMIN_URL}]]},
            )
    elif text.startswith("/menu"):
        if has_access(user_id):
            send(chat_id, WELCOME, main_keyboard(user_id))
        else:
            access_denied(chat_id)
    elif text.startswith("/admin") or text.startswith("/panel"):
        if is_admin(user_id):
            PENDING_EDIT.pop(user_id, None)
            PENDING_SUB.pop(user_id, None)
            waiting = sum(1 for e in SUBS.values() if e.get("exp", 0) <= time.time())
            send(
                chat_id,
                ADMIN_PANEL.replace(
                    "\n\nTap",
                    f"\n\n🔔 Waiting users: <b>{waiting}</b>\n\nTap",
                ),
                admin_keyboard(),
            )
        else:
            print(f"[deny] {user_id} tried /admin", flush=True)
            send(chat_id, "⛔️ Sorry, admin panel is for the owner only.")
    elif text.startswith("/help"):
        send(
            chat_id,
            "Commands:\n/start - main menu\n/menu - main menu\n/ping - check bot\n\n"
            f"Subscription & support: {ADMIN_USERNAME}",
            back_keyboard(),
        )
    elif user_id in HELP_MODE and not text.startswith("/"):
        if text.startswith("/cancel"):
            HELP_MODE.discard(user_id)
            send(chat_id, "🔕 Support chat closed. Use the menu anytime.", main_keyboard(user_id))
            return
        header = send(
            OWNER_ID,
            "✉️ <b>Support message</b>\n"
            f"👤 <b>{html.escape(name)}</b> • ID: <code>{user_id}</code>\n\n"
            "↩️ Reply to THIS message to answer the user.",
        )
        fwd = call(
            "forwardMessage",
            chat_id=OWNER_ID,
            from_chat_id=chat_id,
            message_id=user_msg_id or 0,
        )
        if header and fwd:
            RELAY_MAP[header["message_id"]] = user_id
            RELAY_MAP[fwd["message_id"]] = user_id
            send(
                chat_id,
                "✅ <b>Sent to the admin.</b>\n"
                "You can keep typing here — replies arrive in this chat.",
                back_keyboard(),
            )
            print(f"[help] {user_id} -> admin", flush=True)
        else:
            send(chat_id, "⚠️ Could not reach the admin right now — try again.", back_keyboard())
        return

    elif is_admin(user_id) and re.fullmatch(r"SK-[A-Z0-9]{4}-[A-Z0-9]{4}", text.strip().upper()):
        wanted = text.strip().strip("<>,;\n").upper()
        print(f"[tok-auto] {user_id} typed {wanted}", flush=True)
        target = next(
            (uid for uid, e in SUBS.items() if (e.get("token") or "").upper() == wanted),
            None,
        )
        if target is None:
            send(
                chat_id,
                f"⚠️ Token <code>{html.escape(wanted)}</code> does not match any user.\n\n"
                "Make sure the user pressed /start first, then check 📋 List tokens.",
                tokens_keyboard(),
            )
        else:
            PENDING_ACCEPT[user_id] = target
            exp = sub_expiry(target)
            status = (
                "✅ active until " + time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
                if exp > time.time()
                else "⛔️ no active subscription"
            )
            nm = SUBS[target].get("name") or "-"
            send(
                chat_id,
                "🔎 <b>Token found</b>\n\n"
                f"👤 Name: {html.escape(nm)}\n"
                f"🪪 ID: <code>{target}</code>\n"
                f"🔑 Token: <code>{wanted}</code>\n"
                f"📊 Status: {status}\n\n"
                "Accept this user?",
                {
                    "inline_keyboard": [[
                        {"text": "✅ Accept", "callback_data": "adm:tok:ok"},
                        {"text": "❌ Reject", "callback_data": "adm:tok:no"},
                    ]]
                },
            )
        return

    elif text.startswith("/ping"):
        send(chat_id, "🏓 Pong — bot online.", back_keyboard())
    elif text.startswith("/version"):
        send(
            chat_id,
            f"🤖 snapdark-bot\ncommit: <code>{current_commit()}</code>\n"
            f"apps: {len(VPNS)}\ncooldown: {COOLDOWN_SECONDS // 3600}h per app",
            back_keyboard(),
        )
    else:
        print(f"[msg] {chat_id} {name}: {text[:120]}", flush=True)
        if has_access(user_id):
            send(chat_id, "Please use the menu 👇", main_keyboard(user_id))
        else:
            access_denied(chat_id)


def handle_callback(cb):
    reload_content()
    msg = cb.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    message_id = msg.get("message_id")
    user_id = (cb.get("from") or {}).get("id")
    data = cb.get("data") or ""
    if chat_id is None:
        call("answerCallbackQuery", callback_query_id=cb["id"])
        return

    # ---- admin panel routes
    if data.startswith("adm:"):
        if not is_admin(user_id):
            call("answerCallbackQuery", callback_query_id=cb["id"], text="Admin only", show_alert=True)
            print(f"[deny] {user_id} tried {data}", flush=True)
            return
        call("answerCallbackQuery", callback_query_id=cb["id"])

        if data == "adm:stats":
            now = time.time()
            active = sum(1 for e in SUBS.values() if e.get("exp", 0) > now)
            expired = sum(
                1 for e in SUBS.values()
                if 0 < e.get("exp", 0) <= now
            )
            fresh = len(SUBS) - active - expired
            cool_users = len(COOLDOWNS)
            cool_used = sum(len(v) for v in COOLDOWNS.values())
            tokens_on = sum(1 for e in SUBS.values() if e.get("token"))
            body = (
                "📊 <b>SnapDark — Admin Stats</b>\n\n"
                f"👥 Users started: <b>{len(SUBS)}</b>\n"
                f"• active subscriptions: <b>{active}</b>\n"
                f"• expired: <b>{expired}</b>\n"
                f"• no subscription yet: <b>{fresh}</b>\n\n"
                f"📡 VPN apps installed: <b>{len(VPNS)}</b>\n"
                f"⏳ Cooldowns: <b>{cool_used} locked builds</b> over {cool_users} users\n\n"
                f"🔑 Tokens with value: <b>{tokens_on}</b>\n"
                f"💰 Prices set: <b>{len(PRICES)}/{len(PLANS)}</b>\n"
                f"🤖 Version: <code>{current_commit()}</code>"
            )
            edit(chat_id, message_id, body, admin_keyboard())
            return

        if data == "adm:close":
            PENDING_EDIT.pop(user_id, None)
            PENDING_SUB.pop(user_id, None)
            edit(chat_id, message_id, "Panel closed.", back_keyboard())
            return

        if data == "adm:subs":
            PENDING_SUB.pop(user_id, None)
            edit(chat_id, message_id, SUB_PANEL, subs_keyboard())
            return

        if data == "adm:joins":
            PENDING_SUB.pop(user_id, None)
            now = time.time()
            waiting = [
                (uid, e)
                for uid, e in SUBS.items()
                if e.get("exp", 0) <= now
            ]
            waiting.sort(key=lambda x: x[1].get("created", 0), reverse=True)
            rows, shown = [], []
            for uid, e in waiting[:40]:
                nm = e.get("name") or ""
                age = int(now - e.get("created", 0))
                mark = "🆕" if age < 86400 and e.get("exp", 0) <= 0 else "⏳"
                label = f"{mark} {nm[:18]} · {uid}" if nm else f"👤 {uid}"
                rows.append([{"text": label, "callback_data": f"adm:req:{uid}"}])
                shown.append(uid)
            rows.append([{"text": "✅ Accept by token", "callback_data": "adm:tok:accept"}])
            rows.append([{"text": "⬅️ Back", "callback_data": "adm:panel"}])
            body = (
                f"🔔 <b>New user requests: {len(waiting)} waiting</b>\n\n"
                "🆕 = joined, never activated\n"
                "⏳ = subscription expired, needs renewal\n\n"
                "Tap a user → choose the plan → activated instantly."
                if waiting
                else "🔔 <b>No waiting users.</b>\n\nEveryone is active."
            )
            edit(chat_id, message_id, body, {"inline_keyboard": rows})
            return

        if data.startswith("adm:req:"):
            try:
                target = int(data.split("adm:req:", 1)[1])
            except ValueError:
                edit(chat_id, message_id, "⚠️ Bad user id.", tokens_keyboard())
                return
            entry = SUBS.get(target)
            if entry is None:
                edit(chat_id, message_id, "⚠️ User no longer exists.", tokens_keyboard())
                return
            nm = entry.get("name") or "-"
            body = (
                "👤 <b>User request</b>\n\n"
                f"Name: {html.escape(nm)}\n"
                f"ID: <code>{target}</code>\n"
                f"Token: <code>{entry.get('token') or '-'}</code>\n"
                f"Status: {user_status_text(target).split(': ', 1)[1] if ': ' in user_status_text(target) else ''}\n\n"
                "Choose the subscription plan to accept:"
            )
            edit(chat_id, message_id, body, plans_keyboard(prefix=f"adm:accept:{target}:"))
            return

        if data == "adm:tokens":
            PENDING_SUB.pop(user_id, None)
            edit(chat_id, message_id, TOKEN_PANEL, tokens_keyboard())
            return

        if data == "adm:tok:list":
            if not SUBS:
                body = "No users yet."
            else:
                lines = [f"🔑 <b>Tokens: {len(SUBS)}</b>\n"]
                for uid, e in sorted(SUBS.items()):
                    status = "✅ active" if e.get("exp", 0) > time.time() else "⛔️ inactive"
                    token = e.get("token") or "-"
                    lines.append(f"• <code>{uid}</code> — <code>{token}</code> — {status}")
                body = "\n".join(lines[:50])
            edit(chat_id, message_id, body, tokens_keyboard())
            return

        if data == "adm:tok:newlist":
            PENDING_SUB.pop(user_id, None)
            now = time.time()
            idle = [(uid, e) for uid, e in sorted(SUBS.items()) if e.get("exp", 0) <= now]
            rows = []
            for uid, e in idle[:40]:
                label = f"{'🔑' if e.get('token') else '🚫'} {uid}"
                rows.append([{"text": label, "callback_data": f"adm:tok:new:{uid}"}])
            rows.append([{"text": "⬅️ Back", "callback_data": "adm:tokens"}])
            body = (
                f"👥 <b>Users without an active subscription: {len(idle)}</b>\n\n"
                "Tap a user to create a new token for them."
                if idle
                else "👥 <b>No users without a subscription.</b>\n\nNobody has started the bot yet."
            )
            edit(chat_id, message_id, body, {"inline_keyboard": rows})
            return

        if data.startswith("adm:tok:new:"):
            try:
                target = int(data.split("adm:tok:new:", 1)[1])
            except ValueError:
                edit(chat_id, message_id, "⚠️ Bad user id.", tokens_keyboard())
                return
            entry = SUBS.get(target)
            if entry is None:
                entry = {"exp": 0, "plan": None, "created": time.time()}
                SUBS[target] = entry
            entry["token"] = gen_token()
            save_subs()
            print(f"[token] {user_id} created token for {target}", flush=True)
            delivered = send(
                target,
                f"🔑 Your new token: <code>{entry['token']}</code>\n\n"
                f"Send it to {ADMIN_USERNAME} to activate your subscription.",
            )
            note = "" if delivered else (
                "\n\n⚠️ Could not message this user — they must press /start first."
            )
            edit(
                chat_id,
                message_id,
                f"🔑 Token for <b>{target}</b>: <code>{entry['token']}</code>{note}",
                tokens_keyboard(),
            )
            return

        if data == "adm:tok:add":
            PENDING_SUB[user_id] = {"action": "tok_add"}
            edit(
                chat_id,
                message_id,
                "➕ <b>Create token by user id</b>\n\n"
                "Send the <b>user id</b> to create a new token.\n\n"
                "• not sure of the id? use 👥 <b>New users</b>\n"
                "• your own token text: <code>user_id MY-TOKEN</code>\n\n"
                "Send /cancel to abort.",
            )
            return

        if data == "adm:tok:accept":
            PENDING_SUB[user_id] = {"action": "tok_accept"}
            PENDING_ACCEPT.pop(user_id, None)
            send(
                chat_id,
                "✅ <b>Accept token</b>\n\n"
                "Paste the token the user sent you (example: <code>SK-AB12-CD34</code>) "
                "in the box below 👇\n\n"
                "Send /cancel to abort.",
                {"force_reply": True, "input_field_placeholder": "Paste token here…"},
            )
            return

        if data == "adm:tok:ok":
            target = PENDING_ACCEPT.pop(user_id, None)
            if not target:
                edit(chat_id, message_id, "⚠️ Session expired, tap ✅ Accept token again.", tokens_keyboard())
                return
            edit(
                chat_id,
                message_id,
                f"✅ Accepted <code>{target}</code>.\n\n"
                "Now choose the <b>subscription plan</b>:",
                plans_keyboard(prefix=f"adm:accept:{target}:"),
            )
            return

        if data == "adm:tok:no":
            PENDING_ACCEPT.pop(user_id, None)
            edit(chat_id, message_id, "❌ Token rejected — nothing was changed.", tokens_keyboard())
            return

        if data.startswith("adm:accept:"):
            try:
                _, _, target, plan = data.split(":", 3)
            except ValueError:
                edit(chat_id, message_id, "⚠️ Bad button data.", tokens_keyboard())
                return
            try:
                target = int(target)
            except ValueError:
                pass
            if plan not in PLAN_SECONDS or target not in SUBS:
                edit(chat_id, message_id, "⚠️ User or plan not found.", tokens_keyboard())
                return
            exp = apply_plan(target, plan)
            left = fmt_left(exp - time.time())
            print(f"[admin] {user_id} accepted token of {target} -> {plan}", flush=True)
            edit(
                chat_id,
                message_id,
                f"✅ Token accepted.\n\n"
                f"👤 User: <code>{target}</code>\n"
                f"🗓 Plan: <b>{PLAN_NAME[plan]}</b>\n"
                f"📅 Expires: {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}\n"
                f"Remaining: <b>{left}</b>",
                tokens_keyboard(),
            )
            send(
                target,
                "✅ <b>Token accepted — subscription activated</b>\n\n"
                f"Plan: <b>{PLAN_NAME[plan]}</b>\n"
                f"Expires: {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}\n"
                f"Remaining: <b>{left}</b>\n\nUse /start to open the menu.",
            )
            return

        if data == "adm:tok:del":
            PENDING_SUB[user_id] = {"action": "tok_del"}
            edit(
                chat_id,
                message_id,
                "🗑 Send the <b>user id</b> whose token should be removed.\n\n"
                "Send /cancel to abort.",
            )
            return

        if data == "adm:subs:add":
            PENDING_SUB.pop(user_id, None)
            edit(chat_id, message_id, "🗓 <b>Choose plan</b> for the user:", plans_keyboard())
            return

        if data.startswith("adm:plan:"):
            plan = data.split("adm:plan:", 1)[1]
            if plan not in PLAN_SECONDS:
                edit(chat_id, message_id, "Unknown plan.", plans_keyboard())
                return
            PENDING_SUB[user_id] = {"action": "give", "plan": plan}
            edit(
                chat_id,
                message_id,
                f"🗓 Plan: <b>{PLAN_NAME[plan]}</b>\n\n"
                "Now send the <b>user id</b>, or reply to / forward a message from that user.\n\n"
                "Send /cancel to abort.",
            )
            return

        if data in ("adm:subs:del", "adm:subs:check"):
            action = "remove" if data.endswith("del") else "check"
            PENDING_SUB[user_id] = {"action": action}
            word = "remove the subscription of" if action == "remove" else "check"
            edit(
                chat_id,
                message_id,
                f"Send the <b>user id</b> to {word}, or reply to / forward a message from that user.\n\n"
                "Send /cancel to abort.",
            )
            return

        if data == "adm:subs:list":
            active = [(uid, e) for uid, e in SUBS.items() if e.get("exp", 0) > time.time()]
            active.sort(key=lambda kv: kv[1]["exp"])
            if not active:
                body = "No active subscriptions."
            else:
                lines = [f"📋 <b>Active: {len(active)}</b>\n"]
                for uid, e in active[:50]:
                    lines.append(
                        f"• <code>{uid}</code> — {PLAN_NAME.get(e.get('plan'), e.get('plan'))} — "
                        f"{fmt_left(e['exp'] - time.time())} left"
                    )
                body = "\n".join(lines)
            edit(chat_id, message_id, body, subs_keyboard())
            return

        if data.startswith("adm:edit:"):
            key = data.split("adm:edit:", 1)[1]
            if key not in TEXTS:
                edit(chat_id, message_id, "Unknown section.", admin_keyboard())
                return
            PENDING_EDIT[user_id] = key
            PENDING_SUB.pop(user_id, None)
            edit(
                chat_id,
                message_id,
                f"✏️ <b>{LABELS[key]}</b>\n\n"
                "Send the new text for this section.\n"
                'HTML allowed: &lt;b&gt;bold&lt;/b&gt;, &lt;a href="..."&gt;link&lt;/a&gt;.\n\n'
                "Send /cancel to abort.",
            )
            return

        if data == "adm:cast":
            PENDING_SUB[user_id] = {"action": "broadcast"}
            PENDING_EDIT.pop(user_id, None)
            edit(
                chat_id,
                message_id,
                "📣 Send the message to broadcast to all users.\n\n"
                "HTML allowed. Send /cancel to abort.",
            )
            return

        if data == "adm:prices":
            PENDING_SUB.pop(user_id, None)
            lines = ["💰 <b>Prices</b>\n"]
            for label, key, _ in PLANS:
                lines.append(f"• {PLAN_NAME[key]}: {PRICES.get(key) or 'not set'}")
            lines.append("\nTap a plan to set its price.")
            edit(chat_id, message_id, "\n".join(lines), prices_keyboard())
            return

        if data.startswith("adm:price:"):
            plan = data.split("adm:price:", 1)[1]
            if plan not in PLAN_SECONDS:
                edit(chat_id, message_id, "Unknown plan.", prices_keyboard())
                return
            PENDING_SUB[user_id] = {"action": "price", "plan": plan}
            edit(
                chat_id,
                message_id,
                f"💰 Price for <b>{PLAN_NAME[plan]}</b>\n\nSend the price text, e.g. "
                "<code>150 BDT</code> or <code>Free</code>.\n\nSend /cancel to abort.",
            )
            return

        if data == "adm:cool":
            PENDING_SUB[user_id] = {"action": "cool_reset"}
            edit(
                chat_id,
                message_id,
                "♻️ Send the <b>user id</b> to reset all of that user's config cooldowns.\n\n"
                "Send /cancel to abort.",
            )
            return

        if data == "adm:adm:list":
            if not is_owner(user_id):
                edit(chat_id, message_id, "⛔️ Only the owner can manage admins.", admin_keyboard())
                return
            body = "👤 <b>Admins</b>\n\n" + "\n".join(
                [f"• <code>{OWNER_ID}</code> — owner"]
                + [f"• <code>{a}</code>" for a in ADMINS]
                + ["", "Tap ➕ / ➖ to change."]
            )
            edit(chat_id, message_id, body, admins_keyboard())
            return

        if data in ("adm:adm:add", "adm:adm:del"):
            if not is_owner(user_id):
                edit(chat_id, message_id, "⛔️ Only the owner can manage admins.", admin_keyboard())
                return
            act = "admin_add" if data.endswith("add") else "admin_del"
            PENDING_SUB[user_id] = {"action": act}
            edit(
                chat_id,
                message_id,
                "👤 Send the <b>user id</b> " + ("to add as admin." if act == "admin_add" else "to remove from admins.") +
                "\n\nSend /cancel to abort.",
            )
            return

        now = time.time()
        waiting = sum(1 for e in SUBS.values() if e.get("exp", 0) <= now)
        edit(
            chat_id,
            message_id,
            ADMIN_PANEL.replace(
                "\n\nTap",
                f"\n\n🔔 Waiting users: <b>{waiting}</b>\n\nTap",
            ),
            admin_keyboard(),
        )
        return

    # ---- public routes (need active subscription)
    if data == "menu":
        if not has_access(user_id):
            call("answerCallbackQuery", callback_query_id=cb["id"], text="Subscription expired", show_alert=True)
            access_denied(chat_id)
            return
        call("answerCallbackQuery", callback_query_id=cb["id"])
        edit(chat_id, message_id, WELCOME, main_keyboard(user_id))
        return

    if data.startswith("off:"):
        key = data[4:]
        name = next(
            (n for n, _w in OFFLINE_APPS if slug(n) == key), key
        )
        why = next((w for n, w in OFFLINE_APPS if slug(n) == key), "Under maintenance")
        call(
            "answerCallbackQuery",
            callback_query_id=cb["id"],
            text=f"🚫 {name}: {why}",
            show_alert=True,
        )
        return

    if data == "help_write":
        HELP_MODE.add(user_id)
        call("answerCallbackQuery", callback_query_id=cb["id"], text="Connecting you…")
        send(
            chat_id,
            "✉️ <b>Write your message</b> — it goes straight to the admin",
            {"force_reply": True, "input_field_placeholder": "Write your question to reply…"},
        )
        return

    if data == "mytoken":
        entry = ensure_user(user_id)
        call("answerCallbackQuery", callback_query_id=cb["id"], text="Token ready")
        exp = sub_expiry(user_id)
        if is_owner(user_id):
            state = "👑 Owner account — unlimited access"
        elif exp > time.time():
            state = "✅ Active until " + time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
        else:
            state = "⏳ Not active yet — send this token to the admin"
        edit(
            chat_id,
            message_id,
            f"🔑 <b>Your token</b>\n\n<code>{entry['token']}</code>\n\n{state}\n\n"
            f"Tap the token to copy it, then send it to {ADMIN_USERNAME} to activate "
            "your subscription.",
            back_keyboard(),
        )
        return

    if not has_access(user_id):
        call(
            "answerCallbackQuery",
            callback_query_id=cb["id"],
            text="⛔️ Subscription expired. Contact admin.",
            show_alert=True,
        )
        print(f"[deny] {user_id} tried {data} (expired)", flush=True)
        access_denied(chat_id)
        return

    call("answerCallbackQuery", callback_query_id=cb["id"])

    if data.startswith("vpn:"):
        key = data.split("vpn:", 1)[1]
        threading.Thread(target=build_vpn, args=(chat_id, key), daemon=True).start()
        return

    if data == "expire":
        entry = SUBS.get(user_id)
        if is_owner(user_id):
            text = "⏳ <b>Expire Date</b>\n\nOwner account — no expiry."
        elif entry:
            text = (
                "⏳ <b>Your Subscription</b>\n\n"
                f"Token: <code>{entry.get('token') or '-'}</code>\n"
                f"Plan: <b>{PLAN_NAME.get(entry.get('plan'), entry.get('plan'))}</b>\n"
                f"Expires: {time.strftime('%Y-%m-%d %H:%M', time.localtime(entry['exp']))}\n"
                f"Remaining: <b>{fmt_left(entry['exp'] - time.time())}</b>"
            )
        else:
            text = "⏳ <b>Expire Date</b>\n\nNo subscription found."
        edit(chat_id, message_id, text, back_keyboard())
        return

    text = TEXTS.get(data)
    if text is None:
        edit(chat_id, message_id, "Unknown option.", back_keyboard())
        return
    if data == "subscription" and PRICES:
        text += "\n\n<b>Prices</b>\n" + "\n".join(
            f"• {PLAN_NAME.get(k, k)}: <b>{PRICES[k]}</b>"
            for k in [p[1] for p in PLANS] if k in PRICES
        )
    print(f"[cb] {chat_id}: {data}", flush=True)
    if data == "help_line":
        kb = section_back_keyboard()
        kb["inline_keyboard"].insert(
            0, [{"text": "✉️ Message the Admin", "callback_data": "help_write"}]
        )
        text += (
            "\n\n✉️ <b>Direct chat with the admin</b>\n"
            "• tap ✉️ <b>Message the Admin</b>\n"
            "• type your problem\n"
            "• the answer comes back right here\n\n"
            f"Or message directly: {ADMIN_USERNAME}"
        )
        edit(chat_id, message_id, text, kb)
        return
    if data == "all_vpn":
        text += "\n\n👇 <b>Tap an app</b> to get its live config JSON."
        edit(chat_id, message_id, text, vpn_keyboard())
        return
    if data == "offline_list":
        total = len(VPNS)
        text = (
            f"🚫 <b>Offline VPN List</b>\n"
            f"{len(OFFLINE_APPS)} apps offline · "
            f"{total - len(OFFLINE_APPS)} apps working now ✅\n\n"
        )
        for name, why in OFFLINE_APPS:
            text += f"• 🔴 <b>{name}</b> — {why}\n"
        text += "\n🛠 We are working on them — they come back automatically.\n"
        edit(chat_id, message_id, text, offline_keyboard())
        return
    edit(chat_id, message_id, text, section_back_keyboard())


def git(*args):
    return subprocess.run(
        ["git", "-C", HERE, *args], capture_output=True, text=True, timeout=180
    )


def current_commit():
    r = git("rev-parse", "--short", "HEAD")
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def update_once():
    """Fetch origin/main; if it moved, pull and let the supervisor restart us."""
    try:
        if git("fetch", "--quiet", "origin", "main").returncode != 0:
            return False
        local = git("rev-parse", "HEAD").stdout.strip()
        remote = git("rev-parse", "origin/main").stdout.strip()
        if not local or not remote or local == remote:
            return False
        print(f"[update] {local[:7]} -> {remote[:7]}", flush=True)
        if git("pull", "--ff-only", "--quiet", "origin", "main").returncode == 0:
            print("[update] code updated, restarting", flush=True)
            return True
        print("[update] pull failed (local changes?), keeping current code", flush=True)
    except Exception as exc:
        print(f"[update] {exc}", flush=True)
    return False


def update_watcher():
    if os.environ.get("SNAPDARK_NO_UPDATE") == "1":
        print("[update] disabled", flush=True)
        return
    time.sleep(15)
    while True:
        if update_once():
            time.sleep(2)
            os._exit(0)
        time.sleep(300)


def ddns_updater():
    """Keep the fps.ms free-DDNS record in sync with our current public IP."""
    token = os.environ.get("FPS_MS_DDNS", "").strip()
    if not token:
        return
    while True:
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=15) as r:
                ip = r.read().decode().strip()
            with urllib.request.urlopen(
                f"https://panel.fps.ms/api/ddns/update?token={token}&ip={ip}",
                timeout=20,
            ) as r:
                print(f"[ddns] {r.read().decode().strip()[:120]}", flush=True)
        except Exception as exc:
            print(f"[ddns] update failed: {exc}", flush=True)
        time.sleep(600)


def health_server():
    """Tiny HTTP endpoint so cloud hosts (Koyeb/Render) see the service as healthy."""
    port = int(os.environ.get("PORT", "8080"))

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"snapdark-bot ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    try:
        http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
    except Exception as exc:
        print(f"[health] disabled: {exc}", flush=True)


def main():
    # single-instance lock: any second copy exits immediately (no poller conflicts)
    global _BOT_LOCK
    _BOT_LOCK = open(os.path.join(HERE, "bot.lock"), "w")
    try:
        fcntl.flock(_BOT_LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("[lock] another bot instance already polling -> exiting", flush=True)
        os._exit(0)
    print(f"bot started (owner {OWNER_ID}, {len(SUBS)} subs, {current_commit()})", flush=True)
    threading.Thread(target=update_watcher, daemon=True).start()
    threading.Thread(target=health_server, daemon=True).start()
    threading.Thread(target=ddns_updater, daemon=True).start()
    threading.Thread(target=expire_watcher, daemon=True).start()
    offset = None
    last_beat = time.time()
    last_ok = time.time()
    while True:
        params = {"timeout": 20}
        if offset is not None:
            params["offset"] = offset
        updates = call("getUpdates", **params)
        if updates is None:
            print("[warn] poll failed, retrying", flush=True)
            if time.time() - last_ok > 180:
                print("[watchdog] no Telegram contact for 180s -> recycling", flush=True)
                os._exit(0)
            time.sleep(2)
            continue
        last_ok = time.time()
        if not updates:
            if time.time() - last_beat > 600:
                last_beat = time.time()
                print(f"[beat] idle, offset={offset}", flush=True)
            continue
        for upd in updates:
            offset = upd["update_id"] + 1
            if upd.get("message") or upd.get("channel_post"):
                EX_POOL.submit(handle_message, upd.get("message") or upd.get("channel_post"))
            elif upd.get("callback_query"):
                EX_POOL.submit(handle_callback, upd["callback_query"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
