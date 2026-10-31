#!/usr/bin/env python3
"""Long-polling Telegram bot for @SnapDarkBot (stdlib only).

Public: menu with VPN sections (needs an active subscription).
Admin (owner only): /admin -> edit section texts + give/remove/extend subscriptions.
Data: content.json (section texts), subs.json (subscriptions).
"""

import html
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.telegram.org/bot{token}/{method}"
HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, "token.txt")
CONTENT_FILE = os.path.join(HERE, "content.json")
SUBS_FILE = os.path.join(HERE, "subs.json")
ADMINS_FILE = os.path.join(HERE, "admins.json")
PRICES_FILE = os.path.join(HERE, "prices.json")

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
SUBS = {int(k): v for k, v in _load_json(SUBS_FILE, {}).items()}

ADMINS = [int(x) for x in _load_json(ADMINS_FILE, [])]
PRICES = _load_json(PRICES_FILE, {})

PENDING_EDIT = {}  # admin uid -> section key
PENDING_SUB = {}   # admin uid -> {"action": ..., "plan": ...}


def save_content():
    _save_json(CONTENT_FILE, TEXTS)


def save_subs():
    _save_json(SUBS_FILE, {str(k): v for k, v in SUBS.items()})


def save_admins():
    _save_json(ADMINS_FILE, ADMINS)


def save_prices():
    _save_json(PRICES_FILE, PRICES)


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
def call(method: str, **params):
    url = API.format(token=TOKEN, method=method)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode() or "{}")
    except Exception as exc:  # network hiccup
        print(f"[warn] {method}: {exc}", flush=True)
        return None
    if not payload.get("ok"):
        print(f"[warn] {method}: {payload.get('description')}", flush=True)
        return None
    return payload.get("result")


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
        params.pop("parse_mode", None)
        if call("editMessageText", **params) is None:
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
def main_keyboard():
    rows, row = [], []
    for label, data in MENU:
        row.append({"text": label, "callback_data": data})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
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
        row.append({"text": "✏️ " + label.split(" ", 1)[1], "callback_data": "adm:edit:" + data})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append(
        [
            {"text": "🗓 Subscriptions", "callback_data": "adm:subs"},
            {"text": "🔑 Tokens", "callback_data": "adm:tokens"},
        ]
    )
    rows.append(
        [
            {"text": "📣 Broadcast", "callback_data": "adm:cast"},
            {"text": "💰 Prices", "callback_data": "adm:prices"},
        ]
    )
    rows.append([{"text": "👤 Admins", "callback_data": "adm:admins"}])
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
            [{"text": "📋 List tokens", "callback_data": "adm:tok:list"}],
            [{"text": "➕ Add / regenerate", "callback_data": "adm:tok:add"}],
            [{"text": "🗑 Remove token", "callback_data": "adm:tok:del"}],
            [{"text": "⬅️ Back", "callback_data": "adm:panel"}],
        ]
    }


WELCOME = "👋 <b>Welcome to SnapDark</b>\n\nChoose an option from the menu below 👇"
ADMIN_PANEL = "🛠 <b>Admin Panel</b>\n\nSections, subscriptions and access — all here."
SUB_PANEL = "🗓 <b>Subscriptions</b>\n\nAdd, extend, remove or check any user."
TOKEN_PANEL = "🔑 <b>Tokens</b>\n\nOne token per user, created automatically on join."
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
    SUBS[user_id] = {
        "plan": plan,
        "exp": base + seconds,
        "started": now,
        "updated": now,
    }
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
            send(
                target,
                f"🔑 Your token: <code>{entry['token']}</code>\n\n"
                f"Send it to {ADMIN_USERNAME} to activate your subscription.",
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
        token_line = f"🔑 Your token: <code>{entry['token']}</code>"
        if has_access(user_id):
            left = "owner" if is_owner(user_id) else fmt_left(sub_expiry(user_id) - time.time())
            send(
                chat_id,
                f"{WELCOME}\n\nHi <b>{name}</b>!\n{token_line}\nAccess: <b>{left}</b>",
                main_keyboard(),
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
            send(chat_id, WELCOME, main_keyboard())
        else:
            access_denied(chat_id)
    elif text.startswith("/admin") or text.startswith("/panel"):
        if is_admin(user_id):
            PENDING_EDIT.pop(user_id, None)
            PENDING_SUB.pop(user_id, None)
            send(chat_id, ADMIN_PANEL, admin_keyboard())
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
    elif text.startswith("/ping"):
        send(chat_id, "🏓 Pong — bot online.", back_keyboard())
    else:
        print(f"[msg] {chat_id} {name}: {text[:120]}", flush=True)
        if has_access(user_id):
            send(chat_id, "Please use the menu 👇", main_keyboard())
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

        if data == "adm:close":
            PENDING_EDIT.pop(user_id, None)
            PENDING_SUB.pop(user_id, None)
            edit(chat_id, message_id, "Panel closed.", back_keyboard())
            return

        if data == "adm:subs":
            PENDING_SUB.pop(user_id, None)
            edit(chat_id, message_id, SUB_PANEL, subs_keyboard())
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

        if data == "adm:tok:add":
            PENDING_SUB[user_id] = {"action": "tok_add"}
            edit(
                chat_id,
                message_id,
                "🔑 Send the <b>user id</b> to create a new token.\n\n"
                "To set your own token text, send: <code>user_id MY-TOKEN</code>\n\n"
                "Send /cancel to abort.",
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

        if data == "adm:admins":
            if not is_owner(user_id):
                edit(chat_id, message_id, "⛔️ Only the owner can manage admins.", admin_keyboard())
                return
            edit(chat_id, message_id, ADMINS_PANEL, admins_keyboard())
            return

        if data == "adm:adm:list":
            body = "👤 <b>Admins</b>\n\n" + "\n".join(
                [f"• <code>{OWNER_ID}</code> — owner"] + [f"• <code>{a}</code>" for a in ADMINS]
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

        edit(chat_id, message_id, ADMIN_PANEL, admin_keyboard())
        return

    # ---- public routes (need active subscription)
    if data == "menu":
        if not has_access(user_id):
            call("answerCallbackQuery", callback_query_id=cb["id"], text="Subscription expired", show_alert=True)
            access_denied(chat_id)
            return
        call("answerCallbackQuery", callback_query_id=cb["id"])
        edit(chat_id, message_id, WELCOME, main_keyboard())
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
            f"• {PLAN_NAME.get(k, k)}: <b>{v}</b>" for k, v in PRICES.items()
        )
    print(f"[cb] {chat_id}: {data}", flush=True)
    edit(chat_id, message_id, text, section_back_keyboard())


def main():
    print(f"bot started (owner {OWNER_ID}, {len(SUBS)} subs)", flush=True)
    threading.Thread(target=expire_watcher, daemon=True).start()
    offset = None
    last_beat = time.time()
    while True:
        params = {"timeout": 20}
        if offset is not None:
            params["offset"] = offset
        updates = call("getUpdates", **params)
        if updates is None:
            print("[warn] poll failed, retrying", flush=True)
            time.sleep(2)
            continue
        if not updates:
            if time.time() - last_beat > 600:
                last_beat = time.time()
                print(f"[beat] idle, offset={offset}", flush=True)
            continue
        for upd in updates:
            offset = upd["update_id"] + 1
            try:
                if upd.get("message"):
                    handle_message(upd["message"])
                elif upd.get("channel_post"):
                    handle_message(upd["channel_post"])
                elif upd.get("callback_query"):
                    handle_callback(upd["callback_query"])
            except Exception as exc:
                print(f"[error] {exc}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
