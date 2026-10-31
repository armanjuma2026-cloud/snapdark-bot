# SnapDark Bot

Telegram bot for **@SnapDarkBot** — VPN list menu with per-user tokens and a subscription system.
Pure Python 3 standard library, no pip packages needed.

## Features

- **Public menu** with 8 sections (inline buttons, 2 per row) + admin contact button.
- **Tokens**: every user gets a unique `SK-XXXX-XXXX` token automatically on first `/start`.
- **Subscriptions**: admin gives/extends/removes plans per user — test 30 min, 1–6 months, 1 year.
- **Auto expiry**: access is checked on every interaction; expired users are blocked instantly.
- **Admin panel** (`/admin`, owner only): edit section texts, manage subscriptions, manage tokens.
- **Supervisor** (`run.sh`): keeps the bot alive and recycles it every 10 minutes.

## Setup

```bash
git clone <this repo>
cd snapdark_bot

# token from @BotFather
printf '%s' '123456:ABC-DEF...' > token.txt
chmod 600 token.txt

# your Telegram numeric user id (owner)
export SNAPDARK_OWNER_ID=123456789

./run.sh          # starts + supervises
tail -f bot.log   # watch activity
```

Or run once without the supervisor:

```bash
python3 -u bot.py
```

## Commands

| Command | Who | Action |
|---|---|---|
| `/start` | everyone | token + menu (or "no subscription" notice) |
| `/menu` | subscribers | main menu |
| `/help` | everyone | command list |
| `/ping` | everyone | liveness check |
| `/admin` | owner | admin panel |
| `/cancel` | owner | abort a pending edit |

## Admin panel

```
✏️ All VPN List      ✏️ Developer List
✏️ Paid VPN List     ✏️ Free VPN List
✏️ Help Line         ✏️ Subscription
✏️ Expire Date       ✏️ New Apps Decode
🗓 Subscriptions      🔑 Tokens
👁 Preview Menu      ✖️ Close
```

- **Subscriptions** → give/extend, remove, check a user, list active users.
- **Tokens** → list, add/regenerate (`user_id` or `user_id MY-TOKEN`), remove.
- **✏️ sections** → send new text, HTML allowed (`<b>`, `<i>`, `<a href>`).

## Files

| File | Purpose | Committed |
|---|---|---|
| `bot.py` | the bot | yes |
| `run.sh` | supervisor loop | yes |
| `token.txt` | bot token | **no** (gitignored) |
| `content.json` | edited section texts | no |
| `subs.json` | tokens + subscriptions | no |
| `*.log` | logs | no |

## Notes

- Only one poller may run per bot token; stop other instances before starting this one.
- Termux: install `termux-wake-lock` and disable battery optimisation, or Android may freeze the process.
