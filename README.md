# SnapDark Bot

Telegram bot for **@SnapDarkBot** — VPN list menu with per-user tokens and a subscription system.
Pure Python 3 standard library, no pip packages needed.

## Features

- **Public menu** with 8 sections (inline buttons, 2 per row) + admin contact button.
- **Live configs**: `📁 All VPN List` → tap an app → bot runs the decryptor and sends the JSON.
- **Tokens**: every user gets a unique `SK-XXXX-XXXX` token automatically on first `/start`.
- **Subscriptions**: admin gives/extends/removes plans per user — test 30 min, 1–6 months, 1 year.
- **Auto expiry**: access is checked on every interaction; expired users are blocked instantly.
- **Admin panel** (`/admin`): edit section texts, subscriptions, tokens, prices, broadcast, extra admins.
- **Hot reload**: `content.json` edits apply on the next interaction, no restart needed.
- **Supervisor** (`run.sh`): keeps the bot alive and recycles it every 10 minutes.
- **runit service**: `snapdark` service for auto-start on Termux boot.

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

## VPN config delivery

`📁 All VPN List` shows one button per decodable app. Tapping one:

1. replies `⏳ Building … live config`
2. runs the decryptor from `scripts/<app>.py` (repo copy, fallback `/storage/emulated/0/senseitunnel/`)
3. uploads the resulting JSON from `/sdcard/VPNs/` as a document

Each user may refresh **the same app once every 8 hours**; other apps stay available.
Cooldowns live in `cooldowns.json` and can be reset from the admin panel (`♻️ Cooldowns`).
Admins and the owner are exempt — they can pull any config any number of times.

If the live run fails, the last cached JSON is sent with a warning. Subscription is checked first.

## Commands

| Command | Who | Action |
|---|---|---|
| `/start` | everyone | token + menu (or "no subscription" notice) |
| `/menu` | subscribers | main menu |
| `/help` | everyone | command list |
| `/ping` | everyone | liveness check |
| `/admin` | admins | admin panel |
| `/panel` | admins | alias of `/admin` |
| `/cancel` | owner | abort a pending edit |

## Admin panel

```
✏️ All VPN List      ✏️ Developer List
✏️ Paid VPN List     ✏️ Free VPN List
✏️ Help Line         ✏️ Subscription
✏️ Expire Date       ✏️ New Apps Decode
🗓 Subscriptions      🔑 Tokens
📣 Broadcast         💰 Prices
👤 Admins
👁 Preview Menu      ✖️ Close
```

- **Subscriptions** → give/extend, remove, check a user, list active users.
- **Tokens** → list, add/regenerate (`user_id` or `user_id MY-TOKEN`), remove.
- **✏️ sections** → send new text, HTML allowed (`<b>`, `<i>`, `<a href>`).
- **💰 Prices** → per plan price text, appended to the Subscription section.
- **📣 Broadcast** → send one message to every known user (HTML allowed).
- **👤 Admins** → add/remove extra admin ids (owner only).

## Files

| File | Purpose | Committed |
|---|---|---|
| `bot.py` | the bot | yes |
| `run.sh` | supervisor loop | yes |
| `token.txt` | bot token | **no** (gitignored) |
| `content.json` | edited section texts | no |
| `subs.json` | tokens + subscriptions | no |
| `prices.json` | plan prices | no |
| `admins.json` | extra admin ids | no |
| `*.log` | logs | no |

## Service (auto start)

```bash
pkg install runit
mkdir -p ~/.termux/boot
# boot script already at ~/.termux/boot/snapdark.sh (needs Termux:Boot app)
export SVDIR=$PREFIX/var/service
sv status snapdark     # run: snapdark: (pid ...)
sv restart snapdark    # or: sv down snapdark / sv up snapdark
```

## Auto update from GitHub

The running bot checks `origin/main` every 5 minutes (and 15 s after start). When a new commit
appears it runs `git pull --ff-only` and restarts itself through the supervisor/runit service:

```
[update] b691cae -> fb2e8d5
[update] code updated, restarting
```

Push a change and the device picks it up automatically. Disable with `SNAPDARK_NO_UPDATE=1`.
`/version` shows the running commit.

## Sync to GitHub

```bash
./sync.sh "your commit message"   # commit + push main
```

## Notes

- Only one poller may run per bot token; stop other instances before starting this one.
- Termux: install `termux-wake-lock` and disable battery optimisation, or Android may freeze the process.
