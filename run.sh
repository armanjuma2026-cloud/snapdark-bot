#!/data/data/com.termux/files/usr/bin/bash
# Supervisor: keeps bot.py alive and recycles it every 10 minutes so a dead
# long-poll socket can never freeze the bot.
cd "$(dirname "$0")" || exit 1
command -v termux-wake-lock >/dev/null && termux-wake-lock

while true; do
    echo "--- $(date '+%F %T') start" >> supervisor.log
    timeout -k 5 600 python3 -u bot.py >> bot.log 2>&1
    code=$?
    echo "--- exit $code, restarting in 2s" >> supervisor.log
    sleep 2
done
