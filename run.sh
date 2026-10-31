#!/data/data/com.termux/files/usr/bin/bash
# Supervisor: keeps bot.py alive and recycles it every 10 minutes so a dead
# long-poll socket can never freeze the bot.
cd "$(dirname "$0")" || exit 1
command -v termux-wake-lock >/dev/null && termux-wake-lock

child=""
cleanup() {
    [ -n "$child" ] && kill -TERM -"$child" 2>/dev/null
    pkill -f "python3 -u bot.py" 2>/dev/null
    exit 0
}
trap cleanup TERM INT

while true; do
    echo "--- $(date '+%F %T') start" >> supervisor.log
    setsid timeout -k 5 600 python3 -u bot.py >> bot.log 2>&1 &
    child=$!
    wait "$child"
    code=$?
    echo "--- exit $code, restarting in 2s" >> supervisor.log
    sleep 2
done
