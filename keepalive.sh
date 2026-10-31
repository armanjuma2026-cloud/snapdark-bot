#!/data/data/com.termux/files/usr/bin/bash
# Keepalive: revive the bot service if Android killed it.
# Called by termux-job-scheduler every ~15 minutes and by ~/.bashrc.
SVDIR=/data/data/com.termux/files/usr/var/service

command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock 2>/dev/null

if ! pgrep -x runsvdir >/dev/null 2>&1; then
    setsid runsvdir -P "$SVDIR" >/dev/null 2>&1 &
    echo "$(date '+%F %T') started runsvdir" >> /data/data/com.termux/files/home/snapdark_bot/keepalive.log
fi

if ! pgrep -f "python3 -u bot.py" >/dev/null 2>&1; then
    export SVDIR
    sv up snapdark >/dev/null 2>&1
    echo "$(date '+%F %T') revived bot" >> /data/data/com.termux/files/home/snapdark_bot/keepalive.log
fi
