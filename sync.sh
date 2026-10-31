#!/data/data/com.termux/files/usr/bin/bash
# Commit + push all bot changes to GitHub.
# Usage: ./sync.sh [commit message]
set -e
cd "$(dirname "$0")" || exit 1

MSG="${*:-bot: update $(date '+%F %H:%M')}"

git add -A
if git diff --cached --quiet; then
    echo "nothing to commit"
else
    git commit -q -m "$MSG"
    echo "committed: $(git log -1 --pretty=%h) $MSG"
fi

git push -q origin main
echo "pushed to $(git remote get-url origin)"
