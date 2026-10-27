#!/usr/bin/env bash
#
# update.sh - fetch the latest code and restart the service.
#
# Refuses to run on a dirty working tree, syntax-checks the new code before
# restarting, and rolls back to the previous commit if the service does not
# come back up.
#
# Author: Glenn Leving
set -euo pipefail

SERVICE="${SERVICE:-webscan}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8422/api/status}"

cd "$(dirname "$0")"

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

# A pull would either fail or bury local work, so stop before touching anything.
if [ -n "$(git status --porcelain)" ]; then
    git status --short >&2
    die "update: the working tree has uncommitted changes - commit or stash them first."
fi

git rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1 \
    || die "update: this branch has no upstream - set one with 'git push -u origin main'."

say "update: fetching ..."
git fetch --quiet origin

old=$(git rev-parse HEAD)
new=$(git rev-parse '@{u}')
if [ "$old" = "$new" ]; then
    say "update: already up to date ($(git rev-parse --short HEAD))."
    exit 0
fi

say "update: $(git rev-parse --short "$old") -> $(git rev-parse --short "$new")"
git log --oneline "$old..$new" | sed 's/^/  /'
git merge --ff-only "$new" --quiet \
    || die "update: cannot fast-forward - the local branch has diverged from origin."

# Catch a broken commit before it takes the running service down.
if ! python3 -m py_compile ./*.py 2>/dev/null; then
    git reset --hard --quiet "$old"
    die "update: the new code does not compile - rolled back, service untouched."
fi

if ! systemctl --user is-enabled "$SERVICE" >/dev/null 2>&1; then
    say "update: code updated. No systemd user service '$SERVICE' - restart it yourself."
    exit 0
fi

# Waits for the service to actually answer, not just for systemd to say it
# started. Quiet while it retries - a starting service refusing connections is
# expected, and only the verdict is worth printing.
wait_healthy() {
    local _
    for _ in $(seq 1 30); do
        curl -fs -o /dev/null --max-time 2 "$HEALTH_URL" && return 0
        sleep 0.5
    done
    return 1
}

say "update: restarting $SERVICE ..."
systemctl --user restart "$SERVICE"

if wait_healthy; then
    say "update: done - $SERVICE is up on $(git rev-parse --short HEAD)."
    exit 0
fi

say "update: $SERVICE did not answer on $HEALTH_URL - rolling back." >&2
git reset --hard --quiet "$old"
systemctl --user restart "$SERVICE"
if wait_healthy; then
    say "update: rolled back to $(git rev-parse --short HEAD), $SERVICE is up again." >&2
else
    say "update: rolled back to $(git rev-parse --short HEAD), but $SERVICE still does not answer." >&2
fi
say "Check: journalctl --user -u $SERVICE -n 40" >&2
exit 1
