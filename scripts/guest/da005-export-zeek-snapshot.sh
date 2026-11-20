#!/usr/bin/env bash
# DA005 operator-owned Host-only Zeek experiment:
# one fixed, bounded, privileged Zeek conn.log -> unprivileged user copy.
# Install ROOT-OWNED at /usr/local/sbin/da005-export-zeek-snapshot.
# NEVER add the Git checkout script itself to sudoers.
set -euo pipefail
umask 077

if (( $# != 0 || EUID != 0 )); then
    echo "DA005_EXPORT_REFUSED" >&2
    exit 64
fi

SOURCE=/opt/zeek/logs/current/conn.log
DEST_DIR=/home/da005/da005-private-logs
MAX_BYTES=15728640
MAX_SNAPSHOTS=100
# /run is root-owned; /run/lock may be writable by unprivileged users.
# Never redirect root output into a path an SSH user can precreate.
LOCK=/run/da005-zeek-export.lock

# Serialize concurrent sessions and ensure the static account-specific folder
# is exactly the operator-owned directory, not an arbitrary user-selected path.
exec 9>"$LOCK"
flock -n 9 || { echo "DA005_EXPORT_LOCKED" >&2; exit 75; }
[[ -d "$DEST_DIR" && ! -L "$DEST_DIR" ]] || exit 66
[[ "$(stat -c %U "$DEST_DIR")" == da005 ]] || exit 66
if [[ ! -f "$SOURCE" || -L "$SOURCE" ]]; then
    # Normal after rotation with no completed flows; never use archived logs
    # or invent a successful/fresh capture to bypass this readiness gate.
    echo "DA005_ZEEK_CURRENT_LOG_NOT_READY" >&2
    exit 66
fi

# Fail rather than exhaust the isolated VM disk during repeated demo runs.
count=$(find "$DEST_DIR" -maxdepth 1 -type f -name 'conn-*.log' | wc -l)
(( count < MAX_SNAPSHOTS )) || exit 73
bytes=$(stat -c %s "$SOURCE")
(( bytes > 0 && bytes <= MAX_BYTES )) || exit 74

stamp=$(date -u +%Y%m%dT%H%M%S)
destination="$DEST_DIR/conn-$stamp.log"
[[ ! -e "$destination" && ! -L "$destination" ]] || exit 73

# Root writes ONLY to a private /run temporary file. The subsequent
# destination write is executed as da005, never as root.
tmp=$(mktemp /run/da005-zeek.XXXXXXXX)
trap 'rm -f -- "$tmp"' EXIT
install -o da005 -g da005 -m 0400 -- "$SOURCE" "$tmp"
snapshot_bytes=$(stat -c %s "$tmp")
(( snapshot_bytes > 0 && snapshot_bytes <= MAX_BYTES )) || exit 74
original_sha=$(sha256sum "$tmp" | cut -d ' ' -f1)

runuser -u da005 -- /bin/bash -c '
    set -euo pipefail
    umask 077
    set -C
    cat -- "$1" > "$2"
    chmod 0600 -- "$2"
' bash "$tmp" "$destination"

[[ -f "$destination" && ! -L "$destination" ]] || exit 74
published_sha=$(sha256sum "$destination" | cut -d ' ' -f1)
[[ "$published_sha" == "$original_sha" ]] || exit 74

# Exactly one machine-parseable success line; failure never prints a path.
printf 'DA005_ZEEK_SNAPSHOT_V1 %s %s\n' "$destination" "$published_sha"
