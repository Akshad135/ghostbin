#!/usr/bin/env bash
# Backup a GhostBin data directory (plan §9: VACUUM INTO + uploads).
#
# VACUUM INTO produces a consistent snapshot even while the server is
# running — never copy the live SQLite file directly (WAL sidecars make a
# plain copy corruptible).
#
# Usage: scripts/backup.sh [data_dir] [output_dir]
# Requires: sqlite3, tar

set -euo pipefail

DATA_DIR="${1:-./data}"
OUTPUT_DIR="${2:-./backups}"
DB_PATH="${DATA_DIR}/ghostbin.sqlite"
UPLOADS_DIR="${DATA_DIR}/uploads"

command -v sqlite3 >/dev/null || { echo "error: sqlite3 is required" >&2; exit 1; }
command -v tar >/dev/null || { echo "error: tar is required" >&2; exit 1; }
[ -f "$DB_PATH" ] || { echo "error: database not found at $DB_PATH" >&2; exit 1; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUTPUT_DIR"

SNAPSHOT="${OUTPUT_DIR}/ghostbin-${STAMP}.sqlite"
# Same-second reruns must not collide with VACUUM INTO's existing-file error.
[ -e "$SNAPSHOT" ] && SNAPSHOT="${OUTPUT_DIR}/ghostbin-${STAMP}-$$.sqlite"
# Escape single quotes so paths containing ' stay valid SQL string literals.
SNAPSHOT_SQL="${SNAPSHOT//\'/\'\'}"
sqlite3 "$DB_PATH" "VACUUM INTO '${SNAPSHOT_SQL}';"
echo "wrote ${SNAPSHOT}"

if [ -d "$UPLOADS_DIR" ]; then
    ARCHIVE="${OUTPUT_DIR}/uploads-${STAMP}.tar.gz"
    # Same-second reruns must not silently overwrite the previous archive.
    [ -e "$ARCHIVE" ] && ARCHIVE="${OUTPUT_DIR}/uploads-${STAMP}-$$.tar.gz"
    # Uploads can be deleted while tar runs (burn/reconcile). Exit 1 from
    # GNU tar means files changed or vanished during the read — keep the
    # archive but say so loudly; anything worse is fatal.
    tar_status=0
    tar --ignore-failed-read -czf "$ARCHIVE" -C "$DATA_DIR" "$(basename "$UPLOADS_DIR")" || tar_status=$?
    if [ "$tar_status" -eq 1 ]; then
        echo "warning: uploads changed during backup; ${ARCHIVE} may be incomplete" >&2
    elif [ "$tar_status" -ne 0 ]; then
        exit "$tar_status"
    fi
    echo "wrote ${ARCHIVE}"
fi

echo "done. Keep the .sqlite snapshot and uploads archive together."
