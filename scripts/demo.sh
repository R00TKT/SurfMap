#!/usr/bin/env bash
# End-to-end demo: start a local target, crawl it, print the findings.
#
#   ./scripts/demo.sh
#
# Everything happens against 127.0.0.1. No external host is contacted.
set -euo pipefail

PORT="${PORT:-8421}"
DB="${DB:-demo.db}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build --quiet

rm -f "$DB" "$DB-wal" "$DB-shm"
python3 examples/demo-site.py "$PORT" &
SITE_PID=$!
trap 'kill "$SITE_PID" 2>/dev/null || true' EXIT

# Wait for the target to accept connections.
for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$PORT/robots.txt" >/dev/null && break
    sleep 0.1
done

BIN=./target/debug/surfmap

echo "=== crawl ==============================================================="
"$BIN" --db "$DB" crawl "http://127.0.0.1:$PORT/" --depth 3 --rate-limit 20 --yes

for report in forms headers params cookies scripts graph errors; do
    echo
    echo "=== report: $report ====================================================="
    "$BIN" --db "$DB" report "$report" --limit 15
done

echo
echo "=== path discovery (finds what nothing links to) ========================"
# The demo site carries /backup.sql, /.env, /config.php.bak, /server-status and
# an /internal/ directory that no page links to, so a crawl cannot reach them.
"$BIN" --db "$DB" brute "http://127.0.0.1:$PORT/" \
  --extensions sql,bak,php --depth 1 --rate-limit 200 --concurrency 8 --yes

echo
echo "=== path discovery vs. a soft 404 ======================================="
# Everything under /portal/ answers "200 OK" with an apology page. Only
# /portal/config.php is real, and calibration is what tells them apart.
"$BIN" --db "$DB" brute "http://127.0.0.1:$PORT/portal/" \
  --extensions php --rate-limit 200 --concurrency 8 --yes

echo
echo "=== ad-hoc SQL =========================================================="
"$BIN" --db "$DB" query \
  "SELECT method, action_url, inputs FROM attack_surface_forms WHERE has_password = 1"

echo
echo "Database written to $DB"
echo "  query it:  $BIN --db $DB query '<your SQL>'"
