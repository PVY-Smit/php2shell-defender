#!/usr/bin/env bash
# Integration test for php2shell-audit.sh against a real, disposable PHP-FPM.
# Needs root and a php-fpm binary (CI installs php8.3-fpm). It CHANGES the
# local FPM pool config and restarts php-fpm, so only run it on a throwaway
# machine or container, never on a real server.
set -u
cd "$(dirname "$0")/.." || exit 1

FPM=${FPM:-$(command -v php-fpm8.3 || command -v php-fpm || true)}
[ -n "$FPM" ] || { echo "php-fpm not found"; exit 1; }
POOL=${POOL:-/etc/php/8.3/fpm/pool.d/www.conf}
[ -f "$POOL" ] || { echo "pool file not found: $POOL"; exit 1; }

PASS=0; FAIL=0
check() { if "${@:2}"; then PASS=$((PASS + 1)); echo "  ok   $1"; else FAIL=$((FAIL + 1)); echo "  FAIL $1"; fi; }

pkill -f 'php-fpm: master' 2>/dev/null; sleep 1
"$FPM" -D; sleep 1

echo "stock config"
OUT=$(scripts/php2shell-audit.sh --php-fpm "$FPM"); RC=$?
printf '%s\n' "$OUT"
check "upload progress ON is a risk" grep -qF "session.upload_progress.enabled is ON" <<< "$OUT"
check "exit code 2" [ "$RC" -eq 2 ]

echo "stopgap written but php-fpm not restarted"
cp -a "$POOL" "$POOL.bak"
sleep 1
printf '\nphp_admin_flag[session.upload_progress.enabled] = off\nphp_admin_value[memory_limit] = -1\n' >> "$POOL"
OUT=$(scripts/php2shell-audit.sh --php-fpm "$FPM")
check "pool shows upload progress locked off" grep -qF "off via php_admin_flag" <<< "$OUT"
check "memory_limit=-1 locked" grep -qF "memory_limit=-1, locked" <<< "$OUT"
check "warns the change is not active until restart" grep -qF "not active until a restart" <<< "$OUT"

echo "after reload"
kill -USR2 "$(pgrep -o -f 'php-fpm: master')"; sleep 2
OUT=$(scripts/php2shell-audit.sh --php-fpm "$FPM"); RC=$?
printf '%s\n' "$OUT"
check "no restart warning any more" grep -qF "No PHP or FPM config file changed" <<< "$OUT"
# shellcheck disable=SC2016  # $1 is meant for the inner bash
check "no RISK lines left" bash -c '! grep -qF "[RISK]" <<< "$1"' _ "$OUT"

echo "emptied php.ini is caught"
INI=$("$FPM" -i 2>/dev/null | awk -F' => ' '$1=="Loaded Configuration File" {print $2; exit}')
cp -a "$INI" "$INI.bak"; : > "$INI"
OUT=$(scripts/php2shell-audit.sh --php-fpm "$FPM")
check "empty php.ini is a risk" grep -qF "php.ini is EMPTY" <<< "$OUT"
cp -a "$INI.bak" "$INI"; cp -a "$POOL.bak" "$POOL"; rm -f "$INI.bak" "$POOL.bak"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
