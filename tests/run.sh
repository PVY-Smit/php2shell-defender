#!/usr/bin/env bash
# Test runner: plain bash, no frameworks. Run from anywhere: tests/run.sh
set -u
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
check() { # description, command...
  local desc=$1; shift
  if "$@"; then PASS=$((PASS + 1)); echo "  ok   $desc"; else FAIL=$((FAIL + 1)); echo "  FAIL $desc"; fi
}
has() { printf '%s' "$OUT" | grep -qF -- "$1"; }
lacks() { ! has "$1"; }

# Fixture files get fresh mtimes on checkout; make sure they are after --since.
touch tests/fixtures/attack/* tests/fixtures/clean/*

echo "logscan: clean logs"
OUT=$(scripts/php2shell-logscan.sh --ioc-file iocs/aws-madpot-2026-10.txt tests/fixtures/clean); RC=$?
check "exit code 0" [ "$RC" -eq 0 ]
check "reports no indicators" has "no PHP2Shell indicators found"
check "harmless 'Unknown on line 0' startup warning is INFO, not a finding" has "[INFO] Other startup messages"

echo "logscan: attack logs"
OUT=$(scripts/php2shell-logscan.sh --ioc-file iocs/aws-madpot-2026-10.txt tests/fixtures/attack); RC=$?
check "exit code 1 (high-signal finding)" [ "$RC" -eq 1 ]
check "memory exhausted before any script ran" has "[HIGH] Memory exhausted before any script ran: 1 line(s)"
check "worker segfault" has "[MEDIUM] PHP worker crashed (segfault): 1 line(s)"
check "reads .gz and matches the IOC IP" has "Known attacker IP (investigate: shared infrastructure, not proof): 1 line(s)"
check "does not match a longer IP containing the IOC (231.223.184.166)" lacks "231.223.184.166"
check "gd startup warning still only INFO" has "usually harmless: 1 line(s)"

echo "logscan: --since filter and usage"
OUT=$(scripts/php2shell-logscan.sh --since 2099-01-01 tests/fixtures/attack); RC=$?
check "files older than --since are skipped" has "No log files modified since 2099-01-01"
scripts/php2shell-logscan.sh >/dev/null 2>&1; RC=$?
check "no arguments is a usage error (exit 2)" [ "$RC" -eq 2 ]

echo "ini-dump-to-php-ini"
OUT=$(tools/ini-dump-to-php-ini.sh --extension-dir tests/fixtures/extdir tests/fixtures/dump-sample.txt); RC=$?
check "exit code 0" [ "$RC" -eq 0 ]
check "string value converted" has 'post_max_size = "300M"'
check "empty value kept" has 'allow_url_include = ""'
check "NULL settings left out" lacks "error_log"
check "fpm.config skipped" lacks "fpm.config"
check "backslash value listed for review, not written" has ";   mbstring.http_output_conv_mimetypes"
# shellcheck disable=SC2016  # $1 is meant for the inner bash
check "shared extensions in load order (mysqlnd before mysqli)" \
  bash -c 'printf "%s" "$1" | grep -E "^extension=" | tr "\n" " " | grep -q "extension=mysqlnd extension=mysqli"' _ "$OUT"
check "compiled-in extension gets no line" lacks "extension=gd"
check "opcache as zend_extension" has "zend_extension=opcache"
printf 'not a dump\n' > /tmp/p2s-not-a-dump.$$
tools/ini-dump-to-php-ini.sh /tmp/p2s-not-a-dump.$$ >/dev/null 2>&1; RC=$?; rm -f /tmp/p2s-not-a-dump.$$
check "rejects input that is not a dump" [ "$RC" -eq 2 ]

echo "dump-live-ini.php"
if command -v php >/dev/null 2>&1; then
  check "PHP syntax" php -l tools/dump-live-ini.php
  DIR=$(mktemp -d); cp tools/dump-live-ini.php "$DIR/d.php"
  PORT=$((20000 + RANDOM % 20000))
  php -S "127.0.0.1:$PORT" -t "$DIR" >/dev/null 2>&1 & SRV=$!
  sleep 1
  OUT=$(curl -s "http://127.0.0.1:$PORT/d.php")
  kill "$SRV" 2>/dev/null; rm -rf "$DIR"
  check "answers localhost with the settings dump" has "; loaded ini:"
  check "includes memory_limit" has "memory_limit = '"
  check "reports live upload-progress value" has "; live session.upload_progress.enabled = "
else
  echo "  skip (php not installed)"
fi

echo "audit"
scripts/php2shell-audit.sh --bogus >/dev/null 2>&1; RC=$?
check "unknown argument is a usage error (exit 3)" [ "$RC" -eq 3 ]

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
