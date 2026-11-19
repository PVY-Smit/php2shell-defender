#!/usr/bin/env bash
# ini-dump-to-php-ini.sh: turn the output of dump-live-ini.php into a php.ini.
#
# Usage:
#   ini-dump-to-php-ini.sh [--extension-dir DIR] DUMP_FILE > php.ini.rebuilt
#
#   DUMP_FILE        output of dump-live-ini.php
#   --extension-dir  PHP's extension_dir; loaded extensions found there as .so
#                    files get an extension= / zend_extension= line (compiled-in
#                    extensions need none)
#
# Every setting with a value is written out explicitly, so the rebuilt file
# reproduces the running configuration exactly. NULL settings are left out
# (they fall back to PHP's defaults, which is what NULL means). Values that
# contain a backslash or a double quote are not written automatically: they are
# listed at the end for a human to check, because php.ini quoting differs from
# PHP's var_export().
#
# The output goes to stdout. Nothing is written to disk by this script.

set -u

EXT_DIR=""
DUMP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --extension-dir) [ $# -ge 2 ] || { echo "Missing value for --extension-dir" >&2; exit 2; }; EXT_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; exit 2 ;;
    *) DUMP="$1"; shift ;;
  esac
done
if [ -z "$DUMP" ] || [ ! -r "$DUMP" ]; then echo "Usage: $0 [--extension-dir DIR] DUMP_FILE" >&2; exit 2; fi
if ! grep -q "^; loaded ini:" "$DUMP"; then
  echo "This does not look like dump-live-ini.php output (no '; loaded ini:' line)." >&2
  exit 2
fi

# Settings that cannot or should not be set from php.ini.
SKIP_RE='^(fpm\.config) '

echo "; Rebuilt $(date +%F) from the running PHP workers (dump-live-ini.php)."
echo "; Every non-NULL value is set explicitly. Review before use."
echo

REVIEW=()
while IFS= read -r line; do
  case "$line" in
    ';'*|'') continue ;;
  esac
  # name = 'value'   (var_export string)  |  name = NULL
  name=${line%% = *}
  value=${line#* = }
  [ "$value" = "NULL" ] && continue
  printf '%s\n' "$line" | grep -qE "$SKIP_RE" && continue
  case "$value" in
    \'*\') inner=${value#\'}; inner=${inner%\'} ;;
    *) REVIEW+=("$line"); continue ;;
  esac
  case "$inner" in
    *\\*|*\"*) REVIEW+=("$line"); continue ;;
  esac
  printf '%s = "%s"\n' "$name" "$inner"
done < "$DUMP"

# Extensions loaded from shared .so files.
EXTS=$(sed -n 's/^; extensions: //p' "$DUMP" | tr ',' '\n' | sed 's/^ *//;s/ *$//')
ZEXTS=$(sed -n 's/^; zend_extensions: //p' "$DUMP" | tr ',' '\n' | sed 's/^ *//;s/ *$//')
echo
echo "; Extensions"
if [ -n "$EXT_DIR" ] && [ -d "$EXT_DIR" ]; then
  # Keep PHP's original load order (the order of the extensions list), so
  # extensions that depend on others (e.g. mysqli on mysqlnd) still load.
  while IFS= read -r ext; do
    [ -n "$ext" ] || continue
    lower=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')
    if [ -e "$EXT_DIR/$lower.so" ]; then echo "extension=$lower"; fi
  done <<< "$EXTS"
  while IFS= read -r zext; do
    [ -n "$zext" ] || continue
    case "$(printf '%s' "$zext" | tr '[:upper:]' '[:lower:]')" in
      *opcache*) [ -e "$EXT_DIR/opcache.so" ] && echo "zend_extension=opcache" ;;
      *xdebug*)  [ -e "$EXT_DIR/xdebug.so" ] && echo "zend_extension=xdebug" ;;
      *) echo "; zend extension '$zext' loaded: add its zend_extension= line by hand" ;;
    esac
  done <<< "$ZEXTS"
else
  printf '%s\n' "$ZEXTS" | grep -qi 'opcache' && echo "zend_extension=opcache"
  echo "; Pass --extension-dir to add extension= lines for shared extensions."
  echo "; Loaded (shared or compiled in): $(printf '%s' "$EXTS" | tr '\n' ' ')"
fi

if [ ${#REVIEW[@]} -gt 0 ]; then
  echo
  echo "; NOT written automatically, check these by hand (special characters):"
  for r in "${REVIEW[@]}"; do echo ";   $r"; done
fi
