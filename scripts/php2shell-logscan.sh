#!/usr/bin/env bash
# php2shell-logscan.sh: read-only log scan for signs of PHP2Shell attempts
# (CVE-2026-109618 / CVE-2026-109619).
#
# It only reads the files you point it at (plain or .gz) and prints what it finds.
# Nothing is changed, sent or deleted.
#
# Usage:
#   php2shell-logscan.sh [--since YYYY-MM-DD] [--ioc-file FILE] [--samples N] PATH...
#
#   PATH        log files or directories (searched recursively)
#   --since     skip files last modified before this date (default: 2026-10-17,
#               the first exploitation seen in the wild)
#   --ioc-file  file with one IP address per line (# comments allowed)
#   --samples   matching lines to print per finding (default: 3, 0 = none)
#
# Exit codes: 0 = nothing high-signal found, 1 = high-signal finding, 2 = usage error.

set -u

SINCE="2026-10-17"
IOC_FILE=""
SAMPLES=3
PATHS=()

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --since)    [ $# -ge 2 ] || usage; SINCE="$2"; shift 2 ;;
    --ioc-file) [ $# -ge 2 ] || usage; IOC_FILE="$2"; shift 2 ;;
    --samples)  [ $# -ge 2 ] || usage; SAMPLES="$2"; shift 2 ;;
    -h|--help)  usage ;;
    --)         shift; PATHS+=("$@"); break ;;
    -*)         echo "Unknown option: $1" >&2; usage ;;
    *)          PATHS+=("$1"); shift ;;
  esac
done

[ ${#PATHS[@]} -gt 0 ] || usage
if ! date -d "$SINCE" >/dev/null 2>&1; then echo "Bad --since date: $SINCE" >&2; exit 2; fi
if [ -n "$IOC_FILE" ] && [ ! -r "$IOC_FILE" ]; then echo "Cannot read IOC file: $IOC_FILE" >&2; exit 2; fi
case "$SAMPLES" in ''|*[!0-9]*) echo "--samples must be a number" >&2; exit 2 ;; esac

# Findings: label | severity | extended regex.
# "in Unknown on line 0" means the error happened before any script started
# (during request startup), which is where both CVEs fire. That phrase alone
# is NOT enough: harmless startup warnings (e.g. "Unable to load dynamic
# library") end the same way, so the memory/time-limit text must be present too.
PATTERNS=(
  "Memory exhausted before any script ran|HIGH|Allowed memory size of [0-9]+ bytes exhausted.*in Unknown on line 0"
  "Time limit hit before any script ran|MEDIUM|Maximum execution time of [0-9]+ seconds? exceeded.*in Unknown on line 0"
  "PHP worker crashed (segfault)|MEDIUM|exit signal Segmentation fault|exited on signal 11|SIGSEGV"
  "Upload-progress field in a request (WAF/ModSecurity logs)|HIGH|PHP_SESSION_UPLOAD_PROGRESS"
)

# Collect files modified on or after --since.
FILES=()
for p in "${PATHS[@]}"; do
  if [ -d "$p" ]; then
    while IFS= read -r -d '' f; do FILES+=("$f"); done \
      < <(find "$p" -type f -newermt "$SINCE" -print0 2>/dev/null | sort -z)
  elif [ -f "$p" ]; then
    if [ -n "$(find "$p" -newermt "$SINCE" 2>/dev/null)" ]; then FILES+=("$p"); fi
  else
    echo "Skipping (not found): $p" >&2
  fi
done

if [ ${#FILES[@]} -eq 0 ]; then
  echo "No log files modified since $SINCE in the given paths."
  exit 0
fi

# Read plain or gzipped files the same way.
reader() { case "$1" in *.gz) zcat -f -- "$1" ;; *) cat -- "$1" ;; esac; }

# IOC IPs: strip comments and blanks into a temp pattern file.
IOC_TMP=""
if [ -n "$IOC_FILE" ]; then
  IOC_TMP=$(mktemp)
  trap 'rm -f "$IOC_TMP"' EXIT
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$IOC_FILE" | grep -v '^$' > "$IOC_TMP" || true
fi

echo "php2shell-logscan: ${#FILES[@]} file(s) modified since $SINCE"
echo

HIGH=0
TOTAL=0
OUT=""

add_finding() { # severity label hits
  local sev=$1 label=$2 hits=$3 n
  n=$(printf '%s\n' "$hits" | wc -l)
  TOTAL=$((TOTAL + 1))
  if [ "$sev" = "HIGH" ]; then HIGH=$((HIGH + 1)); fi
  OUT+=$(printf '  [%s] %s: %s line(s)' "$sev" "$label" "$n")$'\n'
  if [ "$SAMPLES" -gt 0 ]; then
    OUT+=$(printf '%s\n' "$hits" | head -n "$SAMPLES" | sed 's/^/      /')$'\n'
  fi
}

for f in "${FILES[@]}"; do
  OUT=""
  for entry in "${PATTERNS[@]}"; do
    label=${entry%%|*}; rest=${entry#*|}; sev=${rest%%|*}; re=${rest#*|}
    hits=$(reader "$f" 2>/dev/null | grep -E -- "$re" || true)
    if [ -n "$hits" ]; then add_finding "$sev" "$label" "$hits"; fi
  done
  if [ -n "$IOC_TMP" ] && [ -s "$IOC_TMP" ]; then
    hits=$(reader "$f" 2>/dev/null | grep -Fw -f "$IOC_TMP" || true)
    if [ -n "$hits" ]; then
      add_finding HIGH "Known attacker IP (investigate: shared infrastructure, not proof)" "$hits"
    fi
  fi
  # Other "Unknown on line 0" lines, for context only.
  benign=$(reader "$f" 2>/dev/null | grep -E -- "in Unknown on line 0" \
           | grep -cvE -- "Allowed memory size|Maximum execution time" || true)
  if [ -n "$OUT" ] || [ "${benign:-0}" -gt 0 ]; then
    echo "$f"
    if [ -n "$OUT" ]; then printf '%s' "$OUT"; fi
    if [ "${benign:-0}" -gt 0 ]; then
      printf '  [INFO] Other startup messages ending "in Unknown on line 0", usually harmless: %s line(s)\n' "$benign"
    fi
    echo
  fi
done

if [ "$TOTAL" -eq 0 ]; then
  echo "Result: no PHP2Shell indicators found."
  echo "This does not prove the server is clean: patch, and check for signs of a break-in too."
  exit 0
fi
echo "Result: $TOTAL finding(s), $HIGH high-signal. Review the lines above before acting."
if [ "$HIGH" -gt 0 ]; then exit 1; fi
exit 0
