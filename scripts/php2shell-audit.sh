#!/usr/bin/env bash
# php2shell-audit.sh: read-only exposure check for PHP2Shell
# (CVE-2026-109618, CVE-2026-109619) and CVE-2026-115560 on a PHP-FPM server.
#
# It only reads: it runs `php-fpm -v / -i / -tt`, reads config files and
# process information, and prints a report. It never changes, restarts or
# sends anything. Run it as root to see every pool and config file.
#
# Usage:
#   php2shell-audit.sh [--php-fpm PATH] [--webroot DIR]...
#
#   --php-fpm   path to the php-fpm binary (default: taken from the running
#               master process, then from PATH)
#   --webroot   web root to check for .user.ini / .htaccess PHP overrides
#               (repeatable)
#
# Exit codes: 0 = no risks or warnings, 1 = warnings, 2 = risks found, 3 = usage error.

set -u
export LC_ALL=C

FPM=""
WEBROOTS=()

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }

while [ $# -gt 0 ]; do
  case "$1" in
    --php-fpm) [ $# -ge 2 ] || usage; FPM="$2"; shift 2 ;;
    --webroot) [ $# -ge 2 ] || usage; WEBROOTS+=("$2"); shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

RISKS=0; WARNS=0
ok()   { printf '  [OK]   %s\n' "$*"; }
info() { printf '  [INFO] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; WARNS=$((WARNS + 1)); }
risk() { printf '  [RISK] %s\n' "$*"; RISKS=$((RISKS + 1)); }
section() { printf '\n== %s\n' "$*"; }

# "8M" / "1G" / "512K" / "-1" / "1048576" -> bytes (-1 stays -1)
to_bytes() {
  local v=${1// /} n unit
  [ "$v" = "-1" ] && { echo -1; return; }
  n=${v%[KkMmGg]}; unit=${v#"$n"}
  case "$n" in ''|*[!0-9]*) echo ""; return ;; esac
  case "$unit" in
    K|k) echo $((n * 1024)) ;;
    M|m) echo $((n * 1024 * 1024)) ;;
    G|g) echo $((n * 1024 * 1024 * 1024)) ;;
    *)   echo "$n" ;;
  esac
}
is_off() { case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in 0|off|false|no|none|'""'|"") return 0 ;; *) return 1 ;; esac; }
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }   # $1 >= $2

# ---------------------------------------------------------------- php-fpm
section "PHP-FPM"

MASTER_PID=$(pgrep -o -f 'php-fpm: master process' 2>/dev/null || true)
MASTER_CONF=""
if [ -n "$MASTER_PID" ]; then
  MASTER_CONF=$(ps -o args= -p "$MASTER_PID" | sed -n 's/.*(\(.*\)).*/\1/p')
  if [ -z "$FPM" ] && [ -r "/proc/$MASTER_PID/exe" ]; then
    FPM=$(readlink "/proc/$MASTER_PID/exe" 2>/dev/null | sed 's/ (deleted)$//')
  fi
fi
if [ -z "$FPM" ]; then
  FPM=$(command -v php-fpm 2>/dev/null || true)
  if [ -z "$FPM" ]; then
    for c in /usr/sbin/php-fpm* /opt/php/*/sbin/php-fpm; do [ -x "$c" ] && { FPM=$c; break; }; done
  fi
fi
if [ -z "$FPM" ] || [ ! -x "$FPM" ]; then
  risk "No php-fpm binary found. Pass --php-fpm PATH (mod_php-only servers: see the Apache section)."
  FPM=""
fi

PHP_VER=""; INI_FILE=""
if [ -n "$FPM" ]; then
  info "Binary: $FPM"
  VLINE=$("$FPM" -v 2>/dev/null | head -n1)
  PHP_VER=$(printf '%s' "$VLINE" | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p')
  info "Version: ${VLINE:-unknown}"

  # Packaged or hand-built? Distro packages often backport fixes without
  # changing the version number, so the version check alone can mislead.
  PKG=""
  if command -v dpkg >/dev/null 2>&1; then PKG=$(dpkg -S "$FPM" 2>/dev/null | cut -d: -f1 | head -n1); fi
  if [ -z "$PKG" ] && command -v rpm >/dev/null 2>&1; then PKG=$(rpm -qf "$FPM" 2>/dev/null | grep -v 'not owned' | head -n1); fi
  if [ -n "$PKG" ]; then
    info "Installed from package: $PKG (check its changelog for CVE-2026-109618; vendors backport fixes)"
  else
    info "Not owned by any package: hand-built PHP, so only a rebuild or upgrade brings fixes"
  fi

  if [ -z "$PHP_VER" ]; then
    warn "Could not read the PHP version."
  else
    MINOR=${PHP_VER%.*}
    case "$MINOR" in
      8.5) FIXED=8.5.12 ;; 8.4) FIXED=8.4.27 ;; 8.3) FIXED=8.3.36 ;; 8.2) FIXED=8.2.35 ;; *) FIXED="" ;;
    esac
    if [ -n "$FIXED" ] && ver_ge "$PHP_VER" "$FIXED"; then
      ok "PHP $PHP_VER includes the fixes for CVE-2026-109618/109619 (fixed in $FIXED)."
    elif [ -n "$FIXED" ]; then
      if [ -n "$PKG" ]; then
        warn "PHP $PHP_VER is below the upstream fix ($FIXED). Packaged build: confirm in the package changelog."
      else
        risk "PHP $PHP_VER is below the fixed release $FIXED. Upgrade."
      fi
    else
      if [ -n "$PKG" ]; then
        warn "PHP $MINOR is end of life upstream. Only a vendor backport can fix it: check the package changelog."
      else
        risk "PHP $MINOR is end of life and hand-built: no official release fixes these CVEs. Upgrade to 8.3/8.4+."
      fi
    fi
  fi
  info "CVE-2026-115560 has no fix in any release yet: the upload-progress check below is what covers it."

  INI_DUMP=$("$FPM" -i 2>/dev/null || true)
  ini() { printf '%s\n' "$INI_DUMP" | awk -F' => ' -v k="$1" '$1==k {print $3; exit}'; }
  INI_FILE=$(printf '%s\n' "$INI_DUMP" | awk -F' => ' '$1=="Loaded Configuration File" {print $2; exit}')

  if [ -z "$INI_FILE" ] || [ "$INI_FILE" = "(none)" ]; then
    warn "No php.ini loaded: PHP runs on built-in defaults."
  elif [ ! -s "$INI_FILE" ]; then
    risk "php.ini is EMPTY: $INI_FILE. Running workers still use the old settings in memory; the next restart will not. Restore it before restarting."
  else
    info "php.ini: $INI_FILE"
  fi
  INI_UPLOAD=$(ini session.upload_progress.enabled)
  INI_MEM=$(ini memory_limit)
  INI_POST=$(ini post_max_size)
  INI_NEST=$(ini max_input_nesting_level)

  # Pool-level overrides from `php-fpm -tt`: track which pool each line belongs to.
  TT=$("$FPM" -tt ${MASTER_CONF:+-y "$MASTER_CONF"} 2>&1 || true)
  POOLS=$(printf '%s\n' "$TT" | sed -n 's/.*NOTICE: \[\([^]]*\)\]$/\1/p' | grep -vx global || true)
  if [ -z "$POOLS" ]; then
    warn "Could not read the pool configuration (run as root, or the config test failed)."
    printf '%s\n' "$TT" | grep -iE 'error|failed' | head -n3 | sed 's/^/         /'
  fi
  pool_setting() { # pool kind(php_admin_value|php_value) key
    printf '%s\n' "$TT" | awk -v pool="$1" -v want="$2[$3]" '
      /NOTICE: \[[^]]*\]$/ { cur=$0; sub(/.*NOTICE: \[/, "", cur); sub(/\]$/, "", cur); next }
      cur==pool { line=$0; sub(/.*NOTICE:[ \t]*/, "", line)
                  if (index(line, want " = ")==1) { sub(/^[^=]*= */, "", line); print line; exit } }'
  }

  # ------------------------------------------------ CVE-2026-109619 / 115560
  section "Session upload progress (CVE-2026-109619 path in the wild, CVE-2026-115560)"
  if [ -z "$POOLS" ]; then
    if is_off "$INI_UPLOAD"; then warn "Off in php.ini, but pools could not be checked."
    else risk "session.upload_progress.enabled is On (php.ini) and pools could not be checked."; fi
  fi
  for pool in $POOLS; do
    a=$(pool_setting "$pool" php_admin_value session.upload_progress.enabled)
    v=$(pool_setting "$pool" php_value session.upload_progress.enabled)
    if [ -n "$a" ] && is_off "$a"; then
      ok "[$pool] off via php_admin_flag (locked: .user.ini cannot turn it back on)."
    elif [ -n "$v" ] && is_off "$v"; then
      warn "[$pool] off via php_value only: a .user.ini can turn it back on. Use php_admin_flag."
    elif is_off "$INI_UPLOAD" && [ -z "$a$v" ]; then
      warn "[$pool] off in php.ini only: a .user.ini can turn it back on. Prefer php_admin_flag in the pool."
    else
      risk "[$pool] session.upload_progress.enabled is ON. Attackers enable this path themselves; apps not using it does not help."
    fi
  done

  # --------------------------------------------------------- CVE-2026-109618
  section "Request-parsing memory limits (CVE-2026-109618)"
  MEM_B=$(to_bytes "${INI_MEM:-}")
  POST_B=$(to_bytes "${INI_POST:-}")
  for pool in $POOLS; do
    a=$(pool_setting "$pool" php_admin_value memory_limit)
    p=$(pool_setting "$pool" php_admin_value post_max_size)
    [ -n "$a" ] && MEM_B=$(to_bytes "$a")
    [ -n "$p" ] && POST_B=$(to_bytes "$p")
    if [ "$MEM_B" = "-1" ] && [ -n "$a" ]; then
      ok "[$pool] memory_limit=-1, locked with php_admin_value."
    elif [ "$MEM_B" = "-1" ]; then
      warn "[$pool] memory_limit=-1 but not locked: apps calling ini_set('memory_limit', ...) put a finite limit back."
    else
      info "[$pool] memory_limit=${a:-$INI_MEM} (finite: the condition bug 1 needs; on PHP-FPM no full exploit has been shown)."
    fi
    if [ -n "$POST_B" ] && [ "$POST_B" != "-1" ] && [ "$POST_B" -gt $((32 * 1024 * 1024)) ]; then
      warn "[$pool] post_max_size=${p:-$INI_POST}: large request bodies make bug 1 easier. 8M, or 32M if uploads need it."
    elif [ -n "$POST_B" ]; then
      ok "[$pool] post_max_size=${p:-$INI_POST}."
    fi
  done
  [ -n "${INI_NEST:-}" ] && info "max_input_nesting_level=$INI_NEST (lower values limit nested-name upload fields)."
  if [ -n "$MASTER_PID" ] && [ -r "/proc/$MASTER_PID/limits" ]; then
    LIM=$(grep -E '^Max (address space|data size)' "/proc/$MASTER_PID/limits" | grep -v unlimited || true)
    if [ -n "$LIM" ]; then
      warn "php-fpm runs with an address-space/data rlimit (RLIMIT_AS/RLIMIT_DATA triggers bug 1):"
      printf '%s\n' "$LIM" | sed 's/^/         /'
    else
      ok "No RLIMIT_AS/RLIMIT_DATA on the php-fpm master."
    fi
  fi

  # ----------------------------------------------------- running vs on disk
  section "Running workers vs files on disk"
  if [ -n "$MASTER_PID" ]; then
    START=$(ps -o lstart= -p "$MASTER_PID" | sed 's/^ *//')
    START_EPOCH=$(date -d "$START" +%s 2>/dev/null || echo "")
    info "php-fpm master (pid $MASTER_PID) running since: $START"
    info "The checks above read the files on disk. Running workers only have them if php-fpm started after the last change:"
    CHANGED=0
    CONF_DIR=""; [ -n "$MASTER_CONF" ] && CONF_DIR=$(dirname "$MASTER_CONF")
    for f in "$INI_FILE" "$MASTER_CONF" "$CONF_DIR"/pool.d/*.conf "$CONF_DIR"/php-fpm.d/*.conf; do
      [ -n "$f" ] && [ -f "$f" ] || continue
      if [ -n "$START_EPOCH" ] && [ "$(stat -c %Y "$f")" -gt "$START_EPOCH" ]; then
        warn "$f changed after php-fpm started: not active until a restart."
        CHANGED=1
      fi
    done
    [ "$CHANGED" -eq 0 ] && ok "No PHP or FPM config file changed since php-fpm started."
    OPC=$(printf '%s\n' "$INI_DUMP" | awk -F' => ' '$1=="opcache.validate_timestamps" {print $3; exit}')
    if is_off "${OPC:-1}"; then
      info "opcache.validate_timestamps is off: a restart also makes every code change on disk go live."
    fi
  else
    info "No running php-fpm master found."
  fi
fi

# ------------------------------------------------------------------ Apache
HTTPD=$(ps -eo args= 2>/dev/null | awk '$1 ~ /(^|\/)(httpd|apache2)$/ {print $1; exit}')
if [ -n "$HTTPD" ]; then
  section "Apache ($HTTPD)"
  MODS=$("$HTTPD" -M 2>/dev/null || apachectl -M 2>/dev/null || apache2ctl -M 2>/dev/null || true)
  if printf '%s\n' "$MODS" | grep -qE 'php[0-9]*_module'; then
    risk "mod_php is loaded: the setup where both CVEs are confirmed, firing before any app code."
  else
    ok "mod_php is not loaded."
  fi
  printf '%s\n' "$MODS" | grep -q proxy_fcgi_module && info "PHP is handed to PHP-FPM through proxy_fcgi."
  ROOT=$("$HTTPD" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\(.*\)"/\1/p')
  CFG=$("$HTTPD" -V 2>/dev/null | sed -n 's/.*SERVER_CONFIG_FILE="\(.*\)"/\1/p')
  case "$CFG" in /*) CONFDIR=$(dirname "$CFG") ;; ?*) CONFDIR="$ROOT/$(dirname "$CFG")" ;; *) CONFDIR="" ;; esac
  if [ -n "$CONFDIR" ] && [ -d "$CONFDIR" ]; then
    info "Config: $CONFDIR"
    PV=$(grep -rnE '^[^#]*(PHP_VALUE|PHP_ADMIN_VALUE)' "$CONFDIR" 2>/dev/null | head -n5)
    if [ -n "$PV" ]; then
      warn "Apache passes PHP_VALUE/PHP_ADMIN_VALUE to FPM (a known CVE-2026-109619 path if a setting warns):"
      printf '%s\n' "$PV" | sed 's/^/         /'
    else
      ok "No PHP_VALUE/PHP_ADMIN_VALUE passed to PHP-FPM."
    fi
    if grep -rqE '^[^#]*LimitRequestBody' "$CONFDIR" 2>/dev/null; then
      ok "LimitRequestBody is set somewhere in the config."
    else
      info "No LimitRequestBody: Apache does not cap request body size before PHP sees it."
    fi
  fi
fi

# ------------------------------------------------------------------- nginx
if pgrep -x nginx >/dev/null 2>&1 && [ -d /etc/nginx ]; then
  section "nginx"
  if grep -rqE '^[^#]*fastcgi_param[[:space:]]+PHP_(ADMIN_)?VALUE' /etc/nginx 2>/dev/null; then
    warn "nginx passes PHP_VALUE/PHP_ADMIN_VALUE to FPM."
  else
    ok "No PHP_VALUE passed to PHP-FPM in /etc/nginx."
  fi
fi

# --------------------------------------------------------------- web roots
for w in "${WEBROOTS[@]}"; do
  section "Web root overrides: $w"
  if [ ! -d "$w" ]; then warn "Not a directory: $w"; continue; fi
  UI=$(find "$w" \( -name .user.ini -o -name .htaccess \) -type f \
       -exec grep -lE 'upload_progress|php_(admin_)?(value|flag)|memory_limit' {} + 2>/dev/null | head -n10)
  if [ -n "$UI" ]; then
    warn "PHP settings overridden per directory (check none re-enable upload progress or raise limits):"
    printf '%s\n' "$UI" | sed 's/^/         /'
  else
    ok "No .user.ini/.htaccess PHP overrides found."
  fi
  USES=$(grep -rlE 'PHP_SESSION_UPLOAD_PROGRESS' "$w" --include='*.php' --include='*.js' --include='*.html' 2>/dev/null | head -n5)
  if [ -n "$USES" ]; then
    warn "Code that uses upload progress (turning it off will affect these):"
    printf '%s\n' "$USES" | sed 's/^/         /'
  else
    ok "No code uses upload progress: turning it off is safe here."
  fi
done

# ----------------------------------------------------------------- summary
section "Summary"
printf '  %s risk(s), %s warning(s).\n' "$RISKS" "$WARNS"
echo "  Config changes reduce exposure; only a patched PHP fixes CVE-2026-109618/109619."
if [ "$RISKS" -gt 0 ]; then exit 2; fi
if [ "$WARNS" -gt 0 ]; then exit 1; fi
exit 0
