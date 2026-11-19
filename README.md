# php2shell-defender

[![ci](https://github.com/PVY-Smit/php2shell-defender/actions/workflows/ci.yml/badge.svg)](https://github.com/PVY-Smit/php2shell-defender/actions/workflows/ci.yml)

Defensive notes and **read-only** tools for PHP2Shell ([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) and CVE-2026-115560 on PHP-FPM servers, especially hand-built ones where package updates don't apply.

Built from a real incident response, with organisation-specific details removed. There is no exploit code here.

| Path | What it is |
| --- | --- |
| [`docs/analysis.md`](docs/analysis.md) | The two bugs in plain language, where each one bites, and the traps in the usual mitigations |
| [`docs/case-study.md`](docs/case-study.md) | How the response went on hand-built servers, including recovering a deleted `php.ini` from running workers |
| [`scripts/php2shell-audit.sh`](scripts/php2shell-audit.sh) | Read-only exposure check: version and fix status, upload progress per pool, memory limits, Apache/nginx `PHP_VALUE` pass-through, "changed on disk but not live yet" |
| [`scripts/php2shell-logscan.sh`](scripts/php2shell-logscan.sh) | Read-only log scan for attack indicators, without the common false positive |
| [`tools/dump-live-ini.php`](tools/dump-live-ini.php) + [`tools/ini-dump-to-php-ini.sh`](tools/ini-dump-to-php-ini.sh) | Read the settings the running workers use, and rebuild `php.ini` from them |
| [`iocs/`](iocs/) | Public attacker IPs, with source |
| [`tests/`](tests/) | Unit tests, plus an integration test against a real PHP-FPM in CI |

## Audit a server

```bash
sudo ./scripts/php2shell-audit.sh --webroot /srv/www
```

It runs `php-fpm -v`, `-i` and `-tt`, reads config files and process information, and prints `[OK] / [INFO] / [WARN] / [RISK]` lines. It changes nothing. Exit code: 0 clean, 1 warnings, 2 risks.

What it checks that a version check alone misses:

- **Upload progress per pool**, and whether it is locked with `php_admin_flag` or could be turned back on by a `.user.ini`
- **`memory_limit=-1` that applications can undo** with `ini_set()`
- **Packaged vs hand-built PHP**: distro packages backport fixes without changing the version number
- **Config changed after php-fpm started**: the file says one thing, the running workers another
- **An empty `php.ini`**, which only shows up at the next restart
- **mod_php**, and `PHP_VALUE` / `PHP_ADMIN_VALUE` passed from Apache or nginx

Example after applying the stopgap but before restarting:

```text
== Session upload progress (CVE-2026-109619 path in the wild, CVE-2026-115560)
  [OK]   [www] off via php_admin_flag (locked: .user.ini cannot turn it back on).
...
== Running workers vs files on disk
  [WARN] /etc/php/8.3/fpm/pool.d/www.conf changed after php-fpm started: not active until a restart.
```

## Scan logs

```bash
./scripts/php2shell-logscan.sh --ioc-file iocs/aws-madpot-2026-10.txt /var/log/apache2 /var/log/php*-fpm.log
```

Reads plain and `.gz` files modified since 17 Oct 2026 (change with `--since`). The high-signal indicator is a memory error raised before any script ran:

```text
Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
```

Searching only for `Unknown on line 0` gives false positives: harmless startup warnings end the same way. The scanner reports those separately as `[INFO]`.

## Recover php.ini from running workers

PHP-FPM reads `php.ini` only at start, so if the file is lost, the running workers still have every setting. **Don't restart.** Then:

```bash
N=inidump-$(openssl rand -hex 8).php
cp tools/dump-live-ini.php "/path/to/webroot/$N"
curl -s "http://127.0.0.1/$N" > php-ini-recovered.txt   # or https with --resolve, if port 80 redirects
rm -f "/path/to/webroot/$N"
./tools/ini-dump-to-php-ini.sh --extension-dir "$(php-fpm -i | awk -F' => ' '/^extension_dir/{print $2}')" \
  php-ini-recovered.txt > php.ini.rebuilt
```

The script answers only requests from `127.0.0.1` / `::1`. Check the rebuilt file with `php-fpm -t` before putting it in place. After the next restart, dump again and `diff` the two dumps. The tests run this round trip against a real PHP and expect no differences.

## Tests

```bash
tests/run.sh                    # unit tests: log scanner, converter, dump script
sudo tests/integration-fpm.sh   # throwaway machines only: changes and restarts the local PHP-FPM
```

CI runs ShellCheck, the unit tests, and the integration test against `php8.3-fpm` on a fresh runner.

## Scope

- **Defensive only.** No exploit code, payloads or attack tooling.
- **Mitigation is not a fix.** Configuration changes reduce exposure; only PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later (or a vendor backport) fixes CVE-2026-109618/109619. CVE-2026-115560 has no fix yet.
- Run these tools only on systems you are responsible for.

## About

Written by Jean Smit ([@PVY-Smit](https://github.com/PVY-Smit)), software tester. I used Claude (Anthropic) as an assistant for research and drafting; the scripts were tested as described above.

MIT licensed.
