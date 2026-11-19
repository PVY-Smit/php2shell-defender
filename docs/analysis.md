# PHP2Shell: a defender's analysis

CVE-2026-109618 and CVE-2026-109619 were disclosed on 21 October 2026 and fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. Both allow unauthenticated remote code execution, both are rated CVSS 4.0 9.2, and both were exploited in the wild from 17 October, four days before disclosure. A related, still-unpatched issue, CVE-2026-115560, followed on 23 October.

This note explains the bugs at the level a defender needs, and why the obvious mitigations are partly wrong. It contains no exploit code.

## The two bugs

### CVE-2026-109618: out-of-memory corruption

PHP handles running out of memory with a `longjmp()` out of whatever it was doing. If that happens while request data is only half set up, request cleanup later trusts the half-built records. An attacker who controls that state can steer PHP into running code.

The attacker forces the memory failure with a crafted multipart (upload) request. The advisory names three ways in:

- a body with no usable `Content-Length`, which gets past the `post_max_size` check
- one form part carrying a very large number of headers, which cost far more memory inside PHP than on the wire
- many empty file fields with nested names, which do not count toward `max_file_uploads`

Default PHP limits were enough for the proven exploit.

### CVE-2026-109619: stale global state

A PHP worker serves many requests in a row. Some global records point into memory owned by one request. A fatal error (out of memory, or `Maximum execution time exceeded`) can skip the step that clears them. The memory is freed, the pointer stays, and a later request on the same worker uses it: a use-after-free.

It needs two requests on the same worker: one that causes the fatal error, and one that touches the stale record before PHP finishes starting up. The confirmed ways to touch it are:

- **session upload progress**, on by default and needing no `session_start()`; the path most real-world attacks use
- `fatal_error_backtraces` (PHP 8.5)
- warnings from deprecated or invalid INI settings applied per request (`.htaccess` `php_value` on mod_php, `PHP_VALUE` passed to PHP-FPM by the web server)

Hiding errors (`display_errors=Off`, `@`) does not help.

### CVE-2026-115560: another upload-progress path (unpatched)

Announced on 23 October as an informational advisory, with no fix in any release yet. It needs an unusual setup: an app that switches `session.serialize_handler` at runtime before `session_start()`, with upload progress enabled. PHP's only mitigation is the same setting as for CVE-2026-109619: `session.upload_progress.enabled=0`.

## Where each bug bites

| Setup | CVE-2026-109618 | CVE-2026-109619 |
| --- | --- | --- |
| Apache mod_php | RCE confirmed; fires while the body is parsed, before any app code | RCE confirmed |
| PHP-FPM | No full exploit shown; source analysis says likely | Confirmed through session upload progress |
| FrankenPHP | Likely | Likely |

In every setup the bug fires inside PHP before the application runs. **Login pages, input validation and WAF rules written for the application do not see it.** Any URL that reaches PHP will do.

## The mitigations, and their traps

Configuration changes reduce exposure. Only a patched PHP fixes CVE-2026-109618/109619.

### "We don't use upload progress, so we're safe": wrong

Upload progress is enabled by default in PHP's session extension. PHP starts tracking it whenever a request contains a field named `PHP_SESSION_UPLOAD_PROGRESS`, and the attacker writes the request. The application never has to use it. Turning it off is the single most useful change:

```ini
; PHP-FPM pool file, under the pool's [name] section
php_admin_flag[session.upload_progress.enabled] = off
```

Use `php_admin_flag` in the pool (or `php.ini`), not `.user.ini` and not `ini_set()`. `php_admin_*` values are locked: a `.user.ini` cannot switch the setting back on, and it is applied before request parsing.

### `memory_limit=-1` that quietly stops working

Removing the memory limit takes away the trigger for CVE-2026-109618. But many PHP applications raise their own limit at runtime with `ini_set('memory_limit', '512M')` for heavy reports. If the server sets `memory_limit=-1` with `php_value`, those calls put a finite limit straight back. Set it with `php_admin_value`, so the runtime calls fail harmlessly. Watch server memory afterwards: one runaway script can now use all of it.

### Limits that make it worse

The advisory warns against capping PHP with `RLIMIT_AS`, `RLIMIT_DATA` or `ulimit -v`. Those make PHP fail allocations in a way that triggers the bug. Cap request bodies instead: a low `post_max_size` (8M, or 32M if uploads need it) and `LimitRequestBody` in Apache.

### Restart vs reload vs "it's in the file"

PHP-FPM reads `php.ini` and pool files only when the master process starts. A change on disk does nothing until php-fpm restarts or reloads (`SIGUSR2`). `php-fpm -tt` shows what the files say, not what the running workers use. To prove a change is live, ask the running workers (see `tools/dump-live-ini.php`).

Two side effects of the restart are worth checking first:

- with `opcache.validate_timestamps=0`, a restart also makes every code change waiting on disk go live
- a server that has not restarted php-fpm in years may load config changes nobody remembers making

`scripts/php2shell-audit.sh` checks both.

## Checking exposure without attacking yourself

- **Version banners are often hidden** (`expose_php=Off`, no `X-Powered-By`), so passive version scanners can report nothing useful. The reliable check is on the server: `php-fpm -v`.
- **Distribution packages backport fixes** without changing the version number. On a packaged PHP, "8.3.6" can be fixed; on a hand-built one it cannot. Check where the binary came from (`dpkg -S` / `rpm -qf`).
- **Active scanners** exist (for example Assetnote's `php2shell-scanner`) and come from reputable sources, but they work by sending large requests designed to exhaust memory or crash FPM workers. Run them against staging, with sign-off. Once `memory_limit=-1` is set they can give a false all-clear, because the error they look for can no longer happen.
- **Treat third-party write-ups with care.** Within days, anonymous "analyses" appeared that mixed up the two CVEs, contradicted the vendor on severity, and shipped downloadable exploit bundles. Check claims against the vendor advisory before acting on them, and never run unverified exploit code to "test" a production system.

## Detection

The most useful single log signal is a memory error raised before any script ran:

```text
PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
```

`in Unknown on line 0` means the error happened during request startup, where both bugs fire. On its own that phrase is not enough: harmless startup warnings, such as a missing extension, end the same way. `scripts/php2shell-logscan.sh` looks for the full pattern, plus worker segfaults, upload-progress fields in WAF logs, and the attacker IPs Amazon published.

## Related: HTTP2Shell (CVE-2026-111497)

The same week brought an out-of-bounds write in Google's Brotli decoder ("HTTP2Shell", with a Python variant). It fires when something decompresses attacker-supplied `br` data: mainly Node.js, Bun and Python HTTP clients and body parsers. Apache and nginx only compress by default, so PHP web servers are rarely the exposed part; developer machines and CI often are.

## Sources

- [PHP security advisory, 21 Oct 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Amazon Threat Intelligence: exploitation before disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [Unit 42 threat brief](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/)
- [Searchlight Cyber: detection mechanism](https://www.slcyber.io/research/high-fidelity-detection-mechanism-for-php2shell-cve-2026-109618-and-cve-2026-109619)
- [The Hacker News: CVE-2026-115560](https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html)
- [Phoenix Security: HTTP2Shell (CVE-2026-111497)](https://phoenix.security/http2shell-node2shell-cve-2026-111497-brotli-decoder-out-of-bounds-write/)
