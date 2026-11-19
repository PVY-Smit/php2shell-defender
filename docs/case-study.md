# Case study: a PHP2Shell response on hand-built PHP-FPM servers

I was the junior tester on a small team responding to PHP2Shell in October 2026. This is what we did and what I learned. Organisation names, hostnames, addresses, versions and server layouts are left out on purpose.

## The starting point

- Several PHP web applications shared web servers, each running **one PHP-FPM pool** behind Apache (`proxy_fcgi`, no mod_php).
- PHP and Apache were **compiled by hand** into `/opt`, not installed from packages. So no `apt`/`zypper` update would ever bring a fix, and vendor backports (such as Sury's Debian packages) did not apply.
- The PHP version banner was hidden, so an outside check showed nothing. The version had to be read on the server.

## Finding out what was really there

Most of the first day was spent locating things, because nothing was where the documentation for packaged PHP says it would be:

| Expected | Actually |
| --- | --- |
| `php` on the PATH | Not installed; only the FPM binary in `/opt/php/<version>/sbin` |
| Pool file in `php-fpm.d/www.conf` | `php-fpm.d/` held only an unused `.default` sample; the pool was at the bottom of `php-fpm.conf` |
| Logs in `/var/log/apache2` | In the Apache build directory, one weekly rotated file per site |
| `apachectl` on the PATH | In Apache's own `bin/` directory |

Lesson: on a hand-built server, find the real paths from the running processes (`ps`, `/proc/<pid>/exe`, `httpd -V`, `php-fpm -i`) before trusting any guide. `scripts/php2shell-audit.sh` does exactly that.

A first log search came back clean, but only because it searched the default log location, where there were no logs. An empty result from the wrong place is not evidence.

## The stopgap

For each server:

1. **Back up** `php.ini` and the FPM config (`cp -a` to a dated folder).
2. **Append** `php_admin_flag[session.upload_progress.enabled] = off` to the pool. On servers where we were not root, that meant `printf ... | sudo tee -a`, where a missing `-a` would have wiped the file.
3. **Diff** against the backup: only the new lines may differ.
4. **Test** with `php-fpm -t`, and confirm the pool value with `php-fpm -tt`.
5. **Check what a restart would also change.** One server's FPM master had been running for years: we confirmed that no config file was newer than the process before restarting. On another, `opcache.validate_timestamps=0` meant a restart would also publish any code waiting on disk.
6. **Restart**, then **prove it on the running workers** with a localhost-only script that prints `ini_get('session.upload_progress.enabled')`, created and deleted in the same command. The first attempt returned "File not found." from FPM, because Apache mapped PHP requests to one specific web root: the response itself showed the request had reached PHP.
7. **Search the logs** from the first in-the-wild date (17 Oct), not the disclosure date.

Before turning the setting off, we searched every web root for `PHP_SESSION_UPLOAD_PROGRESS` to confirm no application used it, and proved the search worked by searching for something that had to exist (`session_start`).

## The incident: an empty php.ini

While collecting output, I copied lines from the terminal and pasted some of them back into the shell. One of them was:

```text
Loaded Configuration File => /opt/php/<version>/lib64/php.ini
```

Bash reads `=>` as `=` followed by a `>` redirect. The command name `Loaded` did not exist, but bash opens redirect targets before looking up the command, so the line truncated `php.ini` to zero bytes. Running as root, nothing stopped it.

**Why nothing broke:** PHP-FPM reads `php.ini` once, when the master starts, and every worker is forked from the master. The sites kept running on the in-memory copy. The danger was the next restart, which would have started PHP with built-in defaults: different upload limits, OPcache off, error display on.

**Recovery without a restart:**

1. The nightly backup turned out to cover only the website code, not `/opt`, so there was no copy to restore.
2. The settings still existed in the running workers. A localhost-only script (`tools/dump-live-ini.php`) printed every `ini_get_all()` global value. It was created, fetched once with `curl` and deleted in a single command block.
3. `tools/ini-dump-to-php-ini.sh` turned the dump into a new `php.ini`: every non-NULL value explicit, shared extensions listed in their original load order, and a broken `extension=` line for an extension that was actually compiled in left out.
4. Before putting it in place: `php-fpm -t` passed and `php-fpm -i` matched the key values. After the next restart, a second dump was diffed against the first. The only difference was the upload-progress setting we had changed on purpose.

The same round trip is part of this repo's tests: dump a running PHP, rebuild the file, start PHP with only the rebuilt file, dump again, diff.

**What I changed in how I work:**

- PuTTY pastes and runs on right-click. Set Window → Selection → mouse buttons to "Windows", and turn on bracketed paste (`bind 'set enable-bracketed-paste on'`) so pasted text waits for Enter.
- Record sessions (`script -a ~/session-$(date +%F).log`).
- Copy commands only, never output.
- Back up before the first change, not before the "real" one.
- Check backups cover configuration directories, not just application code.

## Correcting an early answer

An early reply to a customer said the servers were not affected because "the vulnerable modules are not in our custom build". The CVEs are in PHP core, and a custom build is the standard source compiled with custom options, so that was wrong. We corrected it in writing with what had been done, what was still open, and the upgrade plan. Being exact about "mitigated" versus "fixed" mattered more than sounding reassuring.

## Outcome

- Upload progress was turned off on each server.
- The permanent fix is new servers on a current OS with patched PHP, with applications moved across after testing.
- Hardening gaps found along the way (backup coverage, access to status pages, old file copies in web roots, SSH login settings) were logged for follow-up rather than mixed into the emergency change.
