<?php
/**
 * dump-live-ini.php: print the PHP settings the RUNNING workers are using.
 *
 * Why: PHP-FPM reads php.ini only when it starts. If php.ini is lost or
 * damaged, the running workers still hold every setting in memory until the
 * next restart. This script reads them back so php.ini can be rebuilt with
 * ini-dump-to-php-ini.sh before anything restarts.
 *
 * Safety:
 *  - answers only requests from the server itself (127.0.0.1 / ::1), 404 otherwise
 *  - read-only: it prints settings and changes nothing
 *  - put it in a web root under a random name, fetch it once with curl from
 *    the server, then delete it straight away (see the README)
 *
 * Output format (one setting per line, var_export values):
 *   ; loaded ini: '/path/to/php.ini'
 *   allow_url_fopen = '1'
 *   error_log = NULL
 *   ...
 *   ; extensions: Core, date, ...
 *   ; zend_extensions: Zend OPcache
 *   ; live session.upload_progress.enabled = '0'
 *
 * global_value is printed (what php.ini / defaults set), so a .user.ini in the
 * folder the script runs from cannot skew the result. FPM pool php_value /
 * php_admin_value settings do not show up as global values; the last line
 * reports the effective upload-progress value separately.
 */

$remote = $_SERVER['REMOTE_ADDR'] ?? '';
if (!in_array($remote, ['127.0.0.1', '::1'], true)) {
    http_response_code(404);
    exit;
}

header('Content-Type: text/plain; charset=UTF-8');

echo '; loaded ini: ', var_export(php_ini_loaded_file(), true), "\n";
foreach (ini_get_all(null, true) as $name => $entry) {
    echo $name, ' = ', var_export($entry['global_value'], true), "\n";
}
echo "\n; extensions: ", implode(', ', get_loaded_extensions()), "\n";
echo '; zend_extensions: ', implode(', ', get_loaded_extensions(true)), "\n";
echo '; live session.upload_progress.enabled = ',
     var_export(ini_get('session.upload_progress.enabled'), true), "\n";
