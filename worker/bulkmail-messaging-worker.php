#!/usr/bin/env php
<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

$appDir=getenv('BULKMAIL_APP_DIR') ?: '/var/www/bulkmail';
$dbFile=getenv('BULKMAIL_DB') ?: '/var/lib/bulkmail/bulkmail.sqlite';
if (!is_file($dbFile)) { fwrite(STDERR,"Existing BulkMail database required.\n"); exit(1); }
require_once $appDir.'/bulkmail-integrations.php';
require_once $appDir.'/bulkmail-messaging-core.php';
if (is_file($appDir.'/bulkmail-identity.php')) require_once $appDir.'/bulkmail-identity.php';

$lock=fopen(dirname($dbFile).'/messaging-worker.lock','c');
if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) { fwrite(STDERR,"A messaging worker is already running.\n"); exit(1); }
$db=new PDO('sqlite:'.$dbFile,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$db->exec('PRAGMA foreign_keys=ON'); $db->exec('PRAGMA busy_timeout=10000');
bm_message_schema($db);
$once=in_array('--once',$argv,true); $running=true; $diagnostics=[];
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM,static function () use (&$running): void { $running=false; });
    pcntl_signal(SIGINT,static function () use (&$running): void { $running=false; });
}
do {
    try {
        $result=bm_message_process_once($db,bm_integration_config());
        if ($once || $result['attempted'] || $result['reconciled'] || $result['blocked']) {
            // Counts and fixed diagnostic codes only; never log credentials, bodies or phone numbers.
            $activity=$result;
            if (!$once) unset($activity['errors']);
            fwrite(STDOUT,gmdate('c').' '.json_encode($activity,JSON_THROW_ON_ERROR).PHP_EOL);
        }
        if (!$once && bm_message_diagnostic_due($result['errors'],$diagnostics,time())) {
            fwrite(STDERR,gmdate('c').' '.json_encode(['errors'=>$result['errors']],JSON_THROW_ON_ERROR).PHP_EOL);
        }
    } catch (Throwable $e) {
        if ($once || bm_message_diagnostic_due(['worker pass incomplete'],$diagnostics,time())) {
            fwrite(STDERR,gmdate('c')." Messaging worker could not complete a pass; no request will be replayed blindly.\n");
        }
        if ($once) exit(1);
    }
    if (!$once && $running) sleep(1);
} while (!$once && $running);
flock($lock,LOCK_UN); fclose($lock);
