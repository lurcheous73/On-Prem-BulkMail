#!/usr/bin/env php
<?php
declare(strict_types=1);

// This is an additive upgrade, never a fresh-install or account-seeding command.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$options=getopt('', ['db:', 'app-dir:']);
$dbFile=(string)($options['db'] ?? '/var/lib/bulkmail/bulkmail.sqlite');
$appDir=(string)($options['app-dir'] ?? dirname(__DIR__).'/app');
$stage='preflight'; $db=null; $transaction=false;
try {
    if (!is_file($dbFile) || is_link($dbFile) || !is_readable($dbFile) || !is_writable($dbFile)) {
        throw new RuntimeException('Existing writable database required.');
    }
    foreach (['bulkmail-identity.php','bulkmail-portal-sso.php','bulkmail-messaging-core.php'] as $file) {
        if (!is_file($appDir.'/'.$file)) throw new RuntimeException('Migration module unavailable.');
        require_once $appDir.'/'.$file;
    }
    // Modules are now loaded. Run SQLite as the existing database owner so new
    // WAL/journal sidecars cannot become root-owned and block the web worker.
    if (!function_exists('posix_geteuid')) throw new RuntimeException('PHP POSIX extension required.');
    $metadata=stat($dbFile);
    if (posix_geteuid()===0 && (int)$metadata['uid']!==0) {
        $stage='database-owner';
        $owner=posix_getpwuid((int)$metadata['uid']);
        if (function_exists('posix_initgroups') && (!$owner || !posix_initgroups($owner['name'],(int)$metadata['gid']))) {
            throw new RuntimeException('Unable to initialise database-owner groups.');
        }
        if (!posix_setgid((int)$metadata['gid']) || !posix_setuid((int)$metadata['uid'])) {
            throw new RuntimeException('Unable to use existing database owner.');
        }
    }
    $db=new PDO('sqlite:'.$dbFile,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA foreign_keys=ON');
    $db->exec('PRAGMA busy_timeout=15000');
    // Obtain the writer lock before either snapshot. Other application writes wait.
    $db->exec('BEGIN IMMEDIATE'); $transaction=true;
    $stage='existing-database-check';
    if ($db->query('PRAGMA integrity_check')->fetchColumn()!=='ok' || $db->query('PRAGMA foreign_key_check')->fetchAll()!==[]) {
        throw new RuntimeException('Database consistency check failed.');
    }
    $usersBefore=$db->query('SELECT * FROM users ORDER BY id')->fetchAll();
    $columnsBefore=$db->query('PRAGMA table_info(users)')->fetchAll();
    $fingerprintBefore=hash('sha256',serialize([$columnsBefore,$usersBefore]));
    $stage='additive-schema';
    bm_identity_schema($db);
    bm_portal_sso_schema($db);
    bm_message_schema($db);
    $stage='user-preservation-check';
    $usersAfter=$db->query('SELECT * FROM users ORDER BY id')->fetchAll();
    $columnsAfter=$db->query('PRAGMA table_info(users)')->fetchAll();
    $fingerprintAfter=hash('sha256',serialize([$columnsAfter,$usersAfter]));
    if (!hash_equals($fingerprintBefore,$fingerprintAfter)) throw new RuntimeException('Existing user data changed.');
    $stage='upgraded-database-check';
    if ($db->query('PRAGMA integrity_check')->fetchColumn()!=='ok' || $db->query('PRAGMA foreign_key_check')->fetchAll()!==[]) {
        throw new RuntimeException('Database consistency check failed.');
    }
    $db->exec('COMMIT'); $transaction=false;
    // Hashes, passwords, usernames and individual account details are never printed.
    echo json_encode(['ok'=>true,'users_preserved'=>true,'user_count'=>count($usersAfter),'integrity'=>'ok'],JSON_THROW_ON_ERROR).PHP_EOL;
} catch (Throwable $e) {
    if ($transaction && $db instanceof PDO) {
        try { $db->exec('ROLLBACK'); } catch (Throwable $ignored) {}
    }
    fwrite(STDERR,'Integration migration failed at '.$stage.'; no database reset was performed.'.PHP_EOL);
    exit(1);
}
