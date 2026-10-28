<?php
declare(strict_types=1);

/** Additive ONLYOFFICE Workspace identity links. No existing users are rewritten. */
final class BMIdentityException extends RuntimeException {
    public function __construct(string $message, public readonly string $reason = 'verification_failed',
        public readonly int $httpStatus = 0, public readonly int $curlCode = 0, public readonly ?int $elapsedMs = null) {
        parent::__construct($message);
    }
}

/** Fixed operational classes only: never emit a credential, identity, body or exception message. */
function bm_identity_portal_diagnostic(string $outcome, int $httpStatus = 0, int $curlCode = 0,
    ?int $elapsedMs = null, string $stage = 'identity_outcome'): void {
    $outcomes = ['disabled','auto_login_disabled','cookie_missing','cookie_invalid','issuer_invalid',
        'https_required','request_invalid','curl_unavailable','transport_failed','http_rejected',
        'json_invalid','response_invalid','profile_invalid_id','profile_inactive','profile_unactivated',
        'profile_visitor','profile_incomplete','link_unavailable','verified','verification_failed','unexpected_failure',
        'api_request','api_result'];
    $dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null;
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
    error_log('BulkMail portal identity '.json_encode([
        'outcome'=>in_array($outcome, $outcomes, true) ? $outcome : 'verification_failed',
        'stage'=>in_array($stage, ['identity_outcome','request_start','request_complete'], true) ? $stage : 'identity_outcome',
        'cookie_present'=>array_key_exists('asc_auth_key', $_COOKIE),
        'cookie_valid_format'=>bm_identity_portal_cookie() !== '',
        'http_status'=>$httpStatus >= 100 && $httpStatus <= 599 ? $httpStatus : 0,
        'curl_code'=>$curlCode >= 0 && $curlCode <= 999 ? $curlCode : 0,
        'elapsed_ms'=>$elapsedMs === null ? null : min(300000,max(0,$elapsedMs)),
        'fetch_dest'=>$dest === null ? 'missing' : (in_array($dest,['document','iframe','empty'],true) ? $dest : 'other'),
        'fetch_site'=>$site === null ? 'missing' : (in_array($site,['same-origin','same-site','cross-site','none'],true) ? $site : 'other'),
    ], JSON_THROW_ON_ERROR));
}

function bm_identity_schema(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS user_identity_links (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        provider TEXT NOT NULL DEFAULT 'ct400' CHECK(provider='ct400'),
        issuer TEXT NOT NULL,
        external_id TEXT NOT NULL,
        external_username TEXT NOT NULL,
        external_email TEXT NOT NULL DEFAULT '',
        external_display_name TEXT NOT NULL DEFAULT '',
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        external_login_enabled INTEGER NOT NULL DEFAULT 0 CHECK(external_login_enabled IN (0,1)),
        verified_at TEXT NOT NULL,
        linked_by_user_id INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(provider,issuer,external_id)
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS audit_identity (
        audit_id INTEGER PRIMARY KEY REFERENCES audit_log(id),
        actor_user_id INTEGER,
        actor_username TEXT,
        actor_display_name TEXT,
        owner_user_id INTEGER,
        owner_username TEXT,
        owner_display_name TEXT,
        actor_ct400_id TEXT,
        actor_ct400_issuer TEXT,
        owner_ct400_id TEXT,
        owner_ct400_issuer TEXT,
        authentication_method TEXT NOT NULL,
        authenticated_ct400_id TEXT,
        captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )");
}

function bm_identity_config(): array {
    $all = function_exists('bm_integration_config') ? bm_integration_config() : [];
    return array_replace([
        'enabled'=>false, 'auto_login'=>false, 'base_url'=>'', 'directory_token'=>'',
        'allow_http'=>false, 'session_ttl'=>3600, 'portal_revalidate_seconds'=>60,
    ], is_array($all['identity'] ?? null) ? $all['identity'] : []);
}

function bm_identity_issuer(array $config): string {
    $url = rtrim(trim((string)$config['base_url']), '/');
    $parts = parse_url($url);
    if (!$parts || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
        || isset($parts['query']) || isset($parts['fragment'])
        || !in_array(strtolower((string)($parts['scheme'] ?? '')), ['http','https'], true)
        || (strtolower($parts['scheme']) !== 'https' && ($config['allow_http'] ?? false) !== true)
        || preg_match('/[\x00-\x20\x7f]/', $url)) {
        throw new BMIdentityException('CT400 needs a valid HTTPS portal URL in the integration configuration.', 'issuer_invalid');
    }
    // Pin identities to the configured portal as well as its stable GUID.
    return strtolower($parts['scheme']).'://'.strtolower($parts['host'])
        .(isset($parts['port']) ? ':'.$parts['port'] : '').rtrim($parts['path'] ?? '', '/');
}

/** Test transport is injected only by code; never selected by request parameters. */
function bm_identity_request(array $config, string $method, string $path, ?array $body = null, string $token = '', ?callable $transport = null): array {
    $base = bm_identity_issuer($config);
    if (empty($config['enabled'])) throw new BMIdentityException('CT400 integration is disabled.', 'disabled');
    if (!str_starts_with($path, '/api/2.0/') || preg_match('/[\r\n]/', $token)) {
        throw new BMIdentityException('Invalid CT400 request configuration.', 'request_invalid');
    }
    if ($transport) {
        $response = $transport($method, $path, $body, $token);
        if (!is_array($response)) throw new BMIdentityException('CT400 returned an invalid response.', 'response_invalid');
        return $response;
    }
    if (!function_exists('curl_init')) throw new BMIdentityException('The server needs PHP cURL for CT400 integration.', 'curl_unavailable');
    $handle = curl_init($base.$path);
    $headers = ['Accept: application/json'];
    if ($token !== '') $headers[] = 'Authorization: '.$token;
    if ($body !== null) $headers[] = 'Content-Type: application/json';
    $buffer = '';
    curl_setopt_array($handle, [
        CURLOPT_CUSTOMREQUEST=>$method, CURLOPT_HTTPHEADER=>$headers,
        CURLOPT_FOLLOWLOCATION=>false, CURLOPT_CONNECTTIMEOUT=>4, CURLOPT_TIMEOUT=>12,
        CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2,
        CURLOPT_PROTOCOLS=>CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_WRITEFUNCTION=>static function ($ch, string $chunk) use (&$buffer): int {
            if (strlen($buffer)+strlen($chunk)>1024*1024) return 0;
            $buffer.=$chunk;
            return strlen($chunk);
        },
    ]);
    if ($body !== null) curl_setopt($handle, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
    $portalSelf = $method === 'GET' && $path === '/api/2.0/people/@self.json';
    if ($portalSelf) bm_identity_portal_diagnostic('api_request',0,0,null,'request_start');
    $started = hrtime(true);
    $ok = curl_exec($handle);
    $status = (int)curl_getinfo($handle, CURLINFO_HTTP_CODE);
    $curlCode = curl_errno($handle);
    $elapsedMs = (int)round((hrtime(true)-$started)/1000000);
    curl_close($handle);
    if ($portalSelf) bm_identity_portal_diagnostic('api_result',$status,$curlCode,$elapsedMs,'request_complete');
    if ($ok === false || $status<200 || $status>=300) {
        // Do not expose a remote body: it may echo credentials or tokens.
        throw new BMIdentityException('CT400 could not verify this request. Check the account and portal connection.',
            $ok === false ? 'transport_failed' : 'http_rejected', $status, $curlCode, $elapsedMs);
    }
    try { $payload = json_decode($buffer, true, 64, JSON_THROW_ON_ERROR); }
    catch (JsonException $e) { throw new BMIdentityException('CT400 returned an invalid response.', 'json_invalid', $status, 0, $elapsedMs); }
    if (!is_array($payload) || !array_key_exists('response', $payload)
        || (isset($payload['status']) && (int)$payload['status'] !== 0)
        || !is_array($payload['response'])) {
        throw new BMIdentityException('CT400 did not return a verified result.', 'response_invalid', $status, 0, $elapsedMs);
    }
    return $payload['response'];
}

function bm_identity_guid(string $value): string {
    $value = strtolower(trim($value));
    if (!preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/D', $value)
        || $value === '00000000-0000-0000-0000-000000000000') {
        throw new BMIdentityException('CT400 did not return a valid user ID.', 'profile_invalid_id');
    }
    return $value;
}

function bm_identity_profile(array $raw): array {
    // Workspace examples use PascalCase; deployed JSON usually uses camelCase.
    $raw = array_change_key_case($raw, CASE_LOWER);
    $id = bm_identity_guid((string)($raw['id'] ?? ''));
    $active = ($raw['status'] ?? null) === 1 || ($raw['status'] ?? null) === '1' || ($raw['status'] ?? null) === 'Active';
    $activated = ($raw['activationstatus'] ?? null) === 1 || ($raw['activationstatus'] ?? null) === '1' || ($raw['activationstatus'] ?? null) === 'Activated';
    if (!$active || !$activated || !empty($raw['isvisitor'])) {
        throw new BMIdentityException('Only an active, activated CT400 member can be linked or sign in.',
            !$active ? 'profile_inactive' : (!$activated ? 'profile_unactivated' : 'profile_visitor'));
    }
    $username = trim((string)($raw['username'] ?? ''));
    $email = trim((string)($raw['email'] ?? ''));
    $display = trim((string)($raw['displayname'] ?? (($raw['firstname'] ?? '').' '.($raw['lastname'] ?? ''))));
    if ($username === '' || strlen($username)>254 || strlen($email)>254 || strlen($display)>254) {
        throw new BMIdentityException('CT400 returned an incomplete user profile.', 'profile_incomplete');
    }
    return ['id'=>$id, 'username'=>$username, 'email'=>$email, 'display_name'=>$display ?: $username];
}

function bm_identity_lookup(string $lookup, ?callable $transport = null): array {
    $cfg = bm_identity_config();
    $lookup = trim($lookup);
    if ($lookup === '' || strlen($lookup)>254 || preg_match('/[\x00-\x1f\x7f\/\\\\]/', $lookup)) {
        throw new BMIdentityException('Enter an exact CT400 username or email address.');
    }
    $token = trim((string)$cfg['directory_token']);
    if ($token === '') {
        // A local administrator may use their real, currently verified portal
        // cookie for this request. Never retain or manufacture a directory token.
        bm_identity_portal_profile($cfg, $transport);
        $token = bm_identity_portal_cookie();
    }
    $path = filter_var($lookup, FILTER_VALIDATE_EMAIL)
        ? '/api/2.0/people/email.json?email='.rawurlencode($lookup)
        : '/api/2.0/people/'.rawurlencode($lookup).'.json';
    return bm_identity_profile(bm_identity_request($cfg, 'GET', $path, null, $token, $transport));
}

/** Read only the cookie actually supplied by this browser request. */
function bm_identity_portal_cookie(): string {
    $token = $_COOKIE['asc_auth_key'] ?? '';
    return is_string($token) && preg_match('/^[\x21-\x7e]{1,16384}$/D', $token) ? $token : '';
}

/** Validate the current portal identity over HTTPS, never from a URL/form claim. */
function bm_identity_portal_profile(array $cfg, ?callable $transport = null): array {
    if (($cfg['enabled'] ?? false) !== true) throw new BMIdentityException('CT400 integration is disabled.', 'disabled');
    $issuer = bm_identity_issuer($cfg);
    if (strtolower((string)parse_url($issuer, PHP_URL_SCHEME)) !== 'https') {
        throw new BMIdentityException('Work portal sign-in requires an HTTPS portal connection.', 'https_required');
    }
    $token = bm_identity_portal_cookie();
    if ($token === '') throw new BMIdentityException('Sign in to the work portal before using its directory.',
        array_key_exists('asc_auth_key', $_COOKIE) ? 'cookie_invalid' : 'cookie_missing');
    return bm_identity_profile(bm_identity_request($cfg, 'GET', '/api/2.0/people/@self.json', null, $token, $transport));
}

/** Only an explicit active identity link can resolve an existing local account. */
function bm_identity_linked_account(PDO $db, array $profile, string $issuer): ?array {
    $stmt = $db->prepare("SELECT u.* FROM users u JOIN user_identity_links l ON l.user_id=u.id
        WHERE l.provider='ct400' AND l.issuer=? AND l.external_id=? AND l.active=1
        AND l.external_login_enabled=1 AND u.active=1");
    $stmt->execute([$issuer,$profile['id']]);
    $local = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$local) return null;
    $local['_ct400_id'] = $profile['id'];
    $local['_ct400_issuer'] = $issuer;
    $local['_ct400_profile'] = $profile;
    return $local;
}

/** Pure verification for BulkMail and the portal broker: no provisioning/session writes. */
function bm_identity_try_portal_login(PDO $db, ?callable $transport = null): ?array {
    $cfg = bm_identity_config();
    if (($cfg['enabled'] ?? false) !== true) { bm_identity_portal_diagnostic('disabled'); return null; }
    if (($cfg['auto_login'] ?? false) !== true) { bm_identity_portal_diagnostic('auto_login_disabled'); return null; }
    if (bm_identity_portal_cookie() === '') {
        bm_identity_portal_diagnostic(array_key_exists('asc_auth_key', $_COOKIE) ? 'cookie_invalid' : 'cookie_missing');
        return null;
    }
    try {
        $profile = bm_identity_portal_profile($cfg, $transport);
        $account = bm_identity_linked_account($db, $profile, bm_identity_issuer($cfg));
        bm_identity_portal_diagnostic($account ? 'verified' : 'link_unavailable');
        return $account;
    } catch (BMIdentityException $e) {
        bm_identity_portal_diagnostic($e->reason, $e->httpStatus, $e->curlCode, $e->elapsedMs);
        return null;
    } catch (Throwable $e) { bm_identity_portal_diagnostic('unexpected_failure'); return null; }
}

/** Automatic sign-in never authenticates a POST or replaces a current local session. */
function bm_identity_should_auto_login(string $page): bool {
    $cfg = bm_identity_config();
    return ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET'
        && empty($_SESSION['user_id']) && empty($_SESSION['portal_auto_login_suppressed'])
        && !in_array($page, ['logout','unsubscribe','portal_sso_authorize','portal_sso_token'], true)
        && ($cfg['enabled'] ?? false) === true && ($cfg['auto_login'] ?? false) === true;
}

/** Establish only an already verified account; keep raw portal credentials out of session state. */
function bm_identity_start_session(array $account, string $method): void {
    if (!in_array($method, ['local','ct400','ct400_portal'], true)) throw new BMIdentityException('Unsupported sign-in method.');
    // A fresh identity cannot inherit another user's preview, recipient choices,
    // pending send flag or CSRF state. Saved work remains owned in the database.
    if ((int)($_SESSION['user_id'] ?? 0) !== (int)$account['id']) $_SESSION=[];
    if (session_status() === PHP_SESSION_ACTIVE) session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$account['id'];
    $_SESSION['display_name'] = $account['display_name'];
    $_SESSION['is_admin'] = (bool)$account['is_admin'];
    $_SESSION['authentication_method'] = $method;
    unset($_SESSION['authenticated_ct400_id'], $_SESSION['authenticated_ct400_issuer'], $_SESSION['authenticated_ct400_at'],
        $_SESSION['portal_cookie_fingerprint'], $_SESSION['portal_checked_at'], $_SESSION['portal_auto_login_suppressed']);
    if ($method !== 'local') {
        $_SESSION['authenticated_ct400_id'] = $account['_ct400_id'];
        $_SESSION['authenticated_ct400_issuer'] = $account['_ct400_issuer'];
        $_SESSION['authenticated_ct400_at'] = time();
    }
    if ($method === 'ct400_portal') {
        $_SESSION['portal_cookie_fingerprint'] = hash('sha256', bm_identity_portal_cookie());
        $_SESSION['portal_checked_at'] = time();
    }
}

function bm_identity_admin(PDO $db): int {
    $actor = (int)($_SESSION['user_id'] ?? 0);
    $stmt = $db->prepare('SELECT id FROM users WHERE id=? AND active=1 AND is_admin=1');
    $stmt->execute([$actor]);
    if (!$stmt->fetchColumn()) throw new BMIdentityException('Administrator access required.');
    return $actor;
}

/** Verify on every save; never trust a hidden form profile or match by email. */
function bm_identity_link(PDO $db, int $userId, string $lookup, string $expectedId, bool $enableLogin, ?callable $transport = null): void {
    $actor = bm_identity_admin($db);
    $profile = bm_identity_lookup($lookup, $transport);
    if (!hash_equals(bm_identity_guid($expectedId), $profile['id'])) throw new BMIdentityException('The CT400 profile changed. Look it up again before linking.');
    $issuer = bm_identity_issuer(bm_identity_config());
    $db->beginTransaction();
    try {
        $stmt = $db->prepare('SELECT id FROM users WHERE id=? AND active=1');
        $stmt->execute([$userId]);
        if (!$stmt->fetchColumn()) throw new BMIdentityException('Select an existing active local account.');
        bm_identity_store_link($db, $userId, $profile, $issuer, $enableLogin, $actor);
        audit($db, 'identity_link', 'user='.$userId.' ct400='.$profile['id'].' external_login='.($enableLogin ? '1':'0'));
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        if ($e instanceof BMIdentityException) throw $e;
        throw new BMIdentityException('That CT400 identity is already linked, or the link could not be saved.');
    }
}

/** Internal persistence; caller has verified the profile against CT400. */
function bm_identity_store_link(PDO $db, int $userId, array $profile, string $issuer, bool $enableLogin, int $actor): void {
    $stmt = $db->prepare('SELECT * FROM user_identity_links WHERE user_id=?');
    $stmt->execute([$userId]); $previous = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($previous && ($previous['issuer'] !== $issuer || $previous['external_id'] !== $profile['id'])) {
        throw new BMIdentityException('This account already has a different CT400 identity. Existing bindings are not silently replaced.');
    }
    $stmt = $db->prepare("INSERT INTO user_identity_links
        (user_id,issuer,external_id,external_username,external_email,external_display_name,external_login_enabled,verified_at,linked_by_user_id)
        VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?)
        ON CONFLICT(user_id) DO UPDATE SET external_username=excluded.external_username,
        external_email=excluded.external_email,external_display_name=excluded.external_display_name,
        external_login_enabled=excluded.external_login_enabled,active=1,
        verified_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,linked_by_user_id=excluded.linked_by_user_id");
    $stmt->execute([$userId,$issuer,$profile['id'],$profile['username'],$profile['email'],$profile['display_name'],$enableLogin ? 1:0,$actor]);
}

function bm_identity_create(PDO $db, string $username, string $organisation, string $lookup, string $expectedId, ?callable $transport = null): int {
    $actor = bm_identity_admin($db);
    $username = trim($username); $organisation = trim($organisation);
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.@+-]{1,127}$/D', $username) || strlen($organisation)>254) {
        throw new BMIdentityException('Use a new local username of 2–128 letters, numbers or . _ @ + - characters.');
    }
    $profile = bm_identity_lookup($lookup, $transport);
    if (!hash_equals(bm_identity_guid($expectedId), $profile['id'])) throw new BMIdentityException('The CT400 profile changed. Look it up again.');
    $issuer = bm_identity_issuer(bm_identity_config());
    $db->beginTransaction();
    try {
        $stmt = $db->prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE OR (email<>\'\' AND email=? COLLATE NOCASE)');
        $stmt->execute([$username,$profile['email']]);
        if ($stmt->fetchColumn()) throw new BMIdentityException('An account with that username or email already exists. Link the existing account instead.');
        // A random, discarded secret creates no shared/default local password.
        $hash = password_hash(bin2hex(random_bytes(48)), PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users(username,password_hash,display_name,email,organisation,account_type,is_admin,active) VALUES(?,?,?,?,?,'internal',0,1)");
        $stmt->execute([$username,$hash,$profile['display_name'],$profile['email'],$organisation]);
        $id = (int)$db->lastInsertId();
        $db->prepare('INSERT INTO organisation_settings(user_id,footer_name) VALUES(?,?)')->execute([$id,$organisation]);
        bm_identity_store_link($db, $id, $profile, $issuer, true, $actor);
        audit($db, 'identity_account_create', 'user='.$id.' ct400='.$profile['id']);
        $db->commit();
        return $id;
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        if ($e instanceof BMIdentityException) throw $e;
        throw new BMIdentityException('The account could not be created. Check for an existing account or CT400 link.');
    }
}

function bm_identity_disable(PDO $db, int $userId): void {
    bm_identity_admin($db);
    $db->beginTransaction();
    try {
        $db->prepare('UPDATE user_identity_links SET active=0,external_login_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE user_id=?')->execute([$userId]);
        audit($db, 'identity_disable', 'user='.$userId);
        $db->commit();
    } catch (Throwable $e) { if ($db->inTransaction()) $db->rollBack(); throw $e; }
}

/** No provisioning or email-based account merging occurs at login. */
function bm_identity_try_login(PDO $db, string $username, string $password, string $code = '', ?callable $transport = null): ?array {
    $cfg = bm_identity_config();
    if (empty($cfg['enabled']) || trim($username)==='' || $password==='' || strlen($username)>254 || strlen($password)>4096) return null;
    if ($code !== '' && !preg_match('/^[A-Za-z0-9-]{4,32}$/D', $code)) return null;
    try {
        $path = '/api/2.0/authentication'.($code !== '' ? '/'.rawurlencode($code) : '').'.json';
        $auth = array_change_key_case(bm_identity_request($cfg, 'POST', $path, ['userName'=>trim($username),'password'=>$password], '', $transport), CASE_LOWER);
        if ($code === '' && (!empty($auth['sms']) || !empty($auth['tfa']))) return null;
        $token = (string)($auth['token'] ?? '');
        if ($token === '' || strlen($token)>16384 || preg_match('/[\r\n]/', $token)) return null;
        $profile = bm_identity_profile(bm_identity_request($cfg, 'GET', '/api/2.0/people/@self.json', null, $token, $transport));
        return bm_identity_linked_account($db, $profile, bm_identity_issuer($cfg));
    } catch (Throwable $e) { return null; }
}

/** Local revocation is immediate; portal credentials are rechecked within a bounded interval. */
function bm_identity_validate_session(PDO $db, ?callable $transport = null): bool {
    $method = $_SESSION['authentication_method'] ?? 'local';
    if (!in_array($method, ['ct400','ct400_portal'], true)) return true;
    $cfg = bm_identity_config();
    $issued = (int)($_SESSION['authenticated_ct400_at'] ?? 0);
    $ttl = max(60, min(86400, (int)$cfg['session_ttl']));
    if (empty($cfg['enabled']) || !$issued || $issued>time()+30 || time()-$issued>$ttl) return false;
    try { $issuer = bm_identity_issuer($cfg); } catch (Throwable $e) { return false; }
    if (!hash_equals($issuer, (string)($_SESSION['authenticated_ct400_issuer'] ?? ''))) return false;
    $stmt = $db->prepare("SELECT 1 FROM user_identity_links l JOIN users u ON u.id=l.user_id
        WHERE l.user_id=? AND l.provider='ct400' AND l.issuer=? AND l.external_id=?
        AND l.active=1 AND l.external_login_enabled=1 AND u.active=1");
    $stmt->execute([(int)($_SESSION['user_id'] ?? 0),$issuer,(string)($_SESSION['authenticated_ct400_id'] ?? '')]);
    if (!$stmt->fetchColumn()) return false;
    if ($method !== 'ct400_portal') return true;
    if (($cfg['auto_login'] ?? false) !== true) return false;
    $token = bm_identity_portal_cookie();
    if ($token === '') return false;
    $fingerprint = hash('sha256', $token);
    $checked = (int)($_SESSION['portal_checked_at'] ?? 0);
    $interval = max(15, min(300, (int)$cfg['portal_revalidate_seconds']));
    if ($checked > 0 && $checked <= time() && time()-$checked < $interval
        && hash_equals((string)($_SESSION['portal_cookie_fingerprint'] ?? ''), $fingerprint)) return true;
    $account = bm_identity_try_portal_login($db, $transport);
    if (!$account || (int)$account['id'] !== (int)($_SESSION['user_id'] ?? 0)
        || !hash_equals((string)$_SESSION['authenticated_ct400_id'], $account['_ct400_id'])
        || !hash_equals($issuer, $account['_ct400_issuer'])) return false;
    $_SESSION['portal_cookie_fingerprint'] = $fingerprint;
    $_SESSION['portal_checked_at'] = time();
    return true;
}

function bm_identity_snapshot(PDO $db, int $userId): array {
    $stmt = $db->prepare("SELECT u.id user_id,u.username,u.display_name,
        l.external_id ct400_id,l.issuer ct400_issuer,l.external_username ct400_username
        FROM users u LEFT JOIN user_identity_links l ON l.user_id=u.id AND l.active=1 WHERE u.id=?");
    $stmt->execute([$userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: ['user_id'=>$userId,'username'=>null,'display_name'=>null,'ct400_id'=>null,'ct400_issuer'=>null,'ct400_username'=>null];
}

function bm_identity_audit_owner(PDO $db, string $action, string $details): ?int {
    if (in_array($action,['mailing_queue','mailing_test_queue'],true) && preg_match('/^mailing=(\d+)(?:\s|$)/D', $details, $match)) {
        $stmt=$db->prepare('SELECT acting_for_user_id FROM mailings WHERE id=?'); $stmt->execute([(int)$match[1]]);
        $owner=$stmt->fetchColumn(); return $owner===false ? null : (int)$owner;
    }
    $prefixActions=['contact_create','contact_update','contact_import','sender_create','group_rename','group_merge','group_delete','group_members','compliance_settings','suppression_add','suppression_remove','editor_image_upload','template_create','template_delete'];
    if (in_array($action,$prefixActions,true) && preg_match('/^owner=(\d+)(?:\s|$)/D', $details, $match)) return (int)$match[1];
    return null;
}

function bm_identity_record_audit(PDO $db, int $auditId, ?int $actorId, string $action, string $details, ?int $ownerId = null): void {
    $actor = $actorId ? bm_identity_snapshot($db,$actorId) : [];
    $ownerId ??= bm_identity_audit_owner($db,$action,$details);
    $owner = $ownerId ? bm_identity_snapshot($db,$ownerId) : [];
    $source = $_SESSION['authentication_method'] ?? 'local';
    $method = in_array($source, ['ct400','ct400_portal'], true) ? $source : ($actorId ? 'local' : 'system');
    $authenticatedId = in_array($method, ['ct400','ct400_portal'], true) ? (string)($_SESSION['authenticated_ct400_id'] ?? '') : null;
    $stmt=$db->prepare('INSERT INTO audit_identity(audit_id,actor_user_id,actor_username,actor_display_name,owner_user_id,owner_username,owner_display_name,actor_ct400_id,actor_ct400_issuer,owner_ct400_id,owner_ct400_issuer,authentication_method,authenticated_ct400_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
    $stmt->execute([$auditId,$actorId,$actor['username']??null,$actor['display_name']??null,$ownerId,$owner['username']??null,$owner['display_name']??null,$actor['ct400_id']??null,$actor['ct400_issuer']??null,$owner['ct400_id']??null,$owner['ct400_issuer']??null,$method,$authenticatedId]);
}

function bm_identity_render_audit(PDO $db): void {
    layout_start('Audit');
    echo '<h1>Audit Log</h1><div class="card"><p>Each new entry keeps the initiating account and any linked CT400 identity as they were when the action happened. The sign-in method is recorded separately.</p><div style="overflow-x:auto"><table><tr><th>Date</th><th>Initiated by</th><th>Acting for</th><th>CT400 identity</th><th>Sign-in</th><th>Action / details</th><th>IP</th></tr>';
    $rows=$db->query('SELECT a.*,u.display_name legacy_name,i.actor_username,i.actor_display_name,i.owner_username,i.owner_display_name,i.actor_ct400_id,i.owner_ct400_id,i.authentication_method,i.authenticated_ct400_id FROM audit_log a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN audit_identity i ON i.audit_id=a.id ORDER BY a.id DESC LIMIT 500');
    foreach ($rows as $r) {
        $name=$r['actor_display_name'] ?? $r['legacy_name'] ?? 'System';
        $method=$r['authentication_method'] ?? 'Legacy record';
        echo '<tr><td>'.h($r['created_at']).'</td><td>'.h($name).'<br><small>'.h($r['actor_username']).'</small></td><td>'.h($r['owner_display_name']).'<br><small>'.h($r['owner_username']).'</small></td><td><small>'.h($r['actor_ct400_id'] ?: 'No link captured').'</small>';
        if (!empty($r['owner_ct400_id'])) echo '<br><small>Owner: '.h($r['owner_ct400_id']).'</small>';
        echo '</td><td>'.h($method === 'ct400_portal' ? 'Work portal verified' : ($method === 'ct400' ? 'CT400 verified' : ($method === 'local' ? 'Local password' : $method))).'</td><td>'.h($r['action']).'<br><small>'.h($r['details']).'</small></td><td>'.h($r['ip_address']).'</td></tr>';
    }
    echo '</table></div></div>'; layout_end();
}

function bm_identity_handle(PDO $db, string $page): void {
    if (!in_array($page,['identity_users','audit'],true)) return;
    try { bm_identity_admin($db); }
    catch (BMIdentityException $e) { http_response_code(403); exit('Administrator access required'); }
    if ($page === 'audit') { bm_identity_render_audit($db); exit; }
    $profile=null; $lookup=''; $error='';
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        check_csrf();
        $action=(string)($_POST['action'] ?? '');
        $lookup=trim((string)($_POST['lookup'] ?? ''));
        try {
            if ($action === 'lookup') $profile=bm_identity_lookup($lookup);
            elseif ($action === 'link') {
                bm_identity_link($db,(int)($_POST['user_id']??0),$lookup,(string)($_POST['external_id']??''),!empty($_POST['external_login_enabled']));
                flash('CT400 identity linked. The existing account, password, permissions and address book are preserved.'); redirect('?page=identity_users');
            } elseif ($action === 'create') {
                $id=bm_identity_create($db,(string)($_POST['username']??''),(string)($_POST['organisation']??''),$lookup,(string)($_POST['external_id']??''));
                flash('New CT400-linked account created. Assign its sender identities and address book access in Users.'); redirect('?page=users&manage='.$id);
            } elseif ($action === 'disable') {
                bm_identity_disable($db,(int)($_POST['user_id']??0));
                flash('CT400 link disabled. Local account access and all existing data are preserved.'); redirect('?page=identity_users');
            } else throw new BMIdentityException('Choose a supported account action.');
        } catch (BMIdentityException $e) { $error=$e->getMessage(); }
        catch (Throwable $e) { $error='The account change could not be completed. Existing accounts have been preserved.'; }
    }
    $cfg=bm_identity_config();
    layout_start('CT400 Accounts');
    echo '<h1>CT400 Accounts</h1><div class="card"><p>Link a verified CT400 person to an existing account, or add a new account. Existing logins and message history stay with their current account.</p><p><a class="button secondary" href="?page=users">Manage local accounts</a></p>';
    if ($error !== '') echo '<div class="flash-error">'.h($error).'</div>';
    if (empty($cfg['enabled'])) echo '<div class="warning">CT400 integration is not enabled yet. Existing local logins continue to work.</div>';
    else echo '<form method="post"><input type="hidden" name="csrf" value="'.h(csrf()).'"><input type="hidden" name="action" value="lookup"><label>Exact CT400 username or email</label><input name="lookup" value="'.h($lookup).'" maxlength="254" required><p><button>Look up CT400 person</button></p></form>';
    echo '</div>';
    if ($profile) {
        $hidden='<input type="hidden" name="csrf" value="'.h(csrf()).'"><input type="hidden" name="lookup" value="'.h($lookup).'"><input type="hidden" name="external_id" value="'.h($profile['id']).'">';
        echo '<div class="card"><h2>'.h($profile['display_name']).'</h2><p>'.h($profile['username']).' · '.h($profile['email']).'<br><small>CT400 ID: '.h($profile['id']).'</small></p><h3>Link an existing account</h3><form method="post">'.$hidden.'<input type="hidden" name="action" value="link"><label>Existing account</label><select name="user_id" required><option value="">Choose the matching person deliberately</option>';
        foreach($db->query('SELECT id,username,display_name,email FROM users WHERE active=1 ORDER BY display_name') as $u) echo '<option value="'.(int)$u['id'].'">'.h($u['display_name'].' — '.$u['username'].' — '.($u['email']??'')).'</option>';
        echo '</select><label class="checkrow"><input type="checkbox" name="external_login_enabled" value="1"> Also allow this person to sign in with CT400 credentials</label><button>Verify and link existing account</button></form><h3>Add a new account</h3><p>Use this only if the person has no existing local account. New accounts have their own empty address book and no administrator rights.</p><form method="post">'.$hidden.'<input type="hidden" name="action" value="create"><label>New local username</label><input name="username" maxlength="128" required><label>Organisation</label><input name="organisation" maxlength="254"><button class="secondary">Create CT400-linked account</button></form></div>';
    }
    echo '<div class="card"><h2>Existing links</h2><div style="overflow-x:auto"><table><tr><th>Local account</th><th>CT400 person</th><th>Sign-in</th><th>Verified</th><th></th></tr>';
    foreach($db->query('SELECT l.*,u.username,u.display_name FROM user_identity_links l JOIN users u ON u.id=l.user_id ORDER BY u.display_name') as $l) {
        echo '<tr><td>'.h($l['display_name']).'<br><small>'.h($l['username']).'</small></td><td>'.h($l['external_display_name']).'<br><small>'.h($l['external_id']).'</small></td><td>'.(!(int)$l['active'] ? 'Link disabled' : ((int)$l['external_login_enabled'] ? 'CT400 allowed; local password unchanged' : 'Local; identity linked for audit')).'</td><td>'.h($l['verified_at']).'</td><td>';
        if ((int)$l['active']) echo '<form method="post"><input type="hidden" name="csrf" value="'.h(csrf()).'"><input type="hidden" name="action" value="disable"><input type="hidden" name="user_id" value="'.(int)$l['user_id'].'"><button class="secondary">Disable CT400 link</button></form>';
        echo '</td></tr>';
    }
    echo '</table></div></div>'; layout_end(); exit;
}
