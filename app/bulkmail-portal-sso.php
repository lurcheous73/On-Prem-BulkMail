<?php
declare(strict_types=1);

/** Narrow, one-use portal identity exchange for explicitly configured local apps. */
final class BMPortalSSOException extends RuntimeException {
    public function __construct(public readonly string $errorCode, public readonly int $httpStatus = 400) {
        parent::__construct($errorCode);
    }
}

function bm_portal_sso_schema(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS portal_sso_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        user_id INTEGER NOT NULL REFERENCES users(id),
        issuer TEXT NOT NULL,
        subject TEXT NOT NULL,
        profile_json TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER
    )");
    $db->exec('CREATE INDEX IF NOT EXISTS portal_sso_expiry ON portal_sso_codes(expires_at)');
}

function bm_portal_sso_client(string $clientId, ?array $config = null): array {
    $config ??= bm_identity_config();
    if (($config['enabled'] ?? false) !== true || ($config['auto_login'] ?? false) !== true) {
        throw new BMPortalSSOException('temporarily_unavailable', 503);
    }
    if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,63}$/D', $clientId)) throw new BMPortalSSOException('invalid_client', 401);
    $clients = $config['sso_clients'] ?? [];
    $client = is_array($clients) && isset($clients[$clientId]) && is_array($clients[$clientId]) ? $clients[$clientId] : [];
    $secret = $client['secret'] ?? null;
    $redirect = $client['redirect_uri'] ?? null;
    $parts = is_string($redirect) ? parse_url($redirect) : false;
    if (($client['enabled'] ?? false) !== true || !is_string($secret) || strlen($secret) < 32 || strlen($secret) > 512
        || preg_match('/[\x00-\x20\x7f]/', $secret) || !$parts || ($parts['scheme'] ?? '') !== 'https'
        || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
        || preg_match('/[\x00-\x20\x7f]/', $redirect)) {
        throw new BMPortalSSOException('invalid_client', 401);
    }
    return ['id'=>$clientId, 'secret'=>$secret, 'redirect_uri'=>$redirect,
        'session_seconds'=>max(60, min(900, (int)($client['session_seconds'] ?? 900)))];
}

function bm_portal_sso_string(array $input, string $name): string {
    $value = $input[$name] ?? '';
    if (!is_string($value)) throw new BMPortalSSOException('invalid_request');
    return $value;
}

function bm_portal_sso_pkce(string $verifier): string {
    if (!preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $verifier)) throw new BMPortalSSOException('invalid_grant');
    return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
}

function bm_portal_sso_authorization_request(array $input, ?array $config = null): array {
    $client = bm_portal_sso_client(bm_portal_sso_string($input, 'client_id'), $config);
    if (!hash_equals($client['redirect_uri'], bm_portal_sso_string($input, 'redirect_uri'))
        || bm_portal_sso_string($input, 'response_type') !== 'code'
        || bm_portal_sso_string($input, 'code_challenge_method') !== 'S256') {
        throw new BMPortalSSOException('invalid_request');
    }
    $state = bm_portal_sso_string($input, 'state');
    $challenge = bm_portal_sso_string($input, 'code_challenge');
    if (!preg_match('/^[A-Za-z0-9_-]{22,128}$/D', $state) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $challenge)) {
        throw new BMPortalSSOException('invalid_request');
    }
    return ['client'=>$client, 'state'=>$state, 'challenge'=>$challenge];
}

/** The account must have been verified against CT400 in this request, not a local password session. */
function bm_portal_sso_issue(PDO $db, array $request, array $account, ?int $at = null): string {
    $at ??= time();
    $profile = $account['_ct400_profile'] ?? null;
    if (!is_array($profile) || empty($account['id']) || empty($account['_ct400_issuer'])
        || !isset($profile['id'], $profile['username'], $profile['email'], $profile['display_name'])
        || !hash_equals((string)$profile['id'], (string)($account['_ct400_id'] ?? ''))) {
        throw new BMPortalSSOException('access_denied', 403);
    }
    bm_portal_sso_schema($db);
    $check = $db->prepare('SELECT 1 FROM users u JOIN user_identity_links l ON l.user_id=u.id
        WHERE u.id=? AND u.active=1 AND l.active=1 AND l.external_login_enabled=1 AND l.issuer=? AND l.external_id=?');
    $check->execute([(int)$account['id'], $account['_ct400_issuer'], $profile['id']]);
    if (!$check->fetchColumn()) throw new BMPortalSSOException('access_denied', 403);
    $code = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $claims = ['issuer'=>(string)$account['_ct400_issuer'], 'subject'=>(string)$profile['id'],
        'username'=>(string)$profile['username'], 'email'=>(string)$profile['email'],
        'display_name'=>(string)$profile['display_name'], 'auth_time'=>$at];
    $db->prepare('DELETE FROM portal_sso_codes WHERE expires_at<?')->execute([$at - 86400]);
    $db->prepare('INSERT INTO portal_sso_codes(code_hash,client_id,redirect_uri,code_challenge,user_id,issuer,subject,profile_json,issued_at,expires_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)')->execute([hash('sha256', $code), $request['client']['id'], $request['client']['redirect_uri'],
            $request['challenge'], (int)$account['id'], $claims['issuer'], $claims['subject'],
            json_encode($claims, JSON_THROW_ON_ERROR), $at, $at + 60]);
    return $code;
}

function bm_portal_sso_exchange(PDO $db, array $input, ?array $config = null, ?int $at = null): array {
    $at ??= time();
    $config ??= bm_identity_config();
    $client = bm_portal_sso_client(bm_portal_sso_string($input, 'client_id'), $config);
    if (!hash_equals($client['secret'], bm_portal_sso_string($input, 'client_secret'))) throw new BMPortalSSOException('invalid_client', 401);
    if (bm_portal_sso_string($input, 'grant_type') !== 'authorization_code'
        || !hash_equals($client['redirect_uri'], bm_portal_sso_string($input, 'redirect_uri'))) throw new BMPortalSSOException('invalid_grant');
    $code = bm_portal_sso_string($input, 'code');
    if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $code)) throw new BMPortalSSOException('invalid_grant');
    $challenge = bm_portal_sso_pkce(bm_portal_sso_string($input, 'code_verifier'));
    bm_portal_sso_schema($db);
    $transaction = false;
    try {
        $db->exec('BEGIN IMMEDIATE'); $transaction = true;
        $q = $db->prepare('SELECT * FROM portal_sso_codes WHERE code_hash=? AND client_id=? AND redirect_uri=? AND consumed_at IS NULL AND expires_at>?');
        $q->execute([hash('sha256', $code), $client['id'], $client['redirect_uri'], $at]);
        $row = $q->fetch(PDO::FETCH_ASSOC);
        if (!$row || !hash_equals($row['code_challenge'], $challenge) || (int)$row['issued_at']>$at+5
            || !hash_equals(bm_identity_issuer($config), $row['issuer'])) throw new BMPortalSSOException('invalid_grant');
        $q = $db->prepare('SELECT 1 FROM users u JOIN user_identity_links l ON l.user_id=u.id
            WHERE u.id=? AND u.active=1 AND l.active=1 AND l.external_login_enabled=1 AND l.issuer=? AND l.external_id=?');
        $q->execute([(int)$row['user_id'], $row['issuer'], $row['subject']]);
        if (!$q->fetchColumn()) throw new BMPortalSSOException('invalid_grant');
        $claims = json_decode($row['profile_json'], true, 16, JSON_THROW_ON_ERROR);
        $db->prepare('UPDATE portal_sso_codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL')->execute([$at, $row['code_hash']]);
        $db->exec('COMMIT'); $transaction = false;
        return ['identity'=>$claims, 'expires_in'=>$client['session_seconds']];
    } catch (Throwable $error) {
        if ($transaction) { try { $db->exec('ROLLBACK'); } catch (Throwable $ignored) {} }
        if ($error instanceof BMPortalSSOException) throw $error;
        throw new BMPortalSSOException('temporarily_unavailable', 503);
    }
}

function bm_portal_sso_json(int $status, array $body): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($body, JSON_THROW_ON_ERROR);
    exit;
}

function bm_portal_sso_handle(PDO $db, string $page): void {
    if (!in_array($page, ['portal_sso_authorize', 'portal_sso_token'], true)) return;
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    try {
        if ($page === 'portal_sso_authorize') {
            if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') throw new BMPortalSSOException('invalid_request', 405);
            $request = bm_portal_sso_authorization_request($_GET);
            $account = bm_identity_try_portal_login($db);
            $params = ['state'=>$request['state']];
            if (!$account) $params['error'] = 'login_required';
            else $params['code'] = bm_portal_sso_issue($db, $request, $account);
            $target = $request['client']['redirect_uri'];
            header('Location: '.$target.(str_contains($target, '?') ? '&' : '?').http_build_query($params, '', '&', PHP_QUERY_RFC3986), true, 302);
            exit;
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') throw new BMPortalSSOException('invalid_request', 405);
        if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0)>8192) throw new BMPortalSSOException('invalid_request', 413);
        $type = strtolower(trim(explode(';', (string)($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
        if ($type === 'application/x-www-form-urlencoded') $input = $_POST;
        elseif ($type === 'application/json') {
            $raw = file_get_contents('php://input', false, null, 0, 8193);
            if (!is_string($raw) || strlen($raw)>8192) throw new BMPortalSSOException('invalid_request', 413);
            try { $input = json_decode($raw, true, 16, JSON_THROW_ON_ERROR); }
            catch (JsonException $error) { throw new BMPortalSSOException('invalid_request'); }
            if (!is_array($input)) throw new BMPortalSSOException('invalid_request');
        } else throw new BMPortalSSOException('invalid_request', 415);
        bm_portal_sso_json(200, bm_portal_sso_exchange($db, $input));
    } catch (BMPortalSSOException $error) {
        bm_portal_sso_json($error->httpStatus, ['error'=>$error->errorCode]);
    } catch (Throwable $error) {
        bm_portal_sso_json(503, ['error'=>'temporarily_unavailable']);
    }
}
