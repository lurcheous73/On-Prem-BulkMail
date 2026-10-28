<?php
declare(strict_types=1);
require __DIR__.'/../app/bulkmail-integrations.php';
require __DIR__.'/../app/bulkmail-identity.php';
require __DIR__.'/../app/bulkmail-portal-sso.php';

$checks = 0;
function sso_check(string $name, bool $value): void {
    global $checks;
    if (!$value) throw new RuntimeException($name);
    $checks++; echo 'PASS '.$name.PHP_EOL;
}
function sso_reject(string $name, callable $call, string $code): void {
    try { $call(); $caught = ''; }
    catch (BMPortalSSOException $error) { $caught = $error->errorCode; }
    sso_check($name, $caught === $code);
}
$db = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$db->exec('PRAGMA foreign_keys=ON');
$db->exec(file_get_contents(__DIR__.'/../database/schema.sql'));
$db->prepare('INSERT INTO users(id,username,password_hash,display_name,email,is_admin,active) VALUES(2,?,?,?,?,1,1)')
    ->execute(['Peter', password_hash('synthetic-only', PASSWORD_DEFAULT), 'Peter', 'peter@example.invalid']);
bm_identity_schema($db);
bm_portal_sso_schema($db);
$profile = ['id'=>'11111111-1111-4111-8111-111111111111','username'=>'peter.ct400','email'=>'peter@example.invalid','display_name'=>'Peter Arnold'];
$issuer = 'https://work.example.invalid';
$db->prepare('INSERT INTO user_identity_links(user_id,issuer,external_id,external_username,external_email,external_display_name,external_login_enabled,verified_at,linked_by_user_id) VALUES(2,?,?,?,?,?,1,CURRENT_TIMESTAMP,2)')
    ->execute([$issuer, $profile['id'], $profile['username'], $profile['email'], $profile['display_name']]);
$before = $db->query('SELECT * FROM users ORDER BY id')->fetchAll();
$secret = str_repeat('fixture-secret-', 5);
$redirect = 'https://meet.example.invalid/host/auth/ct400/callback';
$config = ['enabled'=>true,'auto_login'=>true,'base_url'=>$issuer,'sso_clients'=>['meet-host'=>['enabled'=>true,'secret'=>$secret,'redirect_uri'=>$redirect]]];
$verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
$input = ['client_id'=>'meet-host','redirect_uri'=>$redirect,'response_type'=>'code','code_challenge_method'=>'S256',
    'state'=>str_repeat('a', 32),'code_challenge'=>bm_portal_sso_pkce($verifier)];
$request = bm_portal_sso_authorization_request($input, $config);
$account = ['id'=>2,'_ct400_id'=>$profile['id'],'_ct400_issuer'=>$issuer,'_ct400_profile'=>$profile];
$at = 1800000000;
$payload = ['grant_type'=>'authorization_code','client_id'=>'meet-host','client_secret'=>$secret,'redirect_uri'=>$redirect,'code_verifier'=>$verifier];
function sso_code(): string { global $db,$request,$account,$at; return bm_portal_sso_issue($db,$request,$account,$at); }
function sso_payload(string $code, array $overrides = []): array { global $payload; return array_replace($payload,['code'=>$code],$overrides); }

sso_check('Exact registered HTTPS redirect and S256 request accepted', $request['client']['redirect_uri']===$redirect && $request['state']===$input['state']);
sso_reject('Unregistered client cannot start sign-in', fn()=>bm_portal_sso_authorization_request(array_replace($input,['client_id'=>'unknown']),$config), 'invalid_client');
sso_reject('An arbitrary callback cannot receive an identity code', fn()=>bm_portal_sso_authorization_request(array_replace($input,['redirect_uri'=>'https://attacker.example.invalid/callback']),$config), 'invalid_request');
sso_reject('Plain PKCE is refused', fn()=>bm_portal_sso_authorization_request(array_replace($input,['code_challenge_method'=>'plain']),$config), 'invalid_request');
sso_reject('Missing state is refused', fn()=>bm_portal_sso_authorization_request(array_replace($input,['state'=>'']),$config), 'invalid_request');
sso_reject('Array parameters are refused without a PHP type warning', fn()=>bm_portal_sso_authorization_request(array_replace($input,['state'=>['bad']]),$config), 'invalid_request');
sso_reject('String feature switches do not enable the broker', fn()=>bm_portal_sso_authorization_request($input,array_replace($config,['auto_login'=>'true'])), 'temporarily_unavailable');
$httpConfig=$config;$httpConfig['sso_clients']['meet-host']['redirect_uri']='http://meet.example.invalid/callback';
sso_reject('Production callbacks require HTTPS', fn()=>bm_portal_sso_client('meet-host',$httpConfig), 'invalid_client');
$code=sso_code();
$stored=$db->query('SELECT * FROM portal_sso_codes')->fetch();
sso_check('Database retains no redeemable plaintext code or portal credential', $stored['code_hash']!==$code && !str_contains(json_encode($stored),$secret) && !str_contains($stored['profile_json'],'password'));
sso_reject('Backend client authentication is required', fn()=>bm_portal_sso_exchange($db,sso_payload($code,['client_secret'=>'wrong']),$config,$at+1), 'invalid_client');
sso_reject('A stolen code without its PKCE verifier cannot be exchanged', fn()=>bm_portal_sso_exchange($db,sso_payload($code,['code_verifier'=>str_repeat('b',64)]),$config,$at+1), 'invalid_grant');
sso_reject('Token exchange must use the same exact callback', fn()=>bm_portal_sso_exchange($db,sso_payload($code,['redirect_uri'=>$redirect.'/extra']),$config,$at+1), 'invalid_grant');
$result=bm_portal_sso_exchange($db,sso_payload($code),$config,$at+2);
sso_check('Valid exchange returns the verified CT400 identity only', $result['identity']['subject']===$profile['id'] && $result['identity']['issuer']===$issuer && $result['identity']['username']===$profile['username'] && $result['expires_in']===900 && !isset($result['identity']['is_admin']) && !isset($result['identity']['password_hash']));
sso_reject('A redeemed code cannot be replayed', fn()=>bm_portal_sso_exchange($db,sso_payload($code),$config,$at+3), 'invalid_grant');
$expired=sso_code();
sso_reject('Codes expire at the 60-second boundary', fn()=>bm_portal_sso_exchange($db,sso_payload($expired),$config,$at+60), 'invalid_grant');
$otherConfig=$config;$otherConfig['sso_clients']['other-host']=['enabled'=>true,'secret'=>$secret,'redirect_uri'=>$redirect];
$other=sso_code();
sso_reject('Another registered app cannot redeem this app\'s code', fn()=>bm_portal_sso_exchange($db,sso_payload($other,['client_id'=>'other-host']),$otherConfig,$at+1), 'invalid_grant');
$revoked=sso_code();$db->exec('UPDATE user_identity_links SET external_login_enabled=0 WHERE user_id=2');
sso_reject('Revoking an account link invalidates an outstanding code', fn()=>bm_portal_sso_exchange($db,sso_payload($revoked),$config,$at+1), 'invalid_grant');
sso_reject('A revoked account cannot receive another code', fn()=>sso_code(), 'access_denied');
$db->exec('UPDATE user_identity_links SET external_login_enabled=1 WHERE user_id=2');
$disabled=sso_code();$db->exec('UPDATE users SET active=0 WHERE id=2');
sso_reject('Disabling the local account invalidates an outstanding code', fn()=>bm_portal_sso_exchange($db,sso_payload($disabled),$config,$at+1), 'invalid_grant');
$db->exec('UPDATE users SET active=1 WHERE id=2');
$changedIssuer=sso_code();
sso_reject('Changing the configured portal invalidates earlier codes', fn()=>bm_portal_sso_exchange($db,sso_payload($changedIssuer),array_replace($config,['base_url'=>'https://other.example.invalid']),$at+1), 'invalid_grant');
sso_reject('A local-password account alone is not portal authentication', fn()=>bm_portal_sso_issue($db,$request,['id'=>2],$at), 'access_denied');
sso_check('All original user fields and password hashes remain identical', $db->query('SELECT * FROM users ORDER BY id')->fetchAll()===$before);
sso_check('Identity exchanges never queue email or grant administrator privileges', (int)$db->query('SELECT COUNT(*) FROM mailings')->fetchColumn()===0 && count($before)===1);
$diagnosticLog=tempnam(sys_get_temp_dir(), 'bulkmail-sso-diagnostic-');
$previousLog=ini_get('error_log');
try {
    ini_set('error_log', $diagnosticLog);
    bm_portal_sso_diagnostic('portal_sso_authorize', 'login_required', 302);
    bm_portal_sso_diagnostic('secret-route-'.$secret, 'secret-outcome-'.$verifier, 9999);
    $diagnostics=file_get_contents($diagnosticLog);
    sso_check('Broker diagnostics expose only fixed request outcomes', str_contains($diagnostics, '"outcome":"login_required"') && str_contains($diagnostics, '"status":302'));
    sso_check('Unknown diagnostics cannot disclose credentials or request fields', !str_contains($diagnostics, $secret) && !str_contains($diagnostics, $verifier) && str_contains($diagnostics, '"route":"unknown"') && str_contains($diagnostics, '"status":500'));
} finally {
    ini_set('error_log', $previousLog);
    unlink($diagnosticLog);
}
echo 'PASS '.$checks.' portal SSO exchange checks; synthetic data only.'.PHP_EOL;
