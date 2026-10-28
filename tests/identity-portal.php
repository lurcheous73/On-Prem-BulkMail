<?php
declare(strict_types=1);

// Synthetic users and an injected HTTPS Workspace transport; no portal/network access.
require dirname(__DIR__).'/app/bulkmail-integrations.php';
require dirname(__DIR__).'/app/bulkmail-identity.php';
$checks=0;
function verify_portal(string $name, bool $ok): void {
    global $checks;
    if (!$ok) throw new RuntimeException('FAIL '.$name);
    $checks++; echo 'PASS '.$name.PHP_EOL;
}
function portal_rejects(string $name, callable $fn): void {
    try { $fn(); } catch (BMIdentityException $e) { verify_portal($name,true); return; }
    verify_portal($name,false);
}
$db=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$db->exec('PRAGMA foreign_keys=ON');
$db->exec(file_get_contents(dirname(__DIR__).'/database/schema.sql'));
$insert=$db->prepare('INSERT INTO users(id,username,password_hash,display_name,email,is_admin) VALUES(?,?,?,?,?,?)');
$insert->execute([1,'Admin',password_hash('fixture-admin',PASSWORD_DEFAULT),'QA Administrator','admin@example.invalid',1]);
$insert->execute([2,'Peter',password_hash('fixture-peter',PASSWORD_DEFAULT),'Peter','peter@example.invalid',1]);
$insert->execute([3,'Member',password_hash('fixture-member',PASSWORD_DEFAULT),'QA Member','member@example.invalid',0]);
$usersBefore=$db->query('SELECT * FROM users ORDER BY id')->fetchAll();
bm_identity_schema($db);
$cfg=['enabled'=>true,'auto_login'=>true,'base_url'=>'https://workspace.example.invalid','directory_token'=>'','allow_http'=>false,'session_ttl'=>3600,'portal_revalidate_seconds'=>60];
$file=tempnam(sys_get_temp_dir(),'bulkmail-portal-');
$setConfig=static function(array $value)use($file):void { file_put_contents($file,'<?php return '.var_export(['identity'=>$value],true).';'); };
putenv('BULKMAIL_INTEGRATIONS_CONFIG='.$file);$setConfig($cfg);
$peterId='11111111-1111-4111-8111-111111111111';
$memberId='22222222-2222-4222-8222-222222222222';
$unknownId='33333333-3333-4333-8333-333333333333';
$peter=['id'=>$peterId,'userName'=>'peter.work','email'=>'peter@example.invalid','displayName'=>'Peter Work','status'=>1,'activationStatus'=>1,'isVisitor'=>false,'isAdmin'=>false];
$member=['id'=>$memberId,'userName'=>'member.work','email'=>'member@example.invalid','displayName'=>'Member Work','status'=>1,'activationStatus'=>1,'isVisitor'=>false,'isAdmin'=>true];
bm_identity_store_link($db,2,bm_identity_profile($peter),$cfg['base_url'],true,1);
bm_identity_store_link($db,3,bm_identity_profile($member),$cfg['base_url'],true,1);
$calls=[];$deny=false;$override=null;
$transport=static function(string $method,string $path,?array $body,string $token)use(&$calls,&$deny,&$override,$peter,$member):array {
    $calls[]=[$method,$path,$token];
    if ($deny || $method!=='GET' || $body!==null) throw new BMIdentityException('Portal refused the request.');
    if ($path==='/api/2.0/people/@self.json') {
        if ($token==='fixture-portal-peter') return $override ?? $peter;
        if ($token==='fixture-portal-member') return $member;
        throw new BMIdentityException('Portal refused the request.');
    }
    if ($path==='/api/2.0/people/peter.work.json' && in_array($token,['fixture-portal-peter','fixture-directory'],true)) return $peter;
    throw new BMIdentityException('Portal refused the request.');
};
try {
    $_COOKIE=[];$_GET=['asc_auth_key'=>'fixture-portal-peter','token'=>'fixture-portal-peter'];$_POST=$_GET;$_SESSION=['sentinel'=>'unchanged'];
    verify_portal('URL and form tokens cannot replace a missing request cookie',bm_identity_try_portal_login($db,$transport)===null&&$calls===[]);
    $_COOKIE=['asc_auth_key'=>['fixture-portal-peter']];
    verify_portal('Array cookies are rejected without a network call',bm_identity_try_portal_login($db,$transport)===null&&$calls===[]);
    $_COOKIE=['asc_auth_key'=>"fixture-portal-peter\r\nHeader: bad"];
    verify_portal('Cookie header injection is rejected',bm_identity_try_portal_login($db,$transport)===null&&$calls===[]);
    $_COOKIE=['asc_auth_key'=>'fixture-portal-peter'];
    foreach (['true','false',1] as $flag) {
        $setConfig(array_replace($cfg,['auto_login'=>$flag]));
        verify_portal('Only literal true enables automatic portal login ('.var_export($flag,true).')',bm_identity_try_portal_login($db,$transport)===null&&$calls===[]);
    }
    $setConfig(array_replace($cfg,['enabled'=>false]));
    verify_portal('Disabled integration makes no portal request',bm_identity_try_portal_login($db,$transport)===null&&$calls===[]);
    $setConfig(array_replace($cfg,['base_url'=>'http://workspace.example.invalid','allow_http'=>true]));
    verify_portal('Portal cookies require HTTPS even when legacy HTTP is allowed',bm_identity_try_portal_login($db,$transport)===null&&$calls===[]);
    $setConfig($cfg);$account=bm_identity_try_portal_login($db,$transport);
    verify_portal('Portal login validates the real cookie as raw Workspace Authorization',$calls===[['GET','/api/2.0/people/@self.json','fixture-portal-peter']]);
    verify_portal('Verified portal profile resolves Peter through his explicit link',(int)$account['id']===2&&$account['_ct400_id']===$peterId&&$account['_ct400_profile']['username']==='peter.work');
    verify_portal('Pure portal verifier creates no session',$_SESSION===['sentinel'=>'unchanged']);
    $override=array_replace($peter,['id'=>$unknownId]);
    verify_portal('Same email cannot authenticate an unlinked CT400 identity',bm_identity_try_portal_login($db,$transport)===null);
    foreach ([['status'=>2],['activationStatus'=>2],['isVisitor'=>true]] as $change) {
        $override=array_replace($peter,$change);
        verify_portal('Inactive, pending or visitor portal profile is rejected ('.array_key_first($change).')',bm_identity_try_portal_login($db,$transport)===null);
    }
    $override=null;
    $db->exec('UPDATE user_identity_links SET external_login_enabled=0 WHERE user_id=2');
    verify_portal('An audit-only link does not permit portal login',bm_identity_try_portal_login($db,$transport)===null);
    $db->exec('UPDATE user_identity_links SET external_login_enabled=1,active=0 WHERE user_id=2');
    verify_portal('A disabled explicit link does not permit portal login',bm_identity_try_portal_login($db,$transport)===null);
    $db->exec('UPDATE user_identity_links SET active=1 WHERE user_id=2');
    $db->exec('UPDATE users SET active=0 WHERE id=2');
    verify_portal('A disabled local account cannot sign in through the portal',bm_identity_try_portal_login($db,$transport)===null);
    $db->exec('UPDATE users SET active=1 WHERE id=2');
    $_COOKIE=['asc_auth_key'=>'fixture-portal-member'];$other=bm_identity_try_portal_login($db,$transport);
    verify_portal('Portal administrator status never elevates the local role',(int)$other['id']===3&&(int)$other['is_admin']===0);
    $_COOKIE=['asc_auth_key'=>'fixture-portal-peter'];$account=bm_identity_try_portal_login($db,$transport);
    $_SESSION=['user_id'=>1,'draft'=>['token'=>'previous-preview','acting_for'=>1],'direct_send_pending'=>1,
        'message_previews'=>['previous-message-preview'=>1],'message_form'=>['subject'=>'Previous message'],'csrf'=>'previous-user-csrf'];
    bm_identity_start_session($account,'ct400_portal');
    verify_portal('Changing accounts cannot inherit compose previews, message previews or pending sends',
        array_intersect_key($_SESSION,array_flip(['draft','direct_send_pending','message_previews','message_form','csrf']))===[]&&$_SESSION['user_id']===2);
    verify_portal('Portal session retains the verified identity source and original local user',$_SESSION['authentication_method']==='ct400_portal'&&$_SESSION['user_id']===2&&$_SESSION['authenticated_ct400_id']===$peterId);
    verify_portal('Session stores a fingerprint, never the raw portal credential',!str_contains(json_encode($_SESSION),'fixture-portal-peter')&&$_SESSION['portal_cookie_fingerprint']===hash('sha256','fixture-portal-peter'));
    $session=$_SESSION;$n=count($calls);
    verify_portal('Fresh portal session uses only its bounded verification cache',bm_identity_validate_session($db,$transport)&&count($calls)===$n);
    $_COOKIE=[];
    verify_portal('Missing portal cookie immediately invalidates its app session',!bm_identity_validate_session($db,$transport));
    $_COOKIE=['asc_auth_key'=>'invalid-cookie'];
    verify_portal('Changed invalid portal cookie immediately invalidates its app session',!bm_identity_validate_session($db,$transport));
    $_COOKIE=['asc_auth_key'=>'fixture-portal-member'];
    verify_portal('Changing the portal account cannot take over an existing app session',!bm_identity_validate_session($db,$transport)&&$_SESSION['user_id']===2);
    $_COOKIE=['asc_auth_key'=>'fixture-portal-peter'];$_SESSION=$session;$_SESSION['portal_checked_at']=time()-61;$n=count($calls);
    verify_portal('Portal identity is revalidated when the bounded cache expires',bm_identity_validate_session($db,$transport)&&count($calls)===$n+1&&$_SESSION['portal_checked_at']>time()-5);
    $_SESSION['portal_checked_at']=time()-301;$deny=true;$setConfig(array_replace($cfg,['portal_revalidate_seconds'=>999999]));
    verify_portal('Operator settings cannot extend portal revalidation beyond five minutes',!bm_identity_validate_session($db,$transport));
    $deny=false;$setConfig($cfg);$_SESSION=$session;
    $db->exec('UPDATE user_identity_links SET active=0 WHERE user_id=2');
    verify_portal('Local link revocation invalidates even a freshly verified portal session',!bm_identity_validate_session($db,$transport));
    $db->exec('UPDATE user_identity_links SET active=1 WHERE user_id=2');
    $setConfig(array_replace($cfg,['auto_login'=>false]));
    verify_portal('Disabling portal sign-in revokes portal-derived sessions',!bm_identity_validate_session($db,$transport));
    $setConfig($cfg);$_SESSION=$session;$_SESSION['authenticated_ct400_at']=time()-3601;
    verify_portal('Portal sessions retain the bounded application session lifetime',!bm_identity_validate_session($db,$transport));
    $_SESSION=$session;$setConfig(array_replace($cfg,['base_url'=>'https://another.example.invalid']));
    verify_portal('A changed issuer cannot reuse a previous portal session',!bm_identity_validate_session($db,$transport));
    $setConfig($cfg);$_SESSION=[];$_SERVER['REQUEST_METHOD']='GET';
    verify_portal('Normal unauthenticated GET can use portal sign-in',bm_identity_should_auto_login('home'));
    $_SERVER['REQUEST_METHOD']='POST';
    verify_portal('POST requests cannot automatically acquire an authenticated session',!bm_identity_should_auto_login('home'));
    $_SERVER['REQUEST_METHOD']='GET';$_SESSION=['user_id'=>1,'authentication_method'=>'local'];
    verify_portal('Automatic portal sign-in never replaces an existing local account',!bm_identity_should_auto_login('home'));
    $_SESSION=['portal_auto_login_suppressed'=>true];
    verify_portal('Logout suppression blocks automatic sign-in on the login page',!bm_identity_should_auto_login('login'));
    $_SESSION=[];
    foreach (['logout','unsubscribe','portal_sso_authorize','portal_sso_token'] as $page) verify_portal('Automatic sign-in excludes '.$page,!bm_identity_should_auto_login($page));
    bm_identity_start_session($account,'ct400_portal');
    $db->prepare('INSERT INTO audit_log(user_id,action,details) VALUES(2,"login","")')->execute();
    bm_identity_record_audit($db,(int)$db->lastInsertId(),2,'login','');
    $audit=$db->query('SELECT * FROM audit_identity ORDER BY audit_id DESC LIMIT 1')->fetch();
    verify_portal('Audit distinguishes work-portal authentication from local passwords',$audit['authentication_method']==='ct400_portal'&&$audit['authenticated_ct400_id']===$peterId);
    $_SESSION['portal_auto_login_suppressed']=true;bm_identity_start_session($account,'ct400_portal');
    verify_portal('An explicit verified work sign-in clears logout suppression',empty($_SESSION['portal_auto_login_suppressed']));
    bm_identity_start_session($usersBefore[0],'local');$_COOKIE=[];$n=count($calls);
    verify_portal('Local login remains valid without a portal cookie or network call',bm_identity_validate_session($db,$transport)&&count($calls)===$n&&$_SESSION['user_id']===1);
    verify_portal('Switching deliberately to local login removes portal authentication state',array_intersect_key($_SESSION,array_flip(['authenticated_ct400_id','portal_cookie_fingerprint','portal_checked_at']))===[]);
    $_COOKIE=['asc_auth_key'=>'fixture-portal-peter'];$calls=[];
    $profile=bm_identity_lookup('peter.work',$transport);
    verify_portal('Directory fallback verifies the current portal cookie before lookup',$profile['id']===$peterId&&$calls===[['GET','/api/2.0/people/@self.json','fixture-portal-peter'],['GET','/api/2.0/people/peter.work.json','fixture-portal-peter']]);
    $_COOKIE=[];
    portal_rejects('Missing portal cookie cannot supply directory access',fn()=>bm_identity_lookup('peter.work',$transport));
    $calls=[];$setConfig(array_replace($cfg,['directory_token'=>'fixture-directory']));
    verify_portal('Existing configured directory access remains available',bm_identity_lookup('peter.work',$transport)['id']===$peterId&&$calls===[['GET','/api/2.0/people/peter.work.json','fixture-directory']]);
    $all='';foreach (['users','user_identity_links','audit_identity','audit_log'] as $table) $all.=json_encode($db->query('SELECT * FROM '.$table)->fetchAll());
    verify_portal('Portal and directory credentials are never stored in application tables',!str_contains($all,'fixture-portal-peter')&&!str_contains($all,'fixture-directory'));
    verify_portal('All existing user fields, passwords and roles remain unchanged',$db->query('SELECT * FROM users ORDER BY id')->fetchAll()===$usersBefore);
    verify_portal('Portal sign-in creates no users, messages or contact ownership changes',(int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn()===3&&(int)$db->query('SELECT COUNT(*) FROM mailings')->fetchColumn()===0);
    verify_portal('Portal checks preserve database integrity',$db->query('PRAGMA integrity_check')->fetchColumn()==='ok'&&$db->query('PRAGMA foreign_key_check')->fetchAll()===[]);
    echo 'PASS '.$checks.' portal identity checks; synthetic data only.'.PHP_EOL;
} finally { unlink($file);putenv('BULKMAIL_INTEGRATIONS_CONFIG'); }
