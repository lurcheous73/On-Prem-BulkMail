<?php
declare(strict_types=1);

// Synthetic records and injected responses only; no portal access or real credentials.
require dirname(__DIR__).'/app/bulkmail-identity.php';
$cfg = ['enabled'=>true,'auto_login'=>true,'base_url'=>'https://portal.example.invalid','allow_http'=>false];
function bm_integration_config(): array { global $cfg; return ['identity'=>$cfg]; }
$checks=0;
function diagnostic_check(string $name, bool $condition): void {
    global $checks;
    if (!$condition) throw new RuntimeException('FAIL '.$name);
    $checks++; echo 'PASS '.$name.PHP_EOL;
}
$db = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$db->exec(file_get_contents(dirname(__DIR__).'/database/schema.sql'));
$db->exec("INSERT INTO users(id,username,password_hash,display_name,email,is_admin) VALUES(1,'fixture-local','fixture-password','Fixture member','fixture@example.invalid',0)");
bm_identity_schema($db);
$profile = ['id'=>'44444444-4444-4444-8444-444444444444','userName'=>'fixture-private-name',
    'email'=>'fixture-private-email@example.invalid','displayName'=>'Fixture private display',
    'status'=>1,'activationStatus'=>1,'isVisitor'=>false];
bm_identity_store_link($db,1,bm_identity_profile($profile),$cfg['base_url'],true,1);
$usersBefore = $db->query('SELECT * FROM users')->fetchAll();
$secret = 'fixture-private-cookie+/=';
$privateMessage = 'fixture-private-response-and-error';
$log = tempnam(sys_get_temp_dir(), 'identity-diagnostic-');
$oldLog = ini_set('error_log', $log);
$events=[];
$read = static function()use($log,&$events):array {
    $lines=file($log,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
    $line=end($lines);
    $prefix='BulkMail portal identity ';
    $offset=strpos($line,$prefix);
    if ($offset===false) throw new RuntimeException('Missing fixed diagnostic');
    $event=json_decode(substr($line,$offset+strlen($prefix)),true,32,JSON_THROW_ON_ERROR);
    $events[]=$event;
    return $event;
};
$transport=static fn()=>$profile;
try {
    unset($_SERVER['HTTP_SEC_FETCH_DEST'],$_SERVER['HTTP_SEC_FETCH_SITE']);
    $_COOKIE=[];$_GET=['asc_auth_key'=>$secret];$_POST=$_GET;
    diagnostic_check('Absent request cookie is classified without using URL or form tokens',
        bm_identity_try_portal_login($db,$transport)===null&&($event=$read())['outcome']==='cookie_missing'
        &&$event['cookie_present']===false&&$event['cookie_valid_format']===false);
    foreach ([$secret."\r\nprivate-header",[$secret],''] as $bad) {
        $_COOKIE=['asc_auth_key'=>$bad];
        diagnostic_check('Malformed request cookie is classified without logging its value',
            bm_identity_try_portal_login($db,$transport)===null&&($event=$read())['outcome']==='cookie_invalid'
            &&$event['cookie_present']===true&&$event['cookie_valid_format']===false);
    }
    $_COOKIE=['asc_auth_key'=>$secret];
    foreach (['enabled'=>'disabled','auto_login'=>'auto_login_disabled'] as $field=>$outcome) {
        $cfg[$field]=false;
        diagnostic_check('Disabled feature is classified as '.$outcome,bm_identity_try_portal_login($db,$transport)===null&&$read()['outcome']===$outcome);
        $cfg[$field]=true;
    }
    $cfg['base_url']='https://private:password@portal.example.invalid';
    diagnostic_check('Invalid issuer is classified without printing configuration',bm_identity_try_portal_login($db,$transport)===null&&$read()['outcome']==='issuer_invalid');
    $cfg['base_url']='http://portal.example.invalid';$cfg['allow_http']=true;
    diagnostic_check('HTTPS portal requirement remains enforced',bm_identity_try_portal_login($db,$transport)===null&&$read()['outcome']==='https_required');
    $cfg['base_url']='https://portal.example.invalid';$cfg['allow_http']=false;
    $failure=static function()use($secret,$privateMessage):array { throw new BMIdentityException($secret.$privateMessage,'http_rejected',401,0); };
    diagnostic_check('HTTP refusal records only a fixed class and numeric status',bm_identity_try_portal_login($db,$failure)===null&&($event=$read())['outcome']==='http_rejected'&&$event['http_status']===401&&$event['curl_code']===0);
    $failure=static function()use($secret):array { throw new BMIdentityException($secret,'transport_failed',0,60); };
    diagnostic_check('Transport failure retains the numeric cURL class',bm_identity_try_portal_login($db,$failure)===null&&($event=$read())['outcome']==='transport_failed'&&$event['http_status']===0&&$event['curl_code']===60);
    foreach ([['id'=>'private-invalid-id'],['status'=>2],['activationStatus'=>2],['isVisitor'=>true],['userName'=>'']] as $i=>$change) {
        $outcome=['profile_invalid_id','profile_inactive','profile_unactivated','profile_visitor','profile_incomplete'][$i];
        $badProfile=static fn()=>array_replace($profile,$change);
        diagnostic_check('Profile rejection is classified as '.$outcome,bm_identity_try_portal_login($db,$badProfile)===null&&$read()['outcome']===$outcome);
    }
    $unknown=static fn()=>array_replace($profile,['id'=>'55555555-5555-4555-8555-555555555555']);
    diagnostic_check('Missing explicit link is distinguished from failed portal validation',bm_identity_try_portal_login($db,$unknown)===null&&$read()['outcome']==='link_unavailable');
    diagnostic_check('A verified linked account still signs in without role changes',
        (int)bm_identity_try_portal_login($db,$transport)['id']===1&&($event=$read())['outcome']==='verified'
        &&$event['cookie_present']===true&&$event['cookie_valid_format']===true);
    $failure=static function()use($secret):array { throw new BMIdentityException($secret,$secret,-1,1000000); };
    diagnostic_check('Unrecognized reason and numeric values cannot enter diagnostic output',bm_identity_try_portal_login($db,$failure)===null&&($event=$read())['outcome']==='verification_failed'&&$event['http_status']===0&&$event['curl_code']===0);
    $failure=static function()use($privateMessage):array { throw new RuntimeException($privateMessage); };
    diagnostic_check('Unexpected exception messages are replaced by a fixed class',bm_identity_try_portal_login($db,$failure)===null&&$read()['outcome']==='unexpected_failure');
    $_SERVER['HTTP_SEC_FETCH_DEST']='iframe';$_SERVER['HTTP_SEC_FETCH_SITE']='same-origin';
    bm_identity_portal_diagnostic('api_result',200,0,37,'request_complete');$event=$read();
    diagnostic_check('Known request context and transport duration use fixed enums and numeric timing',
        $event['fetch_dest']==='iframe'&&$event['fetch_site']==='same-origin'&&$event['elapsed_ms']===37&&$event['stage']==='request_complete');
    bm_identity_portal_diagnostic('api_result',200,0,52,'request_complete',
        ['dns'=>0.0014,'connect'=>0.0066,'tls'=>0.023,'first_byte'=>0.045,'total'=>0.0519]);$event=$read();
    diagnostic_check('API results report five cumulative cURL milestones rounded to milliseconds',
        array_slice($event,-5,null,true)===['dns_ms'=>1,'connect_ms'=>7,'tls_ms'=>23,'first_byte_ms'=>45,'total_ms'=>52]);
    bm_identity_portal_diagnostic('api_result',0,28,40040,'request_complete',
        ['dns'=>-1,'connect'=>INF,'tls'=>NAN,'first_byte'=>999999999,'total'=>PHP_INT_MAX,$secret=>$privateMessage]);$event=$read();
    diagnostic_check('Numeric timings reject non-finite values and clamp negative or excessive values',
        array_slice($event,-5,null,true)===['dns_ms'=>0,'connect_ms'=>0,'tls_ms'=>0,'first_byte_ms'=>300000,'total_ms'=>300000]);
    bm_identity_portal_diagnostic('api_result',0,28,40040,'request_complete',
        ['dns'=>$secret,'connect'=>[$privateMessage],'tls'=>(object)['private'=>$secret],'first_byte'=>true,'total'=>null]);$event=$read();
    diagnostic_check('Strings, arrays, objects, booleans and missing timings cannot enter diagnostic output',
        array_slice($event,-5,null,true)===['dns_ms'=>0,'connect_ms'=>0,'tls_ms'=>0,'first_byte_ms'=>0,'total_ms'=>0]);
    bm_identity_portal_diagnostic('api_request',0,0,null,'request_start',['dns'=>1,'url'=>$secret]);$event=$read();
    diagnostic_check('Only API results add timing fields',!array_key_exists('dns_ms',$event));
    $_SERVER['HTTP_SEC_FETCH_DEST']=$secret;$_SERVER['HTTP_SEC_FETCH_SITE']=[$privateMessage];
    bm_identity_portal_diagnostic($secret,999999,-99,999999,$secret);$event=$read();
    diagnostic_check('Forged context headers, stages and timing cannot bypass the diagnostic allowlists',
        $event['fetch_dest']==='other'&&$event['fetch_site']==='other'&&$event['stage']==='identity_outcome'
        &&$event['elapsed_ms']===300000&&$event['http_status']===0&&$event['curl_code']===0);
    foreach ($events as $event) {
        $fields=['outcome','stage','cookie_present','cookie_valid_format','http_status','curl_code','elapsed_ms','fetch_dest','fetch_site'];
        if ($event['outcome']==='api_result') $fields=array_merge($fields,['dns_ms','connect_ms','tls_ms','first_byte_ms','total_ms']);
        if (array_keys($event)!==$fields) throw new RuntimeException('Unexpected diagnostic field');
    }
    diagnostic_check('Diagnostics use only the nine existing fields and five API-result timing fields',true);
    $output=file_get_contents($log);
    foreach ([$secret,hash('sha256',$secret),$privateMessage,$profile['id'],$profile['userName'],$profile['email'],$profile['displayName'],'private-invalid-id','private-header','private:password','portal.example.invalid'] as $private) {
        if (str_contains($output,$private)) throw new RuntimeException('Diagnostic included private fixture data');
    }
    diagnostic_check('Logs contain no cookie, credential hash, identity, URL, body or exception message',true);
    diagnostic_check('Diagnostics preserve every existing account field',$db->query('SELECT * FROM users')->fetchAll()===$usersBefore);
    echo 'PASS '.$checks.' portal diagnostic checks; synthetic data only.'.PHP_EOL;
} finally {
    ini_set('error_log',$oldLog);
    unlink($log);
}
