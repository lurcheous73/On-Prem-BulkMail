<?php
declare(strict_types=1);

/** Offline integration tests: synthetic SQLite records and injected provider transport only. */
require_once __DIR__.'/../app/bulkmail-integrations.php';
require_once __DIR__.'/../app/bulkmail-messaging-core.php';

$configFile=tempnam(sys_get_temp_dir(),'bulkmail-message-config-');
putenv('BULKMAIL_INTEGRATIONS_CONFIG='.$configFile);
register_shutdown_function(static function () use ($configFile): void { @unlink($configFile); });
$config=[
    'sms'=>['enabled'=>true,'base_url'=>'http://192.0.2.10:8080','username'=>'qa-user','password'=>'synthetic-secret','allow_http'=>true,'min_interval_seconds'=>8],
    'whatsapp'=>['enabled'=>true,'base_url'=>'http://127.0.0.1:8787','token'=>str_repeat('x',40),'allow_http'=>true,'min_interval_seconds'=>8],
];
file_put_contents($configFile,'<?php return '.var_export($config,true).';');
chmod($configFile,0600);

function bm_identity_snapshot(PDO $db,int $id): array {
    $u=bm_message_user($db,$id);
    return ['user_id'=>$id,'username'=>$u['username'],'display_name'=>$u['display_name'],'ct400_id'=>'qa-ct400-'.$id,'ct400_issuer'=>'https://ct400.example.invalid'];
}

$passed=[];
function check(string $name,bool $ok): void {
    global $passed;
    if (!$ok) throw new RuntimeException('FAILED: '.$name);
    $passed[]=$name;
    fwrite(STDOUT,'PASS '.$name.PHP_EOL);
}
function denied(string $name,callable $fn): void {
    $denied=false;
    try { $fn(); } catch (RuntimeException $e) { $denied=true; }
    check($name,$denied);
}
function fixture(): PDO {
    $db=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA foreign_keys=ON');
    $db->exec(file_get_contents(__DIR__.'/../database/schema.sql'));
    $q=$db->prepare('INSERT INTO users(id,username,password_hash,display_name,email,organisation,is_admin) VALUES(?,?,?,?,?,?,?)');
    $q->execute([1,'QAAdmin',password_hash('synthetic-admin-password',PASSWORD_DEFAULT),'QA Administrator','admin@example.invalid','QA',1]);
    $q->execute([2,'Peter',password_hash('synthetic-existing-password',PASSWORD_DEFAULT),'Peter Arnold','peter@example.invalid','QA Existing Organisation',0]);
    $q->execute([3,'QAOther',password_hash('synthetic-other-password',PASSWORD_DEFAULT),'QA Other User','other@example.invalid','QA Other Organisation',0]);
    $db->exec("INSERT INTO contacts(id,owner_user_id,name,email,telephone) VALUES
        (1,2,'QA One','one@example.invalid','07700 900001'),
        (2,2,'QA Duplicate','duplicate@example.invalid','+44 7700 900001'),
        (3,2,'QA Invalid','invalid@example.invalid','01234 567890'),
        (4,3,'QA Foreign','foreign@example.invalid','07700 900004'),
        (5,2,'QA Suppressed','suppressed@example.invalid','07700 900005')");
    $db->exec("INSERT INTO groups(id,owner_user_id,name) VALUES(1,2,'QA Group'),(2,3,'QA Foreign Group')");
    $db->exec('INSERT INTO group_members(group_id,contact_id) VALUES(1,1),(1,2),(1,3),(1,5),(2,4)');
    bm_message_schema($db);
    bm_message_set_access($db,1,2,'sms',true);
    bm_message_set_access($db,1,2,'whatsapp',true);
    bm_message_set_access($db,1,3,'sms',true);
    $_SESSION=['user_id'=>2,'auth_method'=>'local'];
    return $db;
}
function campaign(PDO $db,string $channel='sms',int $actor=2,string $number='07700900001'): int {
    $_SESSION=['user_id'=>$actor,'auth_method'=>'local'];
    $preview=bm_message_preview($db,2,$channel,'Synthetic test message',[],[],$number,$actor);
    return bm_message_queue($db,$actor,2,$preview,$preview['token']);
}
function recipient(PDO $db,int $campaign): array {
    $q=$db->prepare('SELECT * FROM message_recipients WHERE campaign_id=? ORDER BY id LIMIT 1');
    $q->execute([$campaign]);return $q->fetch();
}
function due(PDO $db,int $campaign): void {
    $db->prepare("UPDATE message_recipients SET next_attempt_at=datetime('now','-1 minute'),updated_at=datetime('now','-2 minutes') WHERE campaign_id=?")->execute([$campaign]);
    $db->exec('UPDATE message_channel_state SET last_submit_epoch=0');
}

$db=fixture();
$peter=$db->query('SELECT * FROM users WHERE id=2')->fetch();
$contacts=$db->query('SELECT * FROM contacts')->fetchAll();
bm_message_schema($db);bm_message_schema($db);
check('Additive schema is idempotent and preserves Peter account and hash',$peter===$db->query('SELECT * FROM users WHERE id=2')->fetch());
check('Additive schema preserves existing contacts and memberships',$contacts===$db->query('SELECT * FROM contacts')->fetchAll() && (int)$db->query('SELECT COUNT(*) FROM group_members')->fetchColumn()===5);
check('No channel grants are automatically created for existing administrator',!bm_message_has_access($db,1,'sms'));

check('UK local and international mobile forms normalize identically',bm_message_normalize_number('07700 900001')==='+447700900001' && bm_message_normalize_number('0044 (7700) 900001')==='+447700900001' && bm_message_normalize_number('+44 7700-900001')==='+447700900001');
foreach (['07000900001','07600900001','01234567890','+12025550123','hello07700900001','07700900001 x123','+44\n7700900001'] as $number) denied('Invalid or unsupported number rejected: '.$number,fn()=>bm_message_normalize_number($number));
denied('Non-admin cannot grant a channel',fn()=>bm_message_set_access($db,2,3,'sms',true));
denied('Non-admin cannot preview another address book',fn()=>bm_message_preview($db,3,'sms','Hello',[4],[],'',2));
denied('Foreign contact IDs cannot leak into owner preview',fn()=>bm_message_preview($db,2,'sms','Hello',[4],[],'',2));
denied('Foreign group IDs cannot leak into owner preview',fn()=>bm_message_preview($db,2,'sms','Hello',[],[2],'',2));
denied('Message channel is allowlisted',fn()=>bm_message_preview($db,2,'email','Hello',[1],[],'',2));
denied('SMS message size is bounded',fn()=>bm_message_preview($db,2,'sms',str_repeat('x',1601),[1],[],'',2));
denied('Text control characters are rejected',fn()=>bm_message_preview($db,2,'sms',"hello\0world",[1],[],'',2));
bm_message_suppress($db,2,2,'sms','07700900005','Synthetic opt out');
$preview=bm_message_preview($db,2,'sms','Hello',[1],[1],'+447700900001',2);
check('Preview deduplicates across groups, direct contacts and pasted numbers',$preview['unique_count']===1 && $preview['duplicate_count']===3);
check('Preview separates invalid numbers and channel suppressions',$preview['invalid_count']===1 && $preview['suppressed_count']===1);
check('Preview preserves contact identity and normalizes recipient',$preview['recipients'][0]['contact_id']===1 && $preview['recipients'][0]['destination']==='+447700900001');
$modified=$preview;$modified['text']='Changed after preview';
denied('Confirmed payload cannot be changed after preview',fn()=>bm_message_queue($db,2,2,$modified,$preview['token']));
denied('Preview token cannot be used by a different actor',fn()=>bm_message_queue($db,1,2,$preview,$preview['token']));
denied('Preview token cannot switch owner',fn()=>bm_message_queue($db,1,3,$preview,$preview['token']));
$id=bm_message_queue($db,2,2,$preview,$preview['token']);
check('Repeated confirmation is idempotent',bm_message_queue($db,2,2,$preview,$preview['token'])===$id && (int)$db->query('SELECT COUNT(*) FROM message_campaigns')->fetchColumn()===1 && (int)$db->query('SELECT COUNT(*) FROM message_recipients')->fetchColumn()===1);
check('Queueing never changes Peter account, password or existing contacts',$peter===$db->query('SELECT * FROM users WHERE id=2')->fetch() && $contacts===$db->query('SELECT * FROM contacts')->fetchAll());
check('Existing email queues remain empty',(int)$db->query('SELECT COUNT(*) FROM mailings')->fetchColumn()===0 && (int)$db->query('SELECT COUNT(*) FROM mailing_recipients')->fetchColumn()===0);
$p=bm_message_preview($db,2,'sms','New preview',[1],[],'',2);
$db->prepare("UPDATE message_previews SET expires_at=datetime('now','-1 minute') WHERE token=?")->execute([$p['token']]);
denied('Expired previews cannot send',fn()=>bm_message_queue($db,2,2,$p,$p['token']));
$p=bm_message_preview($db,2,'sms','Before contact edit',[1],[],'',2);
$db->exec("UPDATE contacts SET telephone='07700900002' WHERE id=1");
denied('Contact number change requires a fresh preview',fn()=>bm_message_queue($db,2,2,$p,$p['token']));
$db->exec("UPDATE contacts SET telephone='07700 900001' WHERE id=1");
$p=bm_message_preview($db,2,'sms','Before opt out',[1],[],'',2);
bm_message_suppress($db,2,2,'sms','07700900001','New opt out');
denied('Opt out added after preview prevents queueing',fn()=>bm_message_queue($db,2,2,$p,$p['token']));
check('SMS opt out does not suppress WhatsApp',!bm_message_suppressed($db,2,'whatsapp','+447700900001'));
denied('Other user cannot clear suppression',fn()=>bm_message_unsuppress($db,3,2,1));
bm_message_unsuppress($db,2,2,1);
check('Removing a suppression retains its history',(int)$db->query('SELECT active FROM message_suppressions WHERE id=1')->fetchColumn()===0);

$db=fixture();$id=campaign($db,'sms',1);
$c=$db->query('SELECT * FROM message_campaigns WHERE id='.$id)->fetch();
$actor=json_decode($c['actor_identity_json'],true);$owner=json_decode($c['owner_identity_json'],true);
check('Administrator acting for Peter retains distinct initiator and owner',(int)$c['initiated_by_user_id']===1 && (int)$c['acting_for_user_id']===2 && $actor['ct400_id']==='qa-ct400-1' && $owner['ct400_id']==='qa-ct400-2');
check('Account linkage is snapshotted with authentication method',$actor['authentication_method']==='local');

$smsOnly=$config;$smsOnly['whatsapp']['enabled']=false;
$calls=[];
$transport=static function($method,$url,$headers,$body) use (&$calls): array {
    $calls[]=compact('method','url','headers','body');
    return ['status'=>202,'json'=>['id'=>$body['id'],'state'=>'Pending','recipients'=>[['phoneNumber'=>$body['phoneNumbers'][0],'state'=>'Pending']]]];
};
$r=bm_message_process_once($db,$smsOnly,$transport);
$sent=recipient($db,$id);
check('SMSGate uses modern text payload, stable ID and single recipient',$calls[0]['method']==='POST' && $calls[0]['url']==='http://192.0.2.10:8080/messages' && $calls[0]['body']['id']===$sent['client_id'] && $calls[0]['body']['textMessage']['text']==='Synthetic test message' && $calls[0]['body']['phoneNumbers']===['+447700900001'] && $calls[0]['body']['withDeliveryReport']===true);
check('SMSGate local API uses Basic authentication',in_array('Authorization: Basic '.base64_encode('qa-user:synthetic-secret'),$calls[0]['headers'],true));
check('Provider acceptance is submitted, never delivered',$sent['status']==='submitted' && $sent['delivered_at']===null && $r['attempted']===1);
$id2=campaign($db,'sms');
bm_message_process_once($db,$smsOnly,$transport);
check('Per-channel throttle prevents immediate second send',count($calls)===1 && recipient($db,$id2)['status']==='queued');
due($db,$id);
$db->prepare("UPDATE message_recipients SET status='cancelled' WHERE campaign_id=?")->execute([$id2]);
$pollCalls=[];
bm_message_process_once($db,$smsOnly,static function($method,$url,$headers,$body) use (&$pollCalls,$sent): array {
    $pollCalls[]=[$method,$url,$body];
    return ['status'=>200,'json'=>['id'=>$sent['client_id'],'state'=>'Delivered','recipients'=>[['phoneNumber'=>$sent['destination'],'state'=>'Delivered']]]];
});
check('SMSGate delivery status is reconciled by original client ID',$pollCalls===[['GET','http://192.0.2.10:8080/messages/'.$sent['client_id'],null]] && recipient($db,$id)['status']==='delivered');
$mapped=bm_message_provider_state('sms',['json'=>['id'=>$sent['client_id'],'state'=>'Delivered','recipients'=>[]]],$sent);
check('Missing matching recipient cannot claim delivery',$mapped['status']==='submitted');

$db=fixture();$id=campaign($db);$calls=[];
$timeout=static function($method,$url,$headers,$body) use (&$calls): array { $calls[]=$method; return ['status'=>0,'json'=>null,'error'=>'raw SECRET payload']; };
bm_message_process_once($db,$smsOnly,$timeout);
check('Ambiguous POST timeout becomes unknown',recipient($db,$id)['status']==='unknown');
due($db,$id);
bm_message_process_once($db,$smsOnly,static function($method) use (&$calls): array { $calls[]=$method; return ['status'=>404,'json'=>null]; });
check('Missing provider record after timeout never triggers a resend',$calls===['POST','GET'] && recipient($db,$id)['status']==='unknown');
check('Raw provider error and credentials are never stored in message error',!str_contains(recipient($db,$id)['error'],'SECRET'));
$sent=recipient($db,$id);due($db,$id);
bm_message_process_once($db,$smsOnly,static fn()=>['status'=>200,'json'=>['id'=>$sent['client_id'],'state'=>'Sent','recipients'=>[['phoneNumber'=>$sent['destination'],'state'=>'Sent']]]]);
check('Timeout can reconcile to submitted without another POST',recipient($db,$id)['status']==='submitted' && (int)recipient($db,$id)['attempts']===1);

$db=fixture();$id=campaign($db);
$db->prepare("UPDATE message_recipients SET status='submitting',updated_at=datetime('now','-2 minutes'),attempts=1 WHERE campaign_id=?")->execute([$id]);
$methods=[];
bm_message_process_once($db,$smsOnly,static function($method) use (&$methods): array { $methods[]=$method; return ['status'=>404,'json'=>null]; });
check('Interrupted submitting state is reconciled without reposting',$methods===['GET'] && recipient($db,$id)['status']==='unknown');

$db=fixture();$id=campaign($db);$disabled=$smsOnly;$disabled['sms']['enabled']=false;
$calls=0;bm_message_process_once($db,$disabled,static function() use (&$calls): array {$calls++;return [];});
check('Globally disabled channel makes zero provider calls',$calls===0 && recipient($db,$id)['status']==='queued');
bm_message_set_access($db,1,2,'sms',false);
$r=bm_message_process_once($db,$smsOnly,static function() use (&$calls): array {$calls++;return [];});
check('Revoked owner grant blocks queued messages before sending',$calls===0 && recipient($db,$id)['status']==='blocked' && $r['blocked']===1);

$db=fixture();$id=campaign($db,'sms',1);$db->exec('UPDATE users SET is_admin=0 WHERE id=1');
$calls=0;bm_message_process_once($db,$smsOnly,static function() use (&$calls): array {$calls++;return [];});
check('Removed administrator authority blocks acting-for delivery',$calls===0 && recipient($db,$id)['status']==='blocked');
$db=fixture();$id=campaign($db);$db->exec('UPDATE users SET active=0 WHERE id=2');
$calls=0;bm_message_process_once($db,$smsOnly,static function() use (&$calls): array {$calls++;return [];});
check('Deactivated actor or owner blocks queued delivery',$calls===0 && recipient($db,$id)['status']==='blocked');
$db=fixture();$id=campaign($db);bm_message_suppress($db,2,2,'sms','07700900001','Opt out after queue');
$calls=0;bm_message_process_once($db,$smsOnly,static function() use (&$calls): array {$calls++;return [];});
check('Opt out after queue blocks provider submission',$calls===0 && recipient($db,$id)['status']==='blocked');

$db=fixture();$id=campaign($db);$calls=0;
bm_message_process_once($db,$smsOnly,static function() use (&$calls): array {$calls++;return ['status'=>429,'json'=>null];});
check('Unverified SMS rate-limit response remains ambiguous',recipient($db,$id)['status']==='unknown');
bm_message_process_once($db,$smsOnly,static function() use (&$calls): array {$calls++;return [];});
check('Unverified rate-limit response cannot cause a retry send',$calls===1);

$db=fixture();$id=campaign($db);
bm_message_process_once($db,$smsOnly,static fn()=>['status'=>401,'json'=>['error'=>'do not expose SECRET']]);
check('Definite rejection fails safely with redacted error',recipient($db,$id)['status']==='failed' && !str_contains(recipient($db,$id)['error'],'SECRET'));
$db=fixture();$id=campaign($db);
bm_message_process_once($db,$smsOnly,static fn()=>['status'=>202,'json'=>['id'=>'wrong-message-id','state'=>'Delivered']]);
check('Wrong provider response ID cannot confirm a send',recipient($db,$id)['status']==='unknown');

$db=fixture();$id=campaign($db,'whatsapp');$waOnly=$config;$waOnly['sms']['enabled']=false;$calls=[];
bm_message_process_once($db,$waOnly,static function($method,$url,$headers,$body) use (&$calls): array {
    $calls[]=compact('method','url','headers','body');
    return ['status'=>202,'json'=>['id'=>$body['id'],'status'=>'submitted','provider_id'=>'QA-BAILEYS-ID']];
});
$sent=recipient($db,$id);
check('Baileys uses authenticated local API and expected payload',$calls[0]['url']==='http://127.0.0.1:8787/messages' && $calls[0]['body']===['id'=>$sent['client_id'],'to'=>'+447700900001','text'=>'Synthetic test message'] && in_array('Authorization: Bearer '.str_repeat('x',40),$calls[0]['headers'],true));
check('Baileys submission stores provider ID without claiming delivery',$sent['status']==='submitted' && $sent['provider_id']==='QA-BAILEYS-ID' && $sent['delivered_at']===null);
due($db,$id);
bm_message_process_once($db,$waOnly,static fn()=>['status'=>200,'json'=>['id'=>$sent['client_id'],'status'=>'delivered','provider_id'=>'QA-BAILEYS-ID']]);
check('Baileys delivery continues bounded polling for a later read receipt',recipient($db,$id)['status']==='delivered' && recipient($db,$id)['next_attempt_at']!==null);
due($db,$id);
bm_message_process_once($db,$waOnly,static fn()=>['status'=>200,'json'=>['id'=>$sent['client_id'],'status'=>'read','provider_id'=>'QA-BAILEYS-ID']]);
check('Baileys read receipt is stored distinctly',recipient($db,$id)['status']==='read' && recipient($db,$id)['delivered_at']!==null);

foreach ([[503,'not_connected'],[503,'sending_disabled'],[429,'gateway_busy']] as [$http,$code]) {
    $db=fixture();$id=campaign($db,'whatsapp');$calls=0;
    bm_message_process_once($db,$waOnly,static function() use (&$calls,$http,$code): array {$calls++;return ['status'=>$http,'json'=>['error'=>$code]];});
    $r=recipient($db,$id);
    check('Controlled Baileys '.$code.' rejection remains queued with backoff',$r['status']==='queued' && $r['next_attempt_at']>gmdate('Y-m-d H:i:s'));
    bm_message_process_once($db,$waOnly,static function() use (&$calls): array {$calls++;return [];});
    check('Controlled Baileys '.$code.' rejection cannot loop immediately',$calls===1);
    due($db,$id);
    bm_message_process_once($db,$waOnly,static fn($method,$url,$headers,$body)=>['status'=>202,'json'=>['id'=>$body['id'],'status'=>'submitted','provider_id'=>'QA-ID']]);
    check('Controlled Baileys '.$code.' retry keeps the same client ID',recipient($db,$id)['client_id']===$r['client_id'] && recipient($db,$id)['status']==='submitted');
}
$db=fixture();$id=campaign($db,'whatsapp');
bm_message_process_once($db,$waOnly,static fn()=>['status'=>503,'json'=>['error'=>'unknown_proxy_error']]);
check('Generic Baileys service errors are never automatically resent',recipient($db,$id)['status']==='unknown');

$db=fixture();$id=campaign($db,'whatsapp');$methods=[];
bm_message_process_once($db,$waOnly,static function($method) use (&$methods): array {
    $methods[]=$method;
    return ['status'=>409,'json'=>['error'=>'id_conflict','message'=>'other request body SECRET']];
});
$r=recipient($db,$id);
check('Baileys content conflict is terminal failure with a fixed redacted explanation',$r['status']==='failed' && str_contains($r['error'],'conflicts') && !str_contains($r['error'],'SECRET') && $r['next_attempt_at']===null);
due($db,$id);
bm_message_process_once($db,$waOnly,static function($method) use (&$methods,$r): array {
    $methods[]=$method;
    return ['status'=>200,'json'=>['id'=>$r['client_id'],'status'=>'delivered','provider_id'=>'OTHER-CONTENT-ID']];
});
check('Baileys conflict is never polled and cannot adopt delivery of different content',$methods===['POST'] && recipient($db,$id)['status']==='failed' && recipient($db,$id)['provider_id']===null);
$db=fixture();$id=campaign($db,'whatsapp');
bm_message_process_once($db,$waOnly,static fn()=>['status'=>415,'json'=>['error'=>'unsupported_media_type']]);
check('Unsupported request format is a definite rejection',recipient($db,$id)['status']==='failed');

$diagnostics=[];
check('Daemon prints configuration errors on first occurrence',bm_message_diagnostic_due(['sms: configuration incomplete'],$diagnostics,1000));
check('Daemon suppresses repeated diagnostics within one minute',!bm_message_diagnostic_due(['sms: configuration incomplete'],$diagnostics,1059));
check('Daemon repeats unresolved diagnostics after one minute',bm_message_diagnostic_due(['sms: configuration incomplete'],$diagnostics,1060));
check('Daemon reports changed diagnostics immediately',bm_message_diagnostic_due(['whatsapp: status check unavailable'],$diagnostics,1061));
check('Daemon reports recovery once and then stays quiet',bm_message_diagnostic_due([],$diagnostics,1062) && !bm_message_diagnostic_due([],$diagnostics,1122));

$db=fixture();$id=campaign($db);$other=campaign($db);
$db->prepare("UPDATE message_recipients SET status='submitted' WHERE campaign_id=?")->execute([$other]);
denied('Another owner cannot cancel a message',fn()=>bm_message_cancel_campaign($db,3,$id));
check('Cancellation removes only messages still in local queue',bm_message_cancel_campaign($db,2,$id)===1 && recipient($db,$id)['status']==='cancelled' && bm_message_cancel_campaign($db,2,$other)===0 && recipient($db,$other)['status']==='submitted');
check('Database integrity and references remain valid',$db->query('PRAGMA integrity_check')->fetchColumn()==='ok' && $db->query('PRAGMA foreign_key_check')->fetchAll()===[]);

$disabledConfig=$config;$disabledConfig['sms']['enabled']=false;
file_put_contents($configFile,'<?php return '.var_export($disabledConfig,true).';');
denied('Disabled channel cannot create a new preview',fn()=>bm_message_preview($db,2,'sms','Hello',[],[],'07700900001',2));

fwrite(STDOUT,json_encode(['passed'=>count($passed),'synthetic_data_only'=>true,'provider_calls'=>'injected mocks only'],JSON_PRETTY_PRINT).PHP_EOL);
