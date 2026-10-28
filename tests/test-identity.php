<?php
declare(strict_types=1);

// Synthetic SQLite + injected Workspace transport: no connection to CT400 or live data.
require dirname(__DIR__).'/app/bulkmail-integrations.php';
require dirname(__DIR__).'/app/bulkmail-identity.php';

$passed=[];
function check(string $name, bool $ok): void {
    global $passed;
    if (!$ok) throw new RuntimeException('FAIL: '.$name);
    $passed[]=$name; echo 'PASS '.$name."\n";
}
function rejects(string $name, callable $work): void {
    try { $work(); } catch (BMIdentityException $e) { check($name,true); return; }
    check($name,false);
}
function audit(PDO $db,string $action,string $details='',?int $owner=null): void {
    $db->prepare('INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)')->execute([$_SESSION['user_id']??null,$action,$details]);
    bm_identity_record_audit($db,(int)$db->lastInsertId(),$_SESSION['user_id']??null,$action,$details,$owner);
}
function row(PDO $db,string $table,int $id): array {
    $s=$db->prepare('SELECT * FROM '.$table.' WHERE id=?'); $s->execute([$id]); return $s->fetch(PDO::FETCH_ASSOC)?:[];
}
function count_rows(PDO $db,string $table): int { return (int)$db->query('SELECT COUNT(*) FROM '.$table)->fetchColumn(); }

$db=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$db->exec('PRAGMA foreign_keys=ON');
$db->exec(file_get_contents(dirname(__DIR__).'/database/schema.sql'));
$peterPassword='synthetic-Peter-password'; $peterHash=password_hash($peterPassword,PASSWORD_DEFAULT);
$insert=$db->prepare('INSERT INTO users(id,username,password_hash,display_name,email,organisation,is_admin,active) VALUES(?,?,?,?,?,?,?,1)');
$insert->execute([1,'Admin',password_hash('synthetic-admin-secret',PASSWORD_DEFAULT),'Administrator','admin@example.invalid','Test',1]);
$insert->execute([2,'Peter',$peterHash,'Peter Arnold','peter@example.invalid','Derby Masonic Hall Ltd.',1]);
$insert->execute([3,'Other',password_hash('synthetic-other-secret',PASSWORD_DEFAULT),'Other User','other@example.invalid','Other org',0]);
$db->exec("INSERT INTO organisation_settings(user_id,footer_name) VALUES(2,'Derby Masonic Hall Ltd.')");
$db->exec("INSERT INTO contacts(id,owner_user_id,name,email) VALUES(1,2,'Peter contact','contact@example.invalid')");
$db->exec("INSERT INTO groups(id,owner_user_id,name) VALUES(1,2,'Peter group')");
$db->exec('INSERT INTO group_members(group_id,contact_id) VALUES(1,1)');
$db->exec("INSERT INTO sender_identities(id,owner_user_id,label,email) VALUES(1,2,'Peter sender','peter@example.invalid')");
$db->exec("INSERT INTO mailings(id,initiated_by_user_id,acting_for_user_id,sender_identity_id,sender_email,subject,body_html,status) VALUES(1,2,2,1,'peter@example.invalid','Retained email','<p>Retained history</p>','sent')");
$db->exec("INSERT INTO mailing_recipients(id,mailing_id,contact_id,email,status) VALUES(1,1,1,'contact@example.invalid','sent')");
$db->exec("INSERT INTO audit_log(user_id,action,details) VALUES(2,'legacy_login','historic')");
$before=[];
foreach(['users','contacts','groups','group_members','sender_identities','mailings','mailing_recipients','organisation_settings'] as $table) $before[$table]=$db->query('SELECT * FROM '.$table.' ORDER BY rowid')->fetchAll();
bm_identity_schema($db); bm_identity_schema($db);
foreach($before as $table=>$rows) check('Additive repeated migration preserves '.$table,$db->query('SELECT * FROM '.$table.' ORDER BY rowid')->fetchAll()===$rows);
check('Old audit is not retroactively attributed to CT400',count_rows($db,'audit_identity')===0);

$file=tempnam(sys_get_temp_dir(),'bulkmail-identity-');
$cfg=['enabled'=>true,'base_url'=>'https://ct400.example.invalid','directory_token'=>'synthetic-directory-token','allow_http'=>false];
$setConfig=function(array $values) use ($file):void { file_put_contents($file,'<?php return '.var_export(['identity'=>$values],true).';'); };
$setConfig($cfg); putenv('BULKMAIL_INTEGRATIONS_CONFIG='.$file);
$peterId='11111111-1111-4111-8111-111111111111';
$adminId='22222222-2222-4222-8222-222222222222';
$newId='33333333-3333-4333-8333-333333333333';
$cloneId='44444444-4444-4444-8444-444444444444';
$makeProfile=fn(string $id,string $name,string $email)=>['id'=>$id,'userName'=>$name,'email'=>$email,'displayName'=>$name.' CT400','status'=>1,'activationStatus'=>1,'isVisitor'=>false,'isAdmin'=>true];
$profiles=[
    'peter.ct400'=>$makeProfile($peterId,'peter.ct400','peter@example.invalid'),
    'admin.ct400'=>$makeProfile($adminId,'admin.ct400','admin@example.invalid'),
    'new.ct400'=>$makeProfile($newId,'new.ct400','new@example.invalid'),
    'clone.ct400'=>$makeProfile($cloneId,'clone.ct400','peter@example.invalid'),
];
$self='peter.ct400'; $mfa=false; $calls=[];
$transport=function(string $method,string $path,?array $body,string $token)use(&$profiles,&$self,&$mfa,&$calls):array {
    $calls[]=[$method,$path];
    if($method==='POST') {
        if(($body['password']??'')!=='synthetic-ct400-password') throw new BMIdentityException('Denied');
        if($path==='/api/2.0/authentication/123456.json') return ['token'=>'synthetic-short-lived-token'];
        if($path!=='/api/2.0/authentication.json') throw new BMIdentityException('Denied');
        return ['token'=>'synthetic-short-lived-token','tfa'=>$mfa];
    }
    if($path==='/api/2.0/people/@self.json') {
        if($token!=='synthetic-short-lived-token') throw new BMIdentityException('Wrong login token');
        return $profiles[$self];
    }
    if($token!=='synthetic-directory-token') throw new BMIdentityException('Wrong directory token');
    if(str_starts_with($path,'/api/2.0/people/email.json?email=')) {
        $email=rawurldecode(substr($path,strlen('/api/2.0/people/email.json?email=')));
        foreach($profiles as $p) if($p['email']===$email) return $p;
    }
    if(preg_match('#^/api/2.0/people/([^/]+)\.json$#D',$path,$m)) {
        $name=rawurldecode($m[1]); if(isset($profiles[$name])) return $profiles[$name];
    }
    throw new BMIdentityException('Not found');
};

try {
    $_SESSION=['user_id'=>1,'authentication_method'=>'local'];
    rejects('Forged CT400 ID is rejected after server verification',fn()=>bm_identity_link($db,2,'peter.ct400',$cloneId,true,$transport));
    check('Rejected identity creates no link or audit',count_rows($db,'user_identity_links')===0&&count_rows($db,'audit_log')===1);
    bm_identity_link($db,2,'peter.ct400',$peterId,false,$transport);
    check('Verified link preserves Peter row byte for byte',row($db,'users',2)===$before['users'][1]);
    check('Peter local password still verifies',password_verify($peterPassword,row($db,'users',2)['password_hash']));
    foreach($before as $table=>$rows) if($table!=='users') check('Linking retains existing '.$table,$db->query('SELECT * FROM '.$table.' ORDER BY rowid')->fetchAll()===$rows);
    check('Link for audit alone does not enable CT400 login',bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','',$transport)===null);
    rejects('One CT400 identity cannot be assigned to two local accounts',fn()=>bm_identity_link($db,3,'peter.ct400',$peterId,true,$transport));
    rejects('An existing binding cannot silently switch person',fn()=>bm_identity_link($db,2,'clone.ct400',$cloneId,true,$transport));
    bm_identity_link($db,2,'peter.ct400',$peterId,true,$transport);
    $logged=bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','',$transport);
    check('CT400 login resolves the same existing Peter ID and local role',(int)$logged['id']===2&&(int)$logged['is_admin']===1&&$logged['_ct400_id']===$peterId);
    check('Bad CT400 password fails',bm_identity_try_login($db,'peter.ct400','wrong','',$transport)===null);
    $self='clone.ct400';
    check('Matching email cannot hijack an unlinked local account',bm_identity_try_login($db,'clone.ct400','synthetic-ct400-password','',$transport)===null);
    $self='peter.ct400'; $profiles[$self]['status']=2;
    check('Terminated CT400 profile fails login',bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','',$transport)===null);
    $profiles[$self]['status']=1; $profiles[$self]['activationStatus']=2;
    check('Pending CT400 profile fails login',bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','',$transport)===null);
    $profiles[$self]['activationStatus']=1; $mfa=true;
    check('A challenge response cannot bypass CT400 MFA',bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','',$transport)===null);
    check('CT400 code endpoint completes verified login',(int)bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','123456',$transport)['id']===2);
    $mfa=false;
    $callsBefore=count($calls); $setConfig(array_replace($cfg,['enabled'=>false]));
    check('Disabled CT400 makes no network request',bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','',$transport)===null&&count($calls)===$callsBefore);
    check('Disabled integration keeps Peter local password valid',password_verify($peterPassword,row($db,'users',2)['password_hash']));
    $setConfig($cfg);
    $_SESSION=['user_id'=>3,'is_admin'=>true,'authentication_method'=>'local'];
    rejects('Forged stale administrator session cannot link accounts',fn()=>bm_identity_link($db,3,'new.ct400',$newId,true,$transport));
    $_SESSION=['user_id'=>1,'authentication_method'=>'local'];
    bm_identity_link($db,1,'admin.ct400',$adminId,true,$transport);
    $id=bm_identity_create($db,'NewMember','New org','new.ct400',$newId,$transport);
    $created=row($db,'users',$id);
    check('Explicit provisioning makes a separate non-admin even for CT400 admin',$id!==2&&(int)$created['is_admin']===0);
    check('Imported account has no known shared or CT400 local password',!password_verify('synthetic-ct400-password',$created['password_hash'])&&!password_verify('password1',$created['password_hash']));
    $count=count_rows($db,'users');
    rejects('Duplicate email provisioning requires deliberate existing link',fn()=>bm_identity_create($db,'DifferentPeter','New org','clone.ct400',$cloneId,$transport));
    rejects('Repeated import creates no duplicate user',fn()=>bm_identity_create($db,'NewMember','New org','new.ct400',$newId,$transport));
    check('Failed imports leave no partial user rows',count_rows($db,'users')===$count);
    check('Provisioning still leaves Peter entirely unchanged',row($db,'users',2)===$before['users'][1]);

    $_SESSION=['user_id'=>1,'authentication_method'=>'local'];
    audit($db,'message_queue','campaign=9',2);
    $a=$db->query('SELECT * FROM audit_identity ORDER BY audit_id DESC LIMIT 1')->fetch();
    check('Audit separates the initiating person from Peter as owner',(int)$a['actor_user_id']===1&&(int)$a['owner_user_id']===2&&$a['actor_ct400_id']===$adminId&&$a['owner_ct400_id']===$peterId);
    check('Linked identity is not falsely called external authentication',$a['authentication_method']==='local'&&$a['authenticated_ct400_id']===null);
    $auditId=(int)$a['audit_id'];
    bm_identity_disable($db,2);
    $old=$db->query('SELECT * FROM audit_identity WHERE audit_id='.$auditId)->fetch();
    check('Historic CT400 snapshots remain after link deactivation',$old===$a);
    check('Disabling link does not disable or alter Peter account',row($db,'users',2)===$before['users'][1]);
    $_SESSION=['user_id'=>2,'authentication_method'=>'ct400','authenticated_ct400_id'=>$peterId,'authenticated_ct400_issuer'=>$cfg['base_url'],'authenticated_ct400_at'=>time()];
    check('Disabling link invalidates existing external sessions',!bm_identity_validate_session($db));
    $_SESSION['authentication_method']='local';
    check('Link deactivation leaves local sessions valid',bm_identity_validate_session($db));
    $_SESSION=['user_id'=>1,'authentication_method'=>'local'];
    bm_identity_link($db,2,'peter.ct400',$peterId,true,$transport);
    $_SESSION=['user_id'=>2,'authentication_method'=>'ct400','authenticated_ct400_id'=>$peterId,'authenticated_ct400_issuer'=>$cfg['base_url'],'authenticated_ct400_at'=>time()];
    check('Active explicit link accepts verified external session',bm_identity_validate_session($db));
    audit($db,'login');
    $a=$db->query('SELECT * FROM audit_identity ORDER BY audit_id DESC LIMIT 1')->fetch();
    check('External login audit records authenticated stable CT400 ID',$a['authentication_method']==='ct400'&&$a['authenticated_ct400_id']===$peterId);
    $_SESSION['authenticated_ct400_at']=time()-3601;
    check('External session has a bounded reauthentication lifetime',!bm_identity_validate_session($db));
    $_SESSION['authenticated_ct400_at']=time();
    $setConfig(array_replace($cfg,['base_url'=>'https://different.example.invalid']));
    check('Issuer changes cannot reuse another portal identity',!bm_identity_validate_session($db)&&bm_identity_try_login($db,'peter.ct400','synthetic-ct400-password','',$transport)===null);
    $setConfig($cfg);
    rejects('CT400 credentials are not sent over accidental plain HTTP',fn()=>bm_identity_issuer(array_replace($cfg,['base_url'=>'http://ct400.example.invalid'])));
    rejects('Portal URL cannot contain credentials',fn()=>bm_identity_issuer(array_replace($cfg,['base_url'=>'https://name:secret@ct400.example.invalid'])));
    $all=''; foreach(['user_identity_links','audit_identity','audit_log','users'] as $table) $all.=json_encode($db->query('SELECT * FROM '.$table)->fetchAll());
    check('Directory tokens and user credentials are never stored',!str_contains($all,'synthetic-directory-token')&&!str_contains($all,'synthetic-short-lived-token')&&!str_contains($all,'synthetic-ct400-password'));
    check('Database integrity and foreign keys remain valid',$db->query('PRAGMA integrity_check')->fetchColumn()==='ok'&&$db->query('PRAGMA foreign_key_check')->fetchAll()===[]);
    echo 'PASS '.count($passed)." identity checks; synthetic data only.\n";
} finally { @unlink($file); putenv('BULKMAIL_INTEGRATIONS_CONFIG'); }
