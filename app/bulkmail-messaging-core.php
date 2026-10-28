<?php
declare(strict_types=1);

/**
 * SMSGate / Baileys queue. All schema additions are independent of the email queue.
 * A request which may have reached a provider is reconciled by its stable client ID;
 * it is never automatically posted a second time.
 */
function bm_message_schema(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS message_channel_access (
        user_id INTEGER NOT NULL, channel TEXT NOT NULL CHECK(channel IN ('sms','whatsapp')),
        enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
        updated_by_user_id INTEGER, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id,channel), FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(updated_by_user_id) REFERENCES users(id)
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS message_suppressions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, owner_user_id INTEGER NOT NULL,
        channel TEXT NOT NULL CHECK(channel IN ('sms','whatsapp')), destination TEXT NOT NULL,
        reason TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        created_by_user_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(owner_user_id,channel,destination),
        FOREIGN KEY(owner_user_id) REFERENCES users(id), FOREIGN KEY(created_by_user_id) REFERENCES users(id)
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS message_campaigns (
        id INTEGER PRIMARY KEY AUTOINCREMENT, initiated_by_user_id INTEGER NOT NULL,
        acting_for_user_id INTEGER NOT NULL, channel TEXT NOT NULL CHECK(channel IN ('sms','whatsapp')),
        body_text TEXT NOT NULL, preview_token TEXT NOT NULL UNIQUE,
        actor_identity_json TEXT NOT NULL, owner_identity_json TEXT NOT NULL,
        selected_count INTEGER NOT NULL, unique_count INTEGER NOT NULL,
        duplicate_count INTEGER NOT NULL DEFAULT 0, invalid_count INTEGER NOT NULL DEFAULT 0,
        suppressed_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(initiated_by_user_id) REFERENCES users(id), FOREIGN KEY(acting_for_user_id) REFERENCES users(id)
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS message_recipients (
        id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL, contact_id INTEGER,
        destination TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL UNIQUE,
        provider_id TEXT, status TEXT NOT NULL DEFAULT 'queued'
            CHECK(status IN ('queued','submitting','submitted','delivered','read','failed','unknown','blocked','cancelled')),
        error TEXT, attempts INTEGER NOT NULL DEFAULT 0,
        queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, submitted_at TEXT, delivered_at TEXT,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, next_attempt_at TEXT, last_checked_at TEXT,
        UNIQUE(campaign_id,destination), FOREIGN KEY(campaign_id) REFERENCES message_campaigns(id),
        FOREIGN KEY(contact_id) REFERENCES contacts(id) ON DELETE SET NULL
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS message_previews (
        token TEXT PRIMARY KEY, actor_user_id INTEGER NOT NULL, owner_user_id INTEGER NOT NULL,
        preview_json TEXT NOT NULL, expires_at TEXT NOT NULL, campaign_id INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(actor_user_id) REFERENCES users(id), FOREIGN KEY(owner_user_id) REFERENCES users(id),
        FOREIGN KEY(campaign_id) REFERENCES message_campaigns(id)
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS message_channel_state (
        channel TEXT PRIMARY KEY, last_submit_epoch INTEGER NOT NULL DEFAULT 0
    )");
    $db->exec('CREATE INDEX IF NOT EXISTS idx_message_campaign_owner ON message_campaigns(acting_for_user_id,id)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_message_recipient_queue ON message_recipients(status,next_attempt_at,id)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_message_recipient_campaign ON message_recipients(campaign_id,id)');
}

function bm_message_channel(string $channel): string {
    if (!in_array($channel, ['sms','whatsapp'], true)) throw new RuntimeException('Choose SMS or WhatsApp.');
    return $channel;
}

/** Accept UK mobile formats; deliberately exclude 070 personal numbers and 076 pagers. */
function bm_message_normalize_number(string $number): string {
    $value = preg_replace('/[ \t().-]/', '', trim($number));
    if (str_starts_with($value, '0044')) $value = '+44'.substr($value, 4);
    elseif (str_starts_with($value, '0')) $value = '+44'.substr($value, 1);
    if (!preg_match('/^\+447[1-57-9][0-9]{8}$/D', $value)) {
        throw new RuntimeException('Enter a UK mobile number beginning 07 or +447; 070 and 076 are not supported.');
    }
    return $value;
}

function bm_message_user(PDO $db, int $id): array {
    $q = $db->prepare('SELECT id,username,display_name,is_admin,active FROM users WHERE id=?');
    $q->execute([$id]);
    $user = $q->fetch(PDO::FETCH_ASSOC);
    if (!$user || !(int)$user['active']) throw new RuntimeException('The user account is not active.');
    return $user;
}

function bm_message_authorize(PDO $db, int $actor, int $owner): array {
    $user = bm_message_user($db, $actor);
    bm_message_user($db, $owner);
    if ($actor !== $owner && !(int)$user['is_admin']) throw new RuntimeException('This address book is not available to your account.');
    return $user;
}

function bm_message_has_access(PDO $db, int $owner, string $channel, ?array $config = null): bool {
    bm_message_channel($channel);
    $config ??= bm_integration_config();
    if (($config[$channel]['enabled'] ?? false) !== true) return false;
    $q = $db->prepare('SELECT a.enabled FROM message_channel_access a JOIN users u ON u.id=a.user_id WHERE a.user_id=? AND a.channel=? AND u.active=1');
    $q->execute([$owner, $channel]);
    return (int)$q->fetchColumn() === 1;
}

function bm_message_audit(PDO $db, int $actor, int $owner, string $action, string $details): void {
    $q = $db->prepare('INSERT INTO audit_log(user_id,action,details,ip_address) VALUES(?,?,?,?)');
    $q->execute([$actor, $action, 'owner='.$owner.' '.$details, (string)($_SERVER['REMOTE_ADDR'] ?? '')]);
    if (function_exists('bm_identity_record_audit')) {
        // The identity helper takes an optional explicit owner; details also retain it for older hooks.
        bm_identity_record_audit($db, (int)$db->lastInsertId(), $actor, $action, 'owner='.$owner.' '.$details, $owner);
    }
}

function bm_message_set_access(PDO $db, int $admin, int $owner, string $channel, bool $enabled): void {
    if (!(int)bm_message_user($db, $admin)['is_admin']) throw new RuntimeException('Administrator access is required.');
    bm_message_user($db, $owner); bm_message_channel($channel);
    $db->prepare('INSERT INTO message_channel_access(user_id,channel,enabled,updated_by_user_id) VALUES(?,?,?,?) ON CONFLICT(user_id,channel) DO UPDATE SET enabled=excluded.enabled,updated_by_user_id=excluded.updated_by_user_id,updated_at=CURRENT_TIMESTAMP')
        ->execute([$owner,$channel,$enabled?1:0,$admin]);
    bm_message_audit($db,$admin,$owner,'message_access','channel='.$channel.' enabled='.($enabled?'1':'0'));
}

function bm_message_suppressed(PDO $db, int $owner, string $channel, string $number): bool {
    $q=$db->prepare('SELECT 1 FROM message_suppressions WHERE owner_user_id=? AND channel=? AND destination=? AND active=1');
    $q->execute([$owner,$channel,$number]); return (bool)$q->fetchColumn();
}

function bm_message_suppress(PDO $db, int $actor, int $owner, string $channel, string $number, string $reason = 'Opt out'): void {
    bm_message_authorize($db,$actor,$owner); bm_message_channel($channel);
    $number=bm_message_normalize_number($number); $reason=trim($reason);
    if ($reason==='' || mb_strlen($reason)>250) throw new RuntimeException('Enter a suppression reason of up to 250 characters.');
    $db->prepare('INSERT INTO message_suppressions(owner_user_id,channel,destination,reason,created_by_user_id) VALUES(?,?,?,?,?) ON CONFLICT(owner_user_id,channel,destination) DO UPDATE SET active=1,reason=excluded.reason,created_by_user_id=excluded.created_by_user_id,updated_at=CURRENT_TIMESTAMP')
        ->execute([$owner,$channel,$number,$reason,$actor]);
    bm_message_audit($db,$actor,$owner,'message_suppress','channel='.$channel.' destination_suffix='.substr($number,-4));
}

function bm_message_unsuppress(PDO $db, int $actor, int $owner, int $id): void {
    bm_message_authorize($db,$actor,$owner);
    $q=$db->prepare('UPDATE message_suppressions SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND owner_user_id=? AND active=1');
    $q->execute([$id,$owner]);
    if (!$q->rowCount()) throw new RuntimeException('The suppression was not found in this address book.');
    bm_message_audit($db,$actor,$owner,'message_unsuppress','suppression='.$id);
}

function bm_message_text(string $channel, string $text): string {
    bm_message_channel($channel);
    $text=trim(str_replace(["\r\n","\r"],"\n",$text));
    if (!mb_check_encoding($text,'UTF-8') || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/',$text)) throw new RuntimeException('The message contains unsupported characters.');
    $limit=$channel==='sms'?1600:4096;
    if ($text==='' || mb_strlen($text,'UTF-8')>$limit) throw new RuntimeException('Enter a message of between 1 and '.$limit.' characters.');
    return $text;
}

/** The preview is persisted server-side and must be explicitly confirmed with its token. */
function bm_message_preview(PDO $db, int $owner, string $channel, string $text, array $contactIds, array $groupIds, string $pastedNumbers, ?int $actor = null): array {
    $actor ??= (int)($_SESSION['user_id'] ?? 0);
    bm_message_authorize($db,$actor,$owner); bm_message_channel($channel);
    if (!bm_message_has_access($db,$owner,$channel)) throw new RuntimeException('This messaging channel is not enabled for this user.');
    $text=bm_message_text($channel,$text);
    $contactIds=array_values(array_unique(array_map('intval',$contactIds)));
    $groupIds=array_values(array_unique(array_map('intval',$groupIds)));
    if (count($contactIds)>1000 || count($groupIds)>1000 || strlen($pastedNumbers)>40000) throw new RuntimeException('Select at most 1,000 recipients per message.');
    $selected=[];
    if ($contactIds) {
        $q=$db->prepare('SELECT id contact_id,name,telephone FROM contacts WHERE owner_user_id=? AND active=1 AND id IN ('.implode(',',array_fill(0,count($contactIds),'?')).') ORDER BY id');
        $q->execute(array_merge([$owner],$contactIds)); $rows=$q->fetchAll(PDO::FETCH_ASSOC);
        if (count($rows)!==count($contactIds)) throw new RuntimeException('A selected contact is unavailable in this address book.');
        $selected=array_merge($selected,$rows);
    }
    if ($groupIds) {
        $q=$db->prepare('SELECT COUNT(*) FROM groups WHERE owner_user_id=? AND id IN ('.implode(',',array_fill(0,count($groupIds),'?')).')');
        $q->execute(array_merge([$owner],$groupIds));
        if ((int)$q->fetchColumn()!==count($groupIds)) throw new RuntimeException('A selected group is unavailable in this address book.');
        $q=$db->prepare('SELECT c.id contact_id,c.name,c.telephone FROM group_members gm JOIN groups g ON g.id=gm.group_id JOIN contacts c ON c.id=gm.contact_id WHERE g.owner_user_id=? AND c.owner_user_id=? AND c.active=1 AND gm.group_id IN ('.implode(',',array_fill(0,count($groupIds),'?')).') ORDER BY c.id,gm.group_id');
        $q->execute(array_merge([$owner,$owner],$groupIds)); $selected=array_merge($selected,$q->fetchAll(PDO::FETCH_ASSOC));
    }
    foreach (preg_split('/[\r\n,;]+/',$pastedNumbers) as $number) {
        if (trim($number)!=='') $selected[]=['contact_id'=>null,'name'=>'','telephone'=>trim($number)];
    }
    if (count($selected)>5000) throw new RuntimeException('The selected groups contain too many entries; choose a smaller batch.');
    $preview=['token'=>bin2hex(random_bytes(24)),'owner_user_id'=>$owner,'channel'=>$channel,'text'=>$text,'recipients'=>[],
        'selected_count'=>count($selected),'unique_count'=>0,'duplicate_count'=>0,'invalid_count'=>0,'suppressed_count'=>0,'invalid'=>[],
        'created_at'=>gmdate('Y-m-d H:i:s')];
    $seen=[];
    foreach ($selected as $row) {
        try { $number=bm_message_normalize_number((string)($row['telephone']??'')); }
        catch (RuntimeException $e) {
            $preview['invalid_count']++;
            $preview['invalid'][]=['name'=>(string)($row['name']??''),'value'=>(string)($row['telephone']??'')];
            continue;
        }
        if (isset($seen[$number])) { $preview['duplicate_count']++; continue; }
        $seen[$number]=true;
        if (bm_message_suppressed($db,$owner,$channel,$number)) { $preview['suppressed_count']++; continue; }
        $preview['recipients'][]=['contact_id'=>empty($row['contact_id'])?null:(int)$row['contact_id'],'name'=>(string)($row['name']??''),'destination'=>$number];
    }
    $preview['unique_count']=count($preview['recipients']);
    if (!$preview['unique_count']) throw new RuntimeException('No eligible mobile numbers remain after validation and suppressions.');
    if ($preview['unique_count']>1000) throw new RuntimeException('Select at most 1,000 recipients per message.');
    $db->prepare('INSERT INTO message_previews(token,actor_user_id,owner_user_id,preview_json,expires_at) VALUES(?,?,?,?,?)')
        ->execute([$preview['token'],$actor,$owner,json_encode($preview,JSON_THROW_ON_ERROR),gmdate('Y-m-d H:i:s',time()+1800)]);
    return $preview;
}

function bm_message_identity(PDO $db, int $id): array {
    if (function_exists('bm_identity_snapshot')) return bm_identity_snapshot($db,$id);
    $user=bm_message_user($db,$id);
    return ['user_id'=>$id,'username'=>$user['username'],'display_name'=>$user['display_name'],'ct400_id'=>null];
}

function bm_message_queue(PDO $db, int $actor, int $owner, array $preview, string $token): int {
    if (!preg_match('/^[a-f0-9]{48}$/D',$token)) throw new RuntimeException('The preview has expired; create a new preview.');
    $db->beginTransaction();
    try {
        // Acquire the SQLite writer lock before looking up/reusing an idempotency token.
        $db->prepare('UPDATE message_previews SET token=token WHERE token=?')->execute([$token]);
        bm_message_authorize($db,$actor,$owner);
        $q=$db->prepare('SELECT * FROM message_previews WHERE token=? AND actor_user_id=? AND owner_user_id=?');
        $q->execute([$token,$actor,$owner]); $saved=$q->fetch(PDO::FETCH_ASSOC);
        if (!$saved) throw new RuntimeException('The preview is not available to this user.');
        if ((int)$saved['campaign_id']>0) { $id=(int)$saved['campaign_id']; $db->commit(); return $id; }
        if ($saved['expires_at']<gmdate('Y-m-d H:i:s')) throw new RuntimeException('The preview has expired; create a new preview.');
        if (!hash_equals(hash('sha256',$saved['preview_json']),hash('sha256',json_encode($preview,JSON_THROW_ON_ERROR)))) throw new RuntimeException('The preview changed; create a new preview.');
        $p=json_decode($saved['preview_json'],true,512,JSON_THROW_ON_ERROR);
        $channel=bm_message_channel((string)$p['channel']);
        if (!bm_message_has_access($db,$owner,$channel)) throw new RuntimeException('This messaging channel is no longer enabled for this user.');
        $text=bm_message_text($channel,(string)$p['text']);
        foreach ($p['recipients'] as $recipient) {
            $number=bm_message_normalize_number($recipient['destination']);
            if (bm_message_suppressed($db,$owner,$channel,$number)) throw new RuntimeException('A recipient has been suppressed; create a new preview.');
            if ($recipient['contact_id']!==null) {
                $q=$db->prepare('SELECT telephone FROM contacts WHERE id=? AND owner_user_id=? AND active=1');
                $q->execute([$recipient['contact_id'],$owner]); $current=$q->fetchColumn();
                if ($current===false || bm_message_normalize_number((string)$current)!==$number) throw new RuntimeException('A selected contact changed; create a new preview.');
            }
        }
        $actorIdentity=bm_message_identity($db,$actor);
        $actorIdentity['authentication_method']=(string)($_SESSION['authentication_method']??$_SESSION['auth_method']??'local');
        $db->prepare('INSERT INTO message_campaigns(initiated_by_user_id,acting_for_user_id,channel,body_text,preview_token,actor_identity_json,owner_identity_json,selected_count,unique_count,duplicate_count,invalid_count,suppressed_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
            ->execute([$actor,$owner,$channel,$text,$token,json_encode($actorIdentity,JSON_THROW_ON_ERROR),json_encode(bm_message_identity($db,$owner),JSON_THROW_ON_ERROR),$p['selected_count'],count($p['recipients']),$p['duplicate_count'],$p['invalid_count'],$p['suppressed_count']]);
        $id=(int)$db->lastInsertId();
        $q=$db->prepare('INSERT INTO message_recipients(campaign_id,contact_id,destination,name,client_id) VALUES(?,?,?,?,?)');
        foreach ($p['recipients'] as $recipient) $q->execute([$id,$recipient['contact_id'],$recipient['destination'],$recipient['name'],'bm-'.bin2hex(random_bytes(16))]);
        $db->prepare('UPDATE message_previews SET campaign_id=? WHERE token=?')->execute([$id,$token]);
        bm_message_audit($db,$actor,$owner,'message_queue','campaign='.$id.' channel='.$channel.' recipients='.count($p['recipients']));
        $db->commit(); return $id;
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack(); throw $e;
    }
}

function bm_message_refresh_campaign(PDO $db, int $id): void {
    $q=$db->prepare('SELECT status,COUNT(*) count FROM message_recipients WHERE campaign_id=? GROUP BY status');
    $q->execute([$id]); $states=[];
    foreach ($q as $r) $states[$r['status']]=(int)$r['count'];
    if (!empty($states['queued'])) $status='queued';
    elseif (!empty($states['submitting']) || !empty($states['submitted'])) $status='processing';
    elseif (!empty($states['unknown']) || !empty($states['failed']) || !empty($states['blocked'])) $status='attention';
    elseif (count($states)===1 && isset($states['cancelled'])) $status='cancelled';
    else $status='complete';
    $db->prepare('UPDATE message_campaigns SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')->execute([$status,$id]);
}

function bm_message_cancel_campaign(PDO $db, int $actor, int $campaignId): int {
    $q=$db->prepare('SELECT acting_for_user_id FROM message_campaigns WHERE id=?'); $q->execute([$campaignId]);
    $owner=$q->fetchColumn();
    if ($owner===false) throw new RuntimeException('The message was not found.');
    bm_message_authorize($db,$actor,(int)$owner);
    $q=$db->prepare("UPDATE message_recipients SET status='cancelled',error='Cancelled before submission',updated_at=CURRENT_TIMESTAMP WHERE campaign_id=? AND status='queued'");
    $q->execute([$campaignId]); $count=$q->rowCount();
    bm_message_refresh_campaign($db,$campaignId);
    bm_message_audit($db,$actor,(int)$owner,'message_cancel','campaign='.$campaignId.' cancelled='.$count);
    return $count;
}

/** Injectable HTTP contract: fn(method,url,headers,?payload): {status:int,json:?array,error?:string}. */
function bm_message_http(string $method, string $url, array $headers, ?array $payload): array {
    if (!function_exists('curl_init')) return ['status'=>0,'json'=>null,'error'=>'transport_unavailable'];
    $handle=curl_init($url); $body=''; $tooLarge=false;
    curl_setopt_array($handle,[CURLOPT_CUSTOMREQUEST=>$method,CURLOPT_HTTPHEADER=>$headers,
        CURLOPT_FOLLOWLOCATION=>false,CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_TIMEOUT=>20,
        CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
        CURLOPT_PROTOCOLS=>CURLPROTO_HTTP|CURLPROTO_HTTPS,
        CURLOPT_WRITEFUNCTION=>static function ($curl,string $chunk) use (&$body,&$tooLarge): int {
            if (strlen($body)+strlen($chunk)>1048576) { $tooLarge=true; return 0; }
            $body.=$chunk; return strlen($chunk);
        }]);
    if ($payload!==null) curl_setopt($handle,CURLOPT_POSTFIELDS,json_encode($payload,JSON_THROW_ON_ERROR));
    $ok=curl_exec($handle); $status=(int)curl_getinfo($handle,CURLINFO_RESPONSE_CODE); curl_close($handle);
    if ($ok===false || $tooLarge) return ['status'=>0,'json'=>null,'error'=>'transport_error'];
    $json=json_decode($body,true);
    return ['status'=>$status,'json'=>is_array($json)?$json:null];
}

function bm_message_provider_request(string $channel, array $settings, array $recipient, string $text, bool $poll, ?callable $transport = null): array {
    bm_message_channel($channel);
    $base=bm_integration_url((string)($settings['base_url']??''),($settings['allow_http']??false)===true);
    $headers=['Accept: application/json','Content-Type: application/json'];
    if ($channel==='sms') {
        if ((string)($settings['username']??'')==='' || (string)($settings['password']??'')==='') throw new RuntimeException('SMS credentials are not configured.');
        $headers[]='Authorization: Basic '.base64_encode($settings['username'].':'.$settings['password']);
        $payload=['id'=>$recipient['client_id'],'textMessage'=>['text'=>$text],'phoneNumbers'=>[$recipient['destination']],
            'withDeliveryReport'=>true,'ttl'=>3600,'priority'=>0];
        if (isset($settings['sim_number'])) {
            $sim=(int)$settings['sim_number'];
            if ($sim<1 || $sim>3) throw new RuntimeException('The SMS SIM slot is not configured correctly.');
            $payload['simNumber']=$sim;
        }
    } else {
        $token=(string)($settings['token']??'');
        if (strlen($token)<32 || preg_match('/[\r\n]/',$token)) throw new RuntimeException('The WhatsApp gateway token is not configured.');
        $headers[]='Authorization: Bearer '.$token;
        $payload=['id'=>$recipient['client_id'],'to'=>$recipient['destination'],'text'=>$text];
    }
    $url=$base.'/messages'.($poll?'/'.rawurlencode($recipient['client_id']):'');
    $transport ??= 'bm_message_http';
    return $transport($poll?'GET':'POST',$url,$headers,$poll?null:$payload);
}

function bm_message_provider_state(string $channel, array $response, array $recipient): array {
    $json=$response['json']??null;
    if (!is_array($json) || (string)($json['id']??'')!==$recipient['client_id']) return ['status'=>'unknown','provider_id'=>null,'error'=>'Provider response could not be verified'];
    if ($channel==='sms') {
        $state=(string)($json['state']??'');
        // We send precisely one recipient; require its matching status before claiming delivery.
        $matched=null;
        foreach (($json['recipients']??[]) as $r) if (($r['phoneNumber']??null)===$recipient['destination']) $matched=$r;
        if ($matched!==null) $state=(string)($matched['state']??$state);
        $status=match($state) {
            'Pending','Processed','Sent','Cancelling'=>'submitted',
            'Delivered'=>$matched!==null?'delivered':'submitted',
            'Failed'=>'failed','Cancelled'=>'cancelled',default=>'unknown'
        };
        return ['status'=>$status,'provider_id'=>$json['id'],'error'=>$status==='failed'?'The SMS gateway reported failure':($status==='unknown'?'SMS delivery status is not recognised':null)];
    }
    $status=match((string)($json['status']??'')) {
        'queued','sending','submitted'=>'submitted',
        'delivered'=>'delivered','read'=>'read','failed'=>'failed','unknown'=>'unknown',default=>'unknown'
    };
    $providerId=is_string($json['provider_id']??null)?$json['provider_id']:null;
    if ($providerId!==null && (strlen($providerId)>200 || preg_match('/[\x00-\x1f]/',$providerId))) $providerId=null;
    return ['status'=>$status,'provider_id'=>$providerId,'error'=>in_array($status,['failed','unknown'],true)?'The WhatsApp gateway could not confirm submission':null];
}

function bm_message_store_state(PDO $db, array $recipient, array $state, int $pollDelay = 30): void {
    $status=$state['status'];
    // A late or stale status must never move a confirmed delivery backwards.
    if ($recipient['status']==='read') $status='read';
    elseif ($recipient['status']==='delivered' && $status!=='read') $status='delivered';
    $submitted=in_array($status,['submitted','delivered','read'],true)?gmdate('Y-m-d H:i:s'):null;
    $delivered=in_array($status,['delivered','read'],true)?gmdate('Y-m-d H:i:s'):null;
    $needsPoll=in_array($status,['submitted','unknown'],true) || ($status==='delivered' && ($recipient['channel']??'')==='whatsapp');
    $next=$needsPoll?gmdate('Y-m-d H:i:s',time()+$pollDelay):null;
    $q=$db->prepare('UPDATE message_recipients SET status=?,provider_id=COALESCE(?,provider_id),error=?,submitted_at=COALESCE(submitted_at,?),delivered_at=COALESCE(delivered_at,?),updated_at=CURRENT_TIMESTAMP,last_checked_at=CURRENT_TIMESTAMP,next_attempt_at=? WHERE id=?');
    $q->execute([$status,$state['provider_id']??null,$state['error']??null,$submitted,$delivered,$next,$recipient['id']]);
    bm_message_refresh_campaign($db,(int)$recipient['campaign_id']);
}

/** Fixed daemon diagnostics are emitted on change and at most once a minute while unchanged. */
function bm_message_diagnostic_due(array $errors, array &$state, int $now): bool {
    $errors=array_values(array_unique($errors)); sort($errors,SORT_STRING);
    $signature=implode("\n",$errors);
    $previous=(string)($state['signature']??'');
    if ($signature!==$previous || ($errors && $now-(int)($state['last_logged_at']??0)>=60)) {
        $state=['signature'=>$signature,'last_logged_at'=>$now];
        return true;
    }
    return false;
}

/** One bounded pass: at most one status lookup and one new submission per enabled channel. */
function bm_message_process_once(PDO $db, array $config, ?callable $transport = null): array {
    $result=['attempted'=>0,'reconciled'=>0,'blocked'=>0,'errors'=>[]];
    foreach (['sms','whatsapp'] as $channel) {
        $settings=$config[$channel]??[];
        if (($settings['enabled']??false)!==true) continue;
        // Reconcile interrupted submissions and provider accepts; never turn these back into queued.
        $q=$db->prepare("SELECT r.*,c.body_text,c.channel FROM message_recipients r JOIN message_campaigns c ON c.id=r.campaign_id WHERE c.channel=? AND (((r.status IN ('submitted','unknown') OR (r.status='delivered' AND c.channel='whatsapp' AND r.delivered_at>=datetime('now','-1 day'))) AND (r.next_attempt_at IS NULL OR r.next_attempt_at<=CURRENT_TIMESTAMP)) OR (r.status='submitting' AND r.updated_at<=datetime('now','-60 seconds'))) ORDER BY COALESCE(r.last_checked_at,'') ASC,r.id LIMIT 1");
        $q->execute([$channel]); $recipient=$q->fetch(PDO::FETCH_ASSOC);
        if ($recipient) {
            try {
                $response=bm_message_provider_request($channel,$settings,$recipient,$recipient['body_text'],true,$transport);
                $http=(int)($response['status']??0);
                if ($http>=200 && $http<300) $state=bm_message_provider_state($channel,$response,$recipient);
                else $state=['status'=>$recipient['status']==='submitted'?'submitted':'unknown','error'=>$http===404?'Provider has no confirmed record; do not resend automatically':'Provider status is temporarily unavailable'];
                bm_message_store_state($db,$recipient,$state,($http>=200 && $http<300)?30:300); $result['reconciled']++;
            } catch (Throwable $e) { $result['errors'][]=$channel.': status check unavailable'; }
        }

        // Validate configuration before claiming; a configuration fault cannot make a queued item ambiguous.
        try {
            bm_message_provider_request($channel,$settings,['client_id'=>'configuration-check','destination'=>'+447700900000'],'',true,
                static fn()=>['status'=>200,'json'=>[]]);
        } catch (Throwable $e) { $result['errors'][]=$channel.': configuration incomplete'; continue; }

        $db->beginTransaction();
        try {
            $db->prepare('INSERT INTO message_channel_state(channel) VALUES(?) ON CONFLICT(channel) DO UPDATE SET channel=excluded.channel')->execute([$channel]);
            $q=$db->prepare('SELECT last_submit_epoch FROM message_channel_state WHERE channel=?');$q->execute([$channel]);
            $last=(int)$q->fetchColumn(); $interval=max(1,min(3600,(int)($settings['min_interval_seconds']??8)));
            if (time()-$last<$interval) { $db->commit(); continue; }
            $q=$db->prepare("SELECT r.*,c.body_text,c.channel,c.initiated_by_user_id,c.acting_for_user_id FROM message_recipients r JOIN message_campaigns c ON c.id=r.campaign_id WHERE c.channel=? AND r.status='queued' AND (r.next_attempt_at IS NULL OR r.next_attempt_at<=CURRENT_TIMESTAMP) ORDER BY r.id LIMIT 1");
            $q->execute([$channel]); $recipient=$q->fetch(PDO::FETCH_ASSOC);
            if (!$recipient) { $db->commit(); continue; }
            $blocked=null;
            try {
                bm_message_authorize($db,(int)$recipient['initiated_by_user_id'],(int)$recipient['acting_for_user_id']);
                if (!bm_message_has_access($db,(int)$recipient['acting_for_user_id'],$channel,$config)) $blocked='Channel permission was removed';
                elseif (bm_message_suppressed($db,(int)$recipient['acting_for_user_id'],$channel,$recipient['destination'])) $blocked='Recipient was suppressed before submission';
                elseif ($recipient['contact_id']!==null) {
                    $q=$db->prepare('SELECT telephone FROM contacts WHERE id=? AND owner_user_id=? AND active=1');
                    $q->execute([$recipient['contact_id'],$recipient['acting_for_user_id']]); $number=$q->fetchColumn();
                    if ($number===false || bm_message_normalize_number((string)$number)!==$recipient['destination']) $blocked='Contact changed before submission';
                }
            } catch (Throwable $e) { $blocked='User or recipient is no longer authorised'; }
            if ($blocked!==null) {
                $db->prepare("UPDATE message_recipients SET status='blocked',error=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='queued'")->execute([$blocked,$recipient['id']]);
                bm_message_refresh_campaign($db,(int)$recipient['campaign_id']); $db->commit(); $result['blocked']++; continue;
            }
            $db->prepare("UPDATE message_recipients SET status='submitting',attempts=attempts+1,updated_at=CURRENT_TIMESTAMP,next_attempt_at=NULL,error=NULL WHERE id=? AND status='queued'")->execute([$recipient['id']]);
            $db->prepare('UPDATE message_channel_state SET last_submit_epoch=? WHERE channel=?')->execute([time(),$channel]);
            bm_message_refresh_campaign($db,(int)$recipient['campaign_id']); $db->commit();
        } catch (Throwable $e) { if ($db->inTransaction()) $db->rollBack(); throw $e; }

        $result['attempted']++;
        try {
            $response=bm_message_provider_request($channel,$settings,$recipient,$recipient['body_text'],false,$transport);
            $http=(int)($response['status']??0);
            if ($http>=200 && $http<300) $state=bm_message_provider_state($channel,$response,$recipient);
            elseif ($channel==='whatsapp' && (
                ($http===429 && ($response['json']['error']??null)==='gateway_busy')
                || ($http===503 && in_array($response['json']['error']??null,['sending_disabled','not_connected'],true))
            )) {
                // Our local Baileys bridge guarantees these exact errors occur before journal reservation.
                // Generic HTTP 429/503 (including SMSGate) remains ambiguous and is never blindly retried.
                $db->prepare("UPDATE message_recipients SET status='queued',error='Gateway busy; waiting before retry',next_attempt_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='submitting'")
                    ->execute([gmdate('Y-m-d H:i:s',time()+60),$recipient['id']]);
                bm_message_refresh_campaign($db,(int)$recipient['campaign_id']); continue;
            } elseif ($channel==='whatsapp' && $http===409 && ($response['json']['error']??null)==='id_conflict') {
                // The existing journal entry belongs to DIFFERENT content. Never poll/adopt its outcome.
                $state=['status'=>'failed','error'=>'WhatsApp message ID conflicts with a different request; administrator review required'];
            } elseif (in_array($http,[400,401,403,404,405,413,415,422],true)) $state=['status'=>'failed','error'=>'Gateway rejected the request (HTTP '.$http.')'];
            else $state=['status'=>'unknown','error'=>'Submission could not be confirmed; status will be checked without resending'];
        } catch (Throwable $e) { $state=['status'=>'unknown','error'=>'Submission could not be confirmed; status will be checked without resending']; }
        bm_message_store_state($db,$recipient,$state);
    }
    return $result;
}
