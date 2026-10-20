<?php
declare(strict_types=1);
/* Reliability repair, 2026-10-16. No delivery or SMTP calls in this module. */
function bulkmail_reliability_schema(PDO $db): void {
    $db->exec('CREATE TABLE IF NOT EXISTS compose_draft_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        acting_for_user_id INTEGER NOT NULL, subject TEXT NOT NULL,
        snapshot_json TEXT NOT NULL, reason TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE INDEX IF NOT EXISTS draft_versions_user ON compose_draft_versions(user_id,id)');
    $db->exec('CREATE TABLE IF NOT EXISTS prepared_compose_drafts (
        user_id INTEGER NOT NULL, acting_for_user_id INTEGER NOT NULL,
        token TEXT NOT NULL, draft_json TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id,acting_for_user_id))');
}
function bulkmail_archive_draft(PDO $db,int $uid,int $owner,string $reason): void {
    bulkmail_reliability_schema($db);
    $s=$db->prepare('SELECT * FROM compose_drafts WHERE user_id=? AND acting_for_user_id=?');
    $s->execute([$uid,$owner]);$row=$s->fetch();
    if(!$row || (trim($row['subject'])==='' && trim(strip_tags($row['body_html']))==='')) return;
    $json=json_encode($row,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    $s=$db->prepare('SELECT snapshot_json FROM compose_draft_versions WHERE user_id=? AND acting_for_user_id=? ORDER BY id DESC LIMIT 1');
    $s->execute([$uid,$owner]);$last=json_decode((string)($s->fetchColumn()?:'{}'),true);
    $compare=$row;unset($compare['updated_at']);if(is_array($last))unset($last['updated_at']);
    if($compare===$last)return;
    $db->prepare('INSERT INTO compose_draft_versions(user_id,acting_for_user_id,subject,snapshot_json,reason) VALUES(?,?,?,?,?)')
       ->execute([$uid,$owner,$row['subject'],$json,$reason]);
}
function bulkmail_store_compose_fields(PDO $db,int $uid,int $owner,array $f): void {
    bulkmail_ensure_draft_table($db);
    bulkmail_archive_draft($db,$uid,$owner,'Before editing');
    $groups=$f['groups']??[];$contacts=$f['contacts']??[];
    if(!is_array($groups))$groups=[];if(!is_array($contacts))$contacts=[];
    $body=(string)($f['body_html']??'');
    if(trim($body)==='' && !empty($f['body_text_fallback']))$body='<p>'.nl2br(h((string)$f['body_text_fallback']),false).'</p>';
    $db->prepare('INSERT INTO compose_drafts(user_id,acting_for_user_id,sender_identity_id,custom_from,subject,body_html,all_contacts,groups_json,contacts_json,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,acting_for_user_id) DO UPDATE SET
      sender_identity_id=excluded.sender_identity_id,custom_from=excluded.custom_from,subject=excluded.subject,
      body_html=excluded.body_html,all_contacts=excluded.all_contacts,groups_json=excluded.groups_json,
      contacts_json=excluded.contacts_json,updated_at=CURRENT_TIMESTAMP')
      ->execute([$uid,$owner,(int)($f['sender_identity_id']??0)?:null,trim((string)($f['custom_from']??'')),
        trim((string)($f['subject']??'')),sanitize_html($body),!empty($f['all_contacts'])?1:0,
        json_encode(array_values(array_unique(array_map('intval',$groups)))),
        json_encode(array_values(array_unique(array_map('intval',$contacts))))]);
    bulkmail_archive_draft($db,$uid,$owner,'Autosaved');
}
function bulkmail_save_prepared(PDO $db,array $d): void {
    bulkmail_reliability_schema($db);
    $db->prepare('INSERT INTO prepared_compose_drafts(user_id,acting_for_user_id,token,draft_json) VALUES(?,?,?,?)
      ON CONFLICT(user_id,acting_for_user_id) DO UPDATE SET token=excluded.token,draft_json=excluded.draft_json,updated_at=CURRENT_TIMESTAMP')
      ->execute([(int)$_SESSION['user_id'],(int)$d['acting_for'],$d['token'],json_encode($d,JSON_THROW_ON_ERROR)]);
}
function bulkmail_restore_prepared(PDO $db,int $owner): void {
    if(!empty($_SESSION['draft']))return;
    bulkmail_reliability_schema($db);
    $s=$db->prepare('SELECT draft_json FROM prepared_compose_drafts WHERE user_id=? AND acting_for_user_id=?');
    $s->execute([(int)$_SESSION['user_id'],$owner]);$json=$s->fetchColumn();
    if($json){$d=json_decode((string)$json,true);if(is_array($d)&&!empty($d['token']))$_SESSION['draft']=$d;}
}
function bulkmail_forget_prepared(PDO $db,int $owner): void {
    $db->prepare('DELETE FROM prepared_compose_drafts WHERE user_id=? AND acting_for_user_id=?')->execute([(int)$_SESSION['user_id'],$owner]);
}
function bulkmail_status_label(string $status): string {
    return ['queued'=>'Queued — not sent yet','submitting'=>'Sending to mail server',
      'submitted'=>'Sent to delivery service','postfix'=>'Sent to delivery service',
      'processing'=>'Being submitted','failed'=>'Failed — needs attention','partial'=>'Some recipients failed'][$status]??$status;
}
bulkmail_reliability_schema($db);
require_once __DIR__.'/bulkmail-full-drafts.php';
if($page==='draft_recovery') {
    $uid=(int)$_SESSION['user_id'];
    if($_SERVER['REQUEST_METHOD']==='POST'){
        check_csrf();$s=$db->prepare('SELECT * FROM compose_draft_versions WHERE id=? AND user_id=?');
        $s->execute([(int)($_POST['id']??0),$uid]);$v=$s->fetch();
        if(!$v){http_response_code(404);exit('Draft not found');}
        $owner=(int)$v['acting_for_user_id'];allowed_context($db,$owner);
        if($uid===2 && $owner!==2){flash('This older draft belongs to another address book. Ask an administrator to recover it.','error');redirect('?page=draft_recovery');}
        $d=json_decode($v['snapshot_json'],true,512,JSON_THROW_ON_ERROR);
        $d['groups']=json_decode($d['groups_json'],true)?:[];$d['contacts']=json_decode($d['contacts_json'],true)?:[];
        bm_preserve_workspace($db,$uid,$owner);bulkmail_store_compose_fields($db,$uid,$owner,$d);
        bm_end_workspace($db,$uid,$owner,true);bulkmail_forget_prepared($db,$owner);unset($_SESSION['draft']);flash('Earlier text version restored. Files were not part of this old recovery snapshot. Nothing was sent.');
        redirect('?page=compose&acting_for='.$owner);
    }
    layout_start('Saved Drafts');echo '<h1>Earlier autosaved text versions</h1><p>These older text-only recovery versions do not contain files. Use Saved Drafts for complete emails with attachments.</p><div class="card"><table><tr><th>Saved (UTC)</th><th>Subject</th><th>Reason</th><th></th></tr>';
    $s=$db->prepare('SELECT id,subject,reason,created_at FROM compose_draft_versions WHERE user_id=? ORDER BY id DESC LIMIT 100');$s->execute([$uid]);
    foreach($s as $r)echo '<tr><td>'.h($r['created_at']).'</td><td>'.h($r['subject']).'</td><td>'.h($r['reason']).'</td><td><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="id" value="'.(int)$r['id'].'"><button>Restore draft</button></form></td></tr>';
    echo '</table></div>';layout_end();exit;
}
if(in_array($page,['mailing_view','mailing_file'],true)){
    $s=$db->prepare('SELECT * FROM mailings WHERE id=?');$s->execute([(int)($_GET['id']??0)]);$m=$s->fetch();
    if(!$m){http_response_code(404);exit('Mailing not found');}allowed_context($db,(int)$m['acting_for_user_id']);
    if($page==='mailing_file'){
        $kind=(string)($_GET['kind']??'attachment');$fid=(int)($_GET['file']??0);
        if($kind==='asset'){$s=$db->prepare('SELECT stored_path,mime_type,"image.jpg" original_name FROM mailing_assets WHERE id=? AND mailing_id=?');}
        elseif($kind==='individual'){$s=$db->prepare('SELECT a.stored_path,a.mime_type,a.original_name FROM mailing_recipient_attachments a JOIN mailing_recipients r ON r.id=a.mailing_recipient_id WHERE a.id=? AND r.mailing_id=?');}
        else{$s=$db->prepare('SELECT stored_path,mime_type,original_name FROM mailing_attachments WHERE id=? AND mailing_id=?');}
        $s->execute([$fid,(int)$m['id']]);$a=$s->fetch();$path=$a?realpath($a['stored_path']):false;$root=realpath(DATA_DIR.'/mailings');
        if(!$path||!$root||!str_starts_with($path,$root.'/')||!is_file($path)){http_response_code(404);exit('File not found');}
        header('Content-Type: '.($kind==='asset'?'image/jpeg':'application/octet-stream'));
        header('X-Content-Type-Options: nosniff');header('Cache-Control: private, no-store');
        if($kind!=='asset')header("Content-Disposition: attachment; filename*=UTF-8''".rawurlencode(basename($a['original_name'])));
        readfile($path);exit;
    }
    layout_start('Sent email');echo '<h1>'.h($m['subject']).'</h1><div class="card"><p><b>From:</b> '.h($m['sender_email']).'<br><b>Recorded:</b> '.h($m['created_at']).' UTC<br><b>Status:</b> '.h(bulkmail_status_label($m['status'])).'</p><p class="small">A mail-server handoff is not proof of inbox placement or reading. A separate filing task also saves one campaign copy in the sender’s mailbox Sent folder.</p>';
    echo '<p><b>Mailbox Sent folder:</b> '.h(bm_sent_copy_label($db,(int)$m['id'])).'</p>';
    $body=$m['body_html'];$s=$db->prepare('SELECT id,cid FROM mailing_assets WHERE mailing_id=?');$s->execute([(int)$m['id']]);
    foreach($s as $a)$body=str_replace('cid:'.$a['cid'],'?page=mailing_file&amp;kind=asset&amp;id='.(int)$m['id'].'&amp;file='.(int)$a['id'],$body);
    echo '<iframe title="Saved email" sandbox="allow-same-origin" style="width:100%;height:430px;border:1px solid #aaa" srcdoc="'.h('<html><head><link rel="stylesheet" href="/bulkmail-fonts.css?v=20261016r2"></head><body>'.$body.'</body></html>').'"></iframe>';
    $s=$db->prepare('SELECT id,original_name FROM mailing_attachments WHERE mailing_id=?');$s->execute([(int)$m['id']]);
    foreach($s as $a)echo '<p><a href="?page=mailing_file&amp;id='.(int)$m['id'].'&amp;file='.(int)$a['id'].'">'.h($a['original_name']).'</a></p>';
    echo '<h2>Recipients</h2><table><tr><th>Name / address</th><th>Status</th><th>Error</th></tr>';
    $s=$db->prepare('SELECT name,email,status,error FROM mailing_recipients WHERE mailing_id=? ORDER BY id');$s->execute([(int)$m['id']]);
    foreach($s as $r)echo '<tr><td>'.h($r['name']).' &lt;'.h($r['email']).'&gt;</td><td>'.h(bulkmail_status_label($r['status'])).'</td><td>'.h($r['error']).'</td></tr>';
    echo '</table><p><a class="button secondary" href="?page=history">Back to sent history</a></p></div>';layout_end();exit;
}
