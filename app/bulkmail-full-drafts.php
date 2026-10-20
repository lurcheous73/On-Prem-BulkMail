<?php
declare(strict_types=1);
/* Complete drafts: reusable snapshots with retained shared, individual and document files. */
function bm_full_schema(PDO $db): void {
    $db->exec('CREATE TABLE IF NOT EXISTS mailing_send_tokens (user_id INTEGER NOT NULL,draft_token TEXT NOT NULL,mailing_id INTEGER NOT NULL,PRIMARY KEY(user_id,draft_token))');
    $db->exec('CREATE TABLE IF NOT EXISTS compose_file_store (
      token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,
      kind TEXT NOT NULL,contact_id INTEGER NOT NULL DEFAULT 0,original_name TEXT NOT NULL,
      stored_path TEXT NOT NULL,mime_type TEXT NOT NULL,file_size INTEGER NOT NULL,extension TEXT NOT NULL,
      sha256 TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS compose_file_selection (
      user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,token TEXT NOT NULL,
      PRIMARY KEY(user_id,acting_for_user_id,token))');
    $db->exec('CREATE TABLE IF NOT EXISTS mail_saved_drafts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,
      title TEXT NOT NULL,snapshot_json TEXT NOT NULL,files_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS compose_workspaces (
      user_id INTEGER NOT NULL,acting_for_user_id INTEGER NOT NULL,workspace_token TEXT NOT NULL,
      saved_draft_id INTEGER,PRIMARY KEY(user_id,acting_for_user_id))');
    $db->exec('CREATE TABLE IF NOT EXISTS sent_mailbox_copies (
      mailing_id INTEGER PRIMARY KEY,message_key TEXT NOT NULL,status TEXT NOT NULL DEFAULT "pending",
      attempts INTEGER NOT NULL DEFAULT 0,error TEXT,filed_at TEXT,next_attempt_at TEXT,
      archive_path TEXT,mailbox TEXT NOT NULL DEFAULT "Sent")');
}
function bm_workspace(PDO $db,int $uid,int $owner): array {
    $db->prepare('INSERT OR IGNORE INTO compose_workspaces(user_id,acting_for_user_id,workspace_token) VALUES(?,?,?)')->execute([$uid,$owner,bin2hex(random_bytes(16))]);
    $s=$db->prepare('SELECT * FROM compose_workspaces WHERE user_id=? AND acting_for_user_id=?');$s->execute([$uid,$owner]);return $s->fetch();
}
function bm_check_workspace(PDO $db,int $uid,int $owner): void {
    $w=bm_workspace($db,$uid,$owner);
    if(isset($_POST['workspace_token']) && !hash_equals($w['workspace_token'],(string)$_POST['workspace_token'])){
        http_response_code(409);exit('This draft was changed in another tab. Your other saved drafts are safe. Open Saved Drafts to continue.');
    }
}
function bm_files(PDO $db,int $uid,int $owner): array {
    $s=$db->prepare('SELECT f.* FROM compose_file_store f JOIN compose_file_selection s ON s.token=f.token WHERE s.user_id=? AND s.acting_for_user_id=? AND f.user_id=s.user_id AND f.acting_for_user_id=s.acting_for_user_id ORDER BY f.created_at,f.token');$s->execute([$uid,$owner]);return $s->fetchAll();
}
function bm_register_file(PDO $db,int $uid,int $owner,string $kind,int $cid,array $u): string {
    $hash=hash_file('sha256',$u['stored_path']);if($hash===false)throw new RuntimeException('Could not verify attachment');
    $q=$db->prepare('SELECT token FROM compose_file_store WHERE user_id=? AND acting_for_user_id=? AND kind=? AND contact_id=? AND original_name=? AND sha256=? LIMIT 1');
    $q->execute([$uid,$owner,$kind,$cid,$u['original_name'],$hash]);$token=$q->fetchColumn();
    if(!$token){$token=bin2hex(random_bytes(20));$db->prepare('INSERT INTO compose_file_store(token,user_id,acting_for_user_id,kind,contact_id,original_name,stored_path,mime_type,file_size,extension,sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?)')->execute([$token,$uid,$owner,$kind,$cid,$u['original_name'],$u['stored_path'],$u['mime_type'],(int)$u['file_size'],$u['extension']??strtolower(pathinfo($u['original_name'],PATHINFO_EXTENSION)),$hash]);}
    $db->prepare('INSERT OR IGNORE INTO compose_file_selection(user_id,acting_for_user_id,token) VALUES(?,?,?)')->execute([$uid,$owner,$token]);return (string)$token;
}
function bm_import_previous_files(PDO $db,int $uid,int $owner,bool $force=false): void {
    // Import a pre-upgrade prepared preview once, copying files away from its disposable directory.
    $w=bm_workspace($db,$uid,$owner);$marker=DATA_DIR.'/compose-files/'.$uid.'/'.$owner.'/.imported';
    if(is_file($marker)&&!$force)return;
    $s=$db->prepare('SELECT draft_json FROM prepared_compose_drafts WHERE user_id=? AND acting_for_user_id=?');$s->execute([$uid,$owner]);$d=json_decode((string)($s->fetchColumn()?:'{}'),true);
    $rows=[];foreach($d['attachments']??[] as $u)$rows[]=['shared',0,$u];
    foreach($d['recipient_attachments']??[] as $cid=>$aa)foreach($aa as $u)$rows[]=['individual',(int)$cid,$u];
    $dir=dirname($marker);if(!is_dir($dir)&&!mkdir($dir,0750,true))throw new RuntimeException('Could not create retained attachment directory');
    foreach($rows as [$kind,$cid,$u]){
        $path=realpath((string)$u['stored_path']);$root=realpath(DATA_DIR.'/drafts');
        if(!$path||!$root||!str_starts_with($path,$root.'/')||!is_file($path))continue;
        $dest=$dir.'/'.bin2hex(random_bytes(16)).'-'.safe_name($u['original_name']);if(!copy($path,$dest))throw new RuntimeException('Could not retain previous attachment');chmod($dest,0640);$u['stored_path']=$dest;bm_register_file($db,$uid,$owner,$kind,$cid,$u);
    }
    file_put_contents($marker,'Imported '.gmdate(DATE_ATOM));chmod($marker,0640);
}
function bm_validate_file_totals(array $files): void {
    $shared=0;$personal=[];
    foreach($files as $f){$size=(int)$f['file_size'];if($f['kind']==='shared')$shared+=$size;elseif($f['kind']==='individual')$personal[(int)$f['contact_id']]=($personal[(int)$f['contact_id']]??0)+$size;}
    if($shared>=MAX_ATTACHMENT_TOTAL_BYTES)throw new RuntimeException('Shared attachments together must be less than 15 MB.');
    foreach($personal as $size)if($shared+$size>=MAX_ATTACHMENT_TOTAL_BYTES)throw new RuntimeException('Shared plus individual files for one recipient must be less than 15 MB.');
}
function bm_persist_files(PDO $db,int $uid,int $owner): void {
    bm_check_workspace($db,$uid,$owner);bm_import_previous_files($db,$uid,$owner);
    $uploads=[];
    if(isset($_FILES['attachments']['name'])&&is_array($_FILES['attachments']['name']))foreach($_FILES['attachments']['name'] as $i=>$n){$f=[];foreach(['name','type','tmp_name','error','size'] as $k)$f[$k]=$_FILES['attachments'][$k][$i]??null;$uploads[]=['shared',0,$f];}
    if(isset($_FILES['recipient_attachments']['name'])&&is_array($_FILES['recipient_attachments']['name']))foreach($_FILES['recipient_attachments']['name'] as $cid=>$names){
        $q=$db->prepare('SELECT 1 FROM contacts WHERE id=? AND owner_user_id=?');$q->execute([(int)$cid,$owner]);if(!$q->fetchColumn())continue;
        foreach((array)$names as $i=>$n){$f=[];foreach(['name','type','tmp_name','error','size'] as $k)$f[$k]=$_FILES['recipient_attachments'][$k][$cid][$i]??null;$uploads[]=['individual',(int)$cid,$f];}
    }
    if(isset($_FILES['document_email']))$uploads[]=['document',0,$_FILES['document_email']];
    $removes=array_values(array_filter((array)($_POST['remove_file']??[]),'is_string'));
    $created=[];$db->beginTransaction();
    try{
        foreach($removes as $t)$db->prepare('DELETE FROM compose_file_selection WHERE user_id=? AND acting_for_user_id=? AND token=?')->execute([$uid,$owner,$t]);
        foreach($uploads as [$kind,$cid,$f]){
            if(($f['error']??UPLOAD_ERR_NO_FILE)===UPLOAD_ERR_NO_FILE)continue;
            if(($f['error']??-1)!==UPLOAD_ERR_OK)throw new RuntimeException('File upload failed: '.safe_name((string)($f['name']??'attachment')).'. Please select that file again.');
            $ext=$kind==='document'?['pdf','doc','docx','odt']:['pdf','doc','docx','odt','xls','xlsx','csv','txt','jpg','jpeg','png'];
            $u=store_upload($f,DATA_DIR.'/compose-files/'.$uid.'/'.$owner,$ext,$kind==='document'?MAX_DOCUMENT_BYTES:MAX_ATTACHMENT_BYTES);$created[]=$u['stored_path'];
            if($kind==='document')$db->prepare('DELETE FROM compose_file_selection WHERE user_id=? AND acting_for_user_id=? AND token IN (SELECT token FROM compose_file_store WHERE kind="document")')->execute([$uid,$owner]);
            bm_register_file($db,$uid,$owner,$kind,$cid,$u);
        }
        bm_validate_file_totals(bm_files($db,$uid,$owner));$db->commit();
    }catch(Throwable $e){if($db->inTransaction())$db->rollBack();foreach($created as $p)if(is_file($p))unlink($p);throw $e;}
}
function bm_saved_snapshot(PDO $db,int $uid,int $owner): int {
    $q=$db->prepare('SELECT * FROM compose_drafts WHERE user_id=? AND acting_for_user_id=?');$q->execute([$uid,$owner]);$d=$q->fetch();if(!$d)throw new RuntimeException('No current draft to save.');
    $w=bm_workspace($db,$uid,$owner);$files=array_column(bm_files($db,$uid,$owner),'token');$title=trim($d['subject'])?:'Untitled draft';$json=json_encode($d,JSON_THROW_ON_ERROR);$fj=json_encode($files,JSON_THROW_ON_ERROR);
    $q=$db->prepare('UPDATE mail_saved_drafts SET title=?,snapshot_json=?,files_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND acting_for_user_id=?');$q->execute([$title,$json,$fj,(int)($w['saved_draft_id']??0),$uid,$owner]);
    if($q->rowCount()){return (int)$w['saved_draft_id'];}
    $db->prepare('INSERT INTO mail_saved_drafts(user_id,acting_for_user_id,title,snapshot_json,files_json) VALUES(?,?,?,?,?)')->execute([$uid,$owner,$title,$json,$fj]);$id=(int)$db->lastInsertId();
    $db->prepare('UPDATE compose_workspaces SET saved_draft_id=? WHERE user_id=? AND acting_for_user_id=?')->execute([$id,$uid,$owner]);return $id;
}
function bm_preserve_workspace(PDO $db,int $uid,int $owner): void {
    $q=$db->prepare('SELECT subject,body_html FROM compose_drafts WHERE user_id=? AND acting_for_user_id=?');$q->execute([$uid,$owner]);$d=$q->fetch();
    if($d && (trim($d['subject'])!=='' || trim(strip_tags($d['body_html']))!=='' || bm_files($db,$uid,$owner)))bm_saved_snapshot($db,$uid,$owner);
}
function bm_seed_reused_draft(PDO $db,array $m,array $d): void {
    $uid=(int)$_SESSION['user_id'];$owner=(int)$d['acting_for'];
    bm_preserve_workspace($db,$uid,$owner);bm_end_workspace($db,$uid,$owner,true);
    $body=(string)$m['body_html'];$footer=footer_html($db,$owner);if($footer!==''&&str_ends_with($body,$footer))$body=substr($body,0,-strlen($footer));
    $dir=DATA_DIR.'/compose-files/'.$uid.'/'.$owner.'/images';if(!is_dir($dir)&&!mkdir($dir,0750,true))throw new RuntimeException('Could not retain reused images');
    foreach($d['assets'] as $a){
        $token=bin2hex(random_bytes(20));$dest=$dir.'/'.$token.'.jpg';if(!copy($a['path'],$dest))throw new RuntimeException('Could not retain reused image');chmod($dest,0640);
        $db->prepare('INSERT INTO editor_images(token,owner_user_id,uploaded_by_user_id,original_name,stored_path,mime_type,file_size) VALUES(?,?,?,?,?,?,?)')->execute([$token,$owner,$uid,'Reused image.jpg',$dest,'image/jpeg',filesize($dest)]);
        $body=str_replace('cid:'.$a['cid'],'?page=editor_image&amp;token='.$token,$body);
    }
    $ids=array_values(array_filter(array_map(static fn($r)=>(int)($r['id']??0),$d['recipients'])));
    bulkmail_store_compose_fields($db,$uid,$owner,['subject'=>$d['subject'],'body_html'=>$body,'sender_identity_id'=>$d['sender_id'],'contacts'=>$ids,'groups'=>[]]);
    bulkmail_save_prepared($db,$d);bm_import_previous_files($db,$uid,$owner,true);
}
function bm_restore_snapshot(PDO $db,int $uid,int $id): int {
    $q=$db->prepare('SELECT * FROM mail_saved_drafts WHERE id=? AND user_id=?');$q->execute([$id,$uid]);$row=$q->fetch();if(!$row)throw new RuntimeException('Saved draft not found.');
    $owner=(int)$row['acting_for_user_id'];allowed_context($db,$owner);if($uid===2&&$owner!==2)throw new RuntimeException('This draft uses a different address book.');
    bm_preserve_workspace($db,$uid,$owner);
    $q=$db->prepare('SELECT * FROM mail_saved_drafts WHERE id=? AND user_id=?');$q->execute([$id,$uid]);$row=$q->fetch();
    $d=json_decode($row['snapshot_json'],true,512,JSON_THROW_ON_ERROR);$d['groups']=json_decode($d['groups_json'],true)?:[];$d['contacts']=json_decode($d['contacts_json'],true)?:[];
    $files=json_decode($row['files_json'],true,512,JSON_THROW_ON_ERROR);
    // Validate every saved file before changing the working draft.
    foreach($files as $t){$q=$db->prepare('SELECT stored_path FROM compose_file_store WHERE token=? AND user_id=? AND acting_for_user_id=?');$q->execute([$t,$uid,$owner]);$path=$q->fetchColumn();if(!$path||!is_file($path))throw new RuntimeException('A saved attachment is unavailable. The current draft has not been changed.');}
    bulkmail_store_compose_fields($db,$uid,$owner,$d);$db->beginTransaction();
    try{
        $db->prepare('DELETE FROM compose_file_selection WHERE user_id=? AND acting_for_user_id=?')->execute([$uid,$owner]);
        foreach($files as $t)$db->prepare('INSERT INTO compose_file_selection(user_id,acting_for_user_id,token) VALUES(?,?,?)')->execute([$uid,$owner,$t]);
        bm_workspace($db,$uid,$owner);$db->prepare('UPDATE compose_workspaces SET workspace_token=?,saved_draft_id=? WHERE user_id=? AND acting_for_user_id=?')->execute([bin2hex(random_bytes(16)),$id,$uid,$owner]);
        bulkmail_forget_prepared($db,$owner);$db->commit();unset($_SESSION['draft']);
    }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}return $owner;
}
function bm_end_workspace(PDO $db,int $uid,int $owner,bool $keepSaved): void {
    $w=bm_workspace($db,$uid,$owner);
    if(!$keepSaved && !empty($w['saved_draft_id']))$db->prepare('DELETE FROM mail_saved_drafts WHERE id=? AND user_id=?')->execute([(int)$w['saved_draft_id'],$uid]);
    $db->prepare('DELETE FROM compose_file_selection WHERE user_id=? AND acting_for_user_id=?')->execute([$uid,$owner]);
    $db->prepare('UPDATE compose_workspaces SET workspace_token=?,saved_draft_id=NULL WHERE user_id=? AND acting_for_user_id=?')->execute([bin2hex(random_bytes(16)),$uid,$owner]);
}
function bm_render_retained_files(PDO $db,int $uid,int $owner): void {
    $files=bm_files($db,$uid,$owner);if(!$files)return;
    echo '<div class="card" id="retainedFiles"><h2>Saved attachments</h2><p>These files stay with this draft when you preview, return to editing or sign in again. Tick a file to remove it on your next save or preview.</p>';
    foreach($files as $f){$label=['shared'=>'Shared — everyone','individual'=>'Individual recipient','document'=>'Document as email'][$f['kind']]??'Attachment';
        if($f['kind']==='individual'){$q=$db->prepare('SELECT name,email FROM contacts WHERE id=? AND owner_user_id=?');$q->execute([(int)$f['contact_id'],$owner]);$c=$q->fetch();$label.=': '.($c['name']?:$c['email']);}
        echo '<div class="retained-file" data-kind="'.h($f['kind']).'" data-size="'.(int)$f['file_size'].'" data-contact="'.(int)$f['contact_id'].'"><label class="checkrow"><input type="checkbox" name="remove_file[]" value="'.h($f['token']).'"> Remove <a href="?page=draft_file&amp;token='.h($f['token']).'">'.h($f['original_name']).'</a> — '.h($label).' ('.fmt_bytes((int)$f['file_size']).')</label></div>';
    }echo '</div>';
}
function bm_sent_copy_label(PDO $db,int $mid): string {
    $q=$db->prepare('SELECT status,error FROM sent_mailbox_copies WHERE mailing_id=?');$q->execute([$mid]);$r=$q->fetch();
    if(!$r){
        $q=$db->prepare('SELECT created_at,status FROM mailings WHERE id=?');$q->execute([$mid]);$m=$q->fetch();
        if(!$m)return 'Mailing not found';
        if($m['created_at']<'2026-10-16 00:00:00')return 'Historical mailing — not copied to mailbox';
        if(in_array($m['status'],['queued','submitting'],true))return 'Mailbox copy follows submission';
        $q=$db->prepare('SELECT COUNT(*) FROM mailing_recipients WHERE mailing_id=? AND status="postfix"');$q->execute([$mid]);
        if(!(int)$q->fetchColumn())return 'Not filed — no successful submissions';
        return 'Mailbox copy pending';
    }
    if($r['status']==='filed')return 'Saved in mailbox Sent';if($r['status']==='failed')return 'Sent-folder copy needs attention — delivery is not resent';return 'Mailbox copy pending';
}
bm_full_schema($db);
if($page==='draft_file'){
    $uid=(int)$_SESSION['user_id'];$q=$db->prepare('SELECT * FROM compose_file_store WHERE token=? AND user_id=?');$q->execute([(string)($_GET['token']??''),$uid]);$f=$q->fetch();
    $p=$f?realpath($f['stored_path']):false;$root=realpath(DATA_DIR.'/compose-files');if(!$p||!$root||!str_starts_with($p,$root.'/')||!is_file($p)){http_response_code(404);exit('Attachment not found');}
    header('Content-Type: application/octet-stream');header('Cache-Control: private, no-store');header("Content-Disposition: attachment; filename*=UTF-8''".rawurlencode(basename($f['original_name'])));readfile($p);exit;
}
if($page==='drafts'){
    $uid=(int)$_SESSION['user_id'];
    if($_SERVER['REQUEST_METHOD']==='POST'){
        check_csrf();$action=(string)($_POST['action']??'');
        try{
            if($action==='open'){$owner=bm_restore_snapshot($db,$uid,(int)($_POST['id']??0));flash('Draft opened with its recipients, formatting and attachments. Nothing has been sent.');redirect('?page=compose&acting_for='.$owner);}
            if($action==='delete'){$db->prepare('DELETE FROM mail_saved_drafts WHERE id=? AND user_id=?')->execute([(int)($_POST['id']??0),$uid]);flash('Saved draft removed. Existing sent emails are unchanged.');}
        }catch(Throwable $e){flash($e->getMessage(),'error');}redirect('?page=drafts');
    }
    layout_start('Saved Drafts');echo '<h1>Saved Drafts</h1><p>Complete emails saved using <b>Save as Draft</b>. Recipients, formatting, embedded images and file attachments are retained. Opening a draft does not send it.</p><p><a class="button good" href="?page=compose">Continue current message</a> <a class="button secondary" href="?page=draft_recovery">Earlier autosaved text versions</a></p><div class="card"><table><tr><th>Subject</th><th>Saved (UTC)</th><th>Files</th><th></th></tr>';
    $q=$db->prepare('SELECT * FROM mail_saved_drafts WHERE user_id=? ORDER BY updated_at DESC,id DESC');$q->execute([$uid]);$rows=$q->fetchAll();
    if(!$rows)echo '<tr><td colspan="4">No named drafts yet. Use Save as Draft in the email editor.</td></tr>';
    foreach($rows as $r){$files=json_decode($r['files_json'],true)?:[];echo '<tr><td>'.h($r['title']).'</td><td>'.h($r['updated_at']).'</td><td>'.count($files).'</td><td><form method="post" style="display:inline"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="id" value="'.(int)$r['id'].'"><button name="action" value="open">Continue editing</button><button class="secondary" name="action" value="delete" onclick="return confirm(\'Delete this saved draft? Sent emails are not affected.\')">Delete draft</button></form></td></tr>';}
    echo '</table></div>';layout_end();exit;
}
