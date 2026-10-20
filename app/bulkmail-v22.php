<?php
declare(strict_types=1);

/*
 * The Grange Bulk Mail v2.2 helpers:
 * templates, resend/reuse, contact bulk maintenance and inline editor images.
 */

$db->exec('CREATE TABLE IF NOT EXISTS email_templates (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner_user_id INTEGER NOT NULL,
 created_by_user_id INTEGER,
 sender_identity_id INTEGER,
 name TEXT NOT NULL,
 subject TEXT NOT NULL DEFAULT "",
 body_html TEXT NOT NULL DEFAULT "",
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(created_by_user_id) REFERENCES users(id),
 FOREIGN KEY(sender_identity_id) REFERENCES sender_identities(id) ON DELETE SET NULL
)');
$db->exec('CREATE INDEX IF NOT EXISTS idx_templates_owner ON email_templates(owner_user_id,name)');

$db->exec('CREATE TABLE IF NOT EXISTS editor_images (
 token TEXT PRIMARY KEY,
 owner_user_id INTEGER NOT NULL,
 uploaded_by_user_id INTEGER NOT NULL,
 original_name TEXT,
 stored_path TEXT NOT NULL,
 mime_type TEXT NOT NULL DEFAULT "image/jpeg",
 file_size INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(uploaded_by_user_id) REFERENCES users(id) ON DELETE CASCADE
)');
$db->exec('CREATE INDEX IF NOT EXISTS idx_editor_images_owner ON editor_images(owner_user_id)');

function bulkmail_template_owner(PDO $db, int $owner): int {
    if (!is_admin()) return (int)$_SESSION['user_id'];
    return user($db,$owner) ? $owner : (int)$_SESSION['user_id'];
}

function bulkmail_materialize_inline_images(PDO $db,string $body,int $owner,string $draftDir,string $draftToken): array {
    $assets=[];
    if (!preg_match_all('/\\?page=editor_image(?:&amp;|&)token=([a-f0-9]{32,})/i',$body,$m)) {
        return [$body,$assets];
    }
    $tokens=array_values(array_unique($m[1]));
    $page=900;
    @mkdir($draftDir.'/brochure',0750,true);
    foreach($tokens as $imageToken){
        if($page>999) throw new RuntimeException('Too many inline images in one email.');
        $s=$db->prepare('SELECT * FROM editor_images WHERE token=? AND owner_user_id=?');
        $s->execute([$imageToken,$owner]);
        $img=$s->fetch();
        if(!$img || !is_file($img['stored_path'])) continue;
        $file='page-'.str_pad((string)$page,3,'0',STR_PAD_LEFT).'.jpg';
        $dest=$draftDir.'/brochure/'.$file;
        if(!copy($img['stored_path'],$dest)) throw new RuntimeException('Could not prepare inline image.');
        chmod($dest,0640);
        $cid='editor-'.$imageToken;
        $draftUrl='?page=draft_asset&amp;token='.$draftToken.'&amp;f='.$file;
        $body=str_replace(
            ['?page=editor_image&amp;token='.$imageToken,'?page=editor_image&token='.$imageToken],
            $draftUrl,
            $body
        );
        $assets[]=['path'=>$dest,'page'=>$page,'cid'=>$cid];
        $page++;
    }
    return [$body,$assets];
}

if ($page==='inline_image_api') {
    check_csrf();
    header('Content-Type: application/json; charset=utf-8');
    $owner=bulkmail_template_owner($db,(int)($_POST['acting_for']??$_SESSION['user_id']));
    allowed_context($db,$owner);
    if(!isset($_FILES['editor_image'])){
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>'No image uploaded']);
        exit;
    }
    $f=$_FILES['editor_image'];
    $ext=strtolower(pathinfo((string)($f['name']??''),PATHINFO_EXTENSION));
    if(!in_array($ext,['jpg','jpeg','png','heic','heif'],true)){
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>'Only JPEG, PNG and HEIC images are supported. RAW images are not supported.']);
        exit;
    }
    if((int)($f['size']??0)>12*1024*1024){
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>'Image is too large (12 MB maximum).']);
        exit;
    }
    try{
        $raw=store_upload($f,DATA_DIR.'/editor-images/raw',['jpg','jpeg','png','heic','heif'],12*1024*1024);
        $token=random_token(20);
        $dir=DATA_DIR.'/editor-images/'.$owner;
        @mkdir($dir,0750,true);
        $dest=$dir.'/'.$token.'.jpg';
        $cmd='convert '.escapeshellarg($raw['stored_path']).' -auto-orient -strip -resize '.escapeshellarg('1600x1600>').' -background white -alpha remove -alpha off -quality 88 '.escapeshellarg($dest).' 2>&1';
        $out=[];$rc=0;exec($cmd,$out,$rc);
        @unlink($raw['stored_path']);
        if($rc!==0 || !is_file($dest)) throw new RuntimeException('The image could not be converted.');
        chmod($dest,0640);
        $size=(int)filesize($dest);
        $s=$db->prepare('INSERT INTO editor_images(token,owner_user_id,uploaded_by_user_id,original_name,stored_path,mime_type,file_size) VALUES(?,?,?,?,?,?,?)');
        $s->execute([$token,$owner,(int)$_SESSION['user_id'],safe_name((string)$f['name']),$dest,'image/jpeg',$size]);
        audit($db,'editor_image_upload','owner='.$owner.' token='.$token.' bytes='.$size);
        echo json_encode(['ok'=>true,'url'=>'?page=editor_image&token='.$token]);
    }catch(Throwable $e){
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
    }
    exit;
}

if ($page==='editor_image') {
    $token=preg_replace('/[^a-f0-9]/','',strtolower((string)($_GET['token']??'')));
    $s=$db->prepare('SELECT * FROM editor_images WHERE token=?');
    $s->execute([$token]);$img=$s->fetch();
    if(!$img || (!is_admin() && (int)$img['owner_user_id']!==(int)$_SESSION['user_id']) || !is_file($img['stored_path'])){
        http_response_code(404);exit;
    }
    header('Content-Type: image/jpeg');
    header('Content-Length: '.filesize($img['stored_path']));
    header('Cache-Control: private, max-age=3600');
    readfile($img['stored_path']);
    exit;
}

if ($page==='template_api') {
    header('Content-Type: application/json; charset=utf-8');
    if($_SERVER['REQUEST_METHOD']==='GET'){
        $id=(int)($_GET['id']??0);
        $s=$db->prepare('SELECT * FROM email_templates WHERE id=?');
        $s->execute([$id]);$t=$s->fetch();
        if(!$t || (!is_admin() && (int)$t['owner_user_id']!==(int)$_SESSION['user_id'])){
            http_response_code(404);echo json_encode(['ok'=>false]);exit;
        }
        echo json_encode(['ok'=>true,'template'=>[
            'id'=>(int)$t['id'],'name'=>$t['name'],'subject'=>$t['subject'],
            'body_html'=>$t['body_html'],'sender_identity_id'=>$t['sender_identity_id']
        ]]);
        exit;
    }
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);exit;}
    check_csrf();
    $owner=bulkmail_template_owner($db,(int)($_POST['acting_for']??$_SESSION['user_id']));
    allowed_context($db,$owner);
    $name=trim((string)($_POST['name']??''));
    $subject=trim((string)($_POST['subject']??''));
    $body=sanitize_html((string)($_POST['body_html']??''));
    $sender=(int)($_POST['sender_identity_id']??0); if($sender<1)$sender=null;
    if($name==='' || ($subject==='' && trim(strip_tags($body))==='')){
        http_response_code(400);echo json_encode(['ok'=>false,'error'=>'Template name and content are required.']);exit;
    }
    if($sender){
        $q=$db->prepare('SELECT id FROM sender_identities WHERE id=? AND owner_user_id=? AND active=1');
        $q->execute([$sender,$owner]);if(!$q->fetchColumn())$sender=null;
    }
    $s=$db->prepare('INSERT INTO email_templates(owner_user_id,created_by_user_id,sender_identity_id,name,subject,body_html) VALUES(?,?,?,?,?,?)');
    $s->execute([$owner,(int)$_SESSION['user_id'],$sender,$name,$subject,$body]);
    audit($db,'template_create','owner='.$owner.' template='.$db->lastInsertId().' '.$name);
    echo json_encode(['ok'=>true,'id'=>(int)$db->lastInsertId()]);
    exit;
}

if ($page==='template_use') {
    $id=(int)($_GET['id']??0);
    $s=$db->prepare('SELECT * FROM email_templates WHERE id=?');
    $s->execute([$id]);$t=$s->fetch();
    if(!$t || (!is_admin() && (int)$t['owner_user_id']!==(int)$_SESSION['user_id'])){http_response_code(404);exit;}
    $owner=(int)$t['owner_user_id'];
    bm_preserve_workspace($db,(int)$_SESSION['user_id'],$owner);bm_end_workspace($db,(int)$_SESSION['user_id'],$owner,true);bulkmail_forget_prepared($db,$owner);unset($_SESSION['draft']);
    $db->prepare('INSERT INTO compose_drafts(user_id,acting_for_user_id,sender_identity_id,custom_from,subject,body_html,all_contacts,groups_json,contacts_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,acting_for_user_id) DO UPDATE SET sender_identity_id=excluded.sender_identity_id,custom_from="",subject=excluded.subject,body_html=excluded.body_html,all_contacts=0,groups_json="[]",contacts_json="[]",updated_at=CURRENT_TIMESTAMP')
       ->execute([(int)$_SESSION['user_id'],$owner,$t['sender_identity_id'],'',$t['subject'],$t['body_html'],0,'[]','[]']);
    audit($db,'template_use','template='.$id.' owner='.$owner);
    redirect('?page=compose&acting_for='.$owner);
}

if ($page==='templates') {
    $owner=bulkmail_template_owner($db,(int)($_GET['user']??$_POST['acting_for']??$_SESSION['user_id']));
    allowed_context($db,$owner);
    if($_SERVER['REQUEST_METHOD']==='POST'){
        check_csrf();
        if(($_POST['action']??'')==='delete'){
            $id=(int)($_POST['id']??0);
            $db->prepare('DELETE FROM email_templates WHERE id=? AND owner_user_id=?')->execute([$id,$owner]);
            audit($db,'template_delete','owner='.$owner.' template='.$id);
            flash('Template deleted.');
            redirect('?page=templates&user='.$owner);
        }
    }
    layout_start('Templates');
    if(is_admin()){
        echo '<div class="card"><label>Templates for</label><select onchange="location=\'?page=templates&user=\'+this.value">';
        foreach($db->query('SELECT * FROM users WHERE active=1 ORDER BY display_name') as $u) echo '<option value="'.(int)$u['id'].'"'.((int)$u['id']===$owner?' selected':'').'>'.h($u['display_name']).'</option>';
        echo '</select></div>';
    }
    $ou=user($db,$owner);
    echo '<h1>Templates - '.h($ou['display_name']).'</h1><div class="safe">Create templates directly from the email editor using <b>Save as Template</b>. Images embedded in the editor stay with the template.</div>';
    $s=$db->prepare('SELECT * FROM email_templates WHERE owner_user_id=? ORDER BY name,updated_at DESC');$s->execute([$owner]);
    echo '<div class="card"><table><tr><th>Name</th><th>Subject</th><th>Updated</th><th></th></tr>';
    foreach($s as $t){
        echo '<tr><td>'.h($t['name']).'</td><td>'.h($t['subject']).'</td><td>'.h($t['updated_at']).'</td><td><a class="button good" href="?page=template_use&amp;id='.(int)$t['id'].'">Use Template</a><form method="post" style="display:inline" onsubmit="return confirm(\'Delete this template?\')"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="acting_for" value="'.$owner.'"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="'.(int)$t['id'].'"><button class="danger">Delete</button></form></td></tr>';
    }
    echo '</table></div>';
    layout_end();exit;
}

if ($page==='contacts' && $_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='bulk') {
    check_csrf();
    $owner=bulkmail_template_owner($db,(int)($_GET['user']??$_POST['acting_for']??$_SESSION['user_id']));
    allowed_context($db,$owner);
    $ids=array_values(array_unique(array_filter(array_map('intval',$_POST['contact_ids']??[]))));
    $mode=(string)($_POST['bulk_action']??'');
    if(!$ids){flash('Select at least one contact.','error');redirect('?page=contacts&user='.$owner);}
    $marks=implode(',',array_fill(0,count($ids),'?'));
    $params=$ids;$params[]=$owner;
    $q=$db->prepare("SELECT id FROM contacts WHERE id IN ($marks) AND owner_user_id=? AND active=1");
    $q->execute($params);$ids=array_map('intval',array_column($q->fetchAll(),'id'));
    if(!$ids){flash('No valid contacts selected.','error');redirect('?page=contacts&user='.$owner);}
    $gid=(int)($_POST['target_group']??0);
    if(in_array($mode,['add_group','move_group','remove_group'],true)){
        $g=$db->prepare('SELECT id FROM groups WHERE id=? AND owner_user_id=?');$g->execute([$gid,$owner]);
        if(!$g->fetchColumn()){flash('Choose a valid group.','error');redirect('?page=contacts&user='.$owner);}
    }
    $db->beginTransaction();
    try{
        if($mode==='delete_system'){
            $del=$db->prepare('DELETE FROM group_members WHERE contact_id=?');
            $off=$db->prepare('UPDATE contacts SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND owner_user_id=?');
            foreach($ids as $cid){$del->execute([$cid]);$off->execute([$cid,$owner]);}
            $msg=count($ids).' contact(s) removed from the system.';
        }elseif($mode==='remove_group'){
            $st=$db->prepare('DELETE FROM group_members WHERE group_id=? AND contact_id=?');
            foreach($ids as $cid)$st->execute([$gid,$cid]);
            $msg=count($ids).' contact(s) removed from the selected group.';
        }elseif($mode==='move_group'){
            $del=$db->prepare('DELETE FROM group_members WHERE contact_id=?');
            $ins=$db->prepare('INSERT OR IGNORE INTO group_members(group_id,contact_id) VALUES(?,?)');
            foreach($ids as $cid){$del->execute([$cid]);$ins->execute([$gid,$cid]);}
            $msg=count($ids).' contact(s) moved to the selected group.';
        }elseif($mode==='add_group'){
            $ins=$db->prepare('INSERT OR IGNORE INTO group_members(group_id,contact_id) VALUES(?,?)');
            foreach($ids as $cid)$ins->execute([$gid,$cid]);
            $msg=count($ids).' contact(s) added to the selected group.';
        }else{
            throw new RuntimeException('Choose a maintenance action.');
        }
        $db->commit();
        audit($db,'contact_bulk',$mode.' owner='.$owner.' count='.count($ids).' group='.$gid);
        flash($msg);
    }catch(Throwable $e){
        if($db->inTransaction())$db->rollBack();
        flash($e->getMessage(),'error');
    }
    redirect('?page=contacts&user='.$owner);
}

if ($page==='reuse') {
    $id=(int)($_GET['id']??0);
    $s=$db->prepare('SELECT * FROM mailings WHERE id=?');$s->execute([$id]);$m=$s->fetch();
    if(!$m || (!is_admin() && (int)$m['acting_for_user_id']!==(int)$_SESSION['user_id'])){http_response_code(404);exit;}
    $owner=(int)$m['acting_for_user_id'];
    $rs=$db->prepare('SELECT * FROM mailing_recipients WHERE mailing_id=? ORDER BY id');$rs->execute([$id]);$oldRecipients=$rs->fetchAll();
    $recipients=[];$suppressed=0;$au=user($db,$owner);
    foreach($oldRecipients as $r){
        $email=normal_email((string)$r['email']);
        if(($au['account_type']??'internal')==='marketing'){
            $q=$db->prepare('SELECT 1 FROM suppressions WHERE owner_user_id=? AND email=?');$q->execute([$owner,$email]);
            if($q->fetchColumn()){$suppressed++;continue;}
        }
        $recipients[]=['id'=>$r['contact_id'] ? (int)$r['contact_id'] : null,'email'=>$email,'name'=>$r['name']??'','old_recipient_id'=>(int)$r['id']];
    }
    if(!$recipients){flash('No recipients remain after current suppression checks.','error');redirect('?page=history');}
    $token=random_token(18);$ddir=DATA_DIR.'/drafts/'.$token;@mkdir($ddir.'/attachments',0750,true);@mkdir($ddir.'/brochure',0750,true);
    $attachments=[];
    $as=$db->prepare('SELECT * FROM mailing_attachments WHERE mailing_id=? ORDER BY id');$as->execute([$id]);
    foreach($as as $a){if(!is_file($a['stored_path']))continue;$dest=$ddir.'/attachments/'.random_token(6).'-'.safe_name($a['original_name']);copy($a['stored_path'],$dest);$attachments[]=['original_name'=>$a['original_name'],'stored_path'=>$dest,'mime_type'=>$a['mime_type'],'file_size'=>(int)$a['file_size']];}
    $recipientAttachments=[];
    foreach($recipients as $r){
        if(!$r['id'])continue;
        $q=$db->prepare('SELECT * FROM mailing_recipient_attachments WHERE mailing_recipient_id=? ORDER BY id');$q->execute([$r['old_recipient_id']]);
        foreach($q as $a){if(!is_file($a['stored_path']))continue;$dir=$ddir.'/recipient-'.$r['id'];@mkdir($dir,0750,true);$dest=$dir.'/'.random_token(6).'-'.safe_name($a['original_name']);copy($a['stored_path'],$dest);$recipientAttachments[$r['id']][]=['original_name'=>$a['original_name'],'stored_path'=>$dest,'mime_type'=>$a['mime_type'],'file_size'=>(int)$a['file_size']];}
    }
    $body=(string)$m['body_html'];$assets=[];
    $aa=$db->prepare('SELECT * FROM mailing_assets WHERE mailing_id=? ORDER BY page_number,id');$aa->execute([$id]);
    foreach($aa as $a){if(!is_file($a['stored_path']))continue;$pageNo=(int)($a['page_number']??0);if($pageNo<1)$pageNo=900+count($assets);$file='page-'.str_pad((string)$pageNo,3,'0',STR_PAD_LEFT).'.jpg';$dest=$ddir.'/brochure/'.$file;copy($a['stored_path'],$dest);$cid=(string)$a['cid'];$body=str_replace('cid:'.$cid,'?page=draft_asset&amp;token='.$token.'&amp;f='.$file,$body);$assets[]=['path'=>$dest,'page'=>$pageNo,'cid'=>$cid];}
    foreach($recipients as &$r)unset($r['old_recipient_id']);unset($r);
    $_SESSION['draft']=['token'=>$token,'acting_for'=>$owner,'sender_id'=>$m['sender_identity_id'],'sender_email'=>$m['sender_email'],'subject'=>$m['subject'],'body_html'=>$body,'recipients'=>$recipients,'selected_count'=>count($oldRecipients),'unique_count'=>count($recipients),'duplicate_count'=>0,'suppressed_count'=>$suppressed,'attachments'=>$attachments,'recipient_attachments'=>$recipientAttachments,'assets'=>$assets];
    bm_seed_reused_draft($db,$m,$_SESSION['draft']);
    audit($db,'mailing_reuse','source='.$id.' owner='.$owner.' recipients='.count($recipients));
    redirect('?page=compose&acting_for='.$owner.'&preview=1');
}
