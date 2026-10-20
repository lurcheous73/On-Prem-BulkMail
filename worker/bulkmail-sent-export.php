#!/usr/bin/env php
<?php
declare(strict_types=1);
/* Generates mailbox archives only. Never invokes submit_message or sendmail. */
define('BULKMAIL_LIBRARY_ONLY',true);
require '/usr/local/sbin/bulkmail-worker.php';
$db=open_db();$page='sent_export';require '/var/www/bulkmail/bulkmail-full-drafts.php';
$action=$argv[1]??'list';$id=(int)($argv[2]??0);
function sent_key(array $m): string {return hash('sha256','grange-bulkmail|'.$m['id'].'|'.$m['created_at'].'|'.$m['sender_email'].'|'.$m['subject']);}
if($action==='list'){
    $sql="SELECT m.id FROM mailings m LEFT JOIN sent_mailbox_copies c ON c.mailing_id=m.id
      WHERE m.created_at>='2026-10-16 00:00:00' AND m.status IN ('submitted','partial')
        AND EXISTS(SELECT 1 FROM mailing_recipients r WHERE r.mailing_id=m.id AND r.status='postfix')
        AND NOT EXISTS(SELECT 1 FROM mailing_recipients r WHERE r.mailing_id=m.id AND r.status IN ('queued','processing'))
        AND (c.status IS NULL OR c.status<>'filed') AND (c.next_attempt_at IS NULL OR c.next_attempt_at<=CURRENT_TIMESTAMP)
      ORDER BY m.id LIMIT 10";
    echo json_encode(['ids'=>$db->query($sql)->fetchAll(PDO::FETCH_COLUMN)],JSON_THROW_ON_ERROR);exit;
}
$q=$db->prepare('SELECT * FROM mailings WHERE id=?');$q->execute([$id]);$m=$q->fetch();if(!$m)throw new RuntimeException('Mailing not found');$key=sent_key($m);
$db->prepare('INSERT OR IGNORE INTO sent_mailbox_copies(mailing_id,message_key) VALUES(?,?)')->execute([$id,$key]);
if($action==='ack'){
    $result=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
    if(!empty($result['ok'])){$db->prepare('UPDATE sent_mailbox_copies SET status="filed",filed_at=CURRENT_TIMESTAMP,error=NULL,next_attempt_at=NULL,attempts=attempts+1 WHERE mailing_id=?')->execute([$id]);}
    else{$q=$db->prepare('SELECT attempts FROM sent_mailbox_copies WHERE mailing_id=?');$q->execute([$id]);$attempts=(int)$q->fetchColumn()+1;$next=gmdate('Y-m-d H:i:s',time()+min(3600,60*(2**min($attempts,6))));$db->prepare('UPDATE sent_mailbox_copies SET status="failed",error=?,attempts=?,next_attempt_at=? WHERE mailing_id=?')->execute([mb_substr((string)($result['error']??'Mailbox filing failed'),0,1000),$attempts,$next,$id]);}
    echo '{"ok":true}';exit;
}
if($action!=='render')throw new RuntimeException('Unknown archive action');
if(!in_array($m['status'],['submitted','partial'],true))throw new RuntimeException('Mailing has not finished submission');
$q=$db->prepare('SELECT * FROM mailing_recipients WHERE mailing_id=? ORDER BY id');$q->execute([$id]);$recipients=$q->fetchAll();$accepted=[];
foreach($recipients as $r){if(in_array($r['status'],['queued','processing'],true))throw new RuntimeException('Mailing still being submitted');if($r['status']==='postfix')$accepted[]=$r;}
if(!$accepted)throw new RuntimeException('No messages submitted; no sent copy created');
$q=$db->prepare('SELECT 1 FROM sender_identities WHERE id=? AND owner_user_id=? AND email=? COLLATE NOCASE AND active=1');$q->execute([$m['sender_identity_id'],(int)$m['acting_for_user_id'],$m['sender_email']]);
if(!$q->fetchColumn())throw new RuntimeException('Sender is not an approved active mailbox identity');
$path=dirname(DB_FILE).'/mailings/'.$id.'/sent-copy-'.$key.'.eml';
if(!is_file($path)){
    $rep=['id'=>0,'email'=>$m['sender_email'],'name'=>'','unsubscribe_token'=>''];
    $archive=$m;
    // One campaign copy; recipient-specific originals remain in the application's protected history.
    if(str_contains($archive['body_html'],'{{UNSUBSCRIBE_URL}}'))$archive['body_html']=str_replace('{{UNSUBSCRIBE_URL}}','https://work.the-grange.uk:9443/?page=mailing_view&id='.$id,$archive['body_html']);
    $mime=build_message($db,$archive,$rep);
    $mime=preg_replace('/^To:.*\r\n/m','To: undisclosed-recipients:;' . "\r\n",$mime,1);
    $bcc=implode(",\r\n ",array_map(static fn($r)=>strtolower(trim($r['email'])),$accepted));
    $mime=preg_replace('/^Message-ID:.*\r\n/m','Message-ID: <grange-sent-'.$key.'@bulk.the-grange.uk>' . "\r\n" . 'X-Grange-Sent-Copy: '.$key . "\r\n" . 'X-Grange-Mailing-ID: '.$id . "\r\n" . 'X-Grange-Submitted-Recipients: '.count($accepted) . "\r\n" . 'Bcc: '.$bcc . "\r\n",$mime,1);
    $date=new DateTimeImmutable($m['created_at'],new DateTimeZone('UTC'));
    $mime=preg_replace('/^Date:.*\r\n/m','Date: '.$date->format(DATE_RFC2822)."\r\n",$mime,1);
    $tmp=$path.'.'.bin2hex(random_bytes(8)).'.tmp';if(file_put_contents($tmp,$mime)===false)throw new RuntimeException('Could not write mailbox copy');chmod($tmp,0640);if(!rename($tmp,$path))throw new RuntimeException('Could not store mailbox copy');
}
$db->prepare('UPDATE sent_mailbox_copies SET archive_path=? WHERE mailing_id=?')->execute([$path,$id]);
echo json_encode(['id'=>$id,'mailbox'=>strtolower($m['sender_email']),'message_key'=>$key,'eml'=>base64_encode((string)file_get_contents($path))],JSON_THROW_ON_ERROR);
