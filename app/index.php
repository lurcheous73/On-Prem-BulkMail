<?php
declare(strict_types=1);

require_once __DIR__.'/bulkmail-request-diagnostics.php';
bm_request_diagnostic('ingress');
// Both broker routes authenticate independently and always exit their handler.
// They must not wait for or inherit an unrelated local BulkMail session.
if (in_array($_GET['page'] ?? null, ['portal_sso_authorize','portal_sso_token'], true)) {
    bm_request_diagnostic('session_skipped_broker');
} else {
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'use_strict_mode' => true,
    ]);
    bm_request_diagnostic('session_ready');
}

const APP_NAME = 'The Grange Bulk Mail';
const DB_FILE = '/var/lib/bulkmail/bulkmail.sqlite';
const DATA_DIR = '/var/lib/bulkmail';
const DELIVERY_ENABLED = true;
const MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024;
const MAX_ATTACHMENT_WARN_BYTES = 12 * 1024 * 1024;
const MAX_ATTACHMENT_TOTAL_BYTES = 15 * 1024 * 1024;
const MAX_DOCUMENT_BYTES = 30 * 1024 * 1024;

$db = new PDO('sqlite:' . DB_FILE, null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$db->exec('PRAGMA foreign_keys=ON');
$db->exec('PRAGMA busy_timeout=5000');
bm_request_diagnostic('database_ready');
require_once __DIR__.'/bulkmail-integrations.php';
require_once __DIR__.'/bulkmail-identity.php';
require_once __DIR__.'/bulkmail-portal-sso.php';
require_once __DIR__.'/bulkmail-messaging-core.php';
bm_identity_schema($db);
bm_portal_sso_schema($db);
bm_message_schema($db);
$db->exec('CREATE TABLE IF NOT EXISTS mailing_recipient_attachments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mailing_recipient_id INTEGER NOT NULL,
 original_name TEXT NOT NULL,
 stored_path TEXT NOT NULL,
 mime_type TEXT,
 file_size INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(mailing_recipient_id) REFERENCES mailing_recipients(id) ON DELETE CASCADE
)');
$db->exec('CREATE INDEX IF NOT EXISTS idx_recipient_attachments_recipient ON mailing_recipient_attachments(mailing_recipient_id)');
bm_request_diagnostic('schema_ready');

function h(?string $v): string { return htmlspecialchars($v ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function now(): string { return gmdate('Y-m-d H:i:s'); }
function normal_email(string $v): string { return strtolower(trim($v)); }
function is_admin(): bool { return !empty($_SESSION['is_admin']); }
function logged_in(): bool { return !empty($_SESSION['user_id']); }
function csrf(): string { if (empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function check_csrf(): void { if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(400); exit('Invalid CSRF token'); } }
function redirect(string $url): never { header('Location: '.$url); exit; }
function flash(string $m,string $type='ok'): void { $_SESSION['flash'][]=[$type,$m]; }
function require_login(): void { if (!logged_in()) redirect('?page=login'); }
function require_admin(): void { require_login(); if (!is_admin()) { http_response_code(403); exit('Administrator access required'); } }
function ip(): string { return $_SERVER['REMOTE_ADDR'] ?? ''; }
function user(PDO $db,int $id): ?array { $s=$db->prepare('SELECT * FROM users WHERE id=?'); $s->execute([$id]); return $s->fetch() ?: null; }
function audit(PDO $db,string $action,string $details='',?int $ownerId=null): void {
    $actorId=isset($_SESSION['user_id'])?(int)$_SESSION['user_id']:null;
    $s=$db->prepare('INSERT INTO audit_log(user_id,action,details,ip_address) VALUES(?,?,?,?)');
    $s->execute([$actorId,$action,$details,ip()]);
    bm_identity_record_audit($db,(int)$db->lastInsertId(),$actorId,$action,$details,$ownerId);
}
function safe_name(string $name): string { $name=preg_replace('/[^A-Za-z0-9._ -]+/','_',basename($name)); return trim($name) ?: 'file'; }
function fmt_bytes(int $n): string { if ($n<1024) return $n.' B'; if ($n<1048576) return round($n/1024,1).' KB'; return round($n/1048576,1).' MB'; }
function random_token(int $bytes=24): string { return bin2hex(random_bytes($bytes)); }

function current_context(PDO $db): int {
    if (!is_admin()) return (int)$_SESSION['user_id'];
    $id=(int)($_GET['user'] ?? $_POST['acting_for'] ?? $_SESSION['user_id']);
    return user($db,$id) ? $id : (int)$_SESSION['user_id'];
}

function allowed_context(PDO $db,int $owner): void {
    if (is_admin()) return;
    if ($owner !== (int)$_SESSION['user_id']) { http_response_code(403); exit('Access denied'); }
}

function sanitize_html(string $html): string {
    $html=preg_replace('#<(script|style|iframe|object|embed|meta|link)[^>]*>.*?</\\1>#is','',$html);
    $html=preg_replace('#<(script|style|iframe|object|embed|meta|link)[^>]*/?>#is','',$html);
    $doc=new DOMDocument('1.0','UTF-8');
    libxml_use_internal_errors(true);
    $doc->loadHTML('<?xml encoding="utf-8"?><div id="root">'.$html.'</div>', LIBXML_HTML_NOIMPLIED|LIBXML_HTML_NODEFDTD);
    libxml_clear_errors();
    $allowed=['div','p','br','strong','b','em','i','u','s','h1','h2','h3','h4','ul','ol','li','a','img','table','thead','tbody','tfoot','tr','td','th','span','blockquote','hr'];
    $walker=function(DOMNode $node) use (&$walker,$allowed): void {
        if ($node instanceof DOMElement) {
            $tag=strtolower($node->tagName);
            // Older browsers and pasted documents still use FONT elements.
            if($tag==='font'){
                $span=$node->ownerDocument->createElement('span');$styles=[];
                $face=$node->getAttribute('face');
                if($face!=='' && preg_match('/^[A-Za-z0-9 ,"\x27_-]+$/D',$face))$styles[]='font-family:'.$face;
                $sizes=['1'=>'8pt','2'=>'10pt','3'=>'12pt','4'=>'14pt','5'=>'18pt','6'=>'24pt','7'=>'36pt'];
                if(isset($sizes[$node->getAttribute('size')]))$styles[]='font-size:'.$sizes[$node->getAttribute('size')];
                if($node->hasAttribute('style'))$styles[]=$node->getAttribute('style');
                $span->setAttribute('style',implode(';',$styles));
                while($node->firstChild)$span->appendChild($node->firstChild);
                $node->parentNode->replaceChild($span,$node);$node=$span;$tag='span';
            }
            if ($tag!=='div' && !in_array($tag,$allowed,true)) {
                $parent=$node->parentNode;
                if ($parent) {
                    foreach(iterator_to_array($node->childNodes) as $child)$walker($child);
                    while ($node->firstChild) $parent->insertBefore($node->firstChild,$node);
                    $parent->removeChild($node);
                }
                return;
            }
            $keep=[];
            if ($tag==='a' && $node->hasAttribute('href')) {
                $href=trim($node->getAttribute('href'));
                if (preg_match('#^(https?://|mailto:)#i',$href)) $keep['href']=$href;
            }
            if ($tag==='img' && $node->hasAttribute('src')) {
                $src=trim($node->getAttribute('src'));
                if (preg_match('#^\?page=editor_image&token=[a-f0-9]{32,}$#i',$src)) {
                    $keep['src']=$src;
                    $keep['alt']=trim($node->getAttribute('alt'));
                    $keep['style']='max-width:100%;height:auto';
                }
            }
            if ($node->hasAttribute('style')) {
                $style=$node->getAttribute('style');
                $pieces=[];
                foreach (explode(';',$style) as $rule) {
                    if (!str_contains($rule,':')) continue;
                    [$k,$v]=array_map('trim',explode(':',$rule,2));
                    $k=strtolower($k);
                    if (in_array($k,['text-align','font-weight','font-style','text-decoration','font-size','font-family','color','background-color','vertical-align','border','border-collapse','padding'],true)
                        && !preg_match('/expression|url\\s*\\(|javascript/i',$v)) $pieces[]=$k.':'.$v;
                }
                if ($pieces) $keep['style']=implode(';',$pieces);
            }
            while ($node->attributes && $node->attributes->length) $node->removeAttributeNode($node->attributes->item(0));
            foreach ($keep as $k=>$v) $node->setAttribute($k,$v);
        }
        foreach (iterator_to_array($node->childNodes) as $child) $walker($child);
    };
    $root=$doc->getElementById('root');
    if (!$root) return '';
    foreach (iterator_to_array($root->childNodes) as $child) $walker($child);
    $out=''; foreach ($root->childNodes as $child) $out.=$doc->saveHTML($child);
    return trim($out);
}

function footer_html(PDO $db,int $owner): string {
    $s=$db->prepare('SELECT u.organisation,u.account_type,o.* FROM users u LEFT JOIN organisation_settings o ON o.user_id=u.id WHERE u.id=?');
    $s->execute([$owner]); $r=$s->fetch() ?: [];
    $name=$r['footer_name'] ?: ($r['organisation'] ?? '');
    $parts=[];
    if ($name) $parts[]=h($name);
    if (!empty($r['footer_address'])) $parts[]=nl2br(h($r['footer_address']));
    if (!empty($r['footer_phone'])) $parts[]=h($r['footer_phone']);
    $base='<div style="margin-top:28px;padding-top:14px;border-top:1px solid #ccc;font-size:12px;color:#666">'.implode('<br>',$parts);
    if (($r['account_type'] ?? 'internal')==='marketing') {
        $base.='<br><a href="{{UNSUBSCRIBE_URL}}">Unsubscribe from marketing emails</a>';
    }
    return $base.'</div>';
}

function store_upload(array $f,string $dir,array $extensions,int $max): array {
    if (($f['error'] ?? UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_OK) throw new RuntimeException('Upload failed');
    if (($f['size'] ?? 0)>$max) throw new RuntimeException('File is too large');
    $orig=safe_name((string)$f['name']);
    $ext=strtolower(pathinfo($orig,PATHINFO_EXTENSION));
    if (!in_array($ext,$extensions,true)) throw new RuntimeException('File type not allowed: '.$ext);
    @mkdir($dir,0750,true);
    $stored=random_token(12).'.'.$ext;
    $path=$dir.'/'.$stored;
    if (!move_uploaded_file($f['tmp_name'],$path)) throw new RuntimeException('Could not store upload');
    chmod($path,0640);
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($path) ?: 'application/octet-stream';
    return ['original_name'=>$orig,'stored_path'=>$path,'mime_type'=>$mime,'file_size'=>(int)$f['size'],'extension'=>$ext];
}

function process_document_as_email(array $f,string $draftDir,string $senderEmail,bool $stored=false): array {
    $u=$stored?$f:store_upload($f,$draftDir.'/source',['pdf','doc','docx','odt'],MAX_DOCUMENT_BYTES);
    $pdf=$u['stored_path'];
    if ($u['extension']!=='pdf') {
        $out=$draftDir.'/converted'; @mkdir($out,0750,true);
        $cmd='timeout 90s soffice --headless --convert-to pdf --outdir '.escapeshellarg($out).' '.escapeshellarg($u['stored_path']).' 2>&1';
        exec($cmd,$o,$rc);
        $cand=glob($out.'/*.pdf');
        if ($rc!==0 || !$cand) throw new RuntimeException('Could not convert document to PDF');
        $pdf=$cand[0];
    }
    $pagesDir=$draftDir.'/brochure'; @mkdir($pagesDir,0750,true);
    $prefix=$pagesDir.'/raw';
    $cmd='pdftoppm -jpeg -r 170 -jpegopt quality=90 '.escapeshellarg($pdf).' '.escapeshellarg($prefix).' 2>&1';
    exec($cmd,$o,$rc);
    if ($rc!==0) throw new RuntimeException('Could not render document pages');
    $raw=glob($pagesDir.'/raw-*.jpg'); sort($raw,SORT_NATURAL);
    if (!$raw) throw new RuntimeException('Document produced no pages');
    if (count($raw)>30) throw new RuntimeException('Document has more than 30 pages');
    $assets=[]; $n=0;
    foreach ($raw as $src) {
        $n++; $dest=sprintf('%s/page-%03d.jpg',$pagesDir,$n);
        $label='Sent by '.$senderEmail;
        $cmd='convert '.escapeshellarg($src).' -strip -auto-orient -background white -gravity south -splice 0x54 '
            .'-fill "#555555" -font DejaVu-Sans -pointsize 22 -gravity southeast -annotate +24+16 '.escapeshellarg($label).' '
            .'-quality 90 '.escapeshellarg($dest).' 2>&1';
        exec($cmd,$io,$irc);
        if ($irc!==0 || !is_file($dest)) throw new RuntimeException('Could not protect rendered page '.$n);
        @unlink($src); chmod($dest,0640);
        $assets[]=['path'=>$dest,'page'=>$n,'cid'=>'brochure-'.$n.'-'.substr(random_token(6),0,8)];
    }
    return ['source'=>$u,'assets'=>$assets];
}

function layout_start(string $title): void {
    echo '<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>'.h($title).' - '.APP_NAME.'</title>';
    echo <<<'CSS'
<style>
:root{font:17px/1.45 Arial,Helvetica,sans-serif;color:#222;background:#f3f5f7}*{box-sizing:border-box}body{margin:0}header{background:#202733;color:#fff;padding:14px 20px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}header strong{font-size:1.2rem}nav{display:flex;gap:7px;flex-wrap:wrap}nav a{color:#fff;text-decoration:none;background:#354154;padding:8px 11px;border-radius:7px}main{max-width:1260px;margin:22px auto;padding:0 18px 60px}.card{background:#fff;border:1px solid #d5dae0;border-radius:12px;padding:20px;margin-bottom:18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:15px}label{display:block;font-weight:700;margin:12px 0 5px}input,select,textarea{width:100%;padding:10px;font:inherit;border:1px solid #abb3bd;border-radius:7px;background:#fff}textarea{min-height:110px}button,.button{display:inline-block;border:0;border-radius:7px;padding:10px 15px;font:inherit;background:#165bd8;color:#fff;text-decoration:none;cursor:pointer;margin:3px}.secondary{background:#596579}.good{background:#218146}.danger{background:#b33030}.send-big{background:#c51616;color:#fff;font-size:1.35rem;font-weight:800;padding:16px 28px;border:3px solid #850d0d;box-shadow:0 3px 8px rgba(0,0,0,.22)}.send-big:hover{background:#a90f0f}.warning{background:#fff3ca;border:1px solid #d1a72c;border-radius:8px;padding:13px}.safe{background:#e8f7ec;border:1px solid #75b681;border-radius:8px;padding:13px}.flash-ok{background:#e8f7ec;border:1px solid #75b681;padding:12px;margin-bottom:12px}.flash-error{background:#fdeaea;border:1px solid #ce7373;padding:12px;margin-bottom:12px}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}th{background:#edf0f4}.checkrow{display:flex;align-items:center;gap:10px;margin:7px 0}.checkrow input{width:auto;transform:scale(1.2)}.recipient-row{display:grid;grid-template-columns:minmax(280px,1fr) minmax(260px,1fr);gap:14px;align-items:center;padding:8px 4px;border-bottom:1px solid #e2e5e8}.recipient-row:last-child{border-bottom:0}.recipient-row input[type=file]{padding:6px;background:#fff}@media(max-width:800px){.recipient-row{grid-template-columns:1fr}}.groupbox{max-height:330px;overflow:auto;border:1px solid #ccd2d8;border-radius:8px;padding:10px;background:#fafafa}.recipient-group-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:8px;margin:8px 0 16px}.recipient-group-option{border:1px solid #ccd2d8;border-radius:8px;padding:10px;background:#fafafa;margin:0;align-items:flex-start}.recipient-group-option:hover{background:#f1f5fa}.toolbar{border:1px solid #aaa;border-bottom:0;padding:7px;background:#eee}.toolbar button{padding:6px 10px;background:#596579}.toolbar select{width:auto;display:inline-block;padding:6px 8px;margin:3px;vertical-align:middle}.editor{min-height:280px;border:1px solid #aaa;border-radius:0 0 7px 7px;padding:14px;background:#fff}.spell-panel{display:none;margin-top:10px;border:1px solid #ccd2d8;border-radius:8px;padding:12px;background:#fafafa}.spell-item{padding:8px 0;border-bottom:1px solid #e1e4e8}.spell-item:last-child{border-bottom:0}.spell-suggestion{padding:5px 8px;margin:3px;background:#596579}.small{font-size:.85rem;color:#666}.stat{font-size:2rem;font-weight:700}.brochure img{display:block;max-width:100%;height:auto;margin:0 auto 12px;border:1px solid #ddd}.tabs a{margin-right:6px}.pill{display:inline-block;padding:3px 8px;border-radius:12px;background:#e8ebef;font-size:.8rem}.marketing{background:#ffe6c7}.internal{background:#dff0ff}@media(max-width:700px){:root{font-size:16px}table{font-size:.88rem}}
</style>
CSS;
    echo '<link rel="stylesheet" href="/bulkmail-fonts.css?v=20261016r2"></head><body>';
    if (logged_in()) {
        echo '<header><strong>'.APP_NAME.'</strong><nav><a href="?">Home</a><a href="?page=compose">Send Email</a><a href="?page=messages">SMS / WhatsApp</a><a href="?page=contacts">Contacts</a><a href="?page=groups">Groups</a><a href="?page=templates">Templates</a><a href="?page=drafts">Saved Drafts</a><a href="?page=history">Sent / History</a>';
        if (is_admin()) echo '<a href="?page=users">Users</a><a href="?page=identity_users">CT400 Accounts</a><a href="?page=messaging_settings">Messaging Settings</a><a href="?page=domains">Domains</a><a href="?page=senders">Senders</a><a href="?page=compliance">Compliance</a><a href="?page=audit">Audit</a>';
        echo '<a href="?page=logout">Log out</a></nav><span style="margin-left:auto">'.h($_SESSION['display_name'] ?? '').'</span></header>';
    }
    echo '<main>';
    foreach ($_SESSION['flash'] ?? [] as [$type,$msg]) echo '<div class="flash-'.h($type).'">'.h($msg).'</div>';
    unset($_SESSION['flash']);
}
function layout_end(): void { echo '</main></body></html>'; }

$page=$_GET['page'] ?? 'home';

// Broker routes verify their own portal/client authentication. A backend token
// request must never inherit a local login or redirect to the browser login form.
bm_request_diagnostic('broker_dispatch');
bm_portal_sso_handle($db, $page);

// Re-read access rights without changing account rows or passwords.
$portalSessionRejected=false;
if (logged_in()) {
    bm_request_diagnostic('session_validation_start');
    $sessionUser=user($db,(int)$_SESSION['user_id']);
    if (!$sessionUser || !(int)$sessionUser['active'] || !bm_identity_validate_session($db)) {
        bm_request_diagnostic('session_validation_failed');
        $portalSessionRejected=($_SESSION['authentication_method'] ?? '')==='ct400_portal';
        $_SESSION=[];
        session_regenerate_id(true);
        // Public opt-outs and the login form must still work with an expired account session.
        if (!in_array($page,['unsubscribe','login'],true)) redirect('?page=login');
    } else {
        $_SESSION['is_admin']=(bool)$sessionUser['is_admin'];
        $_SESSION['display_name']=$sessionUser['display_name'];
        bm_request_diagnostic('session_validation_complete');
    }
}

$autoLoginReason='portal_session_rejected';
$autoLoginEligible=!$portalSessionRejected && bm_identity_should_auto_login($page, $autoLoginReason);
bm_request_diagnostic('auto_login_gate', $autoLoginReason);
if ($autoLoginEligible) {
    $portalAccount=bm_identity_try_portal_login($db);
    if ($portalAccount) {
        bm_identity_start_session($portalAccount, 'ct400_portal');
        audit($db, 'login');
    }
    bm_request_diagnostic('auto_login_complete', $portalAccount ? 'login_established' : 'login_unavailable');
}

// Public unsubscribe endpoint. No login required.
if ($page==='unsubscribe') {
    $token=preg_replace('/[^a-f0-9]/','',strtolower($_GET['t'] ?? ''));
    layout_start('Unsubscribe');
    if (strlen($token)<32) { echo '<div class="card"><h1>Invalid unsubscribe link</h1></div>'; layout_end(); exit; }
    $s=$db->prepare('SELECT mr.email,m.acting_for_user_id,m.id mailing_id,u.organisation FROM mailing_recipients mr JOIN mailings m ON m.id=mr.mailing_id JOIN users u ON u.id=m.acting_for_user_id WHERE mr.unsubscribe_token=?');
    $s->execute([$token]); $r=$s->fetch();
    if (!$r) { echo '<div class="card"><h1>Unsubscribe link not found</h1></div>'; layout_end(); exit; }
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf();
        $ins=$db->prepare('INSERT INTO suppressions(owner_user_id,email,reason,source_mailing_id) VALUES(?,?,"unsubscribe",?) ON CONFLICT(owner_user_id,email) DO UPDATE SET reason="unsubscribe",source_mailing_id=excluded.source_mailing_id,created_at=CURRENT_TIMESTAMP');
        $ins->execute([(int)$r['acting_for_user_id'],normal_email($r['email']),(int)$r['mailing_id']]);
        echo '<div class="card"><h1>Unsubscribed</h1><p>'.h($r['email']).' will no longer receive marketing emails from '.h($r['organisation'] ?: 'this organisation').'.</p></div>'; layout_end(); exit;
    }
    echo '<div class="card"><h1>Unsubscribe</h1><p>Stop marketing emails to <b>'.h($r['email']).'</b> from '.h($r['organisation'] ?: 'this organisation').'?</p><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><button class="danger">Unsubscribe</button></form></div>'; layout_end(); exit;
}

if ($page==='login') {
    if (logged_in()) redirect('?');
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        if (($_POST['login_method'] ?? '')==='portal') {
            check_csrf();
            $portalAccount=bm_identity_try_portal_login($db);
            if ($portalAccount) {
                bm_identity_start_session($portalAccount, 'ct400_portal');
                audit($db, 'login'); redirect('?');
            }
            flash('Sign in to the work portal using a linked account, then try work sign-in again. Your local login is still available.', 'error');
            redirect('?page=login');
        }
        check_csrf(); $username=trim($_POST['username'] ?? ''); $password=$_POST['password'] ?? ''; $addr=ip();
        $s=$db->prepare("SELECT COUNT(*) FROM login_attempts WHERE username=? AND ip_address=? AND success=0 AND created_at >= datetime('now','-15 minutes')"); $s->execute([$username,$addr]);
        if ((int)$s->fetchColumn()>=8) { flash('Too many failed attempts. Try again later.','error'); redirect('?page=login'); }
        $method=($_POST['login_method'] ?? 'local')==='ct400'?'ct400':'local';
        if ($method==='ct400') {
            try { $u=bm_identity_try_login($db,$username,$password,(string)($_POST['code'] ?? '')); }
            catch (Throwable $e) { $u=null; }
            $ok=(bool)$u;
        } else {
            $s=$db->prepare('SELECT * FROM users WHERE username=? AND active=1'); $s->execute([$username]); $u=$s->fetch();
            $ok=$u && password_verify($password,$u['password_hash']);
        }
        $a=$db->prepare('INSERT INTO login_attempts(username,ip_address,success) VALUES(?,?,?)'); $a->execute([$username,$addr,$ok?1:0]);
        if ($ok) {
            bm_identity_start_session($u, $method);
            audit($db,'login'); redirect('?');
        }
        flash('Login failed.','error');
    }
    layout_start('Login'); echo '<div class="card" style="max-width:520px;margin:70px auto"><h1>'.APP_NAME.'</h1><form method="post"><input type="hidden" name="csrf" value="'.csrf().'">';
    if (bm_integration_config()['identity']['enabled']) echo '<label>Account</label><select name="login_method"><option value="local">Existing Bulk Mail account</option><option value="ct400">Linked CT400 work account</option></select>';
    echo '<label>Username</label><input name="username" autocomplete="username" required autofocus><label>Password</label><input type="password" name="password" autocomplete="current-password" required>';
    if (bm_integration_config()['identity']['enabled']) echo '<label>CT400 verification code (if required)</label><input name="code" inputmode="numeric" autocomplete="one-time-code"><p class="small">Your existing Bulk Mail account continues to work. Work accounts must first be linked by an administrator.</p>';
    echo '<p><button>Log in</button></p></form>';
    $identityConfig=bm_identity_config();
    if (($identityConfig['enabled'] ?? false)===true && ($identityConfig['auto_login'] ?? false)===true) {
        echo '<hr><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="login_method" value="portal"><button class="secondary">Sign in with work portal</button><p class="small">Use the account already signed in at your work portal. Your existing Bulk Mail password still works above.</p></form>';
    }
    echo '</div>'; layout_end(); exit;
}
if ($page==='logout') {
    if (logged_in()) audit($db,'logout');
    $_SESSION=[]; session_regenerate_id(true);
    $_SESSION['portal_auto_login_suppressed']=true;
    redirect('?page=login');
}
require_login();

bm_identity_handle($db,$page);
require_once __DIR__.'/bulkmail-messaging.php';
bm_messaging_handle($db,$page);

require_once __DIR__.'/bulkmail-draft.php';
require_once __DIR__.'/bulkmail-reliability.php';
bulkmail_handle_draft_api($db, $page);
require_once __DIR__.'/bulkmail-v22.php';
require_once __DIR__.'/bulkmail-spell.php';

if ($page==='draft_asset') {
    $token=preg_replace('/[^a-f0-9]/','',strtolower($_GET['token'] ?? '')); $file=basename($_GET['f'] ?? '');
    if (($token !== ($_SESSION['draft']['token'] ?? '')) || !preg_match('/^page-\\d{3}\\.jpg$/',$file)) { http_response_code(404); exit; }
    $path=DATA_DIR.'/drafts/'.$token.'/brochure/'.$file; if (!is_file($path)) { http_response_code(404); exit; }
    header('Content-Type: image/jpeg'); header('Content-Length: '.filesize($path)); readfile($path); exit;
}

if ($page==='home') {
    $uid=(int)$_SESSION['user_id'];
    if (is_admin()) { $users=(int)$db->query('SELECT COUNT(*) FROM users WHERE active=1')->fetchColumn(); $domains=(int)$db->query('SELECT COUNT(*) FROM domains WHERE active=1')->fetchColumn(); $contacts=(int)$db->query('SELECT COUNT(*) FROM contacts WHERE active=1')->fetchColumn(); $queued=(int)$db->query("SELECT COUNT(*) FROM mailing_recipients WHERE status='queued'")->fetchColumn(); }
    else { $s=$db->prepare('SELECT COUNT(*) FROM contacts WHERE owner_user_id=? AND active=1'); $s->execute([$uid]); $contacts=(int)$s->fetchColumn(); $users=1; $domains=0; $s=$db->prepare("SELECT COUNT(*) FROM mailing_recipients mr JOIN mailings m ON m.id=mr.mailing_id WHERE m.acting_for_user_id=? AND mr.status='queued'"); $s->execute([$uid]); $queued=(int)$s->fetchColumn(); }
    layout_start('Home'); echo '<h1>Bulk Email</h1><div class="warning"><b>LIVE DELIVERY:</b> CT300 submits mail through Postfix to mx2.the-grange.uk at the configured drip rate. We can abuse the UI without emailing half of Derby.</div><div class="grid" style="margin-top:18px">';
    if (is_admin()) echo '<div class="card"><div class="stat">'.$users.'</div>Users</div><div class="card"><div class="stat">'.$domains.'</div>Domains</div>';
    echo '<div class="card"><div class="stat">'.$contacts.'</div>Contacts</div><div class="card"><div class="stat">'.$queued.'</div>Queued recipients</div></div>';
    if(is_admin()){
        echo '<div class="card"><h2>Send Email for Client / User</h2><table><tr><th>User</th><th>Organisation</th><th>Type</th><th></th></tr>';
        foreach($db->query('SELECT * FROM users WHERE active=1 ORDER BY display_name') as $hu){
            echo '<tr><td>'.h($hu['display_name']).'</td><td>'.h($hu['organisation']).'</td><td><span class="pill '.h($hu['account_type']).'">'.h($hu['account_type']).'</span></td><td><a class="button good" href="?page=compose&amp;acting_for='.(int)$hu['id'].'">Send Email</a></td></tr>';
        }
        echo '</table></div>';
    }else{
        echo '<div class="card"><a class="button good" href="?page=compose">Send Email</a></div>';
    }
    layout_end(); exit;
}

if ($page==='users') {
    require_admin();
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf(); $action=$_POST['action'] ?? '';
        if ($action==='create') {
            $un=trim($_POST['username'] ?? ''); $name=trim($_POST['display_name'] ?? ''); $pw=$_POST['password'] ?? ''; $type=$_POST['account_type'] ?? 'internal';
            if (!in_array($type,['internal','marketing'],true)) $type='internal';
            if ($un===''||$name===''||strlen($pw)<8) { flash('Username, display name and password of at least 8 characters required.','error'); redirect('?page=users'); }
            try { $s=$db->prepare('INSERT INTO users(username,password_hash,display_name,email,organisation,account_type,is_admin) VALUES(?,?,?,?,?,?,?)'); $s->execute([$un,password_hash($pw,PASSWORD_DEFAULT),$name,normal_email($_POST['email'] ?? ''),trim($_POST['organisation'] ?? ''),$type,!empty($_POST['is_admin'])?1:0]); $new=(int)$db->lastInsertId(); $db->prepare('INSERT INTO organisation_settings(user_id,footer_name) VALUES(?,?)')->execute([$new,trim($_POST['organisation'] ?? '')]); audit($db,'user_create',$un.' type='.$type); flash('User created.'); }
            catch(Throwable $e){ flash('Could not create user: '.$e->getMessage(),'error'); }
            redirect('?page=users');
        }
        if ($action==='save') {
            $id=(int)$_POST['user_id']; $type=$_POST['account_type'] ?? 'internal'; if (!in_array($type,['internal','marketing'],true)) $type='internal';
            $s=$db->prepare('UPDATE users SET display_name=?,email=?,organisation=?,account_type=?,updated_at=CURRENT_TIMESTAMP WHERE id=?'); $s->execute([trim($_POST['display_name'] ?? ''),normal_email($_POST['email'] ?? ''),trim($_POST['organisation'] ?? ''),$type,$id]); audit($db,'user_update','id='.$id.' type='.$type); flash('User updated.'); redirect('?page=users&manage='.$id);
        }
        if ($action==='assign_domains') {
            $id=(int)$_POST['user_id']; $ids=array_unique(array_map('intval',$_POST['domains'] ?? [])); $db->beginTransaction(); $db->prepare('DELETE FROM user_domains WHERE user_id=?')->execute([$id]); $ins=$db->prepare('INSERT INTO user_domains(user_id,domain_id) VALUES(?,?)'); foreach($ids as $d)$ins->execute([$id,$d]); $db->commit(); audit($db,'domain_assign','user='.$id.' domains='.implode(',',$ids)); flash('Domains saved.'); redirect('?page=users&manage='.$id);
        }
        if ($action==='password') { $id=(int)$_POST['user_id']; $pw=$_POST['password'] ?? ''; if(strlen($pw)<8)flash('Password must be at least 8 characters.','error'); else{$db->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($pw,PASSWORD_DEFAULT),$id]);audit($db,'password_reset','user='.$id);flash('Password changed.');} redirect('?page=users&manage='.$id); }
    }
    $users=$db->query('SELECT * FROM users ORDER BY display_name')->fetchAll(); layout_start('Users'); echo '<h1>Users / Clients</h1><div class="card"><h2>Create User</h2><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="create"><div class="grid"><div><label>Username</label><input name="username" required></div><div><label>Display name</label><input name="display_name" required></div><div><label>Organisation</label><input name="organisation"></div><div><label>Email / test-to-self address</label><input type="email" name="email"></div><div><label>Account type</label><select name="account_type"><option value="internal">Internal Client</option><option value="marketing">Marketing</option></select></div><div><label>Initial password</label><input type="password" name="password" required></div></div><label class="checkrow"><input type="checkbox" name="is_admin" value="1"> Administrator</label><p><button>Create User</button></p></form></div><div class="card"><table><tr><th>Name</th><th>Organisation</th><th>Username</th><th>Type</th><th></th></tr>';
    foreach($users as $u) echo '<tr><td>'.h($u['display_name']).'</td><td>'.h($u['organisation']).'</td><td>'.h($u['username']).'</td><td><span class="pill '.h($u['account_type']).'">'.($u['account_type']==='marketing'?'Marketing':'Internal Client').'</span></td><td><a class="button secondary" href="?page=users&manage='.(int)$u['id'].'">Manage</a></td></tr>';
    echo '</table></div>';
    if (!empty($_GET['manage'])) { $id=(int)$_GET['manage']; $u=user($db,$id); if($u){ echo '<div class="card"><h2>Manage '.h($u['display_name']).'</h2><p><a class="button" href="?page=contacts&user='.$id.'">Contacts</a><a class="button" href="?page=groups&user='.$id.'">Groups</a><a class="button" href="?page=senders&user='.$id.'">Sender Addresses</a><a class="button" href="?page=compliance&user='.$id.'">Compliance</a></p><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="save"><input type="hidden" name="user_id" value="'.$id.'"><div class="grid"><div><label>Display name</label><input name="display_name" value="'.h($u['display_name']).'"></div><div><label>Organisation</label><input name="organisation" value="'.h($u['organisation']).'"></div><div><label>Email / test-to-self</label><input type="email" name="email" value="'.h($u['email']).'"></div><div><label>Account type</label><select name="account_type"><option value="internal"'.($u['account_type']==='internal'?' selected':'').'>Internal Client</option><option value="marketing"'.($u['account_type']==='marketing'?' selected':'').'>Marketing</option></select></div></div><p class="small">Changing account type is reversible. Suppression history is retained if you switch back to Internal Client.</p><button>Save User</button></form>';
        $domains=$db->query('SELECT * FROM domains WHERE active=1 ORDER BY domain')->fetchAll(); $s=$db->prepare('SELECT domain_id FROM user_domains WHERE user_id=?');$s->execute([$id]);$assigned=array_map('intval',array_column($s->fetchAll(),'domain_id'));
        echo '<h3>Assigned Domains</h3><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="assign_domains"><input type="hidden" name="user_id" value="'.$id.'"><div class="groupbox">'; foreach($domains as $d)echo '<label class="checkrow"><input type="checkbox" name="domains[]" value="'.(int)$d['id'].'"'.(in_array((int)$d['id'],$assigned,true)?' checked':'').'> '.h($d['domain']).'</label>'; echo '</div><button>Save Domains</button></form><h3>Change Password</h3><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="password"><input type="hidden" name="user_id" value="'.$id.'"><input type="password" name="password" placeholder="New password"><button class="secondary">Set Password</button></form></div>'; }}
    layout_end(); exit;
}

if ($page==='domains') {
    require_admin(); if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$domain=strtolower(trim($_POST['domain']??''));$domain=preg_replace('#^https?://#','',$domain);$domain=rtrim($domain,'/');if(!preg_match('/^[a-z0-9.-]+\\.[a-z]{2,}$/i',$domain)){flash('Invalid domain.','error');redirect('?page=domains');}try{$db->prepare('INSERT INTO domains(domain,description) VALUES(?,?)')->execute([$domain,trim($_POST['description']??'')]);audit($db,'domain_create',$domain);flash('Domain added.');}catch(Throwable $e){flash('Domain already exists or could not be added.','error');}redirect('?page=domains');}
    layout_start('Domains'); echo '<h1>Domains</h1><div class="card"><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><label>Domain</label><input name="domain" placeholder="example.co.uk" required><label>Description</label><input name="description"><button>Add Domain</button></form></div><div class="card"><table><tr><th>Domain</th><th>Description</th><th>Users</th></tr>';
    foreach($db->query('SELECT d.*,COUNT(ud.user_id) users FROM domains d LEFT JOIN user_domains ud ON ud.domain_id=d.id GROUP BY d.id ORDER BY d.domain') as $d) echo '<tr><td>'.h($d['domain']).'</td><td>'.h($d['description']).'</td><td>'.(int)$d['users'].'</td></tr>'; echo '</table></div>'; layout_end(); exit;
}

if ($page==='senders') {
    $owner=is_admin()?(int)($_GET['user']??$_POST['owner_user_id']??$_SESSION['user_id']):(int)$_SESSION['user_id']; allowed_context($db,$owner);
    if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$email=normal_email($_POST['email']??'');$label=trim($_POST['label']??'');if(!filter_var($email,FILTER_VALIDATE_EMAIL)){flash('Invalid sender email.','error');redirect('?page=senders&user='.$owner);} $domainPart=substr(strrchr($email,'@')?:'',1);$s=$db->prepare('SELECT d.id FROM domains d JOIN user_domains ud ON ud.domain_id=d.id WHERE ud.user_id=? AND d.domain=? COLLATE NOCASE');$s->execute([$owner,$domainPart]);$did=$s->fetchColumn();if(!$did){flash('Assign the domain to this user first.','error');redirect('?page=senders&user='.$owner);}try{$db->prepare('INSERT INTO sender_identities(owner_user_id,domain_id,label,email) VALUES(?,?,?,?)')->execute([$owner,$did,$label,$email]);audit($db,'sender_create','owner='.$owner.' '.$email);flash('Sender added.');}catch(Throwable $e){flash('Sender already exists for this user.','error');}redirect('?page=senders&user='.$owner);}
    layout_start('Senders'); if(is_admin()){echo '<div class="card"><label>Manage sender addresses for</label><select onchange="location=\'?page=senders&user=\'+this.value">';foreach($db->query('SELECT * FROM users WHERE active=1 ORDER BY display_name') as $u)echo '<option value="'.(int)$u['id'].'"'.((int)$u['id']===$owner?' selected':'').'>'.h($u['display_name']).'</option>';echo '</select></div>';} $ou=user($db,$owner); echo '<h1>Sender Addresses - '.h($ou['display_name']).'</h1><div class="card"><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="owner_user_id" value="'.$owner.'"><label>Description</label><input name="label" required><label>Email</label><input type="email" name="email" required><button>Add Sender</button></form></div><div class="card"><table><tr><th>Description</th><th>Email</th><th>Domain</th></tr>';$s=$db->prepare('SELECT s.*,d.domain FROM sender_identities s LEFT JOIN domains d ON d.id=s.domain_id WHERE s.owner_user_id=? ORDER BY s.email');$s->execute([$owner]);foreach($s as $r)echo '<tr><td>'.h($r['label']).'</td><td>'.h($r['email']).'</td><td>'.h($r['domain']).'</td></tr>';echo '</table></div>';layout_end();exit;
}

if ($page==='contacts') {
    $owner=current_context($db);
    allowed_context($db,$owner);

    $contactForm=null;
    $contactFormGroups=[];
    $contactConflict=null;
    if($_SERVER['REQUEST_METHOD']==='POST'){
        check_csrf();
        $action=$_POST['action']??'save';

        if($action==='save'){
            $email=normal_email($_POST['email']??'');

            $id=max(0,(int)($_POST['id']??0));
            $groupIds=array_values(array_unique(array_map('intval',(array)($_POST['groups']??[]))));
            $contactForm=['id'=>$id,'email'=>trim($_POST['email']??'')];
            foreach(['name','company','telephone','unit_name','unit_number','notes','lawful_basis','source','source_date'] as $field){
                $contactForm[$field]=trim($_POST[$field]??'');
            }
            $contactFormGroups=$groupIds;

            try{
                if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
                    throw new DomainException('Enter a valid email address.');
                }
                $db->beginTransaction();

                if($id){
                    $check=$db->prepare('SELECT id FROM contacts WHERE id=? AND owner_user_id=?');
                    $check->execute([$id,$owner]);
                    if(!$check->fetchColumn()){
                        throw new DomainException('Contact does not belong to this address book.');
                    }
                    $duplicate=$db->prepare('SELECT id,name,active FROM contacts WHERE owner_user_id=? AND email=? COLLATE NOCASE AND id<>? ORDER BY active DESC,id LIMIT 1');
                    $duplicate->execute([$owner,$email,$id]);
                    $contactConflict=$duplicate->fetch()?:null;
                    if($contactConflict){
                        $label=trim((string)$contactConflict['name'])?:'an unnamed contact';
                        if((int)$contactConflict['active']===1){
                            throw new DomainException('That email address already belongs to '.$label.' in this address book. Open the existing contact or use a different email address.');
                        }
                        throw new DomainException('That email address belongs to an archived contact ('.$label.'). Add that address as a new contact to restore the archived entry.');
                    }
                }

                $vals=[
                    trim($_POST['name']??''),
                    trim($_POST['company']??''),
                    $email,
                    trim($_POST['telephone']??''),
                    trim($_POST['unit_name']??''),
                    trim($_POST['unit_number']??''),
                    trim($_POST['notes']??''),
                    trim($_POST['lawful_basis']??''),
                    trim($_POST['source']??''),
                    trim($_POST['source_date']??'')
                ];

                if($id){
                    $s=$db->prepare(
                        'UPDATE contacts
                         SET name=?,company=?,email=?,telephone=?,unit_name=?,unit_number=?,
                             notes=?,lawful_basis=?,source=?,source_date=?,updated_at=CURRENT_TIMESTAMP
                         WHERE id=? AND owner_user_id=?'
                    );
                    $s->execute([...$vals,$id,$owner]);

                    if($s->rowCount()===0){
                        $check=$db->prepare('SELECT id FROM contacts WHERE id=? AND owner_user_id=?');
                        $check->execute([$id,$owner]);
                        if(!$check->fetchColumn()){
                            throw new DomainException('Contact does not belong to this address book.');
                        }
                    }
                }else{
                    // Archived records retain their email uniqueness and mailing history.
                    // Reuse the archived record rather than failing with a phantom duplicate.
                    $archived=$db->prepare('SELECT id,active FROM contacts WHERE owner_user_id=? AND email=? COLLATE NOCASE');
                    $archived->execute([$owner,$email]);
                    $existing=$archived->fetch(PDO::FETCH_ASSOC);
                    if($existing && (int)$existing['active']===1){
                        $contactConflict=$existing;
                        throw new DomainException('That email address already belongs to an active contact in this address book. Open the existing contact or use a different email address.');
                    }
                    if($existing){
                        $id=(int)$existing['id'];
                        $reactivate=$db->prepare(
                            'UPDATE contacts SET name=?,company=?,email=?,telephone=?,unit_name=?,unit_number=?,
                              notes=?,lawful_basis=?,source=?,source_date=?,active=1,updated_at=CURRENT_TIMESTAMP
                              WHERE id=? AND owner_user_id=? AND active=0'
                        );
                        $reactivate->execute([...$vals,$id,$owner]);
                    }else{
                        $s=$db->prepare(
                            'INSERT INTO contacts
                             (owner_user_id,name,company,email,telephone,unit_name,unit_number,notes,
                              lawful_basis,source,source_date)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?)'
                        );
                        $s->execute([$owner,...$vals]);
                        $id=(int)$db->lastInsertId();
                    }
                }

                // Replace this contact's group memberships with exactly what was ticked.
                $owned=$db->prepare(
                    'SELECT id FROM groups WHERE id=? AND owner_user_id=?'
                );
                $delete=$db->prepare(
                    'DELETE FROM group_members WHERE contact_id=?'
                );
                $insert=$db->prepare(
                    'INSERT OR IGNORE INTO group_members(group_id,contact_id) VALUES(?,?)'
                );

                $delete->execute([$id]);

                foreach($groupIds as $gid){
                    $owned->execute([$gid,$owner]);
                    if($owned->fetchColumn()){
                        $insert->execute([$gid,$id]);
                    }
                }

                audit(
                    $db,
                    'contact_save',
                    'owner='.$owner.' '.$email.' groups='.implode(',',$groupIds)
                );
                $db->commit();
                flash('Contact saved.');
                redirect('?page=contacts&user='.$owner);
            }catch(Throwable $e){
                if($db->inTransaction()){
                    $db->rollBack();
                }

                // PDOException extends RuntimeException: never display database errors.
                if($e instanceof DomainException){
                    $message=$e->getMessage();
                }elseif($e instanceof PDOException && (string)$e->getCode()==='23000' && str_contains($e->getMessage(),'contacts.owner_user_id, contacts.email')){
                    $message='That email address is already in use in this address book. Your changes have not been saved.';
                }else{
                    error_log('Bulk mail contact save failed: '.$e->getMessage());
                    $message='Could not save this contact. Your changes are still shown below; please try again.';
                }
                flash($message,'error');
            }
        }

        if($action==='import' && isset($_FILES['csv'])){
            $fh=fopen($_FILES['csv']['tmp_name'],'r');
            $head=array_map(
                fn($x)=>strtolower(trim((string)$x)),
                fgetcsv($fh)?:[]
            );

            $new=$upd=0;

            while(($row=fgetcsv($fh))!==false){
                $d=[];
                foreach($head as $i=>$k){
                    $d[$k]=trim((string)($row[$i]??''));
                }

                $email=normal_email($d['email']??'');
                if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
                    continue;
                }

                $s=$db->prepare(
                    'SELECT id FROM contacts WHERE owner_user_id=? AND email=?'
                );
                $s->execute([$owner,$email]);
                $id=$s->fetchColumn();

                $vals=[
                    $d['name']??'',
                    $d['company']??'',
                    $d['telephone']??'',
                    $d['unit_name']??($d['unit']??''),
                    $d['unit_number']??'',
                    $d['notes']??'',
                    $d['lawful_basis']??'',
                    $d['source']??'',
                    $d['source_date']??''
                ];

                if($id){
                    $db->prepare(
                        'UPDATE contacts
                         SET name=?,company=?,telephone=?,unit_name=?,unit_number=?,notes=?,
                             lawful_basis=?,source=?,source_date=?,updated_at=CURRENT_TIMESTAMP
                         WHERE id=?'
                    )->execute([...$vals,$id]);
                    $upd++;
                }else{
                    $db->prepare(
                        'INSERT INTO contacts
                         (owner_user_id,name,company,email,telephone,unit_name,unit_number,notes,
                          lawful_basis,source,source_date)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?)'
                    )->execute([
                        $owner,$vals[0],$vals[1],$email,$vals[2],$vals[3],$vals[4],
                        $vals[5],$vals[6],$vals[7],$vals[8]
                    ]);
                    $id=(int)$db->lastInsertId();
                    $new++;
                }

                if(!empty($d['groups'])){
                    foreach(preg_split('/[;|,]+/',$d['groups']) as $gn){
                        $gn=trim($gn);
                        if($gn===''){
                            continue;
                        }

                        $db->prepare(
                            'INSERT OR IGNORE INTO groups(owner_user_id,name) VALUES(?,?)'
                        )->execute([$owner,$gn]);

                        $g=$db->prepare(
                            'SELECT id FROM groups
                             WHERE owner_user_id=? AND name=? COLLATE NOCASE'
                        );
                        $g->execute([$owner,$gn]);
                        $gid=(int)$g->fetchColumn();

                        $db->prepare(
                            'INSERT OR IGNORE INTO group_members(group_id,contact_id)
                             VALUES(?,?)'
                        )->execute([$gid,$id]);
                    }
                }
            }

            fclose($fh);
            audit($db,'contact_import','owner='.$owner.' new='.$new.' updated='.$upd);
            flash("CSV imported: $new new, $upd updated.");
            redirect('?page=contacts&user='.$owner);
        }
    }

    $edit=$contactForm;
    if($contactForm===null && !empty($_GET['edit'])){
        $s=$db->prepare(
            'SELECT * FROM contacts WHERE id=? AND owner_user_id=?'
        );
        $s->execute([(int)$_GET['edit'],$owner]);
        $edit=$s->fetch();
    }

    // Groups available to this user's address book.
    $groupStmt=$db->prepare(
        'SELECT g.*,COUNT(gm.contact_id) members
         FROM groups g
         LEFT JOIN group_members gm ON gm.group_id=g.id
         WHERE g.owner_user_id=?
         GROUP BY g.id
         ORDER BY g.name'
    );
    $groupStmt->execute([$owner]);
    $availableGroups=$groupStmt->fetchAll();

    $selectedGroups=$contactForm!==null?$contactFormGroups:[];
    if($contactForm===null && $edit){
        $selectedStmt=$db->prepare(
            'SELECT gm.group_id
             FROM group_members gm
             JOIN groups g ON g.id=gm.group_id
             WHERE gm.contact_id=? AND g.owner_user_id=?'
        );
        $selectedStmt->execute([(int)$edit['id'],$owner]);
        $selectedGroups=array_map(
            'intval',
            array_column($selectedStmt->fetchAll(),'group_id')
        );
    }

    layout_start('Contacts');

    if(is_admin()){
        echo '<div class="card">';
        echo '<label>Address book for</label>';
        echo '<select onchange="location=\'?page=contacts&user=\'+this.value">';
        foreach($db->query('SELECT * FROM users WHERE active=1 ORDER BY display_name') as $u){
            echo '<option value="'.(int)$u['id'].'"'.((int)$u['id']===$owner?' selected':'').'>'.h($u['display_name']).'</option>';
        }
        echo '</select>';
        echo '</div>';
    }

    $ou=user($db,$owner);

    echo '<h1>Contacts - '.h($ou['display_name']).'</h1>';

    echo '<div class="card">';
    $isContactEdit=(int)($edit['id']??0)>0;
    echo '<h2>'.($isContactEdit?'Edit':'Add').' Contact</h2>';
    if($contactConflict && (int)$contactConflict['active']===1){
        echo '<p><a class="button secondary" href="?page=contacts&amp;user='.$owner.'&amp;edit='.(int)$contactConflict['id'].'">Open existing contact</a></p>';
    }
    echo '<p class="small">One contact entry per email address. The same person can have separate entries for separate units, provided each uses a different email. Re-entering an archived email restores that contact.</p>';
    echo '<form method="post">';
    echo '<input type="hidden" name="csrf" value="'.csrf().'">';
    echo '<input type="hidden" name="action" value="save">';
    echo '<input type="hidden" name="id" value="'.(int)($edit['id']??0).'">';

    echo '<div class="grid">';
    echo '<div><label>Name</label><input name="name" value="'.h($edit['name']??'').'"></div>';
    echo '<div><label>Email</label><input type="email" name="email" required value="'.h($edit['email']??'').'"></div>';
    echo '<div><label>Company</label><input name="company" value="'.h($edit['company']??'').'"></div>';
    echo '<div><label>Telephone</label><input name="telephone" value="'.h($edit['telephone']??'').'"></div>';
    echo '<div><label>Masonic Unit Name</label><input name="unit_name" value="'.h($edit['unit_name']??'').'"></div>';
    echo '<div><label>Masonic Unit Number</label><input name="unit_number" value="'.h($edit['unit_number']??'').'"></div>';
    echo '<div><label>Lawful basis / marketing basis</label><input name="lawful_basis" value="'.h($edit['lawful_basis']??'').'"></div>';
    echo '<div><label>Source</label><input name="source" value="'.h($edit['source']??'').'"></div>';
    echo '<div><label>Source date</label><input type="date" name="source_date" value="'.h($edit['source_date']??'').'"></div>';
    echo '</div>';

    echo '<label>Groups</label>';

    if(!$availableGroups){
        echo '<div class="safe">';
        echo 'No groups exist for this user yet. The contact can still be saved as an individual contact.';
        echo '</div>';
    }else{
        echo '<div class="groupbox">';
        foreach($availableGroups as $g){
            $checked=in_array((int)$g['id'],$selectedGroups,true)?' checked':'';
            echo '<label class="checkrow">';
            echo '<input type="checkbox" name="groups[]" value="'.(int)$g['id'].'"'.$checked.'>';
            echo '<span>'.h($g['name']).' <span class="small">('.(int)$g['members'].' members)</span></span>';
            echo '</label>';
        }
        echo '</div>';
        echo '<p class="small">A contact may belong to any number of groups. Leave all unticked for an individual-only contact.</p>';
    }

    echo '<label>Notes</label>';
    echo '<textarea name="notes">'.h($edit['notes']??'').'</textarea>';

    echo '<p><button>Save Contact</button>';
    if($edit){
        echo ' <a class="button secondary" href="?page=contacts&user='.$owner.'">'.($isContactEdit?'Cancel Edit':'Clear Form').'</a>';
    }
    echo '</p>';
    echo '</form>';
    echo '</div>';

    echo '<div class="card">';
    echo '<h2>CSV Import</h2>';
    echo '<p class="small">Columns: name,email,company,telephone,unit_name,unit_number,notes,groups,lawful_basis,source,source_date</p>';
    echo '<form method="post" enctype="multipart/form-data">';
    echo '<input type="hidden" name="csrf" value="'.csrf().'">';
    echo '<input type="hidden" name="action" value="import">';
    echo '<input type="file" name="csv" accept=".csv,text/csv" required>';
    echo '<button>Import CSV</button>';
    echo '</form>';
    echo '</div>';

    $s=$db->prepare(
        'SELECT c.*,GROUP_CONCAT(g.name,", ") groups
         FROM contacts c
         LEFT JOIN group_members gm ON gm.contact_id=c.id
         LEFT JOIN groups g ON g.id=gm.group_id
         WHERE c.owner_user_id=? AND c.active=1
         GROUP BY c.id
         ORDER BY c.name,c.email'
    );
    $s->execute([$owner]);

    echo '<div class="card">';
    echo '<h2>Contact Maintenance</h2><p class="small">Select one or more contacts, then add them to a group, move them to a group, remove them from a group, or remove them from the system.</p>';
    echo '<form method="post" id="contactBulkForm" onsubmit="return bulkContactConfirm(this)">';
    echo '<input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="bulk"><input type="hidden" name="acting_for" value="'.$owner.'">';
    echo '<div class="grid"><div><label>Action</label><select name="bulk_action" required><option value="">Choose...</option><option value="add_group">Add to group</option><option value="move_group">Move to group</option><option value="remove_group">Remove from group only</option><option value="delete_system">Delete from system</option></select></div>';
    echo '<div><label>Group</label><select name="target_group"><option value="">Choose group...</option>';foreach($availableGroups as $g)echo '<option value="'.(int)$g['id'].'">'.h($g['name']).'</option>';echo '</select></div></div>';
    echo '<p><button class="secondary">Apply to Selected Contacts</button> <button type="button" class="secondary" onclick="document.querySelectorAll(\'.contact-maint-check\').forEach(function(x){x.checked=true})">Select All</button> <button type="button" class="secondary" onclick="document.querySelectorAll(\'.contact-maint-check\').forEach(function(x){x.checked=false})">Clear</button></p>';
    echo '<table>';
    echo '<tr><th></th><th>Name</th><th>Email</th><th>Telephone</th><th>Unit</th><th>Groups</th><th></th></tr>';

    foreach($s as $c){
        echo '<tr>';
        echo '<td><input class="contact-maint-check" type="checkbox" name="contact_ids[]" value="'.(int)$c['id'].'"></td>';
        echo '<td>'.h($c['name']).'</td>';
        echo '<td>'.h($c['email']).'</td>';
        echo '<td>'.h($c['telephone']).'</td>';
        echo '<td>'.h(trim(($c['unit_name']??'').' '.($c['unit_number']??''))).'</td>';
        echo '<td>'.h($c['groups']).'</td>';
        echo '<td><a class="button secondary" href="?page=contacts&user='.$owner.'&edit='.(int)$c['id'].'">Edit</a></td>';
        echo '</tr>';
    }

    echo '</table></form>';
    echo '<script>function bulkContactConfirm(f){var a=f.bulk_action.value;if(!a){alert("Choose an action.");return false}if((a==="add_group"||a==="move_group"||a==="remove_group")&&!f.target_group.value){alert("Choose a group.");return false}if(a==="delete_system")return confirm("Remove the selected contacts from the system? Mailing history will be retained.");return true}</script>';
    echo '</div>';

    layout_end();
    exit;
}

if ($page==='groups') {
    $owner=current_context($db);allowed_context($db,$owner);
    if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$action=$_POST['action']??'';if($action==='create'){try{$db->prepare('INSERT INTO groups(owner_user_id,name) VALUES(?,?)')->execute([$owner,trim($_POST['name']??'')]);flash('Group created.');}catch(Throwable $e){flash('Group already exists.','error');}redirect('?page=groups&user='.$owner);}if(in_array($action,['rename','delete','merge'],true)){
 $gid=(int)($_POST['group_id']??0);
 $q=$db->prepare('SELECT id,name FROM groups WHERE id=? AND owner_user_id=?');$q->execute([$gid,$owner]);$group=$q->fetch();
 if(!$group){http_response_code(403);exit;}
 if($action==='rename'){
  $name=trim($_POST['name']??'');
  if($name===''){flash('Group name cannot be empty.','error');}
  else {try{$db->prepare('UPDATE groups SET name=? WHERE id=? AND owner_user_id=?')->execute([$name,$gid,$owner]);audit($db,'group_rename','owner='.$owner.' id='.$gid);flash('Group renamed.');}catch(Throwable $e){flash('That group name already exists.','error');}}
 }elseif($action==='merge'){
  $target=(int)($_POST['target_group_id']??0);
  $q=$db->prepare('SELECT id FROM groups WHERE id=? AND owner_user_id=?');$q->execute([$target]);
  if($target===$gid||!$q->fetchColumn()){flash('Choose a different destination group.','error');}
  else{$db->beginTransaction();
   $db->prepare('INSERT OR IGNORE INTO group_members(group_id,contact_id) SELECT ?,contact_id FROM group_members WHERE group_id=?')->execute([$target,$gid]);
   $db->prepare('DELETE FROM group_members WHERE group_id=?')->execute([$gid]);
   $db->prepare('DELETE FROM groups WHERE id=? AND owner_user_id=?')->execute([$gid,$owner]);
   $db->commit();audit($db,'group_merge','owner='.$owner.' source='.$gid.' target='.$target);flash('Groups merged. Contacts preserved.');}
 }else{
  if(($_POST['confirm_name']??'')!==$group['name']){flash('Deletion not confirmed: enter the exact group name.','error');}
  else{$db->beginTransaction();$db->prepare('DELETE FROM group_members WHERE group_id=?')->execute([$gid]);$db->prepare('DELETE FROM groups WHERE id=? AND owner_user_id=?')->execute([$gid,$owner]);$db->commit();audit($db,'group_delete','owner='.$owner.' id='.$gid);flash('Group deleted; contacts retained.');}
 }
 redirect('?page=groups&user='.$owner);
}
if($action==='members'){$gid=(int)$_POST['group_id'];$chk=$db->prepare('SELECT id FROM groups WHERE id=? AND owner_user_id=?');$chk->execute([$gid,$owner]);if(!$chk->fetchColumn()){http_response_code(403);exit;} $ids=array_unique(array_map('intval',$_POST['contacts']??[]));$db->beginTransaction();$db->prepare('DELETE FROM group_members WHERE group_id=?')->execute([$gid]);$ins=$db->prepare('INSERT INTO group_members(group_id,contact_id) SELECT ?,id FROM contacts WHERE id=? AND owner_user_id=?');foreach($ids as $cid)$ins->execute([$gid,$cid,$owner]);$db->commit();audit($db,'group_members','owner='.$owner.' group='.$gid.' count='.count($ids));flash('Group membership saved.');redirect('?page=groups&user='.$owner);}}
    layout_start('Group Maintenance');if(is_admin()){echo '<div class="card"><label>Groups for</label><select onchange="location=\'?page=groups&user=\'+this.value">';foreach($db->query('SELECT * FROM users WHERE active=1 ORDER BY display_name') as $u)echo '<option value="'.(int)$u['id'].'"'.((int)$u['id']===$owner?' selected':'').'>'.h($u['display_name']).'</option>';echo '</select></div>';} $ou=user($db,$owner);echo '<h1>Group Maintenance - '.h($ou['display_name']).'</h1><div class="card"><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="create"><label>New group</label><input name="name" required><button>Create Group</button></form></div>';
    $gs=$db->prepare('SELECT g.*,COUNT(gm.contact_id) members FROM groups g LEFT JOIN group_members gm ON gm.group_id=g.id WHERE g.owner_user_id=? GROUP BY g.id ORDER BY g.name');$gs->execute([$owner]);$cs=$db->prepare('SELECT id,name,email FROM contacts WHERE owner_user_id=? AND active=1 ORDER BY name,email');$cs->execute([$owner]);$contacts=$cs->fetchAll();$allGroups=$gs->fetchAll();foreach($allGroups as $g){$ms=$db->prepare('SELECT contact_id FROM group_members WHERE group_id=?');$ms->execute([(int)$g['id']]);$sel=array_map('intval',array_column($ms->fetchAll(),'contact_id'));echo '<div class="card"><h2>'.h($g['name']).' ('.(int)$g['members'].')</h2>';
echo '<form method="post" style="margin-bottom:12px"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="rename"><input type="hidden" name="group_id" value="'.(int)$g['id'].'"><label>Rename group</label><input name="name" value="'.h($g['name']).'" required><button type="submit">Rename</button></form>';
echo '<form method="post" style="margin-bottom:12px"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="merge"><input type="hidden" name="group_id" value="'.(int)$g['id'].'"><label>Merge into</label><select name="target_group_id" required><option value="">Select destination</option>';foreach($allGroups as $other){if($other['id']!=$g['id'])echo '<option value="'.(int)$other['id'].'">'.h($other['name']).'</option>';}echo '</select><button type="submit">Merge Groups</button></form>';
echo '<form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="delete"><input type="hidden" name="group_id" value="'.(int)$g['id'].'"><label>Delete group (type exact group name)</label><input name="confirm_name" required><button type="submit" class="secondary">Delete Group</button></form>';
echo '<form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="members"><input type="hidden" name="group_id" value="'.(int)$g['id'].'"><div class="groupbox">';foreach($contacts as $c)echo '<label class="checkrow"><input type="checkbox" name="contacts[]" value="'.(int)$c['id'].'"'.(in_array((int)$c['id'],$sel,true)?' checked':'').'> '.h($c['name']?:$c['email']).' &lt;'.h($c['email']).'&gt;</label>';echo '</div><button>Save Members</button></form></div>';}layout_end();exit;
}

if ($page==='compliance') {
    require_admin();$owner=(int)($_GET['user']??$_POST['user_id']??$_SESSION['user_id']);$ou=user($db,$owner);if(!$ou){redirect('?page=compliance');}
    if($_SERVER['REQUEST_METHOD']==='POST'){check_csrf();$action=$_POST['action']??'';if($action==='settings'){$s=$db->prepare('INSERT INTO organisation_settings(user_id,privacy_notice_url,footer_name,footer_address,footer_phone,retention_months) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET privacy_notice_url=excluded.privacy_notice_url,footer_name=excluded.footer_name,footer_address=excluded.footer_address,footer_phone=excluded.footer_phone,retention_months=excluded.retention_months');$s->execute([$owner,trim($_POST['privacy_notice_url']??''),trim($_POST['footer_name']??''),trim($_POST['footer_address']??''),trim($_POST['footer_phone']??''),max(1,(int)($_POST['retention_months']??36))]);audit($db,'compliance_settings','owner='.$owner);flash('Compliance settings saved.');redirect('?page=compliance&user='.$owner);}if($action==='suppress'){$email=normal_email($_POST['email']??'');if(filter_var($email,FILTER_VALIDATE_EMAIL)){$db->prepare('INSERT INTO suppressions(owner_user_id,email,reason,created_by_user_id) VALUES(?,?,?,?) ON CONFLICT(owner_user_id,email) DO UPDATE SET reason=excluded.reason,created_at=CURRENT_TIMESTAMP,created_by_user_id=excluded.created_by_user_id')->execute([$owner,$email,trim($_POST['reason']??'manual'),$_SESSION['user_id']]);audit($db,'suppression_add','owner='.$owner.' '.$email);flash('Address suppressed.');}redirect('?page=compliance&user='.$owner);}if($action==='unsuppress'){$id=(int)$_POST['id'];$db->prepare('DELETE FROM suppressions WHERE id=? AND owner_user_id=?')->execute([$id,$owner]);audit($db,'suppression_remove','owner='.$owner.' id='.$id);flash('Suppression removed.');redirect('?page=compliance&user='.$owner);}}
    $s=$db->prepare('SELECT * FROM organisation_settings WHERE user_id=?');$s->execute([$owner]);$o=$s->fetch()?:[];layout_start('Compliance');echo '<h1>Compliance - '.h($ou['display_name']).'</h1><div class="card"><label>Client</label><select onchange="location=\'?page=compliance&user=\'+this.value">';foreach($db->query('SELECT * FROM users WHERE active=1 ORDER BY display_name') as $u)echo '<option value="'.(int)$u['id'].'"'.((int)$u['id']===$owner?' selected':'').'>'.h($u['display_name']).' - '.h($u['account_type']).'</option>';echo '</select><p>Account type: <b>'.h($ou['account_type']).'</b>. Change this under Users → Manage.</p></div><div class="card"><h2>Organisation / Privacy Footer</h2><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="settings"><input type="hidden" name="user_id" value="'.$owner.'"><label>Privacy notice URL</label><input name="privacy_notice_url" value="'.h($o['privacy_notice_url']??'').'"><label>Footer organisation name</label><input name="footer_name" value="'.h($o['footer_name']??$ou['organisation']).'"><label>Footer postal/contact address</label><textarea name="footer_address">'.h($o['footer_address']??'').'</textarea><label>Footer phone</label><input name="footer_phone" value="'.h($o['footer_phone']??'').'"><label>Default retention (months)</label><input type="number" min="1" name="retention_months" value="'.(int)($o['retention_months']??36).'"><button>Save Settings</button></form></div><div class="card"><h2>Suppression List</h2><p class="small">Retained even if the account is switched back to Internal Client. Enforced automatically for Marketing accounts.</p><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="suppress"><input type="hidden" name="user_id" value="'.$owner.'"><div class="grid"><div><label>Email</label><input type="email" name="email" required></div><div><label>Reason</label><input name="reason" value="manual opt-out"></div></div><button>Suppress</button></form><table><tr><th>Email</th><th>Reason</th><th>Date</th><th></th></tr>';$ss=$db->prepare('SELECT * FROM suppressions WHERE owner_user_id=? ORDER BY created_at DESC');$ss->execute([$owner]);foreach($ss as $r)echo '<tr><td>'.h($r['email']).'</td><td>'.h($r['reason']).'</td><td>'.h($r['created_at']).'</td><td><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="unsuppress"><input type="hidden" name="user_id" value="'.$owner.'"><input type="hidden" name="id" value="'.(int)$r['id'].'"><button class="secondary">Remove</button></form></td></tr>';echo '</table></div>';layout_end();exit;
}

if ($page==='audit') { require_admin(); layout_start('Audit'); echo '<h1>Audit Log</h1><div class="card"><table><tr><th>Date</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr>';foreach($db->query('SELECT a.*,u.display_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500') as $r)echo '<tr><td>'.h($r['created_at']).'</td><td>'.h($r['display_name']).'</td><td>'.h($r['action']).'</td><td>'.h($r['details']).'</td><td>'.h($r['ip_address']).'</td></tr>';echo '</table></div>';layout_end();exit; }

if ($page==='compose') {
    // Admin sender selection drives the address-book context. Custom From uses explicit context dropdown.
    $selectedSender=(int)($_GET['sender']??$_POST['sender_identity_id']??0);$actingFor=(int)($_GET['acting_for']??$_POST['acting_for']??$_SESSION['user_id']);
    if(is_admin() && $selectedSender){$s=$db->prepare('SELECT owner_user_id FROM sender_identities WHERE id=? AND active=1');$s->execute([$selectedSender]);$x=$s->fetchColumn();if($x)$actingFor=(int)$x;}
    if((int)$_SESSION['user_id']===2){$selectedSender=2;$actingFor=2;}
    if(!is_admin())$actingFor=(int)$_SESSION['user_id'];$acting=user($db,$actingFor);if(!$acting){$actingFor=(int)$_SESSION['user_id'];$acting=user($db,$actingFor);}

    if($_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf();$action=!empty($_POST['save_draft'])?'save_draft':(!empty($_POST['new_message'])?'new_message':($_POST['action']??'preview'));
        if(in_array($action,['preview','save_draft','new_message'],true))bm_check_workspace($db,(int)$_SESSION['user_id'],$actingFor);
        if($action==='back'){redirect('?page=compose&acting_for='.$actingFor);}
        if(in_array($action,['save_draft','new_message'],true)){
            try{
                bulkmail_store_compose_fields($db,(int)$_SESSION['user_id'],$actingFor,$_POST);
                bm_persist_files($db,(int)$_SESSION['user_id'],$actingFor);
                $id=bm_saved_snapshot($db,(int)$_SESSION['user_id'],$actingFor);
                if($action==='new_message'){
                    bulkmail_clear_compose_draft($db,(int)$_SESSION['user_id'],$actingFor);bm_end_workspace($db,(int)$_SESSION['user_id'],$actingFor,true);
                    bulkmail_forget_prepared($db,$actingFor);unset($_SESSION['draft']);
                    flash('Previous message saved as draft #'.$id.'. New message ready. Nothing was sent.');
                }else{bulkmail_forget_prepared($db,$actingFor);unset($_SESSION['draft']);flash('Draft #'.$id.' saved with recipients, formatting and attachments. Nothing has been sent.');}
            }catch(Throwable $e){flash($e->getMessage(),'error');}
            redirect('?page=compose&acting_for='.$actingFor);
        }
        bulkmail_restore_prepared($db,$actingFor);
        if(in_array($action,['queue','test'],true) && !empty($_POST['draft_token']) && !hash_equals((string)($_SESSION['draft']['token']??''),(string)$_POST['draft_token'])){flash('This preview has been replaced by another draft. Open the current preview before sending. Nothing was sent.','error');redirect('?page=compose&acting_for='.$actingFor);}
        if($action==='cancel'){flash('Draft kept. Nothing was sent.');redirect('?page=compose&acting_for='.$actingFor);}
        if(in_array($action,['queue','test'],true)){
            $d=$_SESSION['draft']??null;if(!$d){flash('Draft expired. Please compose again.','error');redirect('?page=compose');}
            $isTest=$action==='test';$recips=$d['recipients'];if($isTest){$testEmail=normal_email((string)($_SESSION['email']??''));$cu=user($db,(int)$_SESSION['user_id']);$testEmail=normal_email($cu['email']??'');if(!filter_var($testEmail,FILTER_VALIDATE_EMAIL)){flash('Your user account needs a valid email address for Send Test to Myself.','error');redirect('?page=compose&preview=1');}$recips=[['id'=>null,'email'=>$testEmail,'name'=>$cu['display_name']]];}
            if(!$isTest){$guard=$db->prepare('SELECT mailing_id FROM mailing_send_tokens WHERE user_id=? AND draft_token=?');$guard->execute([(int)$_SESSION['user_id'],$d['token']]);$already=$guard->fetchColumn();if($already){unset($_SESSION['draft']);flash('This mailing was already submitted as #'.$already.'. It has not been sent again.');redirect('?page=history');}}
            $current=$db->prepare('SELECT token FROM prepared_compose_drafts WHERE user_id=? AND acting_for_user_id=?');$current->execute([(int)$_SESSION['user_id'],(int)$d['acting_for']]);
            if(!hash_equals((string)($current->fetchColumn()?:''),(string)$d['token'])){unset($_SESSION['draft']);flash('This preview is no longer current. Open your saved draft and preview it again. Nothing was sent.','error');redirect('?page=compose&acting_for='.(int)$d['acting_for']);}
            $db->beginTransaction();try{$queuedBody=$d['body_html'];foreach($d['assets'] as $a){$preview='?page=draft_asset&amp;token='.$d['token'].'&amp;f='.basename($a['path']);$queuedBody=str_replace($preview,'cid:'.$a['cid'],$queuedBody);}$s=$db->prepare('INSERT INTO mailings(initiated_by_user_id,acting_for_user_id,sender_identity_id,sender_email,subject,body_html,selected_count,unique_count,duplicate_count,suppressed_count,status,is_test) VALUES(?,?,?,?,?,?,?,?,?,? ,"queued",?)');$s->execute([$_SESSION['user_id'],$d['acting_for'],$d['sender_id'],$d['sender_email'],$d['subject'],$queuedBody,$isTest?1:$d['selected_count'],$isTest?1:$d['unique_count'],$isTest?0:$d['duplicate_count'],$isTest?0:$d['suppressed_count'],$isTest?1:0]);$mid=(int)$db->lastInsertId();if(!$isTest)$db->prepare('INSERT INTO mailing_send_tokens(user_id,draft_token,mailing_id) VALUES(?,?,?)')->execute([(int)$_SESSION['user_id'],$d['token'],$mid]);$mdir=DATA_DIR.'/mailings/'.$mid;@mkdir($mdir,0750,true);$ins=$db->prepare('INSERT INTO mailing_recipients(mailing_id,contact_id,email,name,unsubscribe_token) VALUES(?,?,?,?,?)');foreach($recips as $r){$contactId=(int)($r['id']??0);$ins->execute([$mid,$contactId?:null,normal_email($r['email']),$r['name']??'',random_token(24)]);$rid=(int)$db->lastInsertId();if(!$isTest && $contactId && !empty($d['recipient_attachments'][$contactId])){foreach($d['recipient_attachments'][$contactId] as $a){$dest=$mdir.'/recipient-'.$rid.'-'.random_token(8).'-'.safe_name($a['original_name']);if(!copy($a['stored_path'],$dest))throw new RuntimeException('Could not store recipient attachment');$db->prepare('INSERT INTO mailing_recipient_attachments(mailing_recipient_id,original_name,stored_path,mime_type,file_size) VALUES(?,?,?,?,?)')->execute([$rid,$a['original_name'],$dest,$a['mime_type'],$a['file_size']]);}}}
                foreach($d['attachments'] as $a){$dest=$mdir.'/att-'.random_token(8).'-'.safe_name($a['original_name']);if(!copy($a['stored_path'],$dest))throw new RuntimeException('Could not copy shared attachment');$db->prepare('INSERT INTO mailing_attachments(mailing_id,original_name,stored_path,mime_type,file_size) VALUES(?,?,?,?,?)')->execute([$mid,$a['original_name'],$dest,$a['mime_type'],$a['file_size']]);}
                foreach($d['assets'] as $a){$dest=$mdir.'/page-'.str_pad((string)$a['page'],3,'0',STR_PAD_LEFT).'.jpg';if(!copy($a['path'],$dest))throw new RuntimeException('Could not copy inline image');$db->prepare('INSERT INTO mailing_assets(mailing_id,cid,stored_path,mime_type,page_number) VALUES(?,?,?,?,?)')->execute([$mid,$a['cid'],$dest,'image/jpeg',$a['page']]);}
                $db->commit();if(!$isTest){bulkmail_forget_prepared($db,(int)$d['acting_for']);bulkmail_clear_compose_draft($db,(int)$_SESSION['user_id'],(int)$d['acting_for']);bm_end_workspace($db,(int)$_SESSION['user_id'],(int)$d['acting_for'],false);exec('rm -rf '.escapeshellarg(DATA_DIR.'/drafts/'.$d['token']));unset($_SESSION['draft']);}audit($db,$isTest?'mailing_test_queue':'mailing_queue','mailing='.$mid.' acting_for='.$d['acting_for'].' recipients='.count($recips));if($isTest){flash('Test email queued to your account only. Your message and attachments are still here; the main mailing has NOT been sent.');redirect('?page=compose&acting_for='.(int)$d['acting_for'].'&preview=1');}flash('Mailing #'.$mid.' queued for delivery. A permanent copy is saved in Sent / History.');redirect('?page=history');
            }catch(Throwable $e){if($db->inTransaction())$db->rollBack();throw $e;}
        }
        if($action==='preview'){
            // Persist the actual submission before any validation redirect. Never depend on a departing-page fetch.
            bulkmail_store_compose_fields($db,(int)$_SESSION['user_id'],$actingFor,$_POST);
            try{bm_persist_files($db,(int)$_SESSION['user_id'],$actingFor);}catch(Throwable $e){flash($e->getMessage(),'error');redirect('?page=compose&acting_for='.$actingFor);}
            $retained=bm_files($db,(int)$_SESSION['user_id'],$actingFor);$savedDocument=null;foreach($retained as $f)if($f['kind']==='document')$savedDocument=$f;
            $senderId=(int)($_POST['sender_identity_id']??0);$custom=normal_email($_POST['custom_from']??'');$actingFor=(int)($_POST['acting_for']??$_SESSION['user_id']);if(!is_admin())$actingFor=(int)$_SESSION['user_id'];
            if(is_admin()&&$custom!==''){if(!filter_var($custom,FILTER_VALIDATE_EMAIL)){flash('Custom From is invalid.','error');redirect('?page=compose&acting_for='.$actingFor);}$senderEmail=$custom;$senderId=null;}else{$s=$db->prepare('SELECT * FROM sender_identities WHERE id=? AND owner_user_id=? AND active=1');$s->execute([$senderId,$actingFor]);$sender=$s->fetch();if(!$sender){flash('Select an approved sender.','error');redirect('?page=compose&acting_for='.$actingFor);}$senderEmail=$sender['email'];}
            file_put_contents(
    '/tmp/bulkmail-post-debug.log',
    date('c').' '.
    json_encode([
        'action'=>$_POST['action']??null,
        'subject_len'=>strlen((string)($_POST['subject']??'')),
        'body_html_present'=>array_key_exists('body_html',$_POST),
        'body_html_len'=>strlen((string)($_POST['body_html']??'')),
        'body_text_fallback_present'=>array_key_exists('body_text_fallback',$_POST),
        'body_text_fallback_len'=>strlen((string)($_POST['body_text_fallback']??'')),
        'post_keys'=>array_keys($_POST),
        'document_error'=>$_FILES['document_email']['error']??null
    ],JSON_UNESCAPED_SLASHES).PHP_EOL,
    FILE_APPEND
);
            $subject=trim($_POST['subject']??'');
            $rawBody=trim((string)($_POST['body_html']??''));
            $plainFallback=trim((string)($_POST['body_text_fallback']??''));

            if($rawBody==='' && $plainFallback!==''){
                $rawBody='<p>'.nl2br(h($plainFallback), false).'</p>';
            }

            // contenteditable returns bare text when the user simply types into
            // an empty editor. Wrap bare text before sanitising so it is not
            // discarded as a root-level text node.
            if($rawBody!=='' && !preg_match('/<[^>]+>/', $rawBody)){
                $rawBody='<p>'.nl2br(h($rawBody), false).'</p>';
            }

            $body=sanitize_html($rawBody);
            $hasDocument=$savedDocument!==null;

            if($subject===''||(trim(strip_tags(html_entity_decode($body,ENT_QUOTES|ENT_HTML5,'UTF-8')))===''&&!$hasDocument)){
                flash('Subject and either a message or document-as-email are required.','error');
                redirect('?page=compose&acting_for='.$actingFor);
            }
            $raw=[];if(!empty($_POST['all_contacts'])){$s=$db->prepare('SELECT * FROM contacts WHERE owner_user_id=? AND active=1');$s->execute([$actingFor]);$raw=array_merge($raw,$s->fetchAll());}$gids=array_unique(array_map('intval',$_POST['groups']??[]));if($gids){$marks=implode(',',array_fill(0,count($gids),'?'));$p=$gids;$p[]=$actingFor;$s=$db->prepare("SELECT c.* FROM contacts c JOIN group_members gm ON gm.contact_id=c.id JOIN groups g ON g.id=gm.group_id WHERE g.id IN ($marks) AND g.owner_user_id=? AND c.active=1");$s->execute($p);$raw=array_merge($raw,$s->fetchAll());}$cids=array_unique(array_map('intval',$_POST['contacts']??[]));if($cids){$marks=implode(',',array_fill(0,count($cids),'?'));$p=$cids;$p[]=$actingFor;$s=$db->prepare("SELECT * FROM contacts WHERE id IN ($marks) AND owner_user_id=? AND active=1");$s->execute($p);$raw=array_merge($raw,$s->fetchAll());}
            $unique=[];foreach($raw as $c){$e=normal_email($c['email']);if($e!==''&&!isset($unique[$e]))$unique[$e]=$c;}$selected=count($raw);$dupes=max(0,$selected-count($unique));$supp=0;$au=user($db,$actingFor);if(($au['account_type']??'internal')==='marketing'){foreach(array_keys($unique) as $e){$s=$db->prepare('SELECT 1 FROM suppressions WHERE owner_user_id=? AND email=?');$s->execute([$actingFor,$e]);if($s->fetchColumn()){unset($unique[$e]);$supp++;}}}
            if(!$unique){flash('No recipients remain after selection/suppression checks.','error');redirect('?page=compose&acting_for='.$actingFor);}
            $token=random_token(18);$ddir=DATA_DIR.'/drafts/'.$token;if(!is_dir($ddir)&&!mkdir($ddir,0750,true))throw new RuntimeException('Could not prepare preview');
            $attachments=[];$recipientAttachments=[];$selectedContactIds=[];
            foreach($unique as $u){$cid=(int)($u['id']??0);if($cid)$selectedContactIds[$cid]=true;}
            foreach($retained as $f){
                if(!is_file($f['stored_path'])){flash('A saved attachment is unavailable: '.$f['original_name'],'error');redirect('?page=compose&acting_for='.$actingFor);}
                if($f['kind']==='shared')$attachments[]=$f;
                if($f['kind']==='individual'&&!empty($selectedContactIds[(int)$f['contact_id']]))$recipientAttachments[(int)$f['contact_id']][]=$f;
            }
            $assets=[];[$body,$inlineAssets]=bulkmail_materialize_inline_images($db,$body,$actingFor,$ddir,$token);$assets=array_merge($assets,$inlineAssets);
            if($savedDocument){
                try{$processed=process_document_as_email($savedDocument,$ddir,$senderEmail,true);}catch(Throwable $e){flash($e->getMessage().'. Your draft and source document are retained.','error');redirect('?page=compose&acting_for='.$actingFor);}
                $assets=array_merge($assets,$processed['assets']);$body.='<div class="brochure">';foreach($processed['assets'] as $a)$body.='<p><img src="?page=draft_asset&amp;token='.$token.'&amp;f='.h(basename($a['path'])).'" alt="Document page '.(int)$a['page'].'"></p>';$body.='</div>';
            }
            $body.=footer_html($db,$actingFor);$_SESSION['draft']=['token'=>$token,'acting_for'=>$actingFor,'sender_id'=>$senderId,'sender_email'=>$senderEmail,'subject'=>$subject,'body_html'=>$body,'recipients'=>array_values($unique),'selected_count'=>$selected,'unique_count'=>count($unique),'duplicate_count'=>$dupes,'suppressed_count'=>$supp,'attachments'=>$attachments,'recipient_attachments'=>$recipientAttachments,'assets'=>$assets];bulkmail_save_prepared($db,$_SESSION['draft']);if(!empty($_POST['direct_send'])){$_SESSION['direct_send_pending']=1;redirect('?page=compose&preview=1&autosend=1');}redirect('?page=compose&preview=1');
        }
    }

    bulkmail_restore_prepared($db,$actingFor);
    bm_import_previous_files($db,(int)$_SESSION['user_id'],$actingFor);$workspace=bm_workspace($db,(int)$_SESSION['user_id'],$actingFor);
    layout_start('Compose');echo '<h1>Send Bulk Email</h1><div class="safe"><b>LIVE DELIVERY:</b> mail is sent through the controlled Postfix/Xeams delivery path.</div>';
    if(!empty($_GET['preview'])&&!empty($_SESSION['draft'])){$d=$_SESSION['draft'];$autoSend=!empty($_GET['autosend'])&&!empty($_SESSION['direct_send_pending']);unset($_SESSION['direct_send_pending']);echo '<div class="card"><h2>Final Preview — NOT SENT YET</h2><p>Check the message below, then use the red SEND button. Leaving this page does not send anything. Returning to the editor keeps your message and its attachments.</p><div class="grid"><div class="safe"><div class="stat">'.(int)$d['selected_count'].'</div>Selected entries</div><div class="safe"><div class="stat">'.(int)$d['unique_count'].'</div>Unique recipients</div><div class="safe"><div class="stat">'.(int)$d['duplicate_count'].'</div>Duplicates removed</div><div class="safe"><div class="stat">'.(int)$d['suppressed_count'].'</div>Suppressed</div></div><p><b>From:</b> '.h($d['sender_email']).'</p><p><b>Subject:</b> '.h($d['subject']).'</p>';if($d['attachments']){echo '<h3>Shared Attachments (sent to everyone)</h3><ul>';foreach($d['attachments'] as $a)echo '<li>'.h($a['original_name']).' — '.fmt_bytes((int)$a['file_size']).'</li>';echo '</ul>';}if(!empty($d['recipient_attachments'])){echo '<h3>Individual Attachments</h3><ul>';foreach($d['recipients'] as $rr){$cid=(int)($rr['id']??0);if(!$cid||empty($d['recipient_attachments'][$cid]))continue;foreach($d['recipient_attachments'][$cid] as $a)echo '<li><b>'.h($rr['name']?:$rr['email']).'</b>: '.h($a['original_name']).' — '.fmt_bytes((int)$a['file_size']).'</li>';}echo '</ul><p class="small">Each individual attachment is sent only to the named recipient. Send Test to Myself includes shared attachments only.</p>';}echo '<h3>Email</h3><div style="border:1px solid #aaa;padding:18px;background:#fff">'.$d['body_html'].'</div><div style="margin-top:15px"><form method="post" style="display:inline"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="test"><input type="hidden" name="draft_token" value="'.h($d['token']).'"><button class="secondary">Send Test to Myself</button></form><form method="post" style="display:inline" id="queueMailForm"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="queue"><input type="hidden" name="draft_token" value="'.h($d['token']).'"><button class="send-big">SEND '.(int)$d['unique_count'].' EMAILS NOW</button></form><form method="post" style="display:inline"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="back"><button class="secondary">Back to editing (keep everything)</button></form></div><p class="small">Marketing accounts automatically get unsubscribe links and suppression enforcement. Internal Client accounts do not.</p></div>';if($autoSend)echo '<script>document.getElementById("queueMailForm").submit();</script>';layout_end();exit;}

    // Admin: all approved senders shown. Selecting one reloads and automatically shows that owner's groups/contacts.
    if(is_admin() && (int)$_SESSION['user_id']!==2){echo '<div class="card"><h2>1. Client / Sender</h2><label>Approved sender address</label><select id="adminSender"><option value="">Choose...</option>';foreach($db->query('SELECT s.*,u.display_name FROM sender_identities s JOIN users u ON u.id=s.owner_user_id WHERE s.active=1 AND u.active=1 ORDER BY u.display_name,s.email') as $s)echo '<option value="'.(int)$s['id'].'"'.((int)$s['id']===$selectedSender?' selected':'').'>'.h($s['display_name']).' — '.h($s['email']).'</option>';echo '</select><p class="small">Selecting an address loads that client’s groups and contacts automatically.</p><label>Or use a custom/test From address</label><input type="email" id="customFromTop" placeholder="Admin only"><label>Use address book/groups belonging to</label><select id="customContext">';foreach($db->query('SELECT * FROM users WHERE active=1 ORDER BY display_name') as $u)echo '<option value="'.(int)$u['id'].'"'.((int)$u['id']===$actingFor?' selected':'').'>'.h($u['display_name']).'</option>';echo '</select></div><script>document.getElementById("adminSender").addEventListener("change",e=>{if(e.target.value)location="?page=compose&sender="+e.target.value});</script>';} 

    $s=$db->prepare('SELECT * FROM sender_identities WHERE owner_user_id=? AND active=1 ORDER BY label,email');$s->execute([$actingFor]);$senders=$s->fetchAll();$g=$db->prepare('SELECT g.*,COUNT(gm.contact_id) members FROM groups g LEFT JOIN group_members gm ON gm.group_id=g.id WHERE g.owner_user_id=? GROUP BY g.id ORDER BY g.name');$g->execute([$actingFor]);$groups=$g->fetchAll();$c=$db->prepare('SELECT c.id,c.name,c.email,c.company,GROUP_CONCAT(g.name, ", ") groups FROM contacts c LEFT JOIN group_members gm ON gm.contact_id=c.id LEFT JOIN groups g ON g.id=gm.group_id WHERE c.owner_user_id=? AND c.active=1 GROUP BY c.id ORDER BY c.name,c.email');$c->execute([$actingFor]);$contacts=$c->fetchAll();$tq=$db->prepare('SELECT id,name,subject FROM email_templates WHERE owner_user_id=? ORDER BY name');$tq->execute([$actingFor]);$templates=$tq->fetchAll();
    echo '<div class="card"><h2>Templates</h2><div class="grid"><div><label>Saved template</label><select id="templateSelect"><option value="">Choose...</option>';foreach($templates as $t)echo '<option value="'.(int)$t['id'].'">'.h($t['name']).' — '.h($t['subject']).'</option>';echo '</select></div><div style="align-self:end"><button type="button" id="loadTemplateButton" class="secondary">Load Template</button> <button type="button" id="saveTemplateButton" class="good">Save Current as Template</button> <a class="button secondary" href="?page=templates&amp;user='.$actingFor.'">Manage Templates</a></div></div></div>';
    echo '<form method="post" enctype="multipart/form-data" id="composeForm" data-user-id="'.(int)$_SESSION['user_id'].'" data-workspace="'.h($workspace['workspace_token']).'"><input type="hidden" name="workspace_token" value="'.h($workspace['workspace_token']).'"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="preview"><input type="hidden" name="acting_for" value="'.$actingFor.'"><div class="card"><h2>Sender</h2><p><b>Address book:</b> '.h($acting['display_name']).' <span class="pill '.h($acting['account_type']).'">'.h($acting['account_type']).'</span></p><label>From</label><select name="sender_identity_id"><option value="">Choose...</option>';foreach($senders as $r)echo '<option value="'.(int)$r['id'].'"'.((int)$r['id']===$selectedSender?' selected':'').'>'.h($r['label']).' — '.h($r['email']).'</option>';echo '</select>';if(is_admin() && (int)$_SESSION['user_id']!==2)echo '<label>Admin custom/test From (optional override)</label><input type="email" name="custom_from" id="customFromBottom">';echo '</div><div class="card"><h2>2. Recipients</h2><label class="checkrow"><input type="checkbox" name="all_contacts" value="1"> <b>All contacts ('.count($contacts).')</b></label><h3>Recipient Groups</h3><p class="small">Tick one or more groups to send to everyone in those groups. You can combine groups and individual contacts; duplicates are removed automatically.</p><div class="recipient-group-grid">';if(!$groups)echo '<p>No groups yet.</p>';foreach($groups as $r)echo '<label class="checkrow recipient-group-option"><input type="checkbox" name="groups[]" value="'.(int)$r['id'].'"><span><b>'.h($r['name']).'</b><br><span class="small">'.(int)$r['members'].' recipient'.((int)$r['members']===1?'':'s').'</span></span></label>';echo '</div><h3>Individual contacts</h3><p class="small">Tick recipients normally. To send a file to just one person, choose it in that person&#39;s <b>Individual attachment</b> box; choosing a file automatically ticks that contact.</p><div class="groupbox">';foreach($contacts as $r){$cid=(int)$r['id'];echo '<div class="recipient-row"><label class="checkrow"><input type="checkbox" name="contacts[]" value="'.$cid.'" id="contact-'.$cid.'"> '.h($r['name']?:$r['email']).($r['company']?' — '.h($r['company']):'').' &lt;'.h($r['email']).'&gt;'.(!empty($r['groups'])?'<br><span class="small">Groups: '.h($r['groups']).'</span>':'').'</label><div><span class="small">Individual attachment — only this recipient</span><input type="file" class="recipient-attachment" data-contact="'.$cid.'" name="recipient_attachments['.$cid.'][]" multiple></div></div>';}echo '</div></div><div class="card"><h2>3. Message</h2><label>Subject</label><input name="subject" required spellcheck="true" lang="en-GB" autocomplete="off"><label>Write or paste from Word / ONLYOFFICE</label><div class="toolbar"><button type="button" onclick="fmt(\'bold\')"><b>B</b></button><button type="button" onclick="fmt(\'italic\')"><i>I</i></button><button type="button" onclick="fmt(\'underline\')"><u>U</u></button><button type="button" onclick="fmt(\'insertUnorderedList\')">Bullets</button><button type="button" onclick="fmt(\'insertOrderedList\')">Numbers</button><button type="button" onclick="addLink()">Link</button><button type="button" onclick="addInlineImage()">Image</button><select id="fontPicker" onchange="applyEditorFont(this.value)" aria-label="Font"><option value="">Choose message font</option><option value="Arial, Helvetica, sans-serif">Arial</option><option value="Calibri, Carlito, Arial, sans-serif">Calibri / Carlito</option><option value="Georgia, serif">Georgia</option><option value="Times New Roman, Times, serif">Times New Roman</option><option value="Verdana, Arial, sans-serif">Verdana</option><option value="Tahoma, Arial, sans-serif">Tahoma</option><option value="Trebuchet MS, Arial, sans-serif">Trebuchet MS</option><option value="Courier New, Courier, monospace">Courier New</option><option value="OpenDyslexic, Arial, sans-serif">OpenDyslexic</option><option value="Noto Sans, Arial, sans-serif">Noto Sans</option><option value="Dancing Script, Segoe Script, cursive">Dancing Script — signature</option><option value="Lato, Arial, sans-serif">Lato</option><option value="Merriweather, Georgia, serif">Merriweather</option><option value="Montserrat, Arial, sans-serif">Montserrat</option><option value="Open Sans, Arial, sans-serif">Open Sans</option></select><button type="button" onclick="checkSpelling()">Check Spelling</button><button type="button" onclick="fmt(\'justifyLeft\')">Left</button><button type="button" onclick="fmt(\'justifyCenter\')">Centre</button><button type="button" onclick="fmt(\'justifyRight\')">Right</button></div><textarea name="body_html" id="body_html" class="editor" placeholder="Write or paste your email here..." spellcheck="true" lang="en-GB"></textarea><div id="editor" class="editor" contenteditable="true" spellcheck="true" lang="en-GB" style="display:none"></div><div id="spellPanel" class="spell-panel"></div><input type="file" id="inlineImageInput" accept=".jpg,.jpeg,.png,.heic,.heif,image/jpeg,image/png,image/heic,image/heif" style="display:none"><textarea name="body_text_fallback" id="body_text_fallback" style="display:none"></textarea><p class="small">Paste directly from Word/ONLYOFFICE. UK English spell checking is enabled in the subject and editor. Highlight text to change its font, or choose a font with no selection to change the whole message. The five additional fonts load automatically here. Email programs that do not support web fonts use the closest fallback. The server cleans scripts, hidden junk and unsupported markup before queueing.</p><hr><h3>Upload Document as Email</h3><input type="file" name="document_email" accept=".pdf,.doc,.docx,.odt"><p class="small">PDF/Word/ODT is flattened to printable page images, metadata stripped, and <b>the selected sender email is permanently burned into every page</b>.</p><h3>Shared Attachments</h3><p class="small">These files are sent to every recipient. Use up to six separate attachment slots for easier checking before send.</p><div class="grid"><div><label>Attachment 1</label><input type="file" name="attachments[]" accept=".pdf,.doc,.docx,.odt,.xls,.xlsx,.csv,.txt,.jpg,.jpeg,.png"></div><div><label>Attachment 2</label><input type="file" name="attachments[]" accept=".pdf,.doc,.docx,.odt,.xls,.xlsx,.csv,.txt,.jpg,.jpeg,.png"></div><div><label>Attachment 3</label><input type="file" name="attachments[]" accept=".pdf,.doc,.docx,.odt,.xls,.xlsx,.csv,.txt,.jpg,.jpeg,.png"></div><div><label>Attachment 4</label><input type="file" name="attachments[]" accept=".pdf,.doc,.docx,.odt,.xls,.xlsx,.csv,.txt,.jpg,.jpeg,.png"></div><div><label>Attachment 5</label><input type="file" name="attachments[]" accept=".pdf,.doc,.docx,.odt,.xls,.xlsx,.csv,.txt,.jpg,.jpeg,.png"></div><div><label>Attachment 6</label><input type="file" name="attachments[]" accept=".pdf,.doc,.docx,.odt,.xls,.xlsx,.csv,.txt,.jpg,.jpeg,.png"></div></div><p class="small">Individual files are selected beside each contact above. You may use both shared and individual attachments on the same mailing.</p></div>';bm_render_retained_files($db,(int)$_SESSION['user_id'],$actingFor);echo '<div class="card"><button class="secondary" type="submit" name="save_draft" value="1" formnovalidate>Save as Draft</button> <button class="secondary" type="submit" name="new_message" value="1" formnovalidate>Save and start new email</button> <button class="good" type="submit">Preview Recipient Count & Email</button> <button class="send-big" type="submit" name="direct_send" value="1" onclick="return confirm(&quot;Send this email now to the selected recipients?&quot;)">Send Email</button></div></form>';
    echo <<<'JS'
<script src="/bulkmail-compose.js?v=20261016r2" defer></script>
<script>
document.addEventListener('change',function(e){
    var input=e.target.closest && e.target.closest('.recipient-attachment');
    if(!input || !input.files || !input.files.length)return;
    var cb=document.getElementById('contact-'+input.dataset.contact);
    if(cb){cb.checked=true;cb.dispatchEvent(new Event('change',{bubbles:true}));}
});
</script>
JS;
    layout_end();exit;
}

if ($page==='history') {
    layout_start('History');echo '<h1>Sent / Mailing History</h1><p>Only messages actually queued for sending appear here. Previewing does not send. Open a subject to view the saved message and recipient status.</p><div class="card"><table><tr><th>ID</th><th>Date</th><th>Initiated by</th><th>Acting for</th><th>From</th><th>Subject</th><th>Unique</th><th>Dupes</th><th>Suppressed</th><th>Type</th><th>Status</th><th></th></tr>';
    if(is_admin())$s=$db->query('SELECT m.*,a.display_name actor,c.display_name client FROM mailings m JOIN users a ON a.id=m.initiated_by_user_id JOIN users c ON c.id=m.acting_for_user_id ORDER BY m.id DESC');else{$s=$db->prepare('SELECT m.*,a.display_name actor,c.display_name client FROM mailings m JOIN users a ON a.id=m.initiated_by_user_id JOIN users c ON c.id=m.acting_for_user_id WHERE m.acting_for_user_id=? ORDER BY m.id DESC');$s->execute([$_SESSION['user_id']]);}
    foreach($s as $r)echo '<tr><td>#'.(int)$r['id'].'</td><td>'.h($r['created_at']).'</td><td>'.h($r['actor']).'</td><td>'.h($r['client']).'</td><td>'.h($r['sender_email']).'</td><td><a href="?page=mailing_view&amp;id='.(int)$r['id'].'">'.h($r['subject']).'</a></td><td>'.(int)$r['unique_count'].'</td><td>'.(int)$r['duplicate_count'].'</td><td>'.(int)$r['suppressed_count'].'</td><td>'.($r['is_test']?'TEST':'MAIL').'</td><td>'.h(bulkmail_status_label($r['status'])).'<br><span class="small">'.h(bm_sent_copy_label($db,(int)$r['id'])).'</span></td><td><a class="button good" href="?page=reuse&amp;id='.(int)$r['id'].'">Use Again</a></td></tr>';echo '</table></div>';layout_end();exit;
}

http_response_code(404);layout_start('Not Found');echo '<div class="card"><h1>Page not found</h1></div>';layout_end();
