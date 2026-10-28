<?php
declare(strict_types=1);

function bm_messaging_label(string $channel): string {
    return $channel === 'sms' ? 'SMS' : 'WhatsApp';
}

function bm_messaging_campaign_identity(array $campaign,string $role): array {
    $value=json_decode((string)($campaign[$role.'_identity_json'] ?? ''),true);
    $identity=is_array($value)?$value:[];
    $identity['display_name']=(string)($identity['display_name'] ?? $campaign[$role.'_name'] ?? 'Account');
    return $identity;
}

function bm_messaging_owner(PDO $db): int {
    $owner=(int)($_POST['acting_for'] ?? $_GET['user'] ?? $_SESSION['user_id']);
    allowed_context($db,$owner);
    if (!user($db,$owner)) { http_response_code(404); exit('Account not found.'); }
    return $owner;
}

function bm_messaging_tabs(int $owner): void {
    echo '<p class="tabs"><a class="button" href="?page=messages&amp;user='.$owner.'">Write message</a>'
        .'<a class="button secondary" href="?page=message_history&amp;user='.$owner.'">Message history</a>'
        .'<a class="button secondary" href="?page=message_suppressions&amp;user='.$owner.'">Opt-outs</a></p>';
}

function bm_messaging_picker(PDO $db,int $owner,string $page): void {
    if (!is_admin()) return;
    echo '<form method="get" class="card"><input type="hidden" name="page" value="'.h($page).'">'
        .'<label for="message-owner">Send on behalf of / address book</label><select id="message-owner" name="user">';
    foreach ($db->query('SELECT id,display_name,organisation,active FROM users ORDER BY display_name') as $u) {
        echo '<option value="'.(int)$u['id'].'"'.((int)$u['id']===$owner?' selected':'').'>'
            .h($u['display_name'].($u['organisation']?' — '.$u['organisation']:'').(!(int)$u['active']?' (inactive)':'')).'</option>';
    }
    echo '</select><button class="secondary">Choose account</button></form>';
}

/** Only fixed, authenticated local gateway routes are exposed to administrators. */
function bm_messaging_gateway_get(array $config,string $path): array {
    if (!in_array($path,['/status','/pairing'],true)) throw new RuntimeException('Unknown gateway operation.');
    $token=(string)($config['token'] ?? '');
    if (strlen($token)<32 || preg_match('/[\r\n]/',$token)) throw new RuntimeException('The WhatsApp gateway has not been configured.');
    $base=bm_integration_url((string)($config['base_url'] ?? ''),($config['allow_http'] ?? false)===true);
    if (!function_exists('curl_init')) throw new RuntimeException('The gateway connection is not available on this server.');
    $body='';
    $ch=curl_init($base.$path);
    curl_setopt_array($ch,[
        CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$token,'Accept: application/json'],
        CURLOPT_CONNECTTIMEOUT=>3,CURLOPT_TIMEOUT=>8,CURLOPT_FOLLOWLOCATION=>false,
        CURLOPT_PROTOCOLS=>CURLPROTO_HTTP|CURLPROTO_HTTPS,
        CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
        CURLOPT_WRITEFUNCTION=>static function($handle,string $data) use (&$body): int {
            if (strlen($body)+strlen($data)>512*1024) return 0;
            $body.=$data; return strlen($data);
        },
    ]);
    $ok=curl_exec($ch); $status=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE); curl_close($ch);
    if ($ok===false || $status!==200) throw new RuntimeException('The WhatsApp gateway could not be reached or did not accept the connection.');
    $result=json_decode($body,true);
    if (!is_array($result)) throw new RuntimeException('The WhatsApp gateway returned an unexpected response.');
    return $result;
}

function bm_messaging_handle(PDO $db,string $page): void {
    if (!in_array($page,['messages','message_history','message_suppressions','messaging_settings'],true)) return;
    require_login();
    header('Cache-Control: private, no-store');
    if ($page==='messaging_settings') { bm_messaging_settings($db); exit; }
    $owner=bm_messaging_owner($db);
    if ($page==='message_history') { bm_messaging_history($db,$owner); exit; }
    if ($page==='message_suppressions') { bm_messaging_suppressions($db,$owner); exit; }
    bm_messaging_compose($db,$owner);
    exit;
}

function bm_messaging_compose(PDO $db,int $owner): void {
    $actor=(int)$_SESSION['user_id'];
    $form=$_SESSION['message_form'][$owner] ?? ['channel'=>'sms','text'=>'','numbers'=>'','contacts'=>[],'groups'=>[]];
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf();
        $action=(string)($_POST['action'] ?? '');
        try {
            if ($action==='preview') {
                $form=[
                    'channel'=>(string)($_POST['channel'] ?? ''),'text'=>(string)($_POST['text'] ?? ''),
                    'numbers'=>(string)($_POST['numbers'] ?? ''),
                    'contacts'=>array_map('intval',is_array($_POST['contacts'] ?? null)?$_POST['contacts']:[]),
                    'groups'=>array_map('intval',is_array($_POST['groups'] ?? null)?$_POST['groups']:[]),
                ];
                $_SESSION['message_form'][$owner]=$form;
                $preview=bm_message_preview($db,$owner,$form['channel'],$form['text'],$form['contacts'],$form['groups'],$form['numbers'],$actor);
                $_SESSION['message_previews'][$preview['token']]=$preview;
                // A bounded cache supports independent compose tabs without unbounded session growth.
                if (count($_SESSION['message_previews'])>10) array_shift($_SESSION['message_previews']);
                redirect('?page=messages&user='.$owner.'&preview='.rawurlencode($preview['token']));
            }
            if ($action==='send') {
                $token=(string)($_POST['preview_token'] ?? '');
                $preview=$_SESSION['message_previews'][$token] ?? null;
                if (!is_array($preview) || (int)$preview['owner_user_id']!==$owner) throw new RuntimeException('Please preview this message again before sending.');
                $id=bm_message_queue($db,$actor,$owner,$preview,$token);
                flash('Message campaign queued. Its delivery status is shown below.');
                redirect('?page=message_history&user='.$owner.'&id='.$id);
            }
            throw new RuntimeException('Unknown message operation.');
        } catch (Throwable $e) {
            if ($e instanceof PDOException) {
                error_log('BulkMail messaging operation failed.');
                flash('The message could not be saved. Please try again.','error');
            } else flash($e->getMessage(),'error');
        }
    }
    layout_start('SMS / WhatsApp');
    echo '<h1>SMS / WhatsApp</h1>';
    bm_messaging_tabs($owner); bm_messaging_picker($db,$owner,'messages');
    $ownerUser=user($db,$owner);
    echo '<p>Account: <strong>'.h($ownerUser['display_name']).'</strong>. The history records both the sender and the account they act for.</p>';
    $config=bm_integration_config();
    foreach (['sms','whatsapp'] as $channel) {
        if (!bm_message_has_access($db,$owner,$channel,$config)) {
            echo '<p class="warning">'.bm_messaging_label($channel).' sending is not enabled for this account.'
                .(is_admin()?' <a href="?page=messaging_settings">View messaging settings</a>.':' Please contact an administrator.').'</p>';
        }
    }
    $previewToken=(string)($_GET['preview'] ?? '');
    $preview=$_SESSION['message_previews'][$previewToken] ?? null;
    if (is_array($preview) && (int)$preview['owner_user_id']===$owner) {
        echo '<section class="card"><h2>Check your '.bm_messaging_label($preview['channel']).' message</h2>'
            .'<p><strong>'.(int)$preview['unique_count'].' recipients</strong>; '.(int)$preview['duplicate_count'].' duplicates removed; '
            .(int)$preview['suppressed_count'].' opted out; '.(int)$preview['invalid_count'].' invalid or missing mobile numbers.</p>'
            .'<div style="white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #ccd2d8;padding:18px">'.h($preview['text']).'</div>';
        if (!empty($preview['invalid'])) {
            echo '<details><summary>Numbers that cannot be used</summary><ul>';
            foreach (array_slice($preview['invalid'],0,50) as $invalid) echo '<li>'.h(($invalid['name'] ?? '').' — '.($invalid['value'] ?? '')).'</li>';
            echo '</ul></details>';
        }
        echo '<details><summary>Recipients</summary><ul>';
        foreach (array_slice($preview['recipients'],0,100) as $r) echo '<li>'.h(($r['name']?$r['name'].' — ':'').$r['destination']).'</li>';
        echo '</ul>'.(count($preview['recipients'])>100?'<p>Showing the first 100 recipients.</p>':'').'</details>';
        if ((int)$preview['unique_count']>0) {
            echo '<form method="post"><input type="hidden" name="csrf" value="'.csrf().'">'
                .'<input type="hidden" name="action" value="send"><input type="hidden" name="acting_for" value="'.$owner.'">'
                .'<input type="hidden" name="preview_token" value="'.h($previewToken).'">'
                .'<button class="send-big">SEND '.(int)$preview['unique_count'].' '.bm_messaging_label($preview['channel']).' MESSAGES</button></form>';
        }
        echo '<p><a href="?page=messages&amp;user='.$owner.'">Back to editing</a></p></section>';
        layout_end(); return;
    }
    $contacts=$db->prepare("SELECT id,name,telephone,email FROM contacts WHERE owner_user_id=? AND active=1 AND COALESCE(telephone,'')<>'' ORDER BY name,email");
    $contacts->execute([$owner]);
    $groups=$db->prepare('SELECT id,name FROM groups WHERE owner_user_id=? ORDER BY name'); $groups->execute([$owner]);
    echo '<form method="post" class="card"><input type="hidden" name="csrf" value="'.csrf().'">'
        .'<input type="hidden" name="action" value="preview"><input type="hidden" name="acting_for" value="'.$owner.'">'
        .'<label for="message-channel">Send using</label><select name="channel" id="message-channel">'
        .'<option value="sms"'.($form['channel']==='sms'?' selected':'').'>SMS</option>'
        .'<option value="whatsapp"'.($form['channel']==='whatsapp'?' selected':'').'>WhatsApp</option></select>'
        .'<label for="message-text">Message</label><textarea id="message-text" name="text" maxlength="4096" required>'.h($form['text']).'</textarea>'
        .'<p class="small">Plain text and links are supported: up to 1,600 characters for SMS or 4,096 for WhatsApp. Longer SMS messages may use several text segments.</p>'
        .'<div class="grid"><div><label>Contact groups</label><div class="groupbox">';
    foreach ($groups as $g) echo '<label class="checkrow"><input type="checkbox" name="groups[]" value="'.(int)$g['id'].'"'.(in_array((int)$g['id'],$form['groups'],true)?' checked':'').'> '.h($g['name']).'</label>';
    echo '</div></div><div><label>Contacts with a phone number</label><div class="groupbox">';
    foreach ($contacts as $c) echo '<label class="checkrow"><input type="checkbox" name="contacts[]" value="'.(int)$c['id'].'"'.(in_array((int)$c['id'],$form['contacts'],true)?' checked':'').'> '.h(($c['name'] ?: $c['email']).' — '.$c['telephone']).'</label>';
    echo '</div></div></div><label for="message-numbers">Additional UK mobile numbers</label>'
        .'<textarea id="message-numbers" name="numbers" maxlength="40000" placeholder="One mobile number per line">'.h($form['numbers']).'</textarea>'
        .'<p class="small">Use 07… or +447… mobile numbers, one per line. Duplicates and opted-out numbers are excluded.</p>'
        .'<button>Preview message and recipients</button></form>';
    layout_end();
}

function bm_messaging_history(PDO $db,int $owner): void {
    $actor=(int)$_SESSION['user_id']; $id=(int)($_GET['id'] ?? 0);
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf();
        try {
            if (($_POST['action'] ?? '')!=='cancel') throw new RuntimeException('Unknown operation.');
            $campaignId=(int)($_POST['campaign_id'] ?? 0);
            $s=$db->prepare('SELECT acting_for_user_id FROM message_campaigns WHERE id=?'); $s->execute([$campaignId]);
            if ((int)$s->fetchColumn()!==$owner) throw new RuntimeException('Campaign not found for this account.');
            $n=bm_message_cancel_campaign($db,$actor,$campaignId);
            flash($n.' queued recipients cancelled. Messages already submitted cannot be recalled.');
        } catch (Throwable $e) { flash($e instanceof PDOException?'Unable to update the campaign.':$e->getMessage(),'error'); }
        redirect('?page=message_history&user='.$owner.($id?'&id='.$id:''));
    }
    $c=null;
    if ($id) {
        $s=$db->prepare('SELECT c.*,u.display_name actor_name,o.display_name owner_name FROM message_campaigns c JOIN users u ON u.id=c.initiated_by_user_id JOIN users o ON o.id=c.acting_for_user_id WHERE c.id=? AND c.acting_for_user_id=?');
        $s->execute([$id,$owner]); $c=$s->fetch();
        if (!$c) { http_response_code(404); layout_start('Message history'); echo '<p>Campaign not found.</p>'; layout_end(); return; }
    }
    layout_start('Message history'); echo '<h1>Message history</h1>'; bm_messaging_tabs($owner);
    if ($id) {
        $actorSnapshot=bm_messaging_campaign_identity($c,'actor');
        $ownerSnapshot=bm_messaging_campaign_identity($c,'owner');
        echo '<section class="card"><h2>'.bm_messaging_label($c['channel']).' campaign #'.$id.'</h2>'
            .'<p>Requested by <strong>'.h($actorSnapshot['display_name']).'</strong> for <strong>'.h($ownerSnapshot['display_name']).'</strong> at '.h($c['created_at']).' UTC.</p>'
            .'<p class="small">Sign-in: '.match ($actorSnapshot['authentication_method'] ?? 'local') {
                'ct400'=>'CT400 verified', 'ct400_portal'=>'Work portal verified', default=>'Local password'
            }
            .(!empty($actorSnapshot['ct400_id'])?'. Linked CT400 sender: '.h($actorSnapshot['ct400_id']):'')
            .(!empty($ownerSnapshot['ct400_id'])?'. Linked CT400 owner: '.h($ownerSnapshot['ct400_id']):'').'.</p>'
            .'<div style="white-space:pre-wrap;overflow-wrap:anywhere">'.h($c['body_text']).'</div>'
            .'<p><a class="button secondary" href="?page=message_history&amp;user='.$owner.'&amp;id='.$id.'">Refresh status</a></p>'
            .'<form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="acting_for" value="'.$owner.'">'
            .'<input type="hidden" name="action" value="cancel"><input type="hidden" name="campaign_id" value="'.$id.'">'
            .'<button class="danger">Cancel recipients still queued</button></form></section>';
        $r=$db->prepare('SELECT destination,name,status,error,submitted_at,delivered_at FROM message_recipients WHERE campaign_id=? ORDER BY id'); $r->execute([$id]);
        echo '<div class="card"><p class="small">Submitted means the gateway accepted the send. Delivered and read require a receipt. Unknown means the outcome needs checking; it will not be sent again automatically.</p>'
            .'<table><tr><th>Recipient</th><th>Number</th><th>Status</th><th>Details</th></tr>';
        foreach ($r as $recipient) echo '<tr><td>'.h($recipient['name']).'</td><td>'.h($recipient['destination']).'</td><td>'.h($recipient['status']).'</td><td>'.h($recipient['error']).'</td></tr>';
        echo '</table></div>'; layout_end(); return;
    }
    bm_messaging_picker($db,$owner,'message_history');
    $s=$db->prepare('SELECT c.*,u.display_name actor_name FROM message_campaigns c JOIN users u ON u.id=c.initiated_by_user_id WHERE c.acting_for_user_id=? ORDER BY c.id DESC LIMIT 100');
    $s->execute([$owner]);
    echo '<div class="card"><table><tr><th>Date (UTC)</th><th>Channel</th><th>Requested by</th><th>Recipients</th><th>Status</th><th></th></tr>';
    foreach ($s as $c) {
        $snapshot=bm_messaging_campaign_identity($c,'actor');
        echo '<tr><td>'.h($c['created_at']).'</td><td>'.bm_messaging_label($c['channel']).'</td><td>'.h($snapshot['display_name']).'</td><td>'.(int)$c['unique_count'].'</td><td>'.h($c['status']).'</td><td><a href="?page=message_history&amp;user='.$owner.'&amp;id='.(int)$c['id'].'">View</a></td></tr>';
    }
    echo '</table><p class="small">Showing the latest 100 campaigns for this account.</p></div>'; layout_end();
}

function bm_messaging_suppressions(PDO $db,int $owner): void {
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf();
        try {
            if (($_POST['action'] ?? '')==='suppress') {
                bm_message_suppress($db,(int)$_SESSION['user_id'],$owner,(string)($_POST['channel'] ?? ''),(string)($_POST['number'] ?? ''),(string)($_POST['reason'] ?? 'Opted out'));
                flash('The number has been excluded from this channel.');
            } elseif (($_POST['action'] ?? '')==='restore') {
                bm_message_unsuppress($db,(int)$_SESSION['user_id'],$owner,(int)($_POST['id'] ?? 0));
                flash('The opt-out has been withdrawn. Its record is retained.');
            } else throw new RuntimeException('Unknown operation.');
        } catch (Throwable $e) { flash($e instanceof PDOException?'Unable to save the opt-out.':$e->getMessage(),'error'); }
        redirect('?page=message_suppressions&user='.$owner);
    }
    layout_start('Messaging opt-outs'); echo '<h1>Messaging opt-outs</h1>'; bm_messaging_tabs($owner); bm_messaging_picker($db,$owner,'message_suppressions');
    echo '<div class="card"><p>Record requests to stop SMS or WhatsApp messages here. These exclusions apply to this account and channel, including messages that are still queued.</p>'
        .'<form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="acting_for" value="'.$owner.'">'
        .'<input type="hidden" name="action" value="suppress"><div class="grid"><div><label>Channel</label><select name="channel"><option value="sms">SMS</option><option value="whatsapp">WhatsApp</option></select></div>'
        .'<div><label>UK mobile number</label><input name="number" required maxlength="40"></div><div><label>Reason</label><input name="reason" value="Opted out" maxlength="250" required></div></div><button>Add opt-out</button></form></div>';
    $s=$db->prepare('SELECT * FROM message_suppressions WHERE owner_user_id=? ORDER BY active DESC,id DESC LIMIT 500'); $s->execute([$owner]);
    echo '<div class="card"><table><tr><th>Channel</th><th>Number</th><th>Reason</th><th>Status</th><th></th></tr>';
    foreach ($s as $r) {
        echo '<tr><td>'.bm_messaging_label($r['channel']).'</td><td>'.h($r['destination']).'</td><td>'.h($r['reason']).'</td><td>'.((int)$r['active']?'Excluded':'Withdrawn').'</td><td>';
        if ((int)$r['active']) echo '<form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="acting_for" value="'.$owner.'"><input type="hidden" name="action" value="restore"><input type="hidden" name="id" value="'.(int)$r['id'].'"><button class="secondary">Withdraw opt-out</button></form>';
        echo '</td></tr>';
    }
    echo '</table></div>'; layout_end();
}

function bm_messaging_settings(PDO $db): void {
    require_admin(); $config=bm_integration_config(); $gateway=null; $pairing=null;
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf();
        try {
            $action=(string)($_POST['action'] ?? '');
            if ($action==='grant') {
                $owner=(int)($_POST['owner_user_id'] ?? 0);
                $db->beginTransaction();
                try {
                    foreach (['sms','whatsapp'] as $channel) bm_message_set_access($db,(int)$_SESSION['user_id'],$owner,$channel,isset($_POST[$channel]));
                    $db->commit();
                } catch (Throwable $e) { if ($db->inTransaction()) $db->rollBack(); throw $e; }
                flash('Channel access saved.'); redirect('?page=messaging_settings');
            } elseif ($action==='gateway') {
                $gateway=bm_messaging_gateway_get($config['whatsapp'],'/status');
                $pairing=bm_messaging_gateway_get($config['whatsapp'],'/pairing');
                audit($db,'whatsapp_pairing_view');
            } else throw new RuntimeException('Unknown operation.');
        } catch (Throwable $e) { flash($e instanceof PDOException?'Unable to save channel access.':$e->getMessage(),'error'); }
    }
    layout_start('Messaging settings'); echo '<h1>Messaging settings</h1><div class="card"><h2>Services</h2><table><tr><th>Channel</th><th>Sending</th></tr>';
    foreach (['sms','whatsapp'] as $channel) echo '<tr><td>'.bm_messaging_label($channel).'</td><td>'.($config[$channel]['enabled']?'Enabled in server configuration':'Disabled').'</td></tr>';
    echo '</table><p>Each channel also requires account access below. SMS uses the Android handset; WhatsApp uses the account linked to the gateway.</p></div>'
        .'<div class="card"><h2>WhatsApp connection</h2><form method="post"><input type="hidden" name="csrf" value="'.csrf().'"><input type="hidden" name="action" value="gateway"><button>Check connection / show pairing code</button></form>';
    if ($gateway) echo '<p>Gateway status: <strong>'.h((string)($gateway['status'] ?? 'unknown')).'</strong>.</p>';
    if ($pairing) {
        $image=(string)($pairing['qr_data_url'] ?? '');
        if (strlen($image)<450000 && preg_match('#^data:image/png;base64,[A-Za-z0-9+/=]+$#D',$image)) {
            echo '<p>On the WhatsApp phone, open <strong>Linked devices → Link a device</strong> and scan this code.</p>'
                .'<img alt="WhatsApp device pairing QR code" width="300" height="300" src="'.h($image).'">'
                .'<p class="small">The code expires. Use the button again to refresh it.</p>';
        } else echo '<p>'.h((string)($pairing['status'] ?? 'No pairing code is currently available.')).'</p>';
    }
    echo '</div><div class="card"><h2>Account channel access</h2><p>These permissions apply when an account sends its own messages and when an administrator sends on its behalf.</p>';
    $permissions=[];
    foreach ($db->query('SELECT user_id,channel,enabled FROM message_channel_access') as $r) $permissions[(int)$r['user_id']][$r['channel']]=(bool)$r['enabled'];
    foreach ($db->query('SELECT id,display_name,active FROM users ORDER BY display_name') as $u) {
        $uid=(int)$u['id'];
        echo '<form method="post" style="padding:12px 0;border-bottom:1px solid #ddd"><input type="hidden" name="csrf" value="'.csrf().'">'
            .'<input type="hidden" name="action" value="grant"><input type="hidden" name="owner_user_id" value="'.$uid.'">'
            .'<strong>'.h($u['display_name']).(!(int)$u['active']?' (inactive)':'').'</strong><div style="display:flex;gap:20px;flex-wrap:wrap">';
        foreach (['sms','whatsapp'] as $channel) echo '<label class="checkrow"><input type="checkbox" name="'.$channel.'" value="1"'.(!empty($permissions[$uid][$channel])?' checked':'').'> '.bm_messaging_label($channel).'</label>';
        echo '<button class="secondary">Save access</button></div></form>';
    }
    echo '</div>'; layout_end();
}
