#!/usr/bin/env python3
"""Real PHP routes + CLI worker + loopback fake SMSGate; synthetic data, no real delivery."""
import contextlib, hashlib, html, http.cookiejar, http.server, json, os, pathlib, re
import secrets, shutil, socket, sqlite3, subprocess, tempfile, threading, time
import urllib.error, urllib.parse, urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
checks = []
def check(name, condition):
    assert condition, name
    checks.append(name)
    print('PASS:', name, flush=True)

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

class FakeSms(http.server.BaseHTTPRequestHandler):
    posts = []
    messages = {}
    fail_after_accept = False
    def log_message(self, *args): pass
    def response(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_POST(self):
        import base64
        expected = 'Basic ' + base64.b64encode(b'fixture:fixture-password').decode()
        if self.path != '/messages' or self.headers.get('Authorization') != expected:
            self.response(401, {'error': 'not_authorised'}); return
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.posts.append(body)
        self.messages[body['id']] = body
        if self.fail_after_accept:
            self.response(500, {'error': 'reply_failed_after_accept'}); return
        self.response(202, {'id': body['id'], 'state': 'Pending', 'recipients': [
            {'phoneNumber': body['phoneNumbers'][0], 'state': 'Pending'}]})
    def do_GET(self):
        mid = self.path.removeprefix('/messages/')
        body = self.messages.get(mid)
        if not body:
            self.response(404, {}); return
        self.response(200, {'id': mid, 'state': 'Delivered', 'recipients': [
            {'phoneNumber': body['phoneNumbers'][0], 'state': 'Delivered'}]})

with tempfile.TemporaryDirectory(prefix='bulkmail-messaging-http-') as tmp:
    root = pathlib.Path(tmp)
    app = root / 'app'; shutil.copytree(REPO / 'app', app)
    data = root / 'data'; data.mkdir()
    sessions = root / 'sessions'; sessions.mkdir()
    dbpath = data / 'bulkmail.sqlite'
    db = sqlite3.connect(dbpath); db.row_factory = sqlite3.Row
    db.executescript((REPO / 'database/schema.sql').read_text())
    password = secrets.token_urlsafe(24)
    password_hash = subprocess.check_output(['php', '-r', 'echo password_hash($argv[1],PASSWORD_DEFAULT);', password]).decode()
    db.executemany('INSERT INTO users(id,username,password_hash,display_name,email,organisation,is_admin) VALUES(?,?,?,?,?,?,?)', [
        (1,'QAAdmin',password_hash,'QA Admin','admin@example.invalid','QA',1),
        (2,'Peter',password_hash,'Peter','peter@example.invalid','QA Peter organisation',1),
        (3,'QAMember',password_hash,'QA Member','member@example.invalid','QA Member',0),
        (4,'QAOther',password_hash,'QA Other','other@example.invalid','QA Other',0),
    ])
    db.executemany('INSERT INTO contacts(id,owner_user_id,name,email,telephone) VALUES(?,?,?,?,?)', [
        (1,2,'QA One','one@example.invalid','07700 900001'),
        (2,2,'QA Duplicate','duplicate@example.invalid','+447700900001'),
        (3,2,'QA Landline','landline@example.invalid','020 7946 0000'),
        (4,4,'QA Foreign','foreign@example.invalid','07700900050'),
    ])
    db.executemany('INSERT INTO groups(id,owner_user_id,name) VALUES(?,?,?)',[(1,2,'QA Peter group'),(2,4,'QA Foreign group')])
    db.executemany('INSERT INTO group_members VALUES(?,?)',[(1,1),(1,2),(1,3),(2,4)])
    db.execute("INSERT INTO mailings(id,initiated_by_user_id,acting_for_user_id,sender_email,subject,body_html,status) VALUES(1,2,2,'peter@example.invalid','Historic email','Retained historic email','sent')")
    db.execute("INSERT INTO mailing_recipients(mailing_id,contact_id,email,status) VALUES(1,1,'one@example.invalid','sent')")
    db.commit()
    legacy_tables = ['users','contacts','groups','group_members','mailings','mailing_recipients','sender_identities','organisation_settings']
    before = {table: [tuple(row) for row in db.execute('SELECT * FROM '+table)] for table in legacy_tables}
    source = (app / 'index.php').read_text().replace("const DB_FILE = '/var/lib/bulkmail/bulkmail.sqlite';", f"const DB_FILE = '{dbpath}';")
    source = source.replace("const DATA_DIR = '/var/lib/bulkmail';", f"const DATA_DIR = '{data}';").replace('const DELIVERY_ENABLED = true;', 'const DELIVERY_ENABLED = false;')
    (app / 'index.php').write_text(source)
    config = root / 'integrations.php'
    sms = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeSms)
    threading.Thread(target=sms.serve_forever, daemon=True).start()
    def set_config(enabled):
        config.write_text("<?php return ['sms'=>['enabled'=>"+('true' if enabled else 'false')+",'base_url'=>'http://127.0.0.1:"+str(sms.server_port)+"','username'=>'fixture','password'=>'fixture-password','allow_http'=>true,'min_interval_seconds'=>1]];")
    set_config(False)
    env = os.environ.copy()
    env.update(BULKMAIL_INTEGRATIONS_CONFIG=str(config), BULKMAIL_APP_DIR=str(app), BULKMAIL_DB=str(dbpath))
    port = free_port(); url = f'http://127.0.0.1:{port}/'
    class Redirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            if headers.get('Location') == '?': headers.replace_header('Location', url)
            return super().http_error_302(req, fp, code, msg, headers)
    def browser(): return urllib.request.build_opener(Redirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def get(opener, path): return opener.open(url+path,timeout=15).read().decode()
    def csrf(page): return html.unescape(re.search(r'name="csrf" value="([^"]+)"',page)[1])
    def post(opener, path, fields):
        return opener.open(urllib.request.Request(url+path,data=urllib.parse.urlencode(fields,doseq=True).encode()),timeout=15).read().decode()
    def status(call):
        try: call(); return 200
        except urllib.error.HTTPError as error: return error.code
    def login(opener, name):
        page = get(opener,'?page=login')
        return post(opener,'?page=login',{'csrf':csrf(page),'username':name,'password':password})
    def worker():
        return subprocess.check_output(['php',str(REPO/'worker/bulkmail-messaging-worker.php'),'--once'],env=env,text=True,timeout=20)
    log = open(root/'php.log','w')
    server = subprocess.Popen(['php','-d',f'session.save_path={sessions}','-S',f'127.0.0.1:{port}','-t',str(app)],env=env,stdout=log,stderr=log)
    try:
        for attempt in range(80):
            try: get(browser(),'?page=login'); break
            except (urllib.error.URLError,OSError): time.sleep(.1)
        admin=browser(); peter=browser(); member=browser()
        check('Existing Peter username and password still log in', 'SMS / WhatsApp' in login(peter,'Peter'))
        login(admin,'QAAdmin'); login(member,'QAMember')
        for page in ['messages','message_history','message_suppressions','messaging_settings','identity_users','audit']:
            output=get(admin,'?page='+page)
            check('Integrated page loads: '+page,'<!doctype html>' in output and 'Fatal error' not in output)
        p=get(admin,'?page=messaging_settings')
        post(admin,'?page=messaging_settings',{'csrf':csrf(p),'action':'grant','owner_user_id':2,'sms':1})
        p=get(admin,'?page=messages&user=2')
        fields={'csrf':csrf(p),'action':'preview','acting_for':2,'channel':'sms','text':'Synthetic fixture message','groups[]':[1],'numbers':'07700900001\n07700900002'}
        output=post(admin,'?page=messages&user=2',fields)
        check('Global disable blocks preview even after an account grant','not enabled' in output and db.execute('SELECT count(*) FROM message_campaigns').fetchone()[0]==0)
        set_config(True)
        output=post(admin,'?page=messages&user=2',fields)
        preview_token=re.search(r'name="preview_token" value="([^"]+)"',output)[1]
        check('Real preview normalises, deduplicates and excludes invalid numbers','2 recipients' in output and '2 duplicates removed' in output and '1 invalid' in output)
        check('Preview makes no provider requests',len(FakeSms.posts)==0)
        send={'csrf':csrf(output),'action':'send','acting_for':2,'preview_token':preview_token}
        post(admin,'?page=messages&user=2',send)
        post(admin,'?page=messages&user=2',send)
        check('Repeated confirmation queues exactly one campaign and two recipients',db.execute('SELECT count(*) FROM message_campaigns').fetchone()[0]==1 and db.execute('SELECT count(*) FROM message_recipients').fetchone()[0]==2)
        campaign=db.execute('SELECT * FROM message_campaigns').fetchone()
        check('Initiator and Peter campaign owner remain separate',campaign['initiated_by_user_id']==1 and campaign['acting_for_user_id']==2)
        db.execute("UPDATE users SET display_name='Renamed account' WHERE id=1");db.commit()
        history=get(admin,'?page=message_history&user=2&id=1')
        check('Campaign history retains the original actor name after a profile rename','Requested by <strong>QA Admin</strong>' in history)
        db.execute("UPDATE users SET display_name='QA Admin' WHERE id=1");db.commit()
        check('Cross-account composer denied for a normal user',status(lambda:get(member,'?page=messages&user=2'))==403)
        check('Cross-account campaign history does not leak',status(lambda:get(member,'?page=message_history&id=1'))==404)
        check('Channel administration denied for a normal user',status(lambda:get(member,'?page=messaging_settings'))==403)
        check('Confirmation rejects invalid CSRF',status(lambda:post(admin,'?page=messages&user=2',dict(send,csrf='forged')))==400)
        p=get(admin,'?page=messages&user=2')
        invalid_fields=dict(fields,csrf=csrf(p),**{'contacts[]':[4],'groups[]':[]})
        output=post(admin,'?page=messages&user=2',invalid_fields)
        check('Foreign contacts cannot enter an administrator-selected account preview','unavailable in this address book' in output)
        p=get(admin,'?page=message_suppressions&user=2')
        post(admin,'?page=message_suppressions&user=2',{'csrf':csrf(p),'action':'suppress','acting_for':2,'channel':'sms','number':'07700900002','reason':'Synthetic opt-out'})
        worker()
        check('Worker sends the exact SMSGate local API shape',len(FakeSms.posts)==1 and FakeSms.posts[0]['textMessage']['text']=='Synthetic fixture message' and FakeSms.posts[0]['phoneNumbers']==['+447700900001'] and FakeSms.posts[0]['withDeliveryReport'] is True)
        check('Provider acceptance is not reported as delivery',db.execute("SELECT status FROM message_recipients WHERE destination='+447700900001'").fetchone()[0]=='submitted')
        db.execute("UPDATE message_channel_state SET last_submit_epoch=0"); db.execute("UPDATE message_recipients SET next_attempt_at=NULL");db.commit()
        worker()
        check('Receipt lookup reconciles a delivered SMS',db.execute("SELECT status FROM message_recipients WHERE destination='+447700900001'").fetchone()[0]=='delivered')
        check('An opt-out added after queueing blocks the pending send',db.execute("SELECT status FROM message_recipients WHERE destination='+447700900002'").fetchone()[0]=='blocked' and len(FakeSms.posts)==1)
        # Simulate a provider accepting the message but losing its success response.
        FakeSms.fail_after_accept=True
        p=get(admin,'?page=messages&user=2')
        output=post(admin,'?page=messages&user=2',dict(fields,csrf=csrf(p),**{'groups[]':[],'numbers':'07700900003'}))
        token=re.search(r'name="preview_token" value="([^"]+)"',output)[1]
        post(admin,'?page=messages&user=2',dict(send,csrf=csrf(output),preview_token=token))
        db.execute('UPDATE message_channel_state SET last_submit_epoch=0');db.commit();worker()
        check('Ambiguous HTTP failure is retained for reconciliation',db.execute("SELECT status FROM message_recipients WHERE destination='+447700900003'").fetchone()[0]=='unknown')
        db.execute('UPDATE message_recipients SET next_attempt_at=NULL');db.commit();worker()
        check('Ambiguous delivery reconciles without a second POST',len(FakeSms.posts)==2 and db.execute("SELECT status FROM message_recipients WHERE destination='+447700900003'").fetchone()[0]=='delivered')
        after={table:[tuple(row) for row in db.execute('SELECT * FROM '+table)] for table in legacy_tables}
        check('All existing user rows, passwords, contacts, groups and email history are unchanged',before==after)
        check('Database integrity and foreign keys hold',db.execute('PRAGMA integrity_check').fetchone()[0]=='ok' and not db.execute('PRAGMA foreign_key_check').fetchall())
        print(json.dumps({'passed':len(checks),'synthetic_data_only':True,'real_messages_sent':0}),flush=True)
    finally:
        server.terminate();server.wait(timeout=10);sms.shutdown();sms.server_close();log.close();db.close()
