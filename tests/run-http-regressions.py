import tempfile,shutil,pathlib,sqlite3,secrets,subprocess,json,urllib.request,urllib.parse,urllib.error,http.cookiejar,re,html,time,hashlib,os
REPO=pathlib.Path(__file__).resolve().parents[1]
R=pathlib.Path(tempfile.mkdtemp(prefix='bulkmail-http-'));Q=R/'qa';URL='http://127.0.0.1:18890/';passed=[]
(Q/'data').mkdir(parents=True);(Q/'sessions').mkdir()
shutil.copytree(REPO/'app',Q/'app')
seed=sqlite3.connect(Q/'data/bulkmail.sqlite');seed.executescript((REPO/'database/schema.sql').read_text());seed.close()
print('Isolated test directory:',R,flush=True)
db=sqlite3.connect(Q/'data/bulkmail.sqlite');db.row_factory=sqlite3.Row
password=secrets.token_urlsafe(24)
password_hash=subprocess.check_output(['php','-r','echo password_hash($argv[1],PASSWORD_DEFAULT);',password]).decode()
db.executemany('INSERT INTO users(id,username,password_hash,display_name,email,organisation,is_admin) VALUES(?,?,?,?,?,?,?)',[(1,'QAAdmin',password_hash,'QA Admin','admin@example.invalid','QA',1),(2,'Peter',password_hash,'QA Peter','peter@example.invalid','QA',0),(3,'QAOther',password_hash,'QA Other','other@example.invalid','QA Other',0)])
db.execute("INSERT INTO domains(id,domain,description)VALUES(1,'example.invalid','QA')")
db.execute('INSERT INTO user_domains(user_id,domain_id)VALUES(2,1)')
db.execute("INSERT INTO sender_identities(id,owner_user_id,domain_id,label,email)VALUES(2,2,1,'QA Sender','peter@example.invalid')")
db.executemany('INSERT INTO contacts(id,owner_user_id,name,email,active)VALUES(?,?,?,?,?)',[(1,2,'QA Gareth','gareth@example.invalid',1),(2,2,'QA Existing','existing@example.invalid',1),(3,2,'QA Archived','archived@example.invalid',0),(4,3,'QA Other','other@example.invalid',1)])
db.executemany('INSERT INTO groups(id,owner_user_id,name)VALUES(?,?,?)',[(1,2,'QA Group'),(2,2,'QA Second'),(3,3,'QA Foreign')])
db.executemany('INSERT INTO group_members(group_id,contact_id)VALUES(?,?)',[(1,1),(1,2),(3,4)]);db.commit()
def check(name,cond):
 assert cond,name
 passed.append(name);print('PASS: '+name,flush=True)
class Redirect(urllib.request.HTTPRedirectHandler):
 def http_error_302(self,req,fp,code,msg,headers):
  if headers.get('Location')=='?':headers.replace_header('Location',URL)
  return super().http_error_302(req,fp,code,msg,headers)
def browser():return urllib.request.build_opener(Redirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def get(o,path):return o.open(URL+path,timeout=20).read().decode()
def token(s):return re.search(r'name="csrf" value="([^"]+)"',s)[1]
def post(o,fields,path='?page=contacts'):
 return o.open(urllib.request.Request(URL+path,data=urllib.parse.urlencode(fields,doseq=True).encode()),timeout=20).read().decode()
def login(o,name):
 p=get(o,'?page=login');post(o,{'csrf':token(p),'username':name,'password':password},'?page=login')
def form(o,**extra):
 p=get(o,'?page=contacts&edit=1')
 data={'csrf':token(p),'action':'save','id':1,'name':'QA Gareth edited','email':'new@example.invalid','company':'QA Co','telephone':'01234','unit_name':'QA Unit','unit_number':'123','notes':'Keep <details> & all text','lawful_basis':'QA basis','source':'QA source','source_date':'2026-10-20','groups[]':[1,2]}
 data.update(extra);return data
def snapshot(cid):return dict(db.execute('SELECT * FROM contacts WHERE id=?',[cid]).fetchone())
def groups(cid):return [x[0] for x in db.execute('SELECT group_id FROM group_members WHERE contact_id=? ORDER BY group_id',[cid])]
def count(t):return db.execute('SELECT COUNT(*) FROM '+t).fetchone()[0]
def isolated(content):
 return content.replace("const DB_FILE = '/var/lib/bulkmail/bulkmail.sqlite';",f"const DB_FILE = '{Q}/data/bulkmail.sqlite';").replace("const DATA_DIR = '/var/lib/bulkmail';",f"const DATA_DIR = '{Q}/data';").replace("const DELIVERY_ENABLED = true;","const DELIVERY_ENABLED = false;")
log=open(R/'qa-http.log','w')
(Q/'app/index.php').write_text(isolated((REPO/'app/index.php').read_text()))
server=subprocess.Popen(['php','-d',f'session.save_path={Q}/sessions','-S','127.0.0.1:18890','-t',str(Q/'app')],stdout=log,stderr=log)
(R/'qa-server.pid').write_text(str(server.pid))
try:
 for i in range(40):
  try:get(browser(),'?page=login');break
  except (OSError,urllib.error.URLError):time.sleep(.1)
 o=browser();login(o,'Peter')
 p=post(o,form(o))
 check('Unique email edit saves through the real PHP route','Contact saved.' in p and snapshot(1)['email']=='new@example.invalid')
 check('Successful edit keeps contact ID, all details and selected groups',snapshot(1)['name']=='QA Gareth edited' and snapshot(1)['notes']=='Keep <details> & all text' and groups(1)==[1,2])
 p=post(o,form(o,email='  NEW@EXAMPLE.INVALID  '))
 check('Saving the same address normalises case and whitespace','Contact saved.' in p and snapshot(1)['email']=='new@example.invalid')
 before=snapshot(1);gm=groups(1);aud=count('audit_log')
 p=post(o,form(o,email='EXISTING@example.invalid',name='Unsaved revised name',**{'groups[]':[2]}))
 check('Active duplicate explains the conflict without SQL errors','already belongs to QA Existing' in p and 'SQLSTATE' not in p and 'UNIQUE constraint failed' not in p)
 check('Failed edit preserves entered fields and checked groups','value="Unsaved revised name"' in p and 'value="EXISTING@example.invalid"' in p and 'value="2" checked' in p and 'value="1" checked' not in p)
 check('Duplicate failure leaves contact, memberships and audit untouched',snapshot(1)==before and groups(1)==gm and count('audit_log')==aud)
 check('Duplicate offers an owner-scoped link to the existing contact','?page=contacts&amp;user=2&amp;edit=2' in p)
 p=post(o,form(o,email='ARCHIVED@example.invalid'))
 check('Archived conflict provides restoration guidance','archived contact (QA Archived)' in p and 'restore the archived entry' in p and 'SQLSTATE' not in p)
 check('Archived conflict does not silently merge or overwrite either contact',snapshot(1)==before and snapshot(3)['active']==0)
 p=post(o,form(o,id=0,email='existing@example.invalid'))
 check('Creating an active duplicate is also friendly and retains input','already belongs to an active contact' in p and 'SQLSTATE' not in p and 'value="existing@example.invalid"' in p)
 p=post(o,form(o,id=0,email='ARCHIVED@example.invalid'))
 check('Adding an archived address restores its existing contact ID','Contact saved.' in p and snapshot(3)['active']==1 and snapshot(3)['email']=='archived@example.invalid' and groups(3)==[1,2])
 p=post(o,form(o,id=0,email='another-unit@example.invalid'))
 check('Same person with a distinct unit email remains supported','Contact saved.' in p and count('contacts')==5)
 p=post(o,form(o,email='other@example.invalid'))
 check('Same address in a different user address book remains allowed','Contact saved.' in p and snapshot(1)['email']=='other@example.invalid' and snapshot(4)['email']=='other@example.invalid')
 foreign=snapshot(4);fg=groups(4)
 p=post(o,form(o,id=4,name='FORGED',**{'groups[]':[1]}))
 check('Forged contact ID cannot edit another address book','does not belong to this address book' in p and snapshot(4)==foreign and groups(4)==fg)
 p=post(o,form(o,**{'groups[]':[2,3]}))
 check('Foreign groups cannot be assigned to a contact','Contact saved.' in p and groups(1)==[2] and groups(4)==fg)
 before=snapshot(1)
 p=post(o,form(o,email='broken-address',notes='Still here'))
 check('Invalid email retains form and makes no database changes','Enter a valid email address.' in p and 'Still here' in p and 'value="broken-address"' in p and snapshot(1)==before)
 p=post(o,form(o,id=999999))
 check('Missing contact gives a friendly error and creates no phantom memberships','does not belong to this address book' in p and count('contacts')==5)
 for name,msg in [('qa_generic',"forced internal QA database failure"),('qa_unique',"UNIQUE constraint failed: contacts.owner_user_id, contacts.email")]:
  db.execute("CREATE TRIGGER "+name+" BEFORE UPDATE ON contacts BEGIN SELECT RAISE(ABORT,'"+msg+"'); END;");db.commit()
  p=post(o,form(o))
  check('Database exception safely handled: '+name, 'SQLSTATE' not in p and msg not in p and snapshot(1)==before and 'value="new@example.invalid"' in p)
  db.execute('DROP TRIGGER '+name);db.commit()
 try:
  post(o,dict(form(o),csrf='bad'));status=200
 except urllib.error.HTTPError as e:status=e.code
 check('CSRF rejection still works',status==400)
 p=post(o,form(o,**{'groups[]':[]}))
 check('Clearing all group selections remains supported','Contact saved.' in p and groups(1)==[])
 admin=browser();login(admin,'QAAdmin')
 p=post(admin,dict(form(admin),acting_for=2),'?page=contacts&user=2')
 check('Administrator can still save within the selected user context','Contact saved.' in p and snapshot(1)['owner_user_id']==2)
 for page in ['home','contacts','groups','compose','drafts','templates','history']:
  p=get(o,'?page='+page)
  check('Mailer page loads: '+page,'<!doctype html>' in p and 'Fatal error' not in p and 'SQLSTATE' not in p)
 check('Contact regression tests queue zero emails',count('mailings')==0 and count('mailing_recipients')==0)
 check('Isolated database integrity and references pass',db.execute('PRAGMA integrity_check').fetchone()[0]=='ok' and not db.execute('PRAGMA foreign_key_check').fetchall())
 (R/'contact-test-results.json').write_text(json.dumps({'passed':passed,'count':len(passed),'synthetic_data_only':True},indent=2))
 # Reuse the established full-mailer QA suite with synthetic fixtures and no worker.
 db.execute('DELETE FROM group_members');db.execute('DELETE FROM contacts');db.execute('DELETE FROM groups')
 db.executemany('INSERT INTO contacts(id,owner_user_id,name,email)VALUES(?,?,?,?)',[(1,2,'QA One','recipient1@example.invalid'),(2,2,'QA Two','recipient2@example.invalid')])
 db.execute("INSERT INTO groups(id,owner_user_id,name)VALUES(1,2,'QA Group')");db.executemany('INSERT INTO group_members VALUES(?,?)',[(1,1),(1,2)]);db.commit();db.close()
 cfg={'qa':str(Q),'password':password}
 (R/'qa-auth.json').write_text(json.dumps(cfg));os.chmod(R/'qa-auth.json',0o600)
 # DELIVERY_ENABLED only permits queue creation in this isolated database; no worker exists.
 q=Q/'app/index.php';q.write_text(q.read_text().replace('const DELIVERY_ENABLED = false;','const DELIVERY_ENABLED = true;'))
 exporter=(REPO/'worker/bulkmail-sent-export.php').read_text().replace('/var/lib/bulkmail',str(Q/'data')).replace('/usr/local/sbin/bulkmail-worker.php',str(Q/'app/bulkmail-worker.php'))
 (Q/'app/bulkmail-sent-export.php').write_text(exporter)
 worker=(REPO/'worker/bulkmail-worker.php').read_text().replace('/var/lib/bulkmail',str(Q/'data')).replace('/var/www/bulkmail',str(Q/'app'))
 (Q/'app/bulkmail-worker.php').write_text(worker)
 test=(REPO/'tests/full-mailer-http.py').read_text().replace("ROOT=pathlib.Path('/root/bulkmail-complete-drafts-20261016')",f"ROOT=pathlib.Path('{R}')").replace('127.0.0.1:18889','127.0.0.1:18890')
 (R/'full-mailer-tests.py').write_text(test)
 subprocess.run(['python3',str(R/'full-mailer-tests.py'),str(R)],check=True)
finally:
 server.terminate();server.wait(timeout=10);log.close()
 (R/'qa-server.pid').unlink(missing_ok=True)
