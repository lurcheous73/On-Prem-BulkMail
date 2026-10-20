import sys,urllib.request,urllib.parse,urllib.error,http.cookiejar,re,json,sqlite3,pathlib,uuid,html,hashlib,subprocess,base64
from email import policy
from email.parser import BytesParser
ROOT=pathlib.Path(sys.argv[1]);cfg=json.loads((ROOT/'qa-auth.json').read_text());QA=pathlib.Path(cfg['qa']);URL='http://127.0.0.1:18889/'
db=sqlite3.connect(QA/'data/bulkmail.sqlite');db.row_factory=sqlite3.Row;passed=[]
keep={'users','domains','user_domains','sender_identities','contacts','groups','group_members','sqlite_sequence'}
for (t,) in db.execute("select name from sqlite_master where type='table'").fetchall():
 if t not in keep:db.execute('delete from "'+t+'"');db.execute('delete from sqlite_sequence where name=?',[t])
db.commit()
def check(name,condition):
 if not condition:raise AssertionError(name)
 passed.append(name);print('PASS:',name,flush=True)
class BrowserRedirect(urllib.request.HTTPRedirectHandler):
 def http_error_302(self,req,fp,code,msg,headers):
  if headers.get('Location')=='?':headers.replace_header('Location',URL)
  return super().http_error_302(req,fp,code,msg,headers)
def opener():return urllib.request.build_opener(BrowserRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def get(o,path):return o.open(URL+path).read().decode()
def token(page,name='csrf'):
 m=re.search(r'name="'+name+r'" value="([^"]+)"',page)
 if not m:raise RuntimeError('Missing '+name+' in '+page[-250:])
 return html.unescape(m[1])
def post(o,path,fields,files=None):
 if files:
  boundary='qa'+uuid.uuid4().hex;parts=[]
  for k,v in fields.items():parts.extend([f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n'.encode(),str(v).encode(),b'\r\n'])
  for name,filename,data in files:parts.extend([f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),data,b'\r\n'])
  parts.append(f'--{boundary}--\r\n'.encode());data=b''.join(parts);ct='multipart/form-data; boundary='+boundary
 else:data=urllib.parse.urlencode(fields).encode();ct='application/x-www-form-urlencoded'
 return o.open(urllib.request.Request(URL+path,data=data,headers={'Content-Type':ct}),timeout=100).read().decode()
def login(o,username='Peter'):
 p=get(o,'?page=login');return post(o,'?page=login',{'csrf':token(p),'username':username,'password':cfg['password']})
def form(page,subject='Complete retained draft',body='<p style="font-family:Dancing Script, Segoe Script, cursive">Signature QA</p>',**extra):
 f={'csrf':token(page),'workspace_token':token(page,'workspace_token'),'action':'preview','acting_for':'2','sender_identity_id':'2','subject':subject,'body_html':body,'groups[0]':'1'};f.update(extra);return f
def count(t):return db.execute('select count(*) from '+t).fetchone()[0]
# A tiny valid PDF for document-as-email retention / re-rendering.
pdf=base64.b64decode('JVBERi0xLjMKJZOMi54gUmVwb3J0TGFiIEdlbmVyYXRlZCBQREYgZG9jdW1lbnQgKG9wZW5zb3VyY2UpCjEgMCBvYmoKPDwKL0YxIDIgMCBSCj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9CYXNlRm9udCAvSGVsdmV0aWNhIC9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nIC9OYW1lIC9GMSAvU3VidHlwZSAvVHlwZTEgL1R5cGUgL0ZvbnQKPj4KZW5kb2JqCjMgMCBvYmoKPDwKL0NvbnRlbnRzIDcgMCBSIC9NZWRpYUJveCBbIDAgMCAzMDAgMjQwIF0gL1BhcmVudCA2IDAgUiAvUmVzb3VyY2VzIDw8Ci9Gb250IDEgMCBSIC9Qcm9jU2V0IFsgL1BERiAvVGV4dCAvSW1hZ2VCIC9JbWFnZUMgL0ltYWdlSSBdCj4+IC9Sb3RhdGUgMCAvVHJhbnMgPDwKCj4+IAogIC9UeXBlIC9QYWdlCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9QYWdlTW9kZSAvVXNlTm9uZSAvUGFnZXMgNiAwIFIgL1R5cGUgL0NhdGFsb2cKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL0F1dGhvciAoYW5vbnltb3VzKSAvQ3JlYXRpb25EYXRlIChEOjIwMjYxMDE2MTg1ODA3KzAwJzAwJykgL0NyZWF0b3IgKGFub255bW91cykgL0tleXdvcmRzICgpIC9Nb2REYXRlIChEOjIwMjYxMDE2MTg1ODA3KzAwJzAwJykgL1Byb2R1Y2VyIChSZXBvcnRMYWIgUERGIExpYnJhcnkgLSBcKG9wZW5zb3VyY2VcKSkgCiAgL1N1YmplY3QgKHVuc3BlY2lmaWVkKSAvVGl0bGUgKHVudGl0bGVkKSAvVHJhcHBlZCAvRmFsc2UKPj4KZW5kb2JqCjYgMCBvYmoKPDwKL0NvdW50IDEgL0tpZHMgWyAzIDAgUiBdIC9UeXBlIC9QYWdlcwo+PgplbmRvYmoKNyAwIG9iago8PAovRmlsdGVyIFsgL0FTQ0lJODVEZWNvZGUgL0ZsYXRlRGVjb2RlIF0gL0xlbmd0aCAxNTkKPj4Kc3RyZWFtCkdhczMrWW1TPyUocllzWDpbb09XVGYwPj1cMStBNyNmPzw7K2NSKmgjcGVkNClxO1xpalBZY0ZoXlEsVG9rTk1xLVMsYzhbNmgkcFRjSzQuSFlOS0dsPnRBKT4nR2Q4RyJhc1AvPTVhWUE7YldJTmY7QFpoTSpkVW1gPUFtbWJkZFowaUteUGdQIjJISl1tKl1nRmwuaSJHSidQazV+PmVuZHN0cmVhbQplbmRvYmoKeHJlZgowIDgKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDYxIDAwMDAwIG4gCjAwMDAwMDAwOTIgMDAwMDAgbiAKMDAwMDAwMDE5OSAwMDAwMCBuIAowMDAwMDAwMzkyIDAwMDAwIG4gCjAwMDAwMDA0NjAgMDAwMDAgbiAKMDAwMDAwMDcyMSAwMDAwMCBuIAowMDAwMDAwNzgwIDAwMDAwIG4gCnRyYWlsZXIKPDwKL0lEIApbPDhlZThhOTQ0MjE5NGEwMzcwNjhhOTc2ZmYyNjk3MGJjPjw4ZWU4YTk0NDIxOTRhMDM3MDY4YTk3NmZmMjY5NzBiYz5dCiUgUmVwb3J0TGFiIGdlbmVyYXRlZCBQREYgZG9jdW1lbnQgLS0gZGlnZXN0IChvcGVuc291cmNlKQoKL0luZm8gNSAwIFIKL1Jvb3QgNCAwIFIKL1NpemUgOAo+PgpzdGFydHhyZWYKMTAyOQolJUVPRgo=')
o=opener();login(o);page=get(o,'?page=compose');oldworkspace=token(page,'workspace_token')
check('Explicit Save as Draft button is present','>Save as Draft</button>' in page)
blank=form(page,subject='',body='',save_draft='1');blank.pop('groups[0]');page=post(o,'?page=compose',blank)
check('Draft can be saved with no subject/body/recipients',count('mail_saved_drafts')==1 and count('mailings')==0)
files=[('attachments[]','shared.txt',b'SHARED CONTENT'),('recipient_attachments[1][]','private-one.txt',b'PERSON ONE ONLY'),('recipient_attachments[2][]','private-two.txt',b'PERSON TWO ONLY'),('document_email','document.pdf',pdf)]
page=post(o,'?page=compose',form(page,save_draft='1'),files)
check('Explicit save never queues a message',count('mailings')==0)
check('Shared, individual and source document files retained',count('compose_file_selection')==4)
check('Repeated save updates one named draft',count('mail_saved_drafts')==1)
firstid=db.execute('select id from mail_saved_drafts').fetchone()[0]
check('All saved files are byte-for-byte intact',all(hashlib.sha256(pathlib.Path(r['stored_path']).read_bytes()).hexdigest()==r['sha256'] for r in db.execute('select * from compose_file_store')))
check('Saved-file list visible in editor',all(n in page for n in ['shared.txt','private-one.txt','private-two.txt','document.pdf']))
page=post(o,'?page=compose',form(page))
check('Preview works without reselecting files','Final Preview' in page and 'shared.txt' in page and 'private-one.txt' in page)
d=json.loads(db.execute('select draft_json from prepared_compose_drafts').fetchone()[0]);check('Document-as-email renders from retained PDF',len(d['assets'])==1 and pathlib.Path(d['assets'][0]['path']).is_file())
page=post(o,'?page=compose',{'csrf':token(page),'action':'back'})
check('Back to editing retains all four files',page.count('class="retained-file"')==4)
page=post(o,'?page=compose',form(page,subject='Edited retained draft',save_draft='1'))
check('Edited draft preserves recipient group',json.loads(db.execute('select snapshot_json from mail_saved_drafts where id=?',[firstid]).fetchone()[0])['groups_json']=='[1]')
page=post(o,'?page=compose',form(page,subject='Edited retained draft',new_message='1'))
check('New message leaves complete prior draft saved',count('mail_saved_drafts')==1 and count('compose_file_selection')==0)
check('New message rotates workspace identity',token(page,'workspace_token')!=oldworkspace)
page=post(o,'?page=compose',form(page,subject='Second independent draft',body='<p>SECOND</p>',save_draft='1'),[('attachments[]','second.txt',b'SECOND DRAFT')])
check('Two separate drafts retain separate file lists',count('mail_saved_drafts')==2 and sorted(len(json.loads(r[0])) for r in db.execute('select files_json from mail_saved_drafts'))==[1,4])
page=get(o,'?page=drafts');page=post(o,'?page=drafts',{'csrf':token(page),'action':'open','id':firstid})
check('Opening first draft restores its files, not second draft files',page.count('class="retained-file"')==4 and 'second.txt' not in page)
restored=json.loads(get(o,'?page=draft_api&acting_for=2'))['draft']
check('Named draft reload restores formatting and edited subject',restored['subject']=='Edited retained draft' and 'Dancing Script' in restored['body_html'])
other=opener();login(other,'QAOther');t=db.execute('select token from compose_file_store where user_id=2 limit 1').fetchone()[0]
try:get(other,'?page=draft_file&token='+t);denied=False
except urllib.error.HTTPError as e:denied=e.code==404
check('Another account cannot download a draft attachment',denied)
try:post(o,'?page=draft_api&acting_for=2',{'csrf':token(page),'workspace_token':oldworkspace,'subject':'STALE OVERWRITE'});denied=False
except urllib.error.HTTPError as e:denied=e.code==409
check('Old browser tab cannot overwrite a newly opened draft',denied and json.loads(get(o,'?page=draft_api&acting_for=2'))['draft']['subject']=='Edited retained draft')
# New session: all components remain in the server-side workspace.
o2=opener();login(o2);page=get(o2,'?page=compose');check('New login retains all four attachments',page.count('class="retained-file"')==4)
page=post(o2,'?page=compose',form(page,subject='Edited retained draft'))
page=post(o2,'?page=compose&preview=1',{'csrf':token(page),'action':'test','draft_token':token(page,'draft_token')})
check('Self test keeps complete draft and all files',count('compose_file_selection')==4 and count('mail_saved_drafts')==2 and 'main mailing has NOT been sent' in page)
check('Self test excludes personal recipient attachments',count('mailing_recipient_attachments')==0 and count('mailing_attachments')==1)
page=post(o2,'?page=compose',{'csrf':token(page),'action':'back'})
remove=db.execute("select token from compose_file_store where kind='individual' and contact_id=2").fetchone()[0]
f=form(page,subject='Edited retained draft');f['remove_file[0]']=remove
page=post(o2,'?page=compose',f)
check('Explicit removal removes only the chosen working attachment',count('compose_file_selection')==3 and 'private-two.txt' not in page and 'private-one.txt' in page)
o3=opener();login(o3);old_preview=get(o3,'?page=compose&preview=1')
page=post(o2,'?page=compose&preview=1',{'csrf':token(page),'action':'queue','draft_token':token(page,'draft_token')})
post(o3,'?page=compose&preview=1',{'csrf':token(old_preview),'action':'queue','draft_token':token(old_preview,'draft_token')})
check('Another login session cannot submit the same preview twice',count('mailings')==2)
check('Main campaign queues exactly once',count('mailings')==2 and db.execute('select count(*) from mailing_recipients where mailing_id=2').fetchone()[0]==2)
check('Personal file is assigned only to its recipient',[(r[0],r[1]) for r in db.execute('select r.email,a.original_name from mailing_recipient_attachments a join mailing_recipients r on r.id=a.mailing_recipient_id')]==[('recipient1@example.invalid','private-one.txt')])
check('Sending first draft does not delete second saved draft',count('mail_saved_drafts')==1 and db.execute('select title from mail_saved_drafts').fetchone()[0]=='Second independent draft')
check('Sending clears working selection without destroying retained sources',count('compose_file_selection')==0 and all(pathlib.Path(r[0]).is_file() for r in db.execute('select stored_path from compose_file_store')))
# Simulate successful handoff in isolated SQLite ONLY; no mail worker runs here.
db.execute("update mailing_recipients set status='postfix'");db.execute("update mailings set status='submitted'");db.commit()
exp=['php',str(QA/'app/bulkmail-sent-export.php')]
obj=json.loads(subprocess.check_output(exp+['render','2']));eml=base64.b64decode(obj['eml']);msg=BytesParser(policy=policy.default).parsebytes(eml)
check('Sent archive has complete recipient list and deterministic marker',len(msg['Bcc'].addresses)==2 and msg['X-Grange-Sent-Copy']==obj['message_key'])
check('Sent archive retains shared attachment and document image',any(p.get_filename()=='shared.txt' for p in msg.walk()) and any(p.get_content_type()=='image/jpeg' for p in msg.walk()))
check('Sent archive includes signature font CSS',('Dancing Script' in msg.get_body(preferencelist=('html',)).get_content()) and '@font-face' in msg.get_body(preferencelist=('html',)).get_content())
obj2=json.loads(subprocess.check_output(exp+['render','2']));check('Retry generates identical Sent copy, not another message ID',obj2['message_key']==obj['message_key'] and obj2['eml']==obj['eml'])
subprocess.run(exp+['ack','2'],input=b'{"ok":false,"error":"QA mailbox temporarily unavailable"}',check=True,stdout=subprocess.DEVNULL)
check('Filing failure is recorded without requeueing delivery',db.execute('select status from sent_mailbox_copies where mailing_id=2').fetchone()[0]=='failed' and db.execute("select count(*) from mailing_recipients where status<>'postfix'").fetchone()[0]==0)
subprocess.run(exp+['ack','2'],input=b'{"ok":true}',check=True,stdout=subprocess.DEVNULL)
check('Filed campaign excluded from future archive work',2 not in json.loads(subprocess.check_output(exp+['list']))['ids'])
# Existing Use Again workflow must retain its old files and rendered document when editing.
page=get(o2,'?page=reuse&id=2');check('Use Again opens without sending',count('mailings')==2 and 'Final Preview' in page)
page=post(o2,'?page=compose',{'csrf':token(page),'action':'back'})
check('Use Again followed by editing retains both original file attachments',page.count('class="retained-file"')==2 and 'shared.txt' in page and 'private-one.txt' in page)
reuse=json.loads(get(o2,'?page=draft_api&acting_for=2'))['draft']
check('Reused document images remain editable inline images','page=editor_image' in reuse['body_html'])
page=post(o2,'?page=compose',form(page,subject='Reuse edited',body=reuse['body_html']))
d=json.loads(db.execute('select draft_json from prepared_compose_drafts').fetchone()[0]);check('Reused document image survives another preview',len(d['assets'])==1)
page=post(o2,'?page=compose',{'csrf':token(page),'action':'back'});page=post(o2,'?page=compose',form(page,subject='Reuse edited',body=reuse['body_html'],save_draft='1'))
reuseid=db.execute("select id from mail_saved_drafts where title='Reuse edited'").fetchone()[0]
secondid=db.execute("select id from mail_saved_drafts where title='Second independent draft'").fetchone()[0]
page=get(o2,'?page=drafts');page=post(o2,'?page=drafts',{'csrf':token(page),'action':'open','id':secondid})
post(o2,'?page=draft_api&acting_for=2',{'csrf':token(page),'workspace_token':token(page,'workspace_token'),'subject':'New unsaved typing','body_html':'<p>KEEP MY WORK</p>','groups':'[1]','contacts':'[]','sender_identity_id':'2'})
page=get(o2,'?page=drafts');page=post(o2,'?page=drafts',{'csrf':token(page),'action':'open','id':reuseid})
check('Switching drafts preserves current unsaved typing',db.execute('select title from mail_saved_drafts where id=?',[secondid]).fetchone()[0]=='New unsaved typing')
db.execute("insert into email_templates(owner_user_id,created_by_user_id,sender_identity_id,name,subject,body_html)values(2,2,2,'QA Template','Template subject','<p>Template</p>')");tid=db.execute('select last_insert_rowid()').fetchone()[0];db.commit()
page=get(o2,'?page=template_use&id='+str(tid));check('Starting from template cannot inherit unrelated attachments',count('compose_file_selection')==0 and 'class="retained-file"' not in page)
check('All extra recovery/reuse tests leave mailing count unchanged',count('mailings')==2)
(ROOT/'complete-http-results.json').write_text(json.dumps({'passed':passed,'no_customer_emails_sent':True},indent=2))
print('ALL',len(passed),'full-draft/attachment/archive HTTP checks passed.',flush=True)
