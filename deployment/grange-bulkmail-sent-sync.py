#!/usr/bin/env python3
"""File completed Grange mailings into the sender's IMAP Sent folder, once.
No SMTP connection, credentials, shell interpolation or delivery retries are used.
"""
import base64,fcntl,json,os,re,subprocess,sys,uuid
LOCK='/run/lock/grange-bulkmail-sent.lock'
EXPORT=['pct','exec','300','--','runuser','-u','www-data','--','php','/usr/local/sbin/bulkmail-sent-export.php']
DOCKER=['pct','exec','400','--','docker','exec','-i','onlyoffice-mail-server']
def run(args,data=None,timeout=90):
    p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace')[:800] or 'Command failed')
    return p.stdout

def sync_one(mid):
    obj=json.loads(run(EXPORT+['render',str(mid)]));mailbox=obj['mailbox'];key=obj['message_key']
    if not re.fullmatch(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+',mailbox):raise ValueError('Invalid mailbox')
    if not re.fullmatch(r'[a-f0-9]{64}',key):raise ValueError('Invalid archive key')
    message=base64.b64decode(obj['eml'],validate=True)
    if len(message)>100*1024*1024:raise ValueError('Mailbox copy exceeds 100 MB safety limit')
    run(DOCKER+['doveadm','user',mailbox])
    folders=run(DOCKER+['doveadm','mailbox','list','-u',mailbox]).decode().splitlines()
    if 'Sent' not in folders:raise RuntimeError('The sender does not have a Sent mailbox; no folder was guessed')
    query=DOCKER+['doveadm','search','-u',mailbox,'mailbox','Sent','HEADER','X-Grange-Sent-Copy',key]
    if run(query).strip():return 'already filed'
    # Dovecot 2.1 has import, not doveadm save. A private temporary Maildir supplies one Seen message.
    token=uuid.uuid4().hex;path='/tmp/grange-sent-'+token
    setup='set -eu; umask 077; mkdir -p "$1/cur" "$1/new" "$1/tmp" "$1/.Sent/cur" "$1/.Sent/new" "$1/.Sent/tmp"; cat > "$1/.Sent/cur/message:2,S"; chown -R vmail:vmail "$1"'
    try:
        run(DOCKER+['sh','-c',setup,'sent-copy',path],message)
        run(DOCKER+['doveadm','import','-u',mailbox,'-s','maildir:'+path,'','mailbox','Sent'])
        if not run(query).strip():raise RuntimeError('Import returned, but Sent-folder verification did not find the copy')
    finally:
        run(DOCKER+['sh','-c','test "${1#/tmp/grange-sent-}" != "$1" && rm -rf -- "$1"','cleanup',path])
    return 'filed and verified'

def main():
    os.makedirs(os.path.dirname(LOCK),exist_ok=True)
    with open(LOCK,'w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        ids=json.loads(run(EXPORT+['list']))['ids']
        for mid in ids:
            try:
                result=sync_one(int(mid));run(EXPORT+['ack',str(int(mid))],b'{"ok":true}');print('Mailing',mid,result,flush=True)
            except Exception as exc:
                error=str(exc).replace('\n',' ')[:1000]
                try:run(EXPORT+['ack',str(int(mid))],json.dumps({'ok':False,'error':error}).encode())
                except Exception:pass
                print('Mailing',mid,'Sent-folder copy pending:',error,file=sys.stderr,flush=True)
if __name__=='__main__':main()
