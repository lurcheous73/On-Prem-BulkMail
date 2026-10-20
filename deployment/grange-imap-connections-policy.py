#!/usr/bin/env python3
"""Bounded IMAP folder-connection capacity for OnlyOffice's per-folder clients.
No mailbox data, credentials, network access rules or SMTP settings are changed.
"""
from pathlib import Path
import subprocess,re,os,datetime
C='onlyoffice-mail-server';CONF='/etc/dovecot/dovecot.conf';BACKUP=Path('/root/grange-mail-imap-fix-20261016')
def run(args,data=None):
 p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
 if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace')[:800] or 'Command failed')
 return p.stdout
state=subprocess.run(['docker','inspect','--format','{{.State.Running}}',C],capture_output=True,text=True)
if state.returncode or state.stdout.strip()!='true':raise SystemExit(0)
original=run(['docker','exec',C,'cat',CONF]);text=original.decode()
blocks=list(re.finditer(r'(?ms)^protocol imap\s*\{.*?^\}',text))
if len(blocks)!=1:raise SystemExit('IMAP block not unique; configuration left unchanged')
b=blocks[0];block=b.group();match=re.search(r'(?m)^\s*mail_max_userip_connections\s*=\s*(\d+)\s*$',block)
if not match:raise SystemExit('Explicit IMAP limit not found; configuration left unchanged')
if int(match.group(1))>=100:raise SystemExit(0)
changed=re.sub(r'(?m)^(\s*mail_max_userip_connections\s*=\s*)\d+(\s*)$',r'\g<1>100\2',block,count=1)
new=text[:b.start()]+changed+text[b.end():]
BACKUP.mkdir(mode=0o700,exist_ok=True)
backup=BACKUP/('dovecot.conf.'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
backup.write_bytes(original);backup.chmod(0o600)
run(['docker','exec','-i',C,'sh','-c','umask 022; cat > /etc/dovecot/.grange-imap-test.conf'],new.encode())
# Parse candidate before atomic installation. Failed validation never changes the live file.
run(['docker','exec',C,'doveconf','-c','/etc/dovecot/.grange-imap-test.conf','-n'])
run(['docker','exec',C,'mv','/etc/dovecot/.grange-imap-test.conf',CONF])
try:
 run(['docker','exec',C,'doveadm','reload'])
 result=run(['docker','exec',C,'doveconf','-f','protocol=imap','-h','mail_max_userip_connections']).decode().strip()
 if result!='100':raise RuntimeError('Effective IMAP setting did not match')
except Exception:
 run(['docker','exec','-i',C,'sh','-c','cat > /etc/dovecot/dovecot.conf'],original)
 run(['docker','exec',C,'doveadm','reload']);raise
print('IMAP per-account/IP folder-connection limit raised from '+match.group(1)+' to 100; configuration reloaded, mailboxes unchanged.')
