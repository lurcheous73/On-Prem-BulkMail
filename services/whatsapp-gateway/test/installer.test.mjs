import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync, mkdtempSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../src/store.mjs';

const installer=fileURLToPath(new URL('../../../deployment/install-whatsapp-gateway.sh',import.meta.url));
const skip=!existsSync(installer) ? 'Installer checks run in the full repository, not the standalone service bundle' : false;

test('installer rejects wrong managed path types before replacement or rollback', { skip }, t => {
  const directory=mkdtempSync(join(tmpdir(),'bulkmail-wa-paths-'));
  t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const source=readFileSync(installer,'utf8');
  const start=source.indexOf('for path in "$SERVICE_DIR"');
  const guard=source.slice(start,source.indexOf('exec 9>',start));
  assert.ok(guard.includes('contains another object type'));
  const env={...process.env};
  for (const key of ['SERVICE_DIR','STATE_DIR','ENV_FILE','NODE_DIR','UNIT_FILE','DROPIN_DIR']) env[key]=join(directory,key);
  writeFileSync(env.SERVICE_DIR,'pre-existing file must survive');
  let result=spawnSync('bash',['-c',`fail() { exit 7; }\n${guard}`],{env,encoding:'utf8'});
  assert.equal(result.status,7);
  assert.equal(readFileSync(env.SERVICE_DIR,'utf8'),'pre-existing file must survive');
  rmSync(env.SERVICE_DIR);mkdirSync(env.SERVICE_DIR);mkdirSync(env.ENV_FILE);
  result=spawnSync('bash',['-c',`fail() { exit 7; }\n${guard}`],{env,encoding:'utf8'});
  assert.equal(result.status,7);
  assert.equal(statSync(env.ENV_FILE).isDirectory(),true);
});

test('installer preserves integration values and shares one private token without printing it', { skip }, t => {
  const directory=mkdtempSync(join(tmpdir(),'bulkmail-wa-installer-'));
  t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const source=readFileSync(installer,'utf8');
  const helper=source.match(/<<'PHP'\n([\s\S]*?)\nPHP\n/)[1];
  const helperPath=join(directory,'helper.php');
  writeFileSync(helperPath,helper);
  const env=join(directory,'environment'),config=join(directory,'integrations.php'),state=join(directory,'state'),out=join(directory,'output');
  mkdirSync(state);mkdirSync(out);
  writeFileSync(config,"<?php return ['sms'=>['enabled'=>true,'password'=>'existing-sms-secret'],'identity'=>['enabled'=>true,'base_url'=>'https://ct400.invalid'],'custom'=>['unchanged'=>42],'whatsapp'=>['enabled'=>false,'min_interval_seconds'=>12]];");
  const run=(mode='prepare',rotate='false')=>spawnSync('php',[helperPath,mode,env,config,state,out,rotate],{encoding:'utf8'});
  let result=run();
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stdout,'');
  const preparedEnv=readFileSync(join(out,'environment'),'utf8');
  const token=preparedEnv.match(/^GATEWAY_TOKEN="([a-f0-9]{64})"$/m)[1];
  const readConfig=()=>JSON.parse(spawnSync('php',['-r','echo json_encode(require $argv[1]);',join(out,'integrations')],{encoding:'utf8'}).stdout);
  const prepared=readConfig();
  assert.equal(prepared.sms.password,'existing-sms-secret');
  assert.equal(prepared.sms.enabled,true);
  assert.equal(prepared.identity.enabled,true);
  assert.deepEqual(prepared.custom,{unchanged:42});
  assert.equal(prepared.whatsapp.min_interval_seconds,12);
  assert.equal(prepared.whatsapp.token,token);
  assert.equal(prepared.whatsapp.enabled,false);
  assert.match(preparedEnv,/GATEWAY_ENABLED="false"/);
  assert.match(preparedEnv,/GATEWAY_SEND_ENABLED="false"/);
  assert.equal(statSync(join(out,'environment')).mode&0o777,0o600);

  writeFileSync(env,preparedEnv);
  writeFileSync(config,readFileSync(join(out,'integrations')));
  result=run();
  assert.equal(result.status,0,result.stderr);
  assert.equal(readConfig().whatsapp.token,token);
  // A deliberate mismatch must fail without revealing either token.
  const otherToken='z'.repeat(64);
  writeFileSync(env,preparedEnv.replace(token,otherToken));
  result=run();
  assert.equal(result.status,1);
  assert.match(result.stderr,/tokens conflict/);
  assert.ok(!result.stderr.includes(token)&&!result.stderr.includes(otherToken));
  result=run('prepare','true');
  assert.equal(result.status,0,result.stderr);
  assert.notEqual(readConfig().whatsapp.token,token);
  assert.notEqual(readConfig().whatsapp.token,otherToken);

  // Previously active credentials prevent any installer update, even when flags are false.
  const store=new Store(join(state,'gateway.sqlite'));
  store.authBatch([{category:'credentials',id:'primary',value:'{"registered":true}'}]);
  store.reserve('existing-message','existing-hash','provider-existing');
  store.transition('provider-existing','delivered');
  store.close();
  result=run('prepare','true');
  assert.equal(result.status,1);
  assert.match(result.stderr,/automatic upgrade is refused/);
  const preserved=new Store(join(state,'gateway.sqlite'),{recover:false});
  assert.equal(preserved.authGet('credentials','primary'),'{"registered":true}');
  assert.equal(preserved.find('existing-message').status,'delivered');
  preserved.close();
});
