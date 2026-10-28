import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { Store } from '../src/store.mjs';

const project = fileURLToPath(new URL('..', import.meta.url));
const token = 'synthetic-process-test-token-0123456789';

async function unusedPort() {
  const socket = createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}

async function completed(child) {
  return (await once(child, 'exit'))[0];
}

test('disabled process starts privately; concurrent account instance and reset are refused', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'bulkmail-wa-process-'));
  const port = await unusedPort();
  const env = { ...process.env, GATEWAY_TOKEN: token, GATEWAY_DATA_DIR: directory,
    GATEWAY_HOST: '127.0.0.1', GATEWAY_PORT: String(port), GATEWAY_ENABLED: 'false', GATEWAY_SEND_ENABLED: 'false' };
  const child = spawn(process.execPath, ['src/main.mjs'], { cwd: project, env, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await once(child, 'exit');
    }
    rmSync(directory, { recursive: true, force: true });
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Gateway did not start')), 5000);
    child.stdout.on('data', data => {
      if (data.toString().includes('gateway_started_disabled')) { clearTimeout(timer); resolve(); }
    });
    child.once('exit', () => { clearTimeout(timer); reject(new Error('Gateway exited before ready')); });
  });
  const response = await fetch(`http://127.0.0.1:${port}/health`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal((await response.json()).status, 'disabled');
  assert.equal(statSync(directory).mode & 0o777, 0o700);
  assert.equal(statSync(join(directory, 'gateway.sqlite')).mode & 0o777, 0o600);

  const other = spawn(process.execPath, ['src/main.mjs'], {
    cwd: project, env: { ...env, GATEWAY_PORT: String(await unusedPort()) }, stdio: 'ignore'
  });
  assert.equal(await completed(other), 1);
  const reset = spawn(process.execPath, ['src/reset-link.mjs', '--confirm-reset-whatsapp-link'], {
    cwd: project, env, stdio: 'ignore'
  });
  assert.equal(await completed(reset), 1);
  child.kill('SIGTERM');
  assert.equal(await completed(child), 0);
});

test('explicit link reset preserves the durable outbound journal', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'bulkmail-wa-reset-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  let store = new Store(join(directory, 'gateway.sqlite'));
  store.reserve('keep-this-id', 'body-hash', 'provider-existing');
  store.transition('provider-existing', 'delivered');
  store.authBatch([{ category: 'credentials', id: 'primary', value: '{"registered":true}' }]);
  store.close();
  const child = spawn(process.execPath, ['src/reset-link.mjs', '--confirm-reset-whatsapp-link'], {
    cwd: project, env: { ...process.env, GATEWAY_DATA_DIR: directory }, stdio: 'ignore'
  });
  assert.equal(await completed(child), 0);
  store = new Store(join(directory, 'gateway.sqlite'));
  assert.equal(store.find('keep-this-id').status, 'delivered');
  assert.equal(store.authGet('credentials', 'primary'), undefined);
  store.close();
});
