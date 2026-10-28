import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createApi } from '../src/server.mjs';
import { Gateway } from '../src/gateway.mjs';
import { Store } from '../src/store.mjs';

const token = 'test-token-that-is-at-least-32-characters';
const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

async function fixture(t) {
  const store = new Store(':memory:');
  const provider = {
    status: () => ({ status: 'pairing' }),
    ready: () => false,
    pairing: () => ({ status: 'pairing', qr: 'private-qr-payload', expires_at: '2030-01-01T00:00:00.000Z' })
  };
  const gateway = new Gateway({ store, provider, config: { enabled: true, sendEnabled: false, minIntervalMs: 1000 } });
  const server = createApi({ gateway, token, qrEncoder: async value => `data:image/png;base64,${Buffer.from(value).toString('base64')}` });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    store.close();
  });
  return { url: `http://127.0.0.1:${server.address().port}`, store };
}

test('all operational and QR endpoints require bearer authentication', async t => {
  const { url } = await fixture(t);
  for (const path of ['/health', '/status', '/pairing', '/messages/any']) {
    const response = await fetch(url + path);
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error, 'unauthorized');
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
});

test('pairing payload stays inside authenticated no-store JSON response', async t => {
  const { url } = await fixture(t);
  const response = await fetch(url + '/pairing', { headers });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(payload.qr, 'private-qr-payload');
  assert.match(payload.qr_data_url, /^data:image\/png;base64,/);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
});

test('JSON validation, disabled sending and unknown status have distinct errors', async t => {
  const { url } = await fixture(t);
  const malformed = await fetch(url + '/messages', { method: 'POST', headers, body: '{' });
  assert.equal(malformed.status, 400);
  const disabled = await fetch(url + '/messages', { method: 'POST', headers, body: JSON.stringify({ id: '1', to: '+447700900123', text: 'test' }) });
  assert.equal(disabled.status, 503);
  assert.equal((await disabled.json()).error, 'sending_disabled');
  const missing = await fetch(url + '/messages/unknown', { headers });
  assert.equal(missing.status, 404);
  const huge = await fetch(url + '/messages', { method: 'POST', headers, body: 'x'.repeat(33000) });
  assert.equal(huge.status, 413);
});
