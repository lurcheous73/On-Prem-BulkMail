import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Gateway, validateMessage } from '../src/gateway.mjs';
import { loadConfig } from '../src/config.mjs';

const sample = { id: 'bulkmail-101', to: '+447700900123', text: 'Synthetic test only' };

function fixture(t, overrides = {}) {
  const store = new Store(':memory:');
  t.after(() => store.close());
  let calls = 0;
  const provider = {
    ready: () => true,
    status: () => ({ status: 'connected' }),
    newMessageId: () => `provider-${calls + 1}`,
    saveRetryMessage: (id, value) => store.saveMessage(id, JSON.stringify(value)),
    send: async (to, text, id) => { calls++; return { key: { id }, message: { conversation: text } }; },
    ...overrides
  };
  const config = { enabled: true, sendEnabled: true, minIntervalMs: 0, sendTimeoutMs: 50 };
  const gateway = new Gateway({ store, provider, config });
  return { store, provider, config, gateway, calls: () => calls };
}

test('configuration defaults to no connection and no outbound messages', () => {
  const config = loadConfig({ GATEWAY_TOKEN: 'x'.repeat(32) });
  assert.equal(config.enabled, false);
  assert.equal(config.sendEnabled, false);
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.sendTimeoutMs, 15000);
  assert.throws(() => loadConfig({ GATEWAY_TOKEN: 'x'.repeat(32), GATEWAY_HOST: '0.0.0.0' }));
  assert.throws(() => loadConfig({ GATEWAY_TOKEN: 'short' }));
  assert.throws(() => loadConfig({ GATEWAY_TOKEN: 'x'.repeat(32), GATEWAY_ENABLED: 'yes' }));
});

test('only canonical UK mobiles and non-empty bounded text are accepted', () => {
  assert.deepEqual(validateMessage(sample), sample);
  for (const to of ['07700900123', '+447000900123', '+447600900123', '+12025550123', '447700900123@s.whatsapp.net', '+447700900123,evil']) {
    assert.throws(() => validateMessage({ ...sample, to }));
  }
  assert.throws(() => validateMessage({ ...sample, id: '../oops' }));
  assert.throws(() => validateMessage({ ...sample, text: ' ' }));
  assert.throws(() => validateMessage({ ...sample, text: 'x'.repeat(4097) }));
});

test('disabled delivery never inserts an attempt or calls the transport', async t => {
  const f = fixture(t);
  f.config.sendEnabled = false;
  await assert.rejects(f.gateway.submit(sample), error => error.code === 'sending_disabled');
  assert.equal(f.store.find(sample.id), null);
  assert.equal(f.calls(), 0);
});

test('same ID and content are sent once; changed content with same ID conflicts', async t => {
  const f = fixture(t);
  const first = await f.gateway.submit(sample);
  assert.equal(first.message.status, 'submitted');
  assert.equal(first.duplicate, false);
  const again = await f.gateway.submit(sample);
  assert.equal(again.duplicate, true);
  assert.equal(f.calls(), 1);
  await assert.rejects(f.gateway.submit({ ...sample, text: 'different' }), error => error.code === 'id_conflict');
  assert.equal(f.calls(), 1);
  // Reconciliation also works when sending has subsequently been disabled.
  f.config.sendEnabled = false;
  assert.equal((await f.gateway.submit(sample)).message.provider_id, first.message.provider_id);
});

test('a receipt arriving before send completion cannot be downgraded', async t => {
  const f = fixture(t);
  f.provider.send = async (to, text, id) => {
    f.store.transition(id, 'delivered');
    return { key: { id }, message: { conversation: text } };
  };
  const result = await f.gateway.submit(sample);
  assert.equal(result.message.status, 'delivered');
  f.store.transition(result.message.provider_id, 'read');
  f.store.transition(result.message.provider_id, 'failed');
  assert.equal(f.gateway.find(sample.id).status, 'read');
});

test('uncertain transport failure stays unknown and does not resend', async t => {
  let calls = 0;
  const f = fixture(t, { send: async () => { calls++; throw new Error('simulated network failure'); } });
  assert.equal((await f.gateway.submit(sample)).message.status, 'unknown');
  assert.equal((await f.gateway.submit(sample)).duplicate, true);
  assert.equal(calls, 1);
});

test('timeout stays busy until original attempt settles; repeats never call send twice', async t => {
  let complete;
  let calls = 0;
  const f = fixture(t, { send: (to, text, id) => {
    calls++;
    return new Promise(resolve => { complete = () => resolve({ key: { id } }); });
  } });
  f.config.sendTimeoutMs = 10;
  const first = await f.gateway.submit(sample);
  assert.equal(first.message.status, 'unknown');
  assert.equal(f.gateway.status().sending, true);
  assert.equal((await f.gateway.submit(sample)).duplicate, true);
  await assert.rejects(f.gateway.submit({ ...sample, id: 'other' }), error => error.code === 'gateway_busy');
  complete();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.gateway.find(sample.id).status, 'submitted');
  assert.equal(f.gateway.status().sending, false);
  assert.equal(calls, 1);
});

test('crash recovery marks in-flight work unknown without replaying it', t => {
  const directory = mkdtempSync(join(tmpdir(), 'bulkmail-wa-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const filename = join(directory, 'test.sqlite');
  let store = new Store(filename);
  store.reserve('interrupted', 'hash', 'provider-1');
  store.reserve('acknowledged', 'hash2', 'provider-2');
  store.transition('provider-2', 'submitted');
  store.close();
  store = new Store(filename);
  assert.equal(store.find('interrupted').status, 'unknown');
  assert.equal(store.find('interrupted').error, 'gateway_restarted_during_send');
  assert.equal(store.find('acknowledged').status, 'submitted');
  store.close();
});

test('message body retention does not delete idempotency or delivery records', t => {
  const f = fixture(t);
  f.store.reserve('old', 'hash', 'provider-1');
  f.store.saveMessage('provider-1', JSON.stringify({ conversation: 'private' }));
  assert.equal(f.store.pruneMessageBodies('9999-01-01T00:00:00.000Z'), 1);
  assert.equal(f.store.find('old').message_json, null);
  assert.equal(f.store.find('old').content_hash, 'hash');
});
