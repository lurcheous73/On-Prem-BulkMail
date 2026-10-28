import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Store } from '../src/store.mjs';
import { createSqliteAuthState } from '../src/auth-state.mjs';
import { BaileysProvider } from '../src/baileys-provider.mjs';

function libraryStub() {
  const sockets = [];
  const lib = {
    BufferJSON: {
      replacer: (key, value) => value instanceof Uint8Array ? { type: 'Buffer', data: [...value] } : value,
      reviver: (key, value) => value?.type === 'Buffer' ? Buffer.from(value.data) : value
    },
    initAuthCreds: () => ({ registered: false, secret: Buffer.from('test-only') }),
    proto: {
      Message: { AppStateSyncKeyData: { fromObject: value => ({ ...value, hydrated: true }) } },
      WebMessageInfo: { Status: { ERROR: 0, SERVER_ACK: 2, DELIVERY_ACK: 3, READ: 4, PLAYED: 5 } }
    },
    makeCacheableSignalKeyStore: value => value,
    generateMessageIDV2: () => 'provider-id',
    DisconnectReason: { loggedOut: 401, badSession: 500, connectionReplaced: 440, multideviceMismatch: 411, forbidden: 403, restartRequired: 515 },
    default: config => {
      const socket = { config, ev: new EventEmitter(), ended: 0, end() { this.ended++; } };
      sockets.push(socket);
      return socket;
    }
  };
  return { lib, sockets };
}

test('credentials and all key categories persist atomically with binary values', async t => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  const { lib } = libraryStub();
  const first = createSqliteAuthState(store, lib);
  first.saveCreds({ registered: true, me: { id: 'synthetic' } });
  await first.state.keys.set({ session: { a: Buffer.from([1, 2, 3]) }, 'app-state-sync-key': { b: { keyData: Buffer.from([4]) } } });
  const second = createSqliteAuthState(store, lib);
  assert.equal(second.state.creds.registered, true);
  assert.deepEqual(second.state.creds.secret, Buffer.from('test-only'));
  assert.deepEqual((await second.state.keys.get('session', ['a'])).a, Buffer.from([1, 2, 3]));
  assert.equal((await second.state.keys.get('app-state-sync-key', ['b'])).b.hydrated, true);
  await second.state.keys.set({ session: { a: null } });
  assert.equal((await second.state.keys.get('session', ['a'])).a, undefined);
});

test('disabled provider never imports or opens a WhatsApp socket', async t => {
  const store = new Store(':memory:');
  t.after(() => store.close());
  let imports = 0;
  const provider = new BaileysProvider({ store, enabled: false, loadBaileys: async () => { imports++; } });
  await provider.start();
  assert.equal(imports, 0);
  assert.equal(provider.status().status, 'disabled');
});

test('one socket, protected QR, receipt progression and terminal logout halt', async t => {
  const store = new Store(':memory:');
  const { lib, sockets } = libraryStub();
  const provider = new BaileysProvider({ store, enabled: true, loadBaileys: async () => lib });
  t.after(() => { provider.stop(); store.close(); });
  await Promise.all([provider.start(), provider.start()]);
  assert.equal(sockets.length, 1);
  sockets[0].ev.emit('connection.update', { qr: 'sensitive-qr' });
  assert.equal(provider.pairing().qr, 'sensitive-qr');
  sockets[0].ev.emit('connection.update', { connection: 'open' });
  assert.equal(provider.pairing().qr, null);
  assert.equal(provider.ready(), true);
  store.reserve('job', 'hash', 'provider-id');
  sockets[0].ev.emit('messages.update', [{ key: { id: 'provider-id', fromMe: true }, update: { status: 2 } }]);
  assert.equal(store.find('job').status, 'submitted');
  sockets[0].ev.emit('messages.update', [{ key: { id: 'provider-id', fromMe: true }, update: { status: 3 } }]);
  assert.equal(store.find('job').status, 'delivered');
  sockets[0].ev.emit('message-receipt.update', [{ key: { id: 'provider-id', fromMe: true }, receipt: { readTimestamp: 123 } }]);
  assert.equal(store.find('job').status, 'read');
  sockets[0].ev.emit('connection.update', { reachoutTimeLock: { isActive: true } });
  assert.equal(provider.ready(), false);
  sockets[0].ev.emit('connection.update', { connection: 'close', lastDisconnect: { error: { output: { statusCode: 401 } } } });
  assert.equal(provider.status().status, 'logged_out');
  assert.equal(provider.retryTimer, null);
  assert.equal(sockets[0].ended, 1);
  await provider.start();
  assert.equal(sockets.length, 1);
  assert.equal(provider.pairing().qr, null);
});

test('transient close schedules exactly one reconnect and ignores stale socket events', async t => {
  const store = new Store(':memory:');
  const { lib, sockets } = libraryStub();
  const provider = new BaileysProvider({ store, enabled: true, loadBaileys: async () => lib });
  t.after(() => { provider.stop(); store.close(); });
  await provider.start();
  const update = { connection: 'close', lastDisconnect: { error: { output: { statusCode: 408 } } } };
  sockets[0].ev.emit('connection.update', update);
  const timer = provider.retryTimer;
  sockets[0].ev.emit('connection.update', update);
  assert.equal(provider.retryTimer, timer);
  assert.equal(sockets[0].ev.listenerCount('connection.update'), 0);
  sockets[0].ev.emit('connection.update', { qr: 'stale' });
  assert.equal(provider.pairing().qr, null);
});
