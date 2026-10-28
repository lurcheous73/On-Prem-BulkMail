import { mkdirSync, chmodSync, existsSync, closeSync, openSync } from 'node:fs';
import { join } from 'node:path';
import { once } from 'node:events';
import lockfile from 'proper-lockfile';
import QRCode from 'qrcode';
import { loadConfig } from './config.mjs';
import { Store } from './store.mjs';
import { BaileysProvider } from './baileys-provider.mjs';
import { Gateway } from './gateway.mjs';
import { createApi } from './server.mjs';

process.umask(0o077);
const log = event => process.stdout.write(`${JSON.stringify({ time: new Date().toISOString(), event })}\n`);
let release;
let store;
let provider;
let server;
let pruneTimer;
let exiting = false;

async function shutdown(code) {
  if (exiting) return;
  exiting = true;
  clearInterval(pruneTimer);
  server?.close();
  provider?.stop();
  // Any in-flight attempt remains recorded and is unknown after restart.
  // Do not close SQLite beneath an unresolved send/credential callback.
  await release?.().catch(() => {});
  process.exit(code);
}

try {
  const config = loadConfig();
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  chmodSync(config.dataDir, 0o700);
  const filename = join(config.dataDir, 'gateway.sqlite');
  if (!existsSync(filename)) closeSync(openSync(filename, 'wx', 0o600));
  // Lock before opening auth or recovering the journal. Concurrent instances
  // must never share one linked WhatsApp account, even on different HTTP ports.
  release = await lockfile.lock(filename, {
    stale: 15000,
    update: 5000,
    retries: 0,
    onCompromised: () => { log('gateway_lock_lost'); void shutdown(1); }
  });
  store = new Store(filename);
  store.pruneMessageBodies();
  pruneTimer = setInterval(() => store.pruneMessageBodies(), 3600000);
  pruneTimer.unref();
  provider = new BaileysProvider({ store, enabled: config.enabled, log });
  const gateway = new Gateway({ store, provider, config });
  server = createApi({
    gateway,
    token: config.token,
    qrEncoder: qr => QRCode.toDataURL(qr, { errorCorrectionLevel: 'L', margin: 2, width: 400 }),
    log
  });
  server.listen(config.port, config.host);
  await once(server, 'listening');
  await provider.start();
  log(config.enabled ? 'gateway_started' : 'gateway_started_disabled');
  process.on('SIGTERM', () => void shutdown(0));
  process.on('SIGINT', () => void shutdown(0));
  process.on('uncaughtException', () => { log('gateway_uncaught_error'); void shutdown(1); });
  process.on('unhandledRejection', () => { log('gateway_unhandled_rejection'); void shutdown(1); });
} catch {
  log('gateway_start_failed');
  await shutdown(1);
}
