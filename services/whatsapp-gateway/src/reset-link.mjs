import { join } from 'node:path';
import lockfile from 'proper-lockfile';
import { Store } from './store.mjs';

// Operator-only recovery command. It is deliberately absent from the HTTP API.
// No messages are sent; the durable outbound journal is always preserved.
if (process.argv[2] !== '--confirm-reset-whatsapp-link') {
  process.stderr.write('Stop the service, then use --confirm-reset-whatsapp-link to forget this gateway link.\n');
  process.exit(2);
}
if (!process.env.GATEWAY_DATA_DIR) {
  process.stderr.write('Set GATEWAY_DATA_DIR to the existing gateway data directory.\n');
  process.exit(2);
}
process.umask(0o077);
const filename = join(process.env.GATEWAY_DATA_DIR, 'gateway.sqlite');
let release;
let store;
try {
  release = await lockfile.lock(filename, { stale: 15000, retries: 0 });
  store = new Store(filename, { recover: false });
  store.db.exec('DELETE FROM auth_values');
  process.stdout.write('Gateway link forgotten; outbound IDs and receipt history preserved. Scan a new QR after restart.\n');
} catch {
  process.stderr.write('Could not reset the link. Confirm the service is stopped and the data directory is correct.\n');
  process.exitCode = 1;
} finally {
  store?.close();
  await release?.();
}
