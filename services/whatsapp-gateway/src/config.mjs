import { resolve } from 'node:path';

function flag(value, name) {
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error(`${name} must be true or false`);
}

function integer(value, fallback, min, max, name) {
  const result = value === undefined || value === '' ? fallback : Number(value);
  if (!Number.isSafeInteger(result) || result < min || result > max) {
    throw new Error(`${name} is outside its allowed range`);
  }
  return result;
}

export function loadConfig(env = process.env) {
  const token = env.GATEWAY_TOKEN ?? '';
  if (token.length < 32 || token.length > 512 || /\s/.test(token)) {
    throw new Error('GATEWAY_TOKEN must contain 32–512 characters without whitespace');
  }
  const host = env.GATEWAY_HOST || '127.0.0.1';
  // Put a TLS reverse proxy in front if the PHP app is on another machine.
  if (!['127.0.0.1', '::1'].includes(host)) {
    throw new Error('GATEWAY_HOST must be a loopback address');
  }
  return {
    token,
    host,
    port: integer(env.GATEWAY_PORT, 8787, 1, 65535, 'GATEWAY_PORT'),
    dataDir: resolve(env.GATEWAY_DATA_DIR || './data'),
    enabled: flag(env.GATEWAY_ENABLED, 'GATEWAY_ENABLED'),
    sendEnabled: flag(env.GATEWAY_SEND_ENABLED, 'GATEWAY_SEND_ENABLED'),
    minIntervalMs: integer(env.GATEWAY_MIN_INTERVAL_MS, 8000, 1000, 3600000, 'GATEWAY_MIN_INTERVAL_MS'),
    sendTimeoutMs: integer(env.GATEWAY_SEND_TIMEOUT_MS, 15000, 1000, 60000, 'GATEWAY_SEND_TIMEOUT_MS')
  };
}
