import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { ApiError } from './errors.mjs';

const MAX_BODY_BYTES = 32768;

function json(response, status, payload, extra = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extra
  });
  response.end(JSON.stringify(payload));
}

async function readJson(request) {
  if (request.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') {
    throw new ApiError(415, 'json_required', 'Content-Type must be application/json');
  }
  const length = Number(request.headers['content-length'] || 0);
  if (length > MAX_BODY_BYTES) throw new ApiError(413, 'body_too_large', 'Request is too large');
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) throw new ApiError(413, 'body_too_large', 'Request is too large');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new ApiError(400, 'invalid_json', 'Request body is not valid JSON'); }
}

export function createApi({ gateway, token, qrEncoder, log = () => {} }) {
  const expected = createHash('sha256').update(`Bearer ${token}`).digest();
  const server = http.createServer(async (request, response) => {
    try {
      const supplied = request.headers.authorization ?? '';
      if (!timingSafeEqual(expected, createHash('sha256').update(supplied).digest())) {
        return json(response, 401, { error: 'unauthorized' }, { 'WWW-Authenticate': 'Bearer' });
      }
      const url = new URL(request.url, 'http://localhost');
      if (request.method === 'GET' && (url.pathname === '/health' || url.pathname === '/status')) {
        return json(response, 200, { ok: true, ...gateway.status() });
      }
      if (request.method === 'GET' && url.pathname === '/pairing') {
        const state = gateway.provider.pairing();
        const qrDataUrl = state.qr ? await qrEncoder(state.qr) : null;
        return json(response, 200, { ...state, qr_data_url: qrDataUrl });
      }
      if (request.method === 'GET' && /^\/messages\/[^/]+$/.test(url.pathname)) {
        let id;
        try { id = decodeURIComponent(url.pathname.slice('/messages/'.length)); }
        catch { throw new ApiError(400, 'invalid_id', 'Invalid message ID'); }
        return json(response, 200, gateway.find(id));
      }
      if (request.method === 'POST' && url.pathname === '/messages') {
        const result = await gateway.submit(await readJson(request));
        return json(response, result.duplicate ? 200 : 202, result.message);
      }
      return json(response, 404, { error: 'not_found' });
    } catch (error) {
      if (response.destroyed) return;
      if (error instanceof ApiError) {
        const headers = error.retryAfter ? { 'Retry-After': String(error.retryAfter) } : {};
        return json(response, error.status, { error: error.code, message: error.message }, headers);
      }
      log('api_internal_error');
      return json(response, 500, { error: 'internal_error' });
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 32;
  return server;
}
