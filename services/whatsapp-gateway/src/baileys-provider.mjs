import { createSqliteAuthState } from './auth-state.mjs';

// Baileys logging may contain phone numbers, credentials, or message data.
// Keep it silent; this service logs only its own fixed operational event names.
const silentLogger = {
  level: 'silent',
  child() { return this; },
  trace() {}, debug() {}, info() {}, warn() {}, error() {}
};

export class BaileysProvider {
  constructor({ store, enabled, loadBaileys = () => import('baileys'), log = () => {} }) {
    this.store = store;
    this.enabled = enabled;
    this.loadBaileys = loadBaileys;
    this.log = log;
    this.connectionState = enabled ? 'starting' : 'disabled';
    this.socket = null;
    this.retryTimer = null;
    this.retryCount = 0;
    this.qr = null;
    this.qrExpiresAt = null;
    this.stopped = false;
    this.connecting = false;
    this.restricted = false;
    this.reachoutRestricted = false;
    this.capped = false;
    this.library = null;
    this.cleanupSocket = null;
  }

  ready() { return this.connectionState === 'connected' && Boolean(this.socket) && !this.restricted; }

  status() {
    return { status: this.connectionState, connected: this.connectionState === 'connected', restricted: this.restricted };
  }

  pairing() {
    const valid = this.qr && this.qrExpiresAt > Date.now() && this.connectionState === 'pairing';
    return {
      status: this.connectionState,
      qr: valid ? this.qr : null,
      expires_at: valid ? new Date(this.qrExpiresAt).toISOString() : null
    };
  }

  async start() {
    if (!this.enabled || this.stopped || this.socket || this.connecting) return;
    const halt = this.store.authGet('gateway', 'halt');
    if (halt) {
      this.connectionState = halt;
      return;
    }
    this.connecting = true;
    try {
      this.library ??= await this.loadBaileys();
      if (this.stopped) return;
      this.auth ??= createSqliteAuthState(this.store, this.library);
      const { default: makeWASocket, makeCacheableSignalKeyStore } = this.library;
      this.cachedKeys ??= makeCacheableSignalKeyStore(this.auth.state.keys, silentLogger);
      this.connectionState = 'connecting';
      const socket = makeWASocket({
        auth: { creds: this.auth.state.creds, keys: this.cachedKeys },
        logger: silentLogger,
        markOnlineOnConnect: false,
        syncFullHistory: false,
        shouldSyncHistoryMessage: () => false,
        connectTimeoutMs: 30000,
        defaultQueryTimeoutMs: 20000,
        qrTimeout: 45000,
        countryCode: 'GB',
        getMessage: async key => {
          if (!key.id) return undefined;
          const json = this.store.findByProviderId(key.id)?.message_json;
          return json ? JSON.parse(json, this.library.BufferJSON.reviver) : undefined;
        }
      });
      this.socket = socket;
      const current = () => this.socket === socket && !this.stopped;
      const onCreds = update => {
        if (current()) this.auth.saveCreds(update);
      };
      const onConnection = update => {
        if (!current()) return;
        if (update.reachoutTimeLock?.isActive !== undefined) {
          this.reachoutRestricted = update.reachoutTimeLock.isActive;
          this.restricted = this.reachoutRestricted || this.capped;
        }
        if (update.qr) {
          this.qr = update.qr;
          this.qrExpiresAt = Date.now() + 40000;
          this.connectionState = 'pairing';
        }
        if (update.connection === 'open') {
          this.connectionState = 'connected';
          this.retryCount = 0;
          this.clearQr();
          this.log('whatsapp_connected');
        }
        if (update.connection === 'close') {
          this.clearQr();
          this.cleanupSocket?.();
          this.socket = null;
          socket.end(undefined);
          const code = update.lastDisconnect?.error?.output?.statusCode;
          const reasons = this.library.DisconnectReason;
          const terminal = new Set([reasons.loggedOut, reasons.badSession, reasons.connectionReplaced,
            reasons.multideviceMismatch, reasons.forbidden]);
          if (terminal.has(code)) {
            this.connectionState = code === reasons.loggedOut ? 'logged_out' : 'attention_required';
            this.store.authBatch([{ category: 'gateway', id: 'halt', value: this.connectionState }]);
            this.log(this.connectionState);
          } else {
            this.connectionState = 'reconnect_wait';
            const delay = code === reasons.restartRequired ? 500 : Math.min(60000, 1000 * 2 ** Math.min(this.retryCount++, 6));
            this.scheduleReconnect(delay);
          }
        }
      };
      const onMessages = updates => {
        if (!current()) return;
        const statuses = this.library.proto.WebMessageInfo.Status;
        for (const { key, update } of updates) {
          if (!key?.fromMe || !key.id) continue;
          const next = update.status === statuses.READ || update.status === statuses.PLAYED ? 'read'
            : update.status === statuses.DELIVERY_ACK ? 'delivered'
            : update.status === statuses.SERVER_ACK ? 'submitted'
            : update.status === statuses.ERROR ? 'failed' : null;
          if (next) this.store.transition(key.id, next, next === 'failed' ? 'provider_reported_failure' : null);
        }
      };
      const onReceipts = updates => {
        if (!current()) return;
        for (const { key, receipt } of updates) {
          if (!key?.fromMe || !key.id) continue;
          const next = receipt.readTimestamp || receipt.playedTimestamp ? 'read'
            : receipt.receiptTimestamp ? 'delivered' : null;
          if (next) this.store.transition(key.id, next);
        }
      };
      const onCap = update => {
        if (current() && update.capping_status) {
          this.capped = update.capping_status === 'CAPPED';
          this.restricted = this.reachoutRestricted || this.capped;
        }
      };
      const handlers = [
        ['creds.update', onCreds], ['connection.update', onConnection],
        ['messages.update', onMessages], ['message-receipt.update', onReceipts],
        ['message-capping.update', onCap]
      ];
      for (const [event, handler] of handlers) socket.ev.on(event, handler);
      this.cleanupSocket = () => {
        for (const [event, handler] of handlers) socket.ev.off(event, handler);
        this.cleanupSocket = null;
      };
    } catch (error) {
      this.connectionState = 'error';
      this.log('whatsapp_start_failed');
      // Missing/broken packages or invalid auth state need operator attention.
      throw error;
    } finally {
      this.connecting = false;
    }
  }

  scheduleReconnect(delay) {
    if (this.retryTimer || this.stopped) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.start().catch(() => {
        if (!this.stopped) this.scheduleReconnect(60000);
      });
    }, delay);
  }

  clearQr() { this.qr = null; this.qrExpiresAt = null; }

  newMessageId() { return this.library.generateMessageIDV2(this.socket?.user?.id); }

  send(to, text, providerId) {
    if (!this.ready()) throw new Error('WhatsApp disconnected before send');
    return this.socket.sendMessage(`${to.slice(1)}@s.whatsapp.net`, { text, linkPreview: null }, { messageId: providerId });
  }

  saveRetryMessage(providerId, message) {
    this.store.saveMessage(providerId, JSON.stringify(message, this.library.BufferJSON.replacer));
  }

  stop() {
    this.stopped = true;
    clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.clearQr();
    this.cleanupSocket?.();
    const socket = this.socket;
    this.socket = null;
    this.connectionState = 'stopped';
    socket?.end(undefined);
  }
}
