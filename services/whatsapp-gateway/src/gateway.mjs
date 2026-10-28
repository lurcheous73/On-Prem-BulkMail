import { createHash } from 'node:crypto';
import { ApiError } from './errors.mjs';
import { publicMessage } from './store.mjs';

export function validateMessage(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new ApiError(400, 'invalid_message', 'Expected a JSON message object');
  }
  const { id, to, text } = input;
  if (typeof id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)) {
    throw new ApiError(400, 'invalid_id', 'Supply a stable message ID of 1–128 safe characters');
  }
  // UK mobile allocation, excluding 070 personal numbers and 076 paging numbers.
  if (typeof to !== 'string' || !/^\+447[1-57-9]\d{8}$/.test(to)) {
    throw new ApiError(400, 'invalid_recipient', 'Use a UK mobile number in +447… format');
  }
  if (typeof text !== 'string' || text.trim() === '' || [...text].length > 4096 || /\u0000/.test(text)) {
    throw new ApiError(400, 'invalid_text', 'Text must contain 1–4096 characters and no NUL');
  }
  return { id, to, text };
}

export class Gateway {
  constructor({ store, provider, config }) {
    this.store = store;
    this.provider = provider;
    this.config = config;
    this.active = null;
    this.lastStartedAt = 0;
  }

  status() {
    return {
      ...this.provider.status(),
      enabled: this.config.enabled,
      send_enabled: this.config.sendEnabled,
      can_send: this.config.enabled && this.config.sendEnabled && this.provider.ready() && !this.active,
      sending: this.active !== null,
      min_interval_ms: this.config.minIntervalMs
    };
  }

  async submit(input) {
    const message = validateMessage(input);
    const digest = createHash('sha256').update(JSON.stringify([message.to, message.text])).digest('hex');
    const existing = this.store.find(message.id);
    if (existing) {
      if (existing.content_hash !== digest) {
        throw new ApiError(409, 'id_conflict', 'This message ID belongs to different content');
      }
      return { message: publicMessage(existing), duplicate: true };
    }
    if (!this.config.enabled || !this.config.sendEnabled) {
      throw new ApiError(503, 'sending_disabled', 'Outbound WhatsApp delivery is disabled');
    }
    if (!this.provider.ready()) {
      throw new ApiError(503, 'not_connected', 'WhatsApp is not ready to send', 10);
    }
    const remaining = this.config.minIntervalMs - (Date.now() - this.lastStartedAt);
    if (this.active || remaining > 0) {
      throw new ApiError(429, 'gateway_busy', 'Retry later with the same message ID', Math.max(1, Math.ceil(remaining / 1000)));
    }

    const providerId = this.provider.newMessageId();
    // Persist before the network call. Every repeat, including after a crash, sees this ID.
    this.store.reserve(message.id, digest, providerId);
    this.lastStartedAt = Date.now();
    this.active = message.id;
    let timer;
    const operation = Promise.resolve().then(() => this.provider.send(message.to, message.text, providerId))
      .then(result => {
        if (!result?.key?.id || result.key.id !== providerId) {
          this.store.transition(providerId, 'unknown', 'provider_response_unconfirmed');
        } else {
          if (result.message) this.provider.saveRetryMessage(providerId, result.message);
          // A socket send returning is not recipient delivery; receipt events advance it.
          this.store.transition(providerId, 'submitted');
        }
      })
      .catch(() => {
        this.store.transition(providerId, 'unknown', 'send_outcome_unknown');
      })
      .finally(() => { this.active = null; });
    const timeout = new Promise(resolve => {
      timer = setTimeout(() => {
        this.store.transition(providerId, 'unknown', 'send_timeout');
        resolve();
      }, this.config.sendTimeoutMs);
    });
    try {
      await Promise.race([operation, timeout]);
    } finally {
      clearTimeout(timer);
    }
    // The original promise may finish later. Until then the gateway stays busy;
    // its eventual receipt/result can reconcile unknown, but never trigger a retry.
    return { message: publicMessage(this.store.find(message.id)), duplicate: false };
  }

  find(id) {
    const row = this.store.find(id);
    if (!row) throw new ApiError(404, 'message_not_found', 'No journal entry for that ID');
    return publicMessage(row);
  }
}
