# Local WhatsApp gateway

This optional Node service connects the PHP mailer to a WhatsApp account through
[Baileys](https://github.com/WhiskeySockets/Baileys). It is an unofficial linked-device
integration. WhatsApp can restrict or disconnect the account; the service honours
restriction signals and stops after logout or a replaced session. It does not
provide an official WhatsApp Business API service guarantee.

The package is pinned to `baileys@7.0.0-rc14`, published 29 July 2026. This is an
upstream release candidate, not a stable 7.0 release. The included lockfile pins
transitive dependencies. Use **Node 24.22.1 LTS** (or a later security patch within
Node 24) and `npm ci --omit=dev --ignore-scripts`; the gateway uses Node's built-in
SQLite implementation. The pinned package and its required exports were checked
locally. Upstream's own package minimum is Node 20; Node 20 is now end of life.

Connection and outbound delivery are **disabled by default**. Installing or
starting with the supplied example configuration does not link an account or
send any messages. Nothing in this service touches BulkMail's user accounts or
Peter's existing login.

## Installation

For the existing Debian 12 x86-64 BulkMail host, use the repository's
`deployment/install-whatsapp-gateway.sh`; see [installer and offline staging
instructions](deployment/INSTALLER.md). It provisions an isolated verified Node
runtime, private matching tokens and an initially disconnected local service.

Keep the service and its database outside the PHP webroot. This example installs
it alongside the mailer on CT300, where PHP can call its loopback API. Review the
paths for the target host before running the commands.

1. Install the supported Node 24 runtime. Confirm `node --version` is at least
   24.22.1 and below 25.
2. Create a service account and install the code:

   ```sh
   useradd --system --home-dir /var/lib/bulkmail-whatsapp --shell /usr/sbin/nologin bulkmail-whatsapp
   install -d -m 0755 /opt/bulkmail-whatsapp
   # Copy this directory here, including .env.example; exclude node_modules/ and data/.
   cd /opt/bulkmail-whatsapp
   npm ci --omit=dev --ignore-scripts
   install -m 0644 deployment/bulkmail-whatsapp.service /etc/systemd/system/bulkmail-whatsapp.service
   install -m 0600 .env.example /etc/bulkmail-whatsapp.env
   ```

3. Generate a random token with `openssl rand -hex 32` and store it in the
   root-readable environment file. Set the same token in BulkMail's server-side
   gateway configuration. Do not place the token in HTML, browser JavaScript,
   query strings, Git, or chat logs. Keep both enabled flags `false` initially.
4. Run `systemctl daemon-reload` then `systemctl enable --now bulkmail-whatsapp`.
   The health endpoint should report `status: disabled`. The service creates its
   private data directory and SQLite file automatically.

The sample systemd unit deliberately contains no capability grants. Node needs
outbound Internet access for WhatsApp and DNS, and loopback access for PHP. It
does not need USB passthrough, a listening public port, or an inbound router rule.
For a different VM/CT, keep this service on loopback and use an authenticated TLS
reverse proxy restricted to the mailer. Do not expose its plain HTTP API to a LAN
or the Internet.

## Linking an account

Set `GATEWAY_ENABLED=true`, leave `GATEWAY_SEND_ENABLED=false`, and restart the
service. The authenticated `GET /pairing` response contains a QR payload, its
short expiry time and a locally generated PNG data URL. Display that PNG only in
BulkMail's administrator page. On the intended WhatsApp phone, use **Linked
devices → Link a device** and scan it. A fresh QR replaces an expired one; the QR
is never printed to service logs or sent to an external rendering website.

Once `GET /status` reports `connected`, a separate deliberate configuration
change to `GATEWAY_SEND_ENABLED=true` enables outbound delivery. A human should
send the first test from BulkMail to an authorised test recipient. This repository
verification did **not** link an account or send a live WhatsApp message.

## API contract

Every endpoint requires `Authorization: Bearer <GATEWAY_TOKEN>` and returns JSON
with `Cache-Control: no-store`. All request and response field names below are
literal. No CORS permission is granted; PHP calls this API from the server.

| Method and path | Purpose |
| --- | --- |
| `GET /health` | Process/connection status, even while delivery is disabled. |
| `GET /status` | `status`, `connected`, `restricted`, `enabled`, `send_enabled`, `can_send`, `sending`, `min_interval_ms`. |
| `GET /pairing` | `status`, `qr`, `qr_data_url`, `expires_at`; QR fields are null outside a valid pairing window. |
| `POST /messages` | Send one text message, with a caller-supplied durable ID. |
| `GET /messages/:id` | Reconcile an attempt without sending it again. |

`POST /messages` takes `Content-Type: application/json`:

```json
{"id":"bulkmail-whatsapp-123-recipient-456","to":"+447700900123","text":"Example only"}
```

The sample number is synthetic. `id` is 1–128 alphanumeric, dot, underscore,
colon or hyphen characters and must start with an alphanumeric character.
`to` must be a canonical UK mobile number: `+4471…` to `+4475…`, or `+4477…`
to `+4479…`. 070 personal numbers, 076 paging numbers, groups and foreign numbers
are rejected. Text is 1–4096 Unicode characters; whitespace-only text is rejected.

An accepted attempt returns HTTP 202, or HTTP 200 for an existing identical ID:

```json
{
  "id":"bulkmail-whatsapp-123-recipient-456",
  "status":"submitted",
  "provider_id":"WA_MESSAGE_ID",
  "error":null,
  "created_at":"2026-10-28T12:00:00.000Z",
  "updated_at":"2026-10-28T12:00:01.000Z"
}
```

The same ID with different recipient/text returns **409 `id_conflict`**. Keep the
original ID after an HTTP timeout. Query `/messages/:id` or repeat the identical
request; never manufacture a new ID automatically to work around an uncertain
attempt.

The gateway waits **15 seconds** for an attempt before returning its structured
`unknown` result. The bundled PHP caller's HTTP timeout is 20 seconds, leaving
time to receive that result. Keep `GATEWAY_SEND_TIMEOUT_MS` below 20000 with this
caller. Longer custom values are supported only when the caller's HTTP timeout
is increased correspondingly. The original provider attempt may still finish
after the gateway's deadline; it remains in flight and is never started again.

| State | What it means |
| --- | --- |
| `sending` | Attempt recorded durably; the provider call is in flight. |
| `submitted` | Baileys returned from send or reported server acknowledgement. Recipient delivery has not been confirmed. |
| `delivered` | A recipient delivery acknowledgement was observed. |
| `read` | A recipient read acknowledgement was observed. Read receipts depend on the account/recipient settings. |
| `failed` | The provider explicitly reported an error status. The gateway does not retry it automatically. |
| `unknown` | Timeout, connection error, uncertain result or restart during send. No automatic resend. A later acknowledgement may reconcile it. |

Other errors return `{ "error": "machine_code", "message": "safe explanation" }`:

- **401**: missing or incorrect token.
- **400/413/415**: invalid fields/JSON, oversized body or incorrect content type.
- **404 `message_not_found`**: no journal entry for that ID.
- **429 `gateway_busy`**: another attempt is still in flight, or the minimum
  interval has not elapsed. A `Retry-After` header is supplied; no new journal
  record was inserted. Retry the same ID later.
- **503 `sending_disabled` / `not_connected`**: delivery is disabled, the link is
  not ready, or WhatsApp has restricted the account. No attempt was inserted.

There is one send in flight and an eight-second minimum interval by default.
This is an operational throttle, not a promise about WhatsApp account limits.
Contact permissions, suppression rules, actor attribution and campaign approval
belong to BulkMail; this transport has no contact-discovery or scheduled bulk-send
endpoint. It never turns an incoming message into an automatic reply.

## Persistence, backup and recovery

`gateway.sqlite` holds credentials, Signal key categories, session metadata, the
idempotency journal and outgoing message content needed for protocol retries. SQLite WAL plus
FULL synchronous commits persist an attempt before any network send. Key batches
are committed transactionally. This replaces the upstream demonstration
`useMultiFileAuthState` helper, which upstream does not recommend for production.

A process lock prevents two gateway instances using the same data file. On a
crash the lock becomes stale after 15 seconds; the sample systemd unit waits 20
seconds before restarting. Any interrupted `sending` record becomes `unknown`
on startup. There is no replay loop. Delivery metadata and IDs are retained so
repeated requests cannot unexpectedly send again. Actual retry message content
is cleared after seven days; audit retention in BulkMail is independent.

Protect the data directory as credentials: mode 0700, SQLite files mode 0600,
encrypted host backups and no web serving. SQLite is not itself encrypted at
rest. Back up the file while the service is stopped, or use SQLite's online
backup facilities; do not copy just the main file while WAL writes are active.
Never restore an old journal and blindly requeue later messages: the backup may
predate sends which already happened.

Transient disconnections use a single bounded-backoff reconnect timer. Logout,
bad session, replaced connection, incompatible device or forbidden account stops
reconnection and persists an operator-attention marker. Credentials are not
silently deleted to get around those errors.

To deliberately re-link after investigating the reason, stop the service and
run this command as its service user. It forgets only this gateway's link and
retains every outbound ID and receipt; it does not delete a WhatsApp account or
any BulkMail user:

```sh
sudo -u bulkmail-whatsapp env GATEWAY_DATA_DIR=/var/lib/bulkmail-whatsapp \
  /usr/bin/env node /opt/bulkmail-whatsapp/src/reset-link.mjs --confirm-reset-whatsapp-link
```

Restart with outbound delivery disabled, then scan the QR for the intended
account. Remove obsolete linked devices from the phone as appropriate.

## Verification

```sh
npm ci --ignore-scripts
npm test
```

The tests use synthetic numbers, temporary SQLite databases and fake Baileys
sockets. They exercise HTTP authentication, QR privacy headers, disabled delivery,
input bounds, duplicate IDs, contradictory payloads, uncertain sends, delayed
results, receipt order, crash recovery, binary auth persistence, single-socket
startup and logout handling. No test connects to WhatsApp. The API tests need
permission to bind an ephemeral **loopback** port.

Source references checked on 28 October 2026:

- [Pinned release](https://github.com/WhiskeySockets/Baileys/releases/tag/v7.0.0-rc14)
- [Package/runtime requirements](https://github.com/WhiskeySockets/Baileys/blob/v7.0.0-rc14/package.json)
- [Upstream auth adapter guidance](https://github.com/WhiskeySockets/Baileys/blob/v7.0.0-rc14/src/Utils/use-multi-file-auth-state.ts)
- [Socket configuration/types](https://github.com/WhiskeySockets/Baileys/blob/v7.0.0-rc14/src/Types/Socket.ts)
- [Message status events](https://github.com/WhiskeySockets/Baileys/blob/v7.0.0-rc14/src/Types/Events.ts)
- [Node release/support table](https://nodejs.org/en/about/previous-releases)
