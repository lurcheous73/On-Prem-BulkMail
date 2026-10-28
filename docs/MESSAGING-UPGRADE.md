# SMS, WhatsApp and CT400 account upgrade

This release adds SMS through an Android handset running SMSGate, WhatsApp
through a local Baileys service, and explicit links to CT400 user identities.
The existing email workflow continues to use its own worker and delivery route.

**Peter keeps his existing BulkMail account.** The upgrade does not delete or
recreate users, change existing password hashes, rename accounts, reset roles,
transfer contacts or replace the live database. An administrator links Peter's
existing account to his verified CT400 identity; linking does not require a new
BulkMail account or a password reset.

## What is included

| Capability | This release |
| --- | --- |
| SMS | Plain text and links, sent through the configured handset/SIM. Up to 1,600 characters per message; a long or Unicode message can consume several SMS segments. |
| WhatsApp | Plain text and links to individual UK mobile numbers through the linked WhatsApp account. Up to 4,096 characters. |
| Recipients | Existing contact telephone fields, existing contact groups, and pasted mobile numbers without creating artificial email contacts. |
| Confirmation | A recipient/content preview followed by an explicit **SEND** action. Previews expire after 30 minutes. Repeating the same confirmation cannot create another campaign. |
| Access | Separate SMS and WhatsApp permission for each account, enforced for both the owner and an administrator acting on that owner's behalf. |
| Attribution | Immutable initiating-person and account-owner snapshots, including their linked CT400 IDs when present. Local password authentication is distinguished from actual CT400 authentication. |
| Opt-outs | Manual exclusions for each owner, channel and mobile number, checked at preview, confirmation and before submission. |
| History | Separate messaging history with submitted, delivered, read, failed, blocked, cancelled and unknown states. |

Numbers are normalized from `07…`, `+447…` or `00447…` to an international UK
mobile form. The application rejects 070 personal-number and 076 paging ranges,
landlines and foreign numbers. It removes duplicate mobile numbers across
contacts, groups and pasted entries. A campaign is limited to 1,000 eligible
recipients.

This release has no inbound inbox or automatic processing of incoming `STOP`
messages. Monitor replies using the handset/WhatsApp account and record opt-outs
in BulkMail. WhatsApp group chats, media attachments and LinkedIn automation are
not included in this SMS/Baileys release.

## Components and locations

| Component | Default location / role |
| --- | --- |
| Existing PHP application | `/var/www/bulkmail` on CT300. New pages appear alongside the email pages. |
| Existing database | `/var/lib/bulkmail/bulkmail.sqlite`. New tables are created additively. |
| Private integration configuration | `/etc/bulkmail/integrations.php`, owned by `root:www-data`, mode `0640`. |
| Messaging worker | `/usr/local/sbin/bulkmail-messaging-worker.php`, service `bulkmail-messaging-worker`. It uses a separate queue from the email worker. |
| SMS transport | SMSGate's Local Server API on the Android phone, normally port `8080` on its reserved LAN address. |
| WhatsApp service | `/opt/bulkmail-whatsapp`, with private state in `/var/lib/bulkmail-whatsapp`; authenticated API on `127.0.0.1:8787`. |
| Isolated Node runtime | `/opt/bulkmail-node-24.22.1`; the gateway's systemd override selects this runtime without replacing system Node. |
| WhatsApp environment | `/etc/bulkmail-whatsapp.env`, readable only by root; systemd supplies it to the service. |
| CT400 identity service | The existing ONLYOFFICE Workspace portal. No directory or mail-server configuration is changed by this upgrade. |

Only files from `app/` belong in the public document root. Keep configuration,
gateway state, database backups, worker programs and the Node service outside
that directory. The WhatsApp service does not need a public listening port or an
inbound router rule. The SMS local API should remain restricted to the private
network.

## Install the upgrade without replacing accounts

Use the existing-installation script
[`deployment/upgrade-messaging.sh`](../deployment/upgrade-messaging.sh).
It is the additive upgrade path: it backs up the existing installation, installs
the reviewed application/worker code and creates the new tables alongside the
existing data. Run it as root **inside the existing BulkMail server/container**,
from the reviewed repository checkout:

```sh
bash deployment/upgrade-messaging.sh
```

The script checks that the installed entry point matches the reviewed baseline
or this release before replacing it. It stops if unreviewed local changes are
detected. By default it reloads `php8.2-fpm.service` and enables the
separate messaging worker, whose integration switches are still disabled on
first installation. A different supported PHP-FPM service can be supplied
through `BULKMAIL_PHP_FPM_SERVICE`.

`--source-dir` selects another reviewed release directory. `--no-services` skips
service actions but still updates code and the database; it is **not a dry run**.
`--root-prefix /isolated/root` targets an existing isolated filesystem tree and
automatically disables real service actions, for upgrade rehearsals.

Do **not** run the fresh-install `install.sh` against the live system or import
`database/schema.sql` over the existing database. Retain the application backup
and the consistent SQLite backup produced for the upgrade. Confirm Peter's
account ID, profile, active flag, role and password hash are preserved without
printing the hash or asking Peter to change his password.

The PHP runtime needs its existing SQLite, mbstring and XML support plus
**PHP cURL** for the integration calls. The new services start with delivery
disabled. No account receives channel access automatically.

Use
[`deployment/install-whatsapp-gateway.sh`](../deployment/install-whatsapp-gateway.sh)
for the optional gateway. This installs the pinned, isolated **Node 24.22.1**
runtime and the locked gateway dependencies outside the webroot. It requires
**Debian 12 on x86-64**, root, and the private integrations file created by the
application upgrade. For an online installation from the reviewed checkout:

```sh
bash deployment/install-whatsapp-gateway.sh
```

For an offline installation, supply the reviewed gateway directory including
its locked `node_modules` bundle and the official Node archive. Replace the
example paths with the locations of those files:

```sh
bash deployment/install-whatsapp-gateway.sh \
  --offline \
  --source-dir /path/to/verified-bundle/services/whatsapp-gateway \
  --node-archive /path/to/node-v24.22.1-linux-x64.tar.xz
```

`--offline` prohibits downloads. The installer verifies the pinned runtime's
SHA-256 and checks the supplied dependency graph against the lockfile. It can
reuse a previously installed runtime with matching provenance. Its
`--no-services` option installs files without enabling or starting systemd; it
still changes installation files and is not a dry run.

The installer creates or preserves matching private gateway/PHP tokens without
displaying them, leaves connection and sending disabled, and checks the disabled
local API after starting the service. It refuses an enabled or previously linked
installation for operator review; it never deletes existing credentials or the
outbound journal as an upgrade shortcut.

The Node package is pinned to `baileys@7.0.0-rc14`, an upstream release candidate.
Its transitive dependencies are recorded in the package lockfile. Detailed
component configuration, API behaviour, credential storage and recovery are in
the [gateway guide](../services/whatsapp-gateway/README.md).

## Private configuration and default switches

Start with
[`deployment/integrations.php.example`](../deployment/integrations.php.example).
It defines the `identity`, `sms` and `whatsapp` sections. Keep real credentials in
`/etc/bulkmail/integrations.php`; never put them in the repository, browser-side
JavaScript, URLs or chat output.

Each PHP `enabled` value must be the literal boolean `true` to activate that
integration. Missing or invalid configuration fails closed for optional
integrations while retaining the existing local login and email workflow.

| Gate | Purpose |
| --- | --- |
| `sms.enabled` in PHP configuration | Enables the SMS channel globally once its handset connection is ready. |
| `whatsapp.enabled` in PHP configuration | Enables WhatsApp preview/queue creation in BulkMail. |
| Per-account permission in **Messaging Settings** | Authorizes the selected owner's use of that channel. Both the global switch and this permission are required. |
| `GATEWAY_ENABLED` in the WhatsApp environment | Allows the gateway to connect and display a pairing QR. Defaults to `false`. |
| `GATEWAY_SEND_ENABLED` in the WhatsApp environment | Allows the connected gateway to submit messages. Defaults to `false`, independently of pairing. |

The PHP `whatsapp.token` must match the gateway's private `GATEWAY_TOKEN`, with
at least 32 random characters. The installer/configuration guide explains its
private storage. The administrator page proxies only the fixed status/pairing
operations; it does not disclose the token to the browser.

The default queue interval is eight seconds per channel. This is an operational
throttle, not a statement that a mobile tariff or WhatsApp account permits a
particular campaign volume. SMS use remains subject to the actual SIM tariff.
Baileys is an unofficial WhatsApp linked-device integration and may disconnect
or encounter account restrictions.

## Bring SMS online when the handset arrives

1. Put the intended SIM in the unlocked Android handset and confirm ordinary SMS
   works. Install SMSGate from its [official installation instructions](https://docs.sms-gate.app/installation/).
2. Connect the phone to the office Wi-Fi behind the DrayTek and reserve its LAN
   address. Leave it on its USB charger. The LAN arrangement does not require USB
   passthrough into a VM or container.
3. Grant the Android permissions requested by SMSGate, enable **Local Server**
   and start it. Record its local IP/port and Basic Authentication credentials
   directly into the private PHP configuration. Use the actual address shown by
   the phone, not the example address in the repository.
4. Disable battery optimisation for SMSGate and check it continues running when
   the screen is off. Test recovery after idle time and a reboot before relying
   on unattended operation. [SMSGate documents this requirement](https://docs.sms-gate.app/faq/local-server/).
5. Keep `sms.enabled=false` while configuring `base_url`, `username` and
   `password`. Local mode normally uses HTTP, so the example explicitly enables
   `allow_http` for this private connection. Optional `sim_number` selects SIM
   slot 1, 2 or 3; omit it to use the handset's configured selection.
6. When ready for a controlled first test, enable `sms.enabled` and grant SMS
   access only to the chosen test account in **Messaging Settings**. Confirm
   there are no unintended queued campaigns before enabling the worker/channel.
7. In **SMS / WhatsApp**, select SMS, paste your own test number, review the
   single-recipient preview and explicitly send. Check receipt on the phone and
   the application's status history. Grant Peter or other accounts access only
   after this real-device test succeeds.

The code calls `POST /messages` with a caller-generated ID, a `textMessage`, one
phone number and delivery reporting enabled, then reconciles using
`GET /messages/{id}`. Current upstream local-server code supports both `/message`
and `/messages` aliases. Basic authentication and the request format are
documented in the [SMSGate Local Server guide](https://docs.sms-gate.app/getting-started/local-server/)
and implemented in its
[WebService route registration](https://github.com/capcom6/android-sms-gateway/blob/master/app/src/main/java/me/capcom/smsgateway/modules/localserver/WebService.kt)
and [MessagesRoutes class](https://github.com/capcom6/android-sms-gateway/blob/master/app/src/main/java/me/capcom/smsgateway/modules/localserver/routes/MessagesRoutes.kt).

## Link WhatsApp and perform the first controlled test

1. Install the gateway and put its private token in both configurations. Keep
   PHP `whatsapp.enabled=false` initially.
2. Set `GATEWAY_ENABLED=true` while leaving `GATEWAY_SEND_ENABLED=false`, then
   restart `bulkmail-whatsapp`. This permits pairing while preventing outbound
   sends.
3. Sign in as a BulkMail administrator, open **Messaging Settings**, and use
   **Check connection / show pairing code**. On the intended WhatsApp phone,
   open **Linked devices → Link a device** and scan the displayed QR. Refresh
   the administrator page's code if it expires.
4. Check the gateway reports `connected`. The QR is generated locally, is
   accessible only through the administrator workflow and is not sent to a
   third-party QR service.
5. For a deliberate one-recipient test, set `GATEWAY_SEND_ENABLED=true` and
   restart the gateway. Enable PHP `whatsapp.enabled` and grant WhatsApp access
   only to the selected test account. Review any existing queue first.
6. Compose plain text to your own authorized test recipient, review the preview
   and explicitly send. Confirm delivery in WhatsApp and check the application's
   message history. Enable other intended accounts only after that test.

Leave `GATEWAY_SEND_TIMEOUT_MS` at the supplied 15,000 ms value when using the
bundled PHP caller's 20-second HTTP timeout. The gateway can return an uncertain
result before the caller times out. A later acknowledgement can still update
that result, without initiating a new send.

See the [gateway guide](../services/whatsapp-gateway/README.md) for the exact
status/error contract, account disconnection handling and deliberate re-linking.
Never discard the gateway's message journal to work around an uncertain result.

## Link CT400 accounts

Follow [CT400 account links and audit attribution](CT400-ACCOUNTS.md). This is an
explicit administrator workflow against **ONLYOFFICE Workspace**, not DocSpace.
Look up the person, verify the returned stable identity and select the correct
existing BulkMail account. For Peter, select his existing account.

An audit-only link does not automatically enable CT400 login. The optional
CT400 login choice verifies the user's credentials upstream and still requires
an approved link. The existing local login remains available, including during
a CT400 outage. Directory administrator roles are not copied into BulkMail.

If Chris sends on Peter's behalf, the campaign records Chris as the initiating
person and Peter as its owner. Snapshots retain the identity at the time of the
action; later account edits or links do not rewrite that history.

## Daily use and uncertain delivery

Choose the owner/address book first when acting as an administrator, then select
the channel, groups, contacts and/or pasted numbers. Review the message and
recipient counts. Only the explicit **SEND** confirmation creates a queue entry.

| History state | Operator meaning |
| --- | --- |
| `queued` | Waiting in BulkMail; it can still be cancelled locally. |
| `submitting` | An attempt has been recorded and may be in flight. |
| `submitted` | Accepted by the provider/bridge; recipient delivery is not yet confirmed. |
| `delivered` / `read` | A matching delivery/read acknowledgement was received. Read receipts depend on WhatsApp settings. |
| `blocked` | An account, channel permission, contact or opt-out changed before submission. |
| `failed` | A definite rejection or provider failure; inspect the fixed error explanation. |
| `unknown` | The system cannot safely determine whether the attempt was accepted. It checks status using the original ID and does not send again automatically. |
| `cancelled` | A locally queued item was cancelled, or the SMS provider reported cancellation. |

Cancel affects messages still in the local queue; it cannot recall a message
already claimed or submitted. If a result is unknown, investigate the gateway
and recipient history before deliberately creating any new campaign. An SMS
delivery report may remain unavailable even after the recipient receives a
message.

The Baileys bridge's known pre-acceptance errors (`not_connected`,
`sending_disabled`, `gateway_busy`) wait before retrying with the same ID. Generic
timeouts/service failures remain unknown. An ID conflict with different content
is terminal failure and is never reconciled against the other content's result.

Record opt-outs through **Opt-outs** for the correct owner and channel. SMS and
WhatsApp exclusions are independent, and new exclusions also block matching
items that have not yet left BulkMail's queue. Withdrawing an exclusion retains
its record. Incoming `STOP` replies are not automatically imported in this release.

For operational checks, inspect `bulkmail-messaging-worker` and
`bulkmail-whatsapp` service status and logs. Worker logs contain attempt counts
and fixed diagnostics, with repeated configuration faults rate-limited to once
per minute. The original email delivery worker remains separate.

## Verification and remaining live checks

The development verification uses synthetic users/numbers, temporary databases,
mock providers or loopback fixture services. The current suites comprise:

| Suite | Checks |
| --- | ---: |
| [Messaging queue/adapters](../tests/test-messaging-core.php) | 81 |
| [Identity unit](../tests/test-identity.php) and [HTTP workflows](../tests/identity-http.py) | 73 (53 + 20) |
| [Baileys gateway](../services/whatsapp-gateway/test/) | 20 |
| [Private configuration](../tests/test-integration-config.php) | 6 |
| [Existing-install upgrade / rollback](../tests/test-upgrade.py) | 37 |
| [New messaging HTTP workflows](../tests/messaging-http.py) | 26 |
| [Existing contact and full-mailer regressions](../tests/run-http-regressions.py) | 71 (31 + 40) |
| [Work portal identity](../tests/identity-portal.php) | 51 |
| [Work portal HTTPS workflows](../tests/identity-portal-http.py) | 26 |
| [One-use meeting identity exchange](../tests/test-portal-sso.php) | 23 |
| **Total** | **414** |

On 28 October 2026, application revision
`c31ec6d37623984b0baaf73394505b510e51b3a2` passed an isolated CT301 deployment
rehearsal and was installed on CT300. Both environments passed all 25 deployment
checks, including exact preservation of all five existing accounts and all
legacy database tables. The identity and messaging HTTP suites also passed on
the staging server's PHP 8.2.33 runtime. The public HTTPS login was checked after
the live deployment. CT301 was returned to its stopped state with its network
disconnected.

The first deployment installed the new services with SMS, WhatsApp
connection/delivery and CT400 integration disabled. The subsequent work portal
extension adds automatic verified sign-in and the narrowly configured meeting
identity exchange described in the [CT400 account guide](CT400-ACCOUNTS.md).
See the [initial deployment verification record](../tests/verification/messaging-upgrade-20261028.json)
and the [CT400 and meeting activation record](../tests/verification/ct400-work-meet-20261028.json)
for the actual enabled state. CT400 sign-in is now enabled for seven verified
members; the SMS and WhatsApp delivery switches remain disabled pending the
handset and account pairing. No real
messages are sent by the build or deployment tests.

Run the PHP/Python suites from the repository root:

```sh
php tests/test-messaging-core.php
php tests/test-identity.php
python3 tests/identity-http.py
php tests/identity-portal.php
python3 tests/identity-portal-http.py
php tests/test-portal-sso.php
python3 tests/messaging-http.py
python3 tests/run-http-regressions.py
```

Run `npm test` from `services/whatsapp-gateway` with the pinned Node runtime and
locked dependencies installed. The existing full-mailer regressions additionally
need their documented document-conversion dependencies. Consult the final
release verification record under `tests/verification` for the actual packaged
revision and deployment checks.

These checks do not demonstrate a live SMS send, a linked WhatsApp account or
authentication against the customer's configured CT400 MFA flow. Handset
installation, QR linking, private credentials and the authorized one-recipient
live tests remain necessary before enabling customer messaging.

## Rollback

Disable the PHP messaging switches and stop the new messaging worker before
restoring the previous application code. Stop the WhatsApp service as needed.
Restore only the reviewed application/worker/service files from the upgrade
backup and reload the relevant PHP service. The existing email worker and its
configuration should remain on their known-good versions.

Retain the additive database tables, identity links, audit snapshots, message
IDs and gateway journal. Do not overwrite the live database with an older backup
after users have created new work, and do not restore an older gateway journal
and then blindly requeue messages: that can lose knowledge of sends that already
happened. A data-restoration operation needs a separate, reviewed recovery plan.
