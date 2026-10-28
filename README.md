# Brimstone On-Prem BulkMail

Self-hosted PHP/nginx bulk mailer with SQLite, Postfix and per-user address books.

This repository builds on the application deployed on 20 October 2026, including its contact/group, composition, attachment, font, draft and mailbox Sent-copy changes. The optional messaging and CT400-account upgrade adds SMSGate and Baileys integration while preserving existing accounts and email operation.

## Features

- Contact editing, multiple groups, CSV import and archived-contact restoration.
- Friendly duplicate validation with retained form details and checked groups.
- Group rename, delete, merge and membership maintenance.
- UK English spellcheck, inline images and locally hosted fonts with licence notices.
- Document-as-email, shared attachments and recipient-specific attachments.
- Complete saved drafts, recovery snapshots, templates and Use Again.
- Preview, test to self, duplicate-send protection and controlled Postfix queueing.
- Idempotent IMAP Sent filing that cannot resend a campaign.
- SMSGate SMS and Baileys WhatsApp plain-text/link messages, with contact groups and pasted UK mobile numbers.
- Explicit messaging previews, account-specific channel permissions, opt-outs, delivery history and reconciliation without blind retries.
- Verified CT400 identity links, optional automatic work portal sign-in and immutable actor/owner audit snapshots; existing local accounts and passwords are retained.

## Source layout

The app directory is the public webroot. The worker directory contains CLI-only programs installed under /usr/local/sbin; never place these under a webroot. The database directory contains schema only. The deployment directory contains existing-installation upgrade scripts and Grange-specific Proxmox/OnlyOffice integrations. The optional Node service lives in services/whatsapp-gateway and must also remain outside the webroot.

The snapshot retains its deployed Grange branding and public URLs; review these for another installation. Sent filing assumes Proxmox CT300, CT400 and an existing OnlyOffice/Dovecot mailbox. The generic installer does not enable that integration automatically.

## Install or update

See [deployment instructions](docs/DEPLOYMENT.md). The install.sh script is for a fresh Debian 12 installation and refuses an existing database. Its existing bootstrap administrator is admin / password1; change that password before exposure.

For an existing installation, follow the [SMS/WhatsApp upgrade guide](docs/MESSAGING-UPGRADE.md) and use `deployment/upgrade-messaging.sh`. The upgrade is additive: it keeps Peter's existing account, password hash, role, address book and history. Do not import the fresh schema over the live database.

The messaging features require PHP cURL, private server configuration and explicit per-account permissions. Optional services start disabled. SMS needs the Android handset; WhatsApp needs an administrator to link the intended account by QR. The [gateway guide](services/whatsapp-gateway/README.md) documents the pinned Baileys release and isolated Node runtime. The [CT400 account guide](docs/CT400-ACCOUNTS.md) covers verified account links and optional CT400 login.

Messaging currently supports outbound plain text and links. Opt-outs are recorded manually; an inbound inbox, automatic `STOP` processing, WhatsApp media/group-chat delivery and LinkedIn automation are not part of this release.

Postfix defaults: one concurrent destination, one recipient per delivery and an eight-second delay. No customer contacts, messages, databases, mailbox credentials or uploaded documents are included.

## Verification

The deployed contact fix passed 34 isolated contact/page checks, 42 established full-mailer HTTP/attachment/MIME checks and 19 live checks. Historical records are under tests/verification. These records do not mean a fresh-machine installation was tested.

Run python3 tests/run-http-regressions.py with PHP SQLite/mbstring/XML, Python, ImageMagick, Poppler and LibreOffice installed. The suite uses temporary synthetic data, loopback HTTP and no delivery worker.

The portable repository suite was rerun for this synchronization: 31 contact/page checks and 40 full-mailer checks passed, together with the existing-database installer guard, schema restoration, font hashes and syntax checks.

The messaging upgrade adds 81 queue/adapter checks, 73 identity checks, 20 Node gateway checks, 26 messaging HTTP checks, 6 private configuration checks and 37 isolated upgrade/rollback checks. The work portal extension adds 51 portal-identity checks, 26 HTTPS browser-flow checks and 23 one-use broker checks. These use synthetic records and mocked providers or loopback fixtures. They do not send live SMS/WhatsApp messages or prove the customer's handset, pairing and CT400 credentials are configured. See the [upgrade guide](docs/MESSAGING-UPGRADE.md#verification-and-remaining-live-checks) and the final release records under tests/verification.
