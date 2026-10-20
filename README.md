# Brimstone On-Prem BulkMail

Self-hosted PHP/nginx bulk mailer with SQLite, Postfix and per-user address books.

This repository contains the application deployed on 20 October 2026, including the October contact/group, composition, attachment, font, draft and mailbox Sent-copy changes.

## Features

- Contact editing, multiple groups, CSV import and archived-contact restoration.
- Friendly duplicate validation with retained form details and checked groups.
- Group rename, delete, merge and membership maintenance.
- UK English spellcheck, inline images and locally hosted fonts with licence notices.
- Document-as-email, shared attachments and recipient-specific attachments.
- Complete saved drafts, recovery snapshots, templates and Use Again.
- Preview, test to self, duplicate-send protection and controlled Postfix queueing.
- Idempotent IMAP Sent filing that cannot resend a campaign.

## Source layout

The app directory is the public webroot. The worker directory contains CLI-only programs installed under /usr/local/sbin; never place these under a webroot. The database directory contains schema only. The deployment directory contains Grange-specific Proxmox/OnlyOffice integrations.

The snapshot retains its deployed Grange branding and public URLs; review these for another installation. Sent filing assumes Proxmox CT300, CT400 and an existing OnlyOffice/Dovecot mailbox. The generic installer does not enable that integration automatically.

## Install or update

See [deployment instructions](docs/DEPLOYMENT.md). The install.sh script is for a fresh Debian 12 installation and refuses an existing database. Its existing bootstrap administrator is admin / password1; change that password before exposure.

Postfix defaults: one concurrent destination, one recipient per delivery and an eight-second delay. No customer contacts, messages, databases, mailbox credentials or uploaded documents are included.

## Verification

The deployed contact fix passed 34 isolated contact/page checks, 42 established full-mailer HTTP/attachment/MIME checks and 19 live checks. Historical records are under tests/verification. These records do not mean a fresh-machine installation was tested.

Run python3 tests/run-http-regressions.py with PHP SQLite/mbstring/XML, Python, ImageMagick, Poppler and LibreOffice installed. The suite uses temporary synthetic data, loopback HTTP and no delivery worker.

The portable repository suite was rerun for this synchronization: 31 contact/page checks and 40 full-mailer checks passed, together with the existing-database installer guard, schema restoration, font hashes and syntax checks.
