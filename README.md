# Brimstone On-Prem BulkMail

Self-hosted bulk email management and controlled SMTP delivery.

## Core features

- Multi-user administration
- Contact and group management
- Sender identities
- Marketing suppression / unsubscribe handling
- Draft composition
- Multiple attachments
- Mailing history
- Audit logging
- Controlled drip delivery through Postfix
- SQLite database
- PHP / nginx web interface

## Default delivery behaviour

The standard installation uses:

- One concurrent SMTP destination
- One recipient per SMTP delivery
- Eight-second transport delay

These settings may be changed during installation.

## Security

A fresh installation creates a bootstrap administrator.

Default credentials:

    Username: admin
    Password: password1

The bootstrap password must be changed immediately after
installation.

Do not expose an installation to the public Internet while the
default password is still active.

## Data

No example customer, contact or mailing data is included in this
repository.

The installation creates a fresh SQLite database from schema.sql.
