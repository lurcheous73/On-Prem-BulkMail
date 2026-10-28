# Local Certbot lineages and their consumers

`local_lineage.py` manages the three explicitly enrolled lineages below. The
coordinator uses the existing Certbot account, HTTP webroot and private key.
It separates successful issuance from verified deployment, so a failed reload
or TLS check retries the saved certificate without ordering another one.

This document describes installation and recovery. It does not establish that
any live timer, renewal or consumer deployment has passed; record those results
after the operator completes the gates below.

## Exact scope

| Runtime | Config installed under `/etc/grange-certificate-renewal/lineages/` | Consumer TLS endpoints |
| --- | --- | --- |
| Derby Proxmox host | `communityserver.json` | CT400 Work 443; CT400 mail 25/465/587/993/995; CT300 BulkMail 9443 |
| Canada CT102 | `canada-mx2-edge.json` | `mx2.brimstonecottage.uk` HTTPS 443 |
| Canada CT102 | `canada-brimstone-mtasts.json` | `mta-sts.brimstonecottage.uk` HTTPS 443 |

The JSON source files have the `local-` prefix in this repository; omit that
prefix when installing them under `lineages/`. Each pins the exact DNS SANs,
existing SPKI, inspected native Certbot version, public-file paths and private
key paths. Certificate deployment never writes a private key. The CT102 initial
consumer enrollment makes a local, permission-preserving copy of its existing
key; no key is transferred to another host.

CT250's Grange MTA-STS endpoint has a separate public-bundle consumer; it must
not receive a new local Certbot lineage. The four Xeams MXs use the CSR-based
issuer and keystore consumers documented in `README.md`.

## Policy and bounded retries

The deadline is the earlier of `notBefore + 28 days` and the point at which one
third of the certificate's lifetime remains. The daily check acts during the
24-hour horizon before that deadline. Delayed deployment never moves the
issuance clock. A missed run or ACME outage can still delay renewal; inspect
failed units and state rather than assuming a timer guarantees availability.

When due, the command is an exact named `certbot renew` with `--reuse-key`,
`--force-renewal`, `--non-interactive` and `--no-directory-hooks`. There is no
unconditional periodic force-renewal. The configured Certbot version,
authenticator, webroot and production ACME directory are checked before the
command; unreviewed per-lineage hooks reject the operation. An inner 900-second
timeout runs in the same container as Certbot, followed by a 30-second kill
grace; the outer command allows 950 seconds. Existing Certbot locking still
applies.

If Certbot saves a valid replacement before returning a failure, the new
lineage is independently validated and retained. Failed consumer deployment
leaves a pending public certificate and exponential retry deadline. Hourly
retry checks use that state without ordering again. A fresh external renewal
is also adopted without an additional order. When a saved or externally
renewed leaf has itself become too old after prolonged downtime, any partial
deployment is reconciled first and a normally due renewal may issue one fresh
replacement; expired candidates are never newly deployed.

## Stage and inspect before activation

Python 3.9 or newer, the standard library, OpenSSL and the existing inspected
Certbot installation are required in production. Test-only `cryptography` is
not required on servers.

Install `local_lineage.py` and the exact reviewed `renewal_common.py` as
root-owned 0644 files under `/opt/grange-certificate-renewal/`. Create the
configuration directory as 0755 and install only that host's JSON configs as
root-owned 0600. Create each configured state directory as root-owned 0700.
Do not edit existing account files or output a key's contents. Verify the
transferred file hashes against `LOCAL-LINEAGES-MANIFEST.json`.

Use the explicit read-only mode first:

```sh
python3 -B /opt/grange-certificate-renewal/local_lineage.py --config /etc/grange-certificate-renewal/lineages/communityserver.json --check
```

On CT102, substitute `canada-mx2-edge.json` and
`canada-brimstone-mtasts.json`. This mode checks policy, key binding, public
files and actual TLS endpoints without creating state or lock files, issuing
orders, reloading services or sending mail. SMTP probes use only EHLO and
STARTTLS, never authentication or message delivery.

The observed CT400 Dovecot 2.1.17 weak-DH failure on 993/995 must be corrected on
the server before the full CT400 consumer gate can pass. Keep both probes
mandatory; do not disable certificate verification or lower client TLS
security. SMTP 25/465/587 success alone does not prove the entire mail consumer.

## CT102 dedicated consumer enrollment and nginx change

Before a named renewal is allowed to change its Certbot live symlink, the
HTTPS server must use separate consumer files so rollback can restore a
previous public certificate without reversing Certbot's lineage.

For each lineage, first confirm its current fullchain, exact SAN/SPKI and local
private key agree with the corresponding JSON. Copy its existing fullchain and
key locally to these paths, preserving ownership and restrictive key mode:

| Lineage | Dedicated consumer directory |
| --- | --- |
| `mx2.brimstonecottage.uk` | `/etc/grange-certificate-renewal/consumers/mx2/` |
| `mta-sts.brimstonecottage.uk` | `/etc/grange-certificate-renewal/consumers/brimstone-mtasts/` |

The filenames in both directories are `fullchain.pem` and `privkey.pem`.
Reject an existing differing target instead of overwriting an unrelated file.
Verify copied bytes, private-key public halves and modes without printing key
material. Initial copies must contain the unchanged currently served leaf.

Use the single combined nginx candidate prepared from the exact inspected
`http.conf`: both scoped HTTPS path transformations plus the central HTTP-01
fallback. `proxy_config.py` owns these pure transformations. The fallback
keeps the local Certbot webroot first and the existing Xeams fallback last.
Require the current original hash, save a permission-preserving backup, install
the candidate, run the native OpenResty `nginx -t`, then reload once. On failure
restore the complete original config and reload. Verify both public HTTPS
names still present the unchanged expected leaf before any ACME renewal.

## Hand over existing jobs without overlapping writers

Root must compare each existing job with the inventoried exact content and
retain a permission-preserving backup before changing it. Stop scheduling and
allow an existing issuance/copy process to finish before starting a managed
operation; do not terminate an in-flight Certbot account or renewal write.

On Derby, hand over these exact certificate-copy jobs:

- Proxmox `grange-bulkmail-cert-sync.timer` and its service.
- CT400 `onlyoffice-mail-cert-sync.timer` and its service.

Disable the old timers only when the new coordinator is staged and its
read-only probes pass. Preserve the old scripts, units and backups for rollback.
They are superseded because their independent copies/restarts cannot represent
one verified Work/mail/BulkMail deployment transaction.

The final CommunityServer inventory on 2026-10-28 found only
`communityserver.conf`, with native `certbot.timer` active. Its standard
`/etc/cron.d/certbot` entry is suppressed by the existing
`! -d /run/systemd/system` guard. Before handover, recheck that exact scope,
record the timer's enabled/active state and back up the cron and units. Stop
the native timer while the initial managed operation runs; disable it only
after the managed operation and every consumer probe succeeds. On failed
handover, restore the original scheduling state. Preserve the guarded cron
entry and its backup. If any additional lineage appears, stop and coordinate
its scheduling explicitly rather than disabling a shared job. Retain the
existing directory deploy hook for rollback; managed invocations bypass it
with `--no-directory-hooks`.

On Canada CT102, replace only these two exact backed-up named cron entries:

- `/etc/cron.d/brimstone-mx2-bimi-renew`
- `/etc/cron.d/brimstone-mtasts-cert`

Their old direct nginx reloads would leave the new dedicated consumer files
stale. The final CT102 inventory found no `certbot.timer` and no unscoped
Certbot cron. Its eight unrelated lineages are `npm-*` and remain untouched.
The inspected exact cron hashes are:

| Existing named job | SHA256 |
| --- | --- |
| `brimstone-mx2-bimi-renew` | `2f27d13cf608d07e95506b838635398a20203884b4f82a65514d223d2ce5c93e` |
| `brimstone-mtasts-cert` | `f6f5ab59c2df9f0abd9f82ed9c96f16e89d85c18b98a48c7b2157930e20d98e4` |

Recheck those hashes and the absence of a broader enabled job at handover;
coordinate any unexpected scheduler explicitly. Preserve unrelated NPM jobs.

## Install timers and run the first managed operation

Install the four `grange-local-lineage` service/timer templates under
`/etc/systemd/system/`, preserving their names. On CT102 also install the two
`canada-brimstone-mtasts.timer.d/schedule.conf` drop-ins in the matching systemd
directories. These reset the inherited calendar; they do not add a second run.

| Instance | Daily check, UTC | Pending retry, UTC |
| --- | --- | --- |
| `communityserver` | 02:20 | Hourly at minute 35 |
| `canada-mx2-edge` | 02:20 | Hourly at minute 35 |
| `canada-brimstone-mtasts` | 03:00 | Hourly at minute 05 |

The two CT102 schedules are staggered to reduce native Certbot lock contention.
Per-lineage locks serialize ordinary and retry runs for the same lineage. Each
oneshot has a one-hour outer service limit to allow issuance and bounded
activation/rollback tails; normal unchanged checks do not reload anything.

Validate units with `systemd-analyze verify`, run `systemctl daemon-reload`, and
verify calculated next runs. After the preflight and old-job handover, execute
the matching ordinary service once and inspect its result. **Ordinary invocation
is the applying mode**; `--check` is the explicit read-only mode.

```sh
systemctl start grange-local-lineage@communityserver.service
systemctl enable --now grange-local-lineage@communityserver.timer grange-local-lineage-retry@communityserver.timer
```

Use the two CT102 instance names there. Record issued/deployed fingerprints,
actual endpoint results, enabled/active timer states, next runs and all stopped
old jobs. Do not call an initial failed service healthy merely because its
timer is enabled.

## Deployment, interruption and rollback

Only consumers with differing public bytes or a differing live certificate
are activated. Work/BulkMail/OpenResty use their existing validated reloads;
CT400's mail container uses its existing restart mechanism when its certificate
needs activation. Its five endpoints must all validate and present the exact
candidate DER fingerprint. The key remains the enrolled unchanged key.

Before writing, the coordinator snapshots every changed consumer's public
files, modes and owners into root-private state. A candidate cannot downgrade
a newer consumer. The live source and target hashes are checked again around
replacement and activation. Failure restores the old public files, reactivates
each consumer and verifies its exact snapshotted leaf. An unrelated concurrent
edit is retained for review instead of being overwritten.

For interrupted work, a fully installed and healthy candidate is committed
without a reload. Partial state is rolled back using a complete validated
backup set before retrying. Each consumer's entire backup set is checked before
its first restore write, so a corrupt chain backup cannot leave a partial
restore. If rollback cannot finish, the transaction remains marked
`rollback_failed`; no new ACME order proceeds through it.

An old snapshotted leaf can expire while recovery is interrupted. Rollback
alone may then establish TLS without CA/date validation **only to compare the
exact previously recorded DER fingerprint**, after SAN/SPKI and unchanged key
checks. This verifies restoration of that previous identity; it does not make
the expired certificate healthy. Fresh deployments and healthy checks always
require normal trusted TLS. The operator must resolve the due renewal after
restoration.

Private `state.json`, cached public certificate files and transaction snapshots
live under each configured state directory. JSON output and the systemd
journal contain fixed reasons, policy and public certificate metadata; no
email/Slack notifications are sent. `--deploy-only` repairs or retries consumers
without issuing an order. `--retry-only` exits without writes when there is no
pending operation and respects stored retry deadlines. Disable the timers to
stop future actions; retain state and certificate backups for review.

## Offline evidence

Run from the repository root:

```sh
python3 -B integrations/certificate-renewal/tests/test_local_lineage.py
```

The fixtures create an ephemeral CA and real certificates and exercise native
validation, snapshot, file/state write and rollback code. They mock issuance,
activation and live peers only. They cover policy timing, exact key/SAN/version
guards, no-order deployment retries, corrupt/expired pending state, externally
renewed expired state, partial interruptions, downgrade rejection, concurrent
edits, complete backup validation and strict new-deployment versus pinned old
rollback identity. No production credentials, ACME requests, sockets or mail
are used.
