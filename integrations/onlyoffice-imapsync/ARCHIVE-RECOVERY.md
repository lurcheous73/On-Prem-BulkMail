# Recovering confirmed sent-message drafts

This is the bounded recovery procedure for the CT400 incident investigated on
28 October 2026. The service fix prevents the verified multi-mailbox routing
defect. Existing copies require separate inspection and recovery.

The maintenance scripts are specific to this deployment: CT300 BulkMail sender
2 / local user 2 and CT400 tenant 1 / mailbox 22. The operator must supply the
independently verified CT400 owner GUID. The scripts check that the active local
account link, sender address and server mailbox still agree. They do not create
accounts, change account roles, send messages, or write mailbox SQL records.

Keep the comparison report, owner GUID, output logs and journal in the private
incident directory. Do not commit them to this repository. The upstream service
source and applicable license notices are described in [NOTICE.md](NOTICE.md).

## Reviewed artifacts

| Artifact | SHA-256 |
| --- | --- |
| Corrected ImapSync service DLL | `ffeef42868c9dc0c190ddb56b4dda2b384145bc9f6ef51d09af17f3bf2583b16` |
| `archive-sent-drafts.py` | `99106de97abcfe76ca32da28550e086dfe1e275bb913bbca220c14797c105c34` |
| `request-imap-activity.py` | `b31f457644a7be4878927b6410ab128a85bf96812abafd7ff8968e410fc072da` |
| `maintain-and-archive.py` | `b12e6431d981e66369b734df9fc2b3724a7660b5de3bca553f8370787d977bf5` |

The archive helper passed 16 local safety fixtures and an independent source
review. The activity helper passed 11 fixtures and an independent source review.
The maintenance wrapper passed 19 fixtures and an independent source review,
including bounded activity, readiness and completing an admitted move after a
stop. Run the existing fixtures without
contacting a server:

```sh
python -B integrations/onlyoffice-imapsync/tests/test_archive_safety.py
python -B integrations/onlyoffice-imapsync/tests/test_activity_safety.py
python -B integrations/onlyoffice-imapsync/tests/test_maintenance_safety.py
```

## 1. Inspect the candidates without changing messages

Run `compare-sent-drafts.py` on the Proxmox host and retain its complete JSONL
report privately. It inventories the approved mailbox and compares Draft/Sent
pairs. Its normalized comparison identifies candidates; it is not the final
permission to move a message.

Place `archive-sent-drafts.py` beside `compare-sent-drafts.py` on that host. Run
the strict preflight with the reviewed report and expected candidate count:

```sh
python3 archive-sent-drafts.py \
  --report /root/incident/all-sent-draft-comparison.jsonl \
  --expected-owner-guid '<verified-owner-guid>' \
  --expected-count 21
```

The default mode creates no folder or journal and moves nothing. A successful
run ends with `dry_run_complete`, the number of exact pairs, the current Drafts
and Sent counts, and `mutations: 0`. The count above is the reviewed incident
count, not a general default. A changed report or count requires a new review
of the fresh evidence.

The strict gate rereads the database metadata and both current MIME messages.
It preserves body whitespace, MIME part order, attachment bytes and names,
part metadata, multipart preamble/epilogue, recipients and relevant message
headers. It permits CRLF versus LF differences only in inline body text. A
newer draft, edited payload, changed identity or changed account owner stops
the run before a move.

The message fetch is length-framed: it consumes exactly `size.physical` bytes
and requires the observed Dovecot formatter suffix `FF LF`. It never trims the
message body. Unexpected framing is a stop condition.

## 2. Establish normal per-user IMAP tracking

An active ImapSync service alone does not establish that this user's folders
are being tracked. If a message is moved while no client is tracking the
original Draft list, a later cold start can leave a stale portal Draft record.
Verify tracking before the recovery operation.

Run `request-imap-activity.py` **inside the community container**, first in its
default read-only mode:

```sh
python3 request-imap-activity.py --user-guid '<verified-owner-guid>'
```

It checks the service PID, working directory and reviewed DLL hash; reads the
effective native JSON, environment and command-line configuration privately;
and performs Redis `PING` and `PUBSUB NUMSUB` on the exact native user-activity
channel. Redis credentials remain in process memory. The output includes
connection metadata and a hash of the user GUID, but no credentials or raw
GUID. This mode does not publish anything.

After that probe passes, one invocation with `--publish` requests the same
ordinary user-alive notification produced by the native application:

```sh
python3 request-imap-activity.py \
  --user-guid '<verified-owner-guid>' \
  --publish
```

The payload contains `Tenant: 1`, the verified `UserName`, `MailBoxId: 0`,
`Folder: -1`, `Tags: null` and the native insert action. It creates no login
session and enqueues no send action. Publication is attempted once. If its
outcome is uncertain, inspect the service before considering another request;
the helper does not retry automatically.

Publication acknowledgement is not proof of loaded tracking. The helper
deliberately reports `tracking_ready: false`. In the current service log,
verify that both `ASC.Mail.SImap_22_Drafts` and `ASC.Mail.SImap_22_Sent` have
loaded their IMAP message lists and changed to their work folders after the
current service start. Check that neither subsequently cancelled or
disconnected. Do not substitute open TCP connections or a Redis subscriber
count for that evidence.

The native service expires an offline user's client after its configured alive
interval (one minute in the observed deployment). A single acknowledged
notification does not keep tracking active through a multi-minute preflight
and recovery. An unattended recovery must use the reviewed bounded maintenance
wrapper to maintain ordinary activity and monitor the same service process.
It must stop admitting new moves when its deadline or readiness gate fails,
while allowing an already-admitted move to finish its journal and verification.

The new recovery folder also needs a loaded client before its first message
move. Native idle discovery normally runs every ten seconds, but pending
message fetches can delay it. Create and subscribe the empty recovery folder,
then verify its exact mailbox-22 Loaded/WorkFolder log markers. A database
folder record alone does not prove readiness because it is created before the
folder client initializes.

## 3. Move only the freshly verified duplicates

After the read-only preflight passes, run the reviewed maintenance wrapper on
the Proxmox host. The activity-helper path is its location **inside the community
container**; the report and journal paths are on the Proxmox host:

```sh
python3 maintain-and-archive.py \
  --report /root/incident/all-sent-draft-comparison.jsonl \
  --expected-owner-guid '<verified-owner-guid>' \
  --expected-count 21 \
  --activity-helper /root/request-imap-activity-v3.py \
  --max-seconds 1800 \
  --journal /root/incident/archive-journal.jsonl \
  --apply
```

The wrapper pins the archive, comparison and activity helper hashes. It checks
ownership before activity, sends acknowledged normal activity at twenty-second
intervals, and checks the same service PID and exact folder readiness. Each
activity request is bounded to twelve seconds. An uncertain acknowledgement
stops future requests and move admission. At the 1800-second limit, it admits no
further move or activity request; an already admitted journal/move/verification
unit finishes within its existing operation timeouts. The final record reports
any completion tail separately. An operator interrupt uses the same cooperative
stop behavior.

The wrapper waits for the recovery folder to load before its first move, checks
all three folders at each pair's start, and performs a single fresh readiness
inspection immediately before the identity-bound move. Its default mode is the
same read-only preflight and publishes no activity.

The helper first repeats the entire preflight. It then creates/subscribes to
`Recovered sent drafts 2026-10-28`. For each candidate it performs two fresh
checks, writes and fsyncs a private mode-0600 journal record, then requests one
Dovecot move. The source query is bound to the exact folder GUID, UID, message
GUID and Message-ID. Message GUIDs retain their exact Maildir representation.

After every move it checks that:

- the original Draft identity is absent;
- exactly one equivalent message exists in the recovery folder;
- the original Sent identity and payload remain present;
- normal portal synchronization removes the active original Draft record,
  retains the Sent record, and imports the recovered copy into the named user
  folder.

The helper waits at most 45 seconds for that portal convergence before stopping.
It never starts the next move while the previous one remains unverified. No SQL
folder correction is performed. The complete event includes before/after
folder counts; assess those alongside the per-message preservation checks,
because a person may legitimately send or edit other mail during maintenance.

## Stops, interrupted moves and reversal

If a move command fails or times out, the helper inspects the exact source,
recovery and Sent identities, journals whatever state it can verify and stops.
It does not retry the move. Inspect the private journal before resuming: a
timed-out command may already have succeeded. A fresh complete scan is required
to select any remaining work; do not change the report merely to bypass a
failed identity or payload check.

If portal synchronization does not converge, keep the recovered message in the
recovery folder and investigate the normal folder-tracking path. The message
has been preserved; manually changing a database folder number would conceal
the synchronization problem.

The journal records both the original proof and the verified recovery-folder
identity. A reversal is a separately observed move of that exact recovery
message back to Drafts. Before reversing, repeat the owner check, locate the
journaled recovery message by folder GUID/UID/message GUID/Message-ID, confirm
its current strict fingerprint and the retained Sent copy, and confirm that
the original Draft identity has not reappeared. Bind the reverse Dovecot move
to those exact current identifiers. Record the reverse operation and verify
normal portal convergence again. Do not move a whole folder, guess a new UID,
or operate on Sent. The helper deliberately has no blind rollback mode.

Keep the private journal and the existing original service backup until the
recovery has been reviewed. The service hotfix and message recovery are
independent operations: rolling the DLL back does not reverse a message move.
