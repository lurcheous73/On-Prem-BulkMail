# ONLYOFFICE Mail: Draft synchronization across multiple mailboxes

This integration fixes sent messages reappearing in Drafts when one ONLYOFFICE user owns multiple mailboxes. It is a source patch for the existing IMAP synchronization service, built against the deployed Core assembly.

Revision 3 is independently reviewed. All 52 regression checks pass without a network operation or starting an IMAP task. The copied original production DLL fails four of the 24 dispatch/selection checks. Revision 2 passes the original 37 checks but fails both newly reproduced semaphore-ownership checks.

## Exact supported version

- Community Server image: `onlyoffice/communityserver:12.8.0.1971`.
- Upstream Mail commit: `bce218db218bff90a8583e9f01dcc1e5464f8bc4`.
- Target: `net8.0`; deployed runtime: .NET 8.0.26.
- Build SDK: .NET 8.0.427.
- Original service DLL SHA256: `9afd281bad21cece51f3ebbe72e226dbef218af6d740fbf763b96ce20a404e8b`.
- Unchanged Core DLL SHA256: `4be22c0e9f7a0dff67fb8a8631949213f3511897d9fbe170058371ce3751710e`.

The production PDB's SourceLink commit and source checksums identify this exact upstream source. Decoded production IL independently confirms the incorrect mailbox selectors. `manifest.json` records the immutable inputs and final artifact hashes. `assembly-verification.json` contains the full comparison of all 37 production and patched assembly reference identities; their names, versions and public-key tokens are identical.

## Behavior changed

The original `SendDraft` handler chooses the first Draft client for the user. That client ignores database message IDs belonging to another mailbox, leaving the sending mailbox's IMAP draft behind. Subsequent synchronization imports it as a new portal Draft record.

The patch dispatches that action across loaded Draft clients. Each client retains its existing database-ID ownership check. Sent clients and other mailboxes' unrelated drafts remain outside the cleanup action.

The original missing-draft recovery also examines the first Sent client without checking the mailbox. Recovery now considers only a loaded Sent client belonging to the same mailbox. Unknown Sent state defers restoration while allowing normal import and flag reconciliation to continue. A marker records the deferred mailbox. When its Sent list initializes, the service retries that mailbox's loaded Draft clients after the engine semaphore has been released. Normal recovery clears the marker, preventing a redundant readiness retry. An unloaded old Sent client cannot hide its loaded replacement during reconnect.

The recovery helper snapshots the selected Sent list, excludes IDs already represented there, and issues only draft-update actions for remaining IDs. It does not issue a send action or invoke restoration for an empty result.

## Shared-context correction in revision 3

The deployed service also had existing initialization/reconciliation races: multiple folder callbacks share one scoped mail-engine context, while user-folder creation and final folder-count recalculation ran outside its semaphore. Historical service logs show the concurrent-context and transaction-strategy errors before revision 2 was deployed.

Revision 3 keeps the mailbox routing/recovery changes and closes those specific gaps. User-folder creation holds the existing semaphore only for its engine operation, then releases it before `Init` can invoke a folder-load callback. Both folder-load methods retain the semaphore through final recalculation and release it in a nested `finally`, even if recalculation fails. Mailbox initialization and deletion now release a permit only when that invocation acquired it. The constructor resolves CRM availability before starting asynchronous folder callbacks.

The Core assembly, dependency versions and service configuration remain unchanged. The regression proves lock exclusion, exception-safe release and the original pre-acquisition ownership failures; production observation is still required to determine whether other historical engine errors remain. The existing offline-user timeout and cancellation-token teardown are outside this patch.

## Source and license

`MailImapClient.cs` contains the complete modified upstream file, including the original copyright/license header and a modification notice. `source.patch` is the complete functional diff against the pinned commit. The build/test helpers are alongside it.

See `NOTICE.md` and `UPSTREAM-LICENSE.txt`. The modified upstream source explicitly uses Apache-2.0. These notices do not replace the licensing of the surrounding BulkMail project or other ONLYOFFICE components. The production Core assembly is referenced unchanged and is not distributed in this directory.

Upstream source: <https://github.com/ONLYOFFICE/Mail/blob/bce218db218bff90a8583e9f01dcc1e5464f8bc4/Services/ASC.Mail.ImapSync.Service/MailImapClient.cs>.

## Reproducing the build

Use a clean checkout of the pinned upstream commit at `/tmp/onlyoffice-imapsync-hotfix-source`, apply `source.patch`, and place a verified copy of the supported production Core assembly at `/tmp/onlyoffice-mail-core.dll`. Run `prepare-build.py` from this integration directory. It verifies the upstream commit, original source hash, patched source hash and Core hash before creating `/tmp/onlyoffice-imapsync-service-build-v3/ASC.Mail.ImapSync.Service.csproj`.

The helper stages the reviewed modified file at `/tmp/onlyoffice-imapsync-hotfix-v3/MailImapClient.cs`, preserving the isolated source path used for this artifact. The service-only project uses the unchanged Core DLL and the upstream service's existing package versions. An unused OpenStack namespace import is omitted from a build copy of `MailEnginesFactoryExtentions.cs`; no compiled method uses that namespace. This avoids rebuilding Core's unavailable public-NuGet `openstack.net` 1.7.9 dependency. No replacement dependency DLL or generated dependency configuration is deployed.

With SDK 8.0.427 available as `dotnet`:

```sh
dotnet build /tmp/onlyoffice-imapsync-service-build-v3/ASC.Mail.ImapSync.Service.csproj -c Release -p:NuGetAudit=false
dotnet run --project tests/Regression.csproj -c Release -p:NuGetAudit=false
```

The fixture project defaults to `/tmp/onlyoffice-imapsync-service-build-v3`; an alternative can be supplied through the `ImapSyncBuildRoot` MSBuild property. To repeat only the original production dispatch/selection regression, run the built fixture with `--dispatch-only` while its service DLL is the copied original production DLL, in an isolated test output directory.

The fixture executes the actual service dispatcher and actual restore/readiness helpers with in-memory transport interfaces. It constructs clients without running network constructors and leaves queued tasks in the `Created` state. It covers multiple mailbox orderings, unrelated IDs, unloaded clients, absent clients, missing/unloaded/loaded Sent transitions, same-mailbox retries, reconnect replacements, consumed markers, all-sent no-ops and known-empty Sent recovery. It also exercises the real semaphore helpers and the original create/delete failure paths without constructing an IMAP connection. The additional 15 checks cover exclusion, exception propagation, guaranteed release and ownership of permits. It does not test live SMTP delivery.

## Reviewed deployment artifacts

Only these two files replace existing service files:

| File | SHA256 |
|---|---|
| ASC.Mail.ImapSync.Service.dll | `ffeef42868c9dc0c190ddb56b4dda2b384145bc9f6ef51d09af17f3bf2583b16` |
| ASC.Mail.ImapSync.Service.pdb | `4925cdb5b0f6b87d5bd34c207ad5f84d9a43649bcd434258875cd51cf5c6b62a` |

The service is `onlyofficeMailImap.service`, running as `onlyoffice:onlyoffice`. Its existing directory is `/var/www/onlyoffice/Services/MailImap`. Preserve the original DLL/PDB, owner and mode before replacing them. Stop only this service, atomically replace the two files with mode 0644 and the existing ownership, and restart it. Keep Core, all other libraries, application settings, `.deps.json` and `.runtimeconfig.json` unchanged.

Verify the file hashes, service health and absence of assembly-loading/missing-method errors. The original files are the rollback unit; restore them and restart the same service if needed. Revision 1 was withdrawn during review and must not be deployed. Preserve the frozen revision 2 bundle separately; its hashes are recorded as `previous_revision_files` in the revision 3 manifest.

## Existing duplicate Drafts

The source patch prevents incorrect dispatch. Existing stale copies need a separate, reversible archive operation after healthy synchronization is confirmed.

`compare-sent-drafts.py` is a read-only diagnostic for the configured deployment. It obtains the approved sender internally, verifies the mailbox owner, and compares matching Draft/Sent Message-IDs using decoded body/attachment fingerprints and address/subject equality. It prints IDs and comparison results, not message bodies or addresses. It distinguishes exact matches from unverified drafts and reports whether the Draft date is no later than the Sent date.

Archive only freshly reverified exact matches to a dedicated IMAP folder. Retain the Sent copies, preserve unverified drafts, and verify normal portal synchronization afterward. Do not change folder numbers directly in SQL or resend messages to clear Drafts. An archived message remains recoverable by moving it back.
