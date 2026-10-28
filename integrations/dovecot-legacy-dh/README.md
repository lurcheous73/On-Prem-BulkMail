# Dovecot 2.1.17 public DH parameter correction

The CT400 mail container serves its expected Work certificate on IMAPS 993 and
POP3S 995, but modern trusted clients reject the 1024-bit temporary DH group with
`DH_KEY_TOO_SMALL`. SMTP 25/465/587 already passes the trusted TLS checks. This
package prepares a server-side public-parameter correction while preserving
the existing certificate, private key, cipher policy, authentication and mail
data. It does not change client TLS security or upgrade the mail image.

## Exact source and compatibility reasoning

The official
[Dovecot 2.1.17 source release](https://dovecot.org/releases/2.1/dovecot-2.1.17.tar.gz)
was retrieved and inspected. Its SHA256 is
`f59cb39ff5839badaf73fa28006c37b79839b48e782baf256c80d5cc56d1421a`.

`src/ssl-params/ssl-params-openssl.c` normally writes two records. Each contains
a native integer selector, a native integer DER length, and PKCS#3 DH parameter
DER. A single zero integer terminates the file. The inspected x86_64 runtime
uses little-endian four-byte integers.

`src/login-common/ssl-proxy-openssl.c` dispatches selectors 512 and 1024 into two
DH object slots using `d2i_DHparams`. It does not compare the actual prime size
with the selector. The normal non-export callback returns the second parsed
object. The selector must remain 1024 even when its DER prime is 3072 bits;
introducing a new selector 3072 would fail the native parser.

The candidate places the same validated 3072-bit public DH group in both native
slots. Each DER payload is 396 bytes; the complete file is 812 bytes. Both actual
primes are strong, while the existing parser and callback remain compatible.
The native `ssl-params.c` reader rejects files over 1024 bytes, so a larger file
must not be substituted casually. This is a format-compatible maintenance
correction for the inspected old version, not a newly supported `ssl_dh`
configuration directive.

The group is the exact generator 2 and prime specified by
[RFC7919 Appendix A.2](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.2).
The independent reviewer recomputed that RFC's prime formula and confirmed
the included DER and PEM. Its DER SHA256 is
`e6c929eaf5be4558cbe49edc31017c7f646723bdc006270bed368afde14acb14`.
It is public group data, not a private key. OpenSSL documents that a normal
server callback may return a sufficiently large DH group independently of its
nominal callback keylength:
[temporary DH callback documentation](https://docs.openssl.org/1.0.2/man3/SSL_CTX_set_tmp_dh_callback/).

The native `ssl-params-settings.c` and `ssl-params.c` support
`ssl_parameters_regenerate = 0`. Zero suppresses scheduled regeneration of
the old weak groups. Missing, empty or oversized parameter files still trigger
native regeneration even at zero, so the file must remain intact and its hash
must be checked after service/container restarts.

## Reviewed artifacts and observed original

| Artifact | Size | SHA256 |
| --- | --- | --- |
| Observed original public file | 230 bytes | `3748ae64860d81ec2c4806bc31a0a0a50019269a9c5a765ac9c0eb4edf364947` |
| Deterministic candidate | 812 bytes | `f8d823cb32adfc3f3ff11f52e0754c89b996dd01aae6896b9aa690f67bebee42` |

The transferred original parses as actual 512-bit and 1024-bit generator 2 groups
in its expected two slots. The observed live path is
`/var/lib/dovecot/ssl-parameters.dat`, root:root 0644. The main config
`/etc/dovecot/dovecot.conf` has no include directives; adding a standalone
`conf.d` file would have no effect. Its observed SHA256 is
`332a9e294ea1ed2e2d3ac1b1f43413ef819cd93fdfa1be066d7986631b8a02d9`.
Effective regeneration is one week. The container reports Dovecot 2.1.17 and
OpenSSL 1.1.1f.

The native main and DH file are root:root 0644. The genuine iRedMail template
is root:root 0664. The installer pins these exact per-file modes and owners,
preserves them, and rejects unexpected metadata changes. It does not change
the template's mode or broadly permit group-writable configuration files.

The parameter file and main config are in the container's writable layer.
The inspected image starts `/usr/src/iRedMail/install_mail.sh`, which calls
`iRedMail.sh` and `run_mailserver.sh`. The genuine configuration template is
`/usr/src/iRedMail/samples/dovecot/dovecot2.conf`; its SHA256 is
`ee61c1bf479996b8c73b4fb82b2413166e84e7785d0342566fb2fcc322018d4b`.
Its copy to the main config is guarded by iRedMail's installation status.
`run_mailserver.sh` only starts Dovecot and has no DH-file removal/generation
operation. The installer therefore appends the supported regeneration setting
to both exact main and template files, preserving every original byte before
that appended directive. A Docker restart retains the writable layer;
container replacement does not. Keep the reviewed package and persistent
host-side backups, and reapply through this guarded procedure if the mail
container is recreated. Do not claim restart persistence until the later
certificate-driven container restart is checked.

## Inspect and build only

The Python helper uses only the standard library and existing OpenSSL. It
reads public parameters and creates a separate exclusive output file. It has
no installation, configuration-edit, service-control, network or mail action.

```sh
python3 -B dovecot_legacy_dh.py inspect --file ORIGINAL
python3 -B dovecot_legacy_dh.py build --original ORIGINAL --expected-original-sha256 3748ae64860d81ec2c4806bc31a0a0a50019269a9c5a765ac9c0eb4edf364947 --der ffdhe3072.der --output CANDIDATE
```

`CANDIDATE` must not exist. The original hash, native record sequence, complete
framing, DER shape, exact pinned group and OpenSSL parameter validation must
all pass. The helper rereads the original before creating output. Its JSON
contains only public hashes, sizes and actual prime strengths. A rejected
input or pre-existing output is preserved.

The reviewed candidate built from the actual transferred original is
`/tmp/dovecot-ssl-parameters-reviewed-candidate.dat` in the operator workspace.
Verify its bytes against the manifest before transfer.

## Guarded deployment gates for the operator

The code and offline tests are independently approved. Live deployment remains
a separate step and must record the following evidence:

1. Confirm exact Dovecot version, native architecture, current parameter hash,
   main-config hash, ownership and the active service-control mechanism. An
   unexpected file or version requires review rather than a blind overwrite.
2. Resolve entrypoint persistence and save permission-preserving backups of
   the actual parameter/config files plus their hashes. Retain a persistent
   public candidate and configuration patch so container recreation cannot
   silently discard the correction.
3. Stage the exact 812-byte candidate and a scoped main-config change setting
   `ssl_parameters_regenerate = 0`. Validate the configuration with the native
   Dovecot configuration checker without printing unrelated settings or
   credentials. Do not change authentication, namespaces or cipher rules.
4. Stop only Dovecot through its native service mechanism and confirm its
   master, login and ssl-params processes are no longer holding the old group.
   Do not replace the file while an old weak-parameter generator can overwrite
   it. Recheck original hashes, then replace the staged files atomically,
   preserving root ownership and 0644 parameter-file mode.
5. Start Dovecot and verify its effective regeneration value, parameter-file
   hash and newly loaded native group. Both 993 and 995 must complete trusted
   TLS with hostname validation and the unchanged expected certificate.
   Record the actual server temporary DH strength as 3072 bits. A mere running
   process or unchanged certificate fingerprint does not prove the DH fix.
6. On failure, restore the complete backed-up file/config pair and original
   service state; retain evidence and do not start certificate automation with
   a false healthy result. The old known DH limitation will remain after such
   rollback and must be reported explicitly.
7. After the subsequent authorized certificate/container restart, repeat the
   hash, effective configuration and trusted 993/995 checks to establish that
   startup did not undo the correction. Keep the full local-lineage consumer
   probe set mandatory.

Existing login processes and the ssl-params service cache the old objects.
A reload is sufficient only if fresh workers and an actual strong handshake
are proven; the reviewed conservative route is a scoped Dovecot restart.

## Guarded host-side installer

`install_dovecot_dh.py` runs as root on CT400's Docker host with Python 3.8 or
newer and its existing Docker/OpenSSL tools. It requires `/usr/bin/timeout`
inside the mail container, but no Python, compiler or package installation
there. Install this script beside the exact reviewed
`dovecot_legacy_dh.py`, whose hash it checks, in a root-private directory.
Transfer the exact candidate public file and verify all transferred hashes.

First run without `--apply`:

```sh
python3 -B /root/grange-dovecot-dh/install_dovecot_dh.py --candidate /root/grange-dovecot-dh/ssl-parameters-candidate.dat --expected-certificate-sha256 1a5610e0a119f37c90b4429e2fcbc84f24b241ef5407a416239fcba759994ed3
```

The leaf fingerprint above is the observed current Work leaf. Reconfirm it
before using the command if issuance has occurred since that inventory.
The default mode reads the three enrolled files, checks their exact baseline
hashes/ownership, validates the pinned group and the Dovecot version, then
stages a complete main config under a private temporary `/var/run` directory for
native `doveconf` validation. It removes that stage on exit. It never changes
the three installed files or stops Dovecot in this mode. Full native command
output, including configuration values, is captured and withheld.

The old mail image has `/var/run` and `/bin/mktemp`, but no `/run`; only the
in-container temporary stage uses that legacy path. The CT400 Docker host's
existing `/run/lock/onlyoffice-mail-cert.lock` remains unchanged.

After a successful validated plan, add `--apply` to the same command. The
installer takes the existing CT400 mail-certificate-copy lock, preventing that
old copy job's independent Docker restart during maintenance. It pins the
container ID and start time throughout, creates root-private durable backups
of all three original/candidate files and a transaction journal, stops only
Dovecot, verifies old Dovecot/login/ssl-params processes have exited, and
atomically replaces each enrolled file with its original owner and mode.

The actual procps 3.2.8 implementation requires separate `-o` arguments:
`ps -e -o pid= -o comm= -o stat=`. Its comma form silently returned PID-only
rows. The installer now rejects empty, malformed, duplicate-PID or incomplete
inventories and requires exactly one live `dovecot` master in the plan and
final service checks. Every classified live worker must exit before a file is
replaced; only `Z` zombies, which have released their memory and descriptors,
are excluded. Service-wrapper success alone is not proof of that stop.

Success requires both trusted Python TLS handshakes with the expected leaf and
OpenSSL's own stderr diagnostics proving a real 3072-bit DH group on 993 and 995.
Application output cannot masquerade as that proof. Each Docker command uses
the actual legacy coreutils 8.4 `timeout --signal=KILL SECONDS` form, with no
unsupported `--kill-after` option. A harmless native one-second probe confirmed
the timeout kills its process group and suppresses a delayed descendant marker.
An early disconnected/nonzero mutating exec retains its full hard deadline
plus a conservative six-second margin; every later native command waits for
that deadline before recovery can proceed.
This prevents an uncertain file-copy shell from overlapping rollback. An
unchanged container identity and all three final hashes/modes are checked
again after activation. Bytes, owner and mode are also rechecked immediately
after the scoped stop and before every replacement.

On an installation failure, the complete rollback set is validated before any
restore write. A changed external file is preserved for review. The installer
restores the old file/config set, starts the original service and reports the
known weak-DH limitation explicitly; it does not lower client TLS security
to produce a false healthy result. The private transaction is retained.

An outside writer can change a file or its ownership/mode while Dovecot is
being stopped. In that case no unreviewed change is overwritten and automatic
rollback can be blocked. The journal records `rollback_failed` and
`failed_phase`; Dovecot may remain stopped until the operator reviews the
outside change and performs a guarded recovery. Do not describe that exception
as a normal successful rollback or assume availability was restored.

An interrupted operation can be recovered explicitly on the same container
generation using its recorded transaction directory:

```sh
python3 -B /root/grange-dovecot-dh/install_dovecot_dh.py --rollback /var/backups/grange-dovecot-dh/transaction-TIMESTAMP-NONCE
```

A changed container, corrupt backup, altered target or unexpected ownership
blocks recovery before overwriting it. Preserve the private journal for
operator review. A successful manual rollback restores the original weak-DH
baseline and therefore does not authorize certificate automation to proceed.

Abrupt SIGTERM/SIGKILL or host/controller failure cannot run the Python
exception handler. Use the explicit journal recovery path after inspecting
the service and files. A new `--rollback` controller waits41 seconds before
recovery, covering the longest possible surviving inner service command and
its conservative margin when it cannot inherit the previous controller's monotonic
deadline. The same container generation and complete original/candidate file
guards still apply; an unrelated outside edit requires operator review.

## Live deployment verified on 28 October 2026

The reviewed installer completed the scoped Dovecot update at 21:17:31 UTC.
Both IMAPS 993 and POP3S 995 passed trusted TLS 1.2 handshakes and actual
3072-bit DH verification with the original Work certificate.

The subsequent managed certificate renewal restarted the same mail container
at `2026-10-28T21:23:02.219166948Z`. After that complete Docker restart, both
ports again passed the installer's trusted TLS and DH3072 checks. The service
had exactly one discovered live Dovecot master and the effective
`ssl_parameters_regenerate` value remained zero. The renewed Work leaf was
`64044df252958db65e6705b7757aa1f93567d67031ef39c87bee7a008b105f94`,
expiring on 26 January 2027 at 20:24:24 UTC; its public key was unchanged.

All three installed files retained their post-installation hashes and original
ownership/modes after the Docker restart:

| Installed file | SHA256 | Mode and owner |
|---|---|---|
| Main Dovecot configuration | `728fa392607ebebf576360a44c0bedebdaa921670381883f4c93cb8dbb1ff060` | `0644`, root:root |
| Genuine iRedMail template | `6abc57d4f580b95b8f04514f38239fd1df64d6670b3ef1a9cee83b387ee25b13` | `0664`, root:root |
| Public DH parameters | `f8d823cb32adfc3f3ff11f52e0754c89b996dd01aae6896b9aa690f67bebee42` | `0644`, root:root |

These results are included in the
[central mail and TLS verification record](../../tests/verification/mail-sync-tls-20261028.json).
They establish persistence across a restart of this container. A newly created
replacement container still requires the documented guarded enrollment and
installation because these files reside in the existing container's writable
layer.

## Offline verification

```sh
python3 -B integrations/dovecot-legacy-dh/tests/test_legacy_dh.py
python3 -B integrations/dovecot-legacy-dh/tests/test_install_dovecot_dh.py
```

All 15 tests pass locally and independently. They exercise exact native framing,
the pinned public group, weaker/different-group rejection, changed original
hashes, invalid selectors, duplicate/truncated/oversized/trailing data and
exclusive candidate creation. The C probe uses the real OpenSSL
`d2i_DHparams`, reproduces the legacy slot selection and verifies that the
non-export callback object contains a valid 3072-bit prime. It is an offline
compatibility check, not a substitute for the final native server handshake.

The test runner needs a C compiler and OpenSSL development headers. The Python
builder does not. No test opens a socket, sends mail, uses production private
keys or changes a real Dovecot service.

The separate installer fixtures exercise the real private file/journal
transaction code with a simulated native service. They cover partial writes,
failed starts, failed trusted TLS, complete rollback, corrupt backups,
concurrent edits, changed container identity, idempotent stop, inner command
timeouts and secrecy of captured native output. They also reproduce a mode
change during stop and an early disconnected exec; the latter uses a fake
clock to prove the recovery command cannot run before remote quiescence.
All 32 installer checks pass locally and independently. The legacy process fixtures exercise the
actual native stop method through the verified three-field parser, prove that
the service stop is invoked, and reject surviving workers, PID-only output and
a running-service report without a discovered live master.
