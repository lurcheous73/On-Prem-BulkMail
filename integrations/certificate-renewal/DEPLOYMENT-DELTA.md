# Reviewed deployment delta after the first live checks

Keep both released archives unchanged. The second reviewed archive is
`grange-renewal28-core-v2-reviewed.tar.gz`, SHA256
`01a57a128d219cd643e71c2e61445279bdd614acdde555dcb63233af281fc247`.
The two standalone helpers below consume that extracted release and apply
only the reviewed compatibility changes. Their code is not inside the frozen
archive and must be transferred separately after its hash is verified.
`DEPLOYMENT-DELTA-MANIFEST.json` records the separate final artifact hashes;
the frozen `REVIEWED-MANIFEST.json` continues to describe the v2 archive.

## MX adapter/config and socket-family update

The initial class validated on three MXs. Canada CT100 uses a different native
parser: the exact inspected `AppConfigAdapter` calls the public static
`TGlob.decryptPassword(value, 8)`. The v2 class pins that parser and decoder
class-resource hash and checks the exact public/static/String signature. The
other MXs retain the inspected public `B.e(value, 8)` API. No accessibility
override, password guessing or replacement decoder is used.

Live systemd tests also showed that `ip -j address` requires `AF_NETLINK`.
The exact same read-only command passed when that one address family was added.
Only the MX and CT250 consumers inventory interfaces, so only those two units
gain the extra family. Issuer/publisher restrictions are unchanged.

Transfer `deploy_mx_adapter_v2.py`, SHA256
`d619153a95ffc06a66b10cf462daf69de26b8966e895abc7e867bf36843299be`,
and run locally on each MX, substituting its exact enrolled hostname and the
actual extracted package path:

```sh
python3 deploy_mx_adapter_v2.py --package /root/renewal28-v2/certificate-renewal --hostname mx2.brimstonecottage.uk
python3 deploy_mx_adapter_v2.py --package /root/renewal28-v2/certificate-renewal --hostname mx2.brimstonecottage.uk --apply
```

The helper validates exact old/new per-host class/config bytes and unchanged
core source pins. It pauses only the corresponding new renewal timer if that
timer was already active, requires the wrapper service not to be running,
and holds the consumer's own lock. It backs up class, config and wrapper unit,
then installs the reviewed class/config plus the exact netlink-only unit delta
atomically, preserving ownership/mode. It checks the effective unit family
list and runs the real `checked_config`/`process(apply=False)` path in a bounded
child while the parent retains the lock. That avoids a second lock attempt
without permitting another consumer operation to run concurrently.

The helper never controls `xeams.service`, issues a certificate, or deploys
one. A failed read-only preflight restores the prior class/config/unit and
prior timer runtime state. Lost stop acknowledgements and backup failures also
restore the prior timer state when captured inputs are intact. An unexpected
outside writer is preserved and the new renewal timer remains paused for
review. Backups are under `/var/backups/grange-certificate-code`.

After the helper passes, run the actual wrapper service once to verify its
systemd sandbox; with the same current public bundle this is a certificate
no-op and writes only the validated cache/health record. Then enable the
appropriate primary or secondary timer. The helper leaves initially inactive
timers inactive.

## Fresh CT250 code staging

Transfer `stage_ct250_from_v2.py`, SHA256
`04e05676961cab839bd791ebf054f248e386068157f11404e66b6a552752ed2b`.
It verifies the exact frozen v2 manifest and six selected artifacts, derives
the pinned service changes below, and only stages code/config/unit files:

```sh
python3 stage_ct250_from_v2.py --package /root/renewal28-v2/certificate-renewal
python3 stage_ct250_from_v2.py --package /root/renewal28-v2/certificate-renewal --apply
```

This step verifies CT250's local address and that its new consumer units are
inactive. It never changes the live certificate, key or Nginx route, and never
enables a timer. It finishes by running the reviewed PEM consumer's read-only
preflight. On failure, staging files return to their previous states; admitted
targets are tracked before atomic writes so interruptions on either side of
rename are handled. Outside changes are not overwritten.

After staging passes, follow `CT250-HANDOVER.md` to apply the public bundle,
check TLS and the MTA-STS policy, test the wrapper service, enable its hourly
timer, and only then disable the old Germany-host private-key copy timer.

### CT250 private temporary directory

The actual systemd service exposed a second concrete prerequisite after the
interface check passed: `nginx -t` attempted to create `/tmp/nginx/body`, while
the service's private temporary directory did not contain `/tmp/nginx`.
An otherwise identical live read-only transient unit passed configuration,
trusted TLS and policy checks after adding exactly:

```ini
ExecStartPre=/usr/bin/mkdir -p /tmp/nginx
```

The final unit retains `PrivateTmp=true`, `PrivateDevices=true`,
`ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true` and the exact
reviewed socket-family list. The existing Nginx executable and configuration
are correct and remain unchanged. No PEM consumer source change is involved.
The staged derivation checks the immutable original unit, the intermediate
AF_NETLINK-only hash, and the final hash after this one extra directive.

For a container already staged with the intermediate unit, require the
consumer to be inactive with `MainPID=0`, verify the intermediate hash
`fc4098e640c7798ce658df5d3da59788bce1c9fbae05b5d9ef77de8c35edba5c`,
save a permission-preserving backup, and atomically install the final pinned
unit. Run `systemd-analyze verify` and `systemctl daemon-reload` before starting
the real consumer. Keep the old host copy timer until the resulting TLS and
policy checks succeed. Three targeted structural regressions and all four
existing staging interruption tests pass for this derivation; independent
review confirmed that the sandbox and transaction logic remain intact.

## CT280 issuer interrupted-attempt retry

The hourly retry now recognizes an interrupted `issuing` or `retry_pending`
phase even if the process stopped before incrementing its failure counter.
Completed-bundle recovery, the recorded backoff and the certificate due window
still precede a new order. The shared policy, DNS configuration, publisher,
consumer code and private keys remain unchanged.

The exact one-file update and rollback command is in `ISSUER-RETRY-DELTA.md`.
It replaces the earlier `a6e5a709...` issuer only after root coordinates idle
services and pauses the two existing issuer timers, while holding the
issuer's own lock. It validates the real read-only plan before the prior timer
states are restored. Seven actual-flow interruption, recovery, backoff,
deadline and read-only regressions pass against the final source, with an
independent review of the exact minimal source correction.

## Final reviewed hashes

| Artifact | SHA256 |
| --- | --- |
| v2 Java class | `5cac7bd6866c87fd8621bc911cbb21150692822a4fe3ae82b7d9474ed4a0e010` |
| MX service with AF_NETLINK | `6ff737612c38423bc95d3be6a442c017bd3a8f6b8941f67a877af414d6fc903a` |
| CT250 service with AF_NETLINK and private Nginx temporary directory | `61f3176f4f8a0eea495aa16d93abc2f8925444f02fce4aea936725369d59e4ae` |
| Final proxy transformer | `7aa1db505ff5bec1a500cbf68c1cc2c4a7f0b6b3d27ec90a0cd1157404977735` |
| CT280 issuer with interrupted-attempt retry | `ce21e755f68c131d0a82ef9417f41ff85a87b1d46bc1ba3fd042d5f56bfab87f` |

The core suite passed 54 checks and the independent issuer/publisher script
passed 14 checks. The deployment delta has another 10 MX updater and four
CT250 staging regressions, independently rerun, plus three CT250 unit-contract
checks and seven issuer interruption checks. Live acceptance remains a
separate requirement; the hashes and offline tests do not assert that a timer
is enabled or that a particular server has loaded a new certificate.
