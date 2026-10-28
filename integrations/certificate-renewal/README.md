# Mail certificate renewal within 28 days

This integration separates certificate issuance from deployment. CT280 issues
certificates from the four existing public CSRs. Each Xeams server pulls a
validated public bundle and updates its own encrypted TLS keystore locally.
Private keys, keystore passwords and Cloudflare tokens are never distributed.

**Rollout status:** the central issuer, publisher, MX consumer and Java adapter
have passed local tests and independent review. Live enrollment, challenge
validation, service/timer activation and post-install probes must be recorded
by the operator before describing this integration as enabled. The separate
CT400/CT102 named-lineage coordinator is developed alongside these files; its
own configuration and verification determine coverage of those consumers.

## Policy and retry behavior

The deadline is the earlier of certificate `notBefore + 28 days` and the point
at which one third of the certificate's lifetime remains. A daily check acts
in the final 24-hour check horizon before that deadline. This also accommodates
shorter certificate lifetimes. A late deployment or reconstructed state cannot
push the issuance deadline later.

The issuer retries failures hourly, subject to exponential backoff of 1–12
hours, a 3-hour cap when fewer than seven days remain, and a later ACME
`Retry-After` deadline. Completed certificate output is recovered and published
before considering another order. A deployment failure never causes an ACME
order: the consumer retries the already-issued public bundle independently.
Persistent timers catch missed checks after a reboot. An outage can still
delay renewal; service failures and the JSON health/state files must be watched.

Exact SANs, the original SPKI, CA trust and certificate validity are checked.
A replacement requires strictly later `notBefore` and `notAfter`; the same
fingerprint is a verified no-op. An extra seven-day expiry advance is deliberately
not required because renewal during the 90-to-64-day lifetime transition can
legitimately extend expiry by only two days.

## Target enrollment

| Target | Location/address | Issuance method | Paired-MX install window, UTC |
| --- | --- | --- | --- |
| mx1.the-grange.uk | Canada CT110, 10.44.0.110 | Existing personal Cloudflare token on CT280 | Minutes 35–44 |
| mx2.the-grange.uk | Germany CT110, 10.50.0.110 | Same token; includes mta-sts.the-grange.uk SAN | Minutes 05–14 |
| mx1.brimstonecottage.uk | Germany CT100, 10.50.0.100 | HTTP-01 through CT250 | Minutes 35–44 |
| mx2.brimstonecottage.uk | Canada CT100, 10.44.0.10 | HTTP-01 through CT102 | Minutes 05–14 |

The existing Brimstone zone is not visible to either authorized Cloudflare
token. The integration therefore uses the existing public HTTP proxy routes
for those CSRs; it does not change DNS-account routing or request new tokens.

## Install reviewed code without activating renewal

Copy only the reviewed Python files, configs, units and compiled
`java/GrangeRenewalKeystore.class` to a root-owned staging directory on each
applicable host. Compile the class from its source with a JDK if necessary:

```sh
java -m jdk.compiler/com.sun.tools.javac.Main --release 8 -d /tmp/grange-renewal28-java java/GrangeRenewalKeystore.java
```

The reviewed class SHA256 is
`5cac7bd6866c87fd8621bc911cbb21150692822a4fe3ae82b7d9474ed4a0e010`.
The enrollment configs pin this class hash. This second automation adapter also supports the exactly inspected named TGlob decoder on Canada CT100; both its parser and decoder class-resource hashes are pinned. The other three MXs retain the inspected public B.e API. Verify the transferred bytes; do
not substitute the older manual-renewal class, which has a different name and
interface. The deployed manual helpers remain untouched.

On **CT280**, use this layout before starting the publisher or issuer:

```sh
install -d -m 0755 /opt/grange-certificate-renewal
install -d -m 0755 /etc/grange-certificate-renewal
install -d -m 0755 /etc/grange-certificate-renewal/csr /etc/grange-certificate-renewal/reference
install -d -m 0755 /var/lib/grange-certificate-renewal
install -d -m 0755 /var/lib/grange-certificate-renewal/public /var/lib/grange-certificate-renewal/challenges
install -d -m 0700 /var/lib/grange-certificate-renewal/issuer
```

The shared parent must be traversable (0755), while the issuer's private state
remains 0700. Create a dedicated system user/group `grange-cert-public`, with
no login shell and no home, if absent. Do not reuse or modify the BIMI service
user. Install `renewal_common.py`, `issuer.py`, and `public_server.py` as
root-owned 0644 files under `/opt/grange-certificate-renewal`. Install the two
matching JSON configs under `/etc/grange-certificate-renewal`, root-owned 0644.
Issuer configuration contains file paths and account selection, not a token.

Copy each MX's **public** `domain.csr` and `domain-chain.crt` to the CSR and
reference filenames declared in `config/issuer.json`. Verify the CSR
self-signature, exact SANs and pinned SPKI. Do not copy `domain.key`, AppConfig
or the PKCS12 store to CT280. The approved existing token stays on CT280.

Run seeding first without `--apply`, then with it:

```sh
python3 -B /opt/grange-certificate-renewal/issuer.py --config /etc/grange-certificate-renewal/issuer.json --seed
python3 -B /opt/grange-certificate-renewal/issuer.py --config /etc/grange-certificate-renewal/issuer.json --seed --apply
```

This validates and publishes the current certificates without ACME orders.
Install the publisher unit, reload systemd and start only that service. The
publisher binds the private address `10.50.0.80:8099`; do not expose it publicly.
Confirm the actual source addresses of all MXs and both HTTP proxies in its
sanitized journal. The example allowlist contains their inventoried private
addresses and CT280 itself. If WireGuard NAT changes a source, enroll only the
observed necessary address after checking the route; never use a broad subnet
allowlist. `/healthz` and the four `/v1/HOST.json` URLs should return HTTP200 from
approved sources. The service serves public certificates and HTTP-01 tokens,
with no directory listing, upload or privileged action.

On **each MX**, create `/opt/grange-certificate-renewal/java` (0755),
`/etc/grange-certificate-renewal` (0755), and private 0700 directories
`/var/lib/grange-certificate-renewal/mx` and
`/var/backups/grange-mx-tls-automatic`. Copy `renewal_common.py`, `mx_consumer.py`,
the compiled adapter and that hostname's config as `consumer.json`; keep all
code/config root-owned and not group/world writable. Run:

```sh
python3 -B /opt/grange-certificate-renewal/mx_consumer.py --config /etc/grange-certificate-renewal/consumer.json
python3 -B /opt/grange-certificate-renewal/mx_consumer.py --config /etc/grange-certificate-renewal/consumer.json --apply
```

The first command validates the local hostname and private IP, CSR/key/store,
published bundle and actual TLS on 443/25/465/587. For an unchanged current
certificate, the second only writes the validated public cache and health
record; it does not restart Xeams. All four current MX certificates were
younger than 28 days when this package was prepared, so do not force redundant
production orders merely to test deployment. Brimstone's existing 999:991 file
ownership is preserved; Grange's root ownership is preserved separately.

## HTTP challenge routing and staging validation

`proxy_config.py` creates a separate candidate from the inspected CT250/CT102
custom include. It changes only the selected Brimstone port80 vhost:

1. Existing local Certbot webroot still takes precedence.
2. A missing local token is requested from CT280 with an exact hostname.
3. Central 404/502/503/504 falls through to the existing Xeams token handler.

The native eight-character `.htm` check and root404 remain unchanged. The
named location uses `proxy_pass http://10.50.0.80:8099` without a URI component.
An allowlist403 remains visible as a configuration failure.

Before installation, compare the live original hash with the inspected file,
save a permission-preserving backup, write the combined candidate, run the
existing Nginx binary's `-t`, reload and check known public challenge paths.
Restore the backup and reload if validation fails. CT102's approved dedicated
HTTPS consumer-path transformation must be combined in the same candidate
only after those certificate/key files and their guarded local-lineage updater
are staged; otherwise use the ACME-only candidate. Preserve unrelated MTA-STS
vhosts/cron jobs until their own reviewed renewal policy is deployed.

With routing verified, test each Brimstone public CSR against staging:

```sh
python3 -B /opt/grange-certificate-renewal/issuer.py --config /etc/grange-certificate-renewal/issuer.json --staging-check mx2.brimstonecottage.uk --apply
python3 -B /opt/grange-certificate-renewal/issuer.py --config /etc/grange-certificate-renewal/issuer.json --staging-check mx1.brimstonecottage.uk --apply
```

Staging certificates are never published or installed, and do not update the
production issuance clock. Keep the private logs for diagnosis. A Grange
staging run may be used to confirm the already-authorized DNS route if needed.

## Activate and verify

After the preceding gates pass, install the provided units and verify them
with `systemd-analyze verify`. On CT280 enable the issuer and retry timers plus
the already-tested publisher service. On an mx1 enable only
`grange-mx-certificate-primary.timer`; on an mx2 enable only
`grange-mx-certificate-secondary.timer`. Both invoke the same local consumer
service. Run the issuer once in plan mode and once with `--apply`; certificates
outside the due horizon must report `certificate_not_due` without an order.

Record active/enabled state, next timer times, per-MX no-op verification and
the exact reviewed file hashes. The issuer checks daily at 02:10UTC, failed
issuance retries are considered at minute45, and consumer retries are hourly
at minute05 or35. Immediately before any actual service stop, a trusted SMTP
probe must confirm the paired MX is healthy and still uses its enrolled key.

## Recovery and operations

The consumer backs up the three changed files (encrypted PFX, public chain,
native date metadata) below `/var/backups/grange-mx-tls-automatic`. It preserves
their original modes/owners, changes them atomically while Xeams is stopped,
starts Xeams, and verifies all four TLS ports. Failure restores all verified
original backup bytes and restarts the previous service. Key/CSR/TLS-setting
changes or a native pending `.pfx.new` defer deployment.

`transaction.json` allows interrupted deployment recovery. Unchanged originals
are started immediately without stopping a running service. Fully installed,
healthy candidate bytes are adopted without a restart. Partial replacement
recovery retains the paired-MX schedule/health guard. An unrelated concurrent
writer is never overwritten. Corrupt backup sets are rejected before any stop.

Read `/var/lib/grange-certificate-renewal/mx/health.json`, the private issuer
state and systemd journal. A cached verified public bundle supports deployment
retry during a publisher outage; health records show that the publisher was
unreachable. Native date fields are synchronized after a successful swap,
preserving existing challenge/account settings and native reminder fallback.
Disabling a timer stops future managed actions without deleting certificates.
Do not blindly restore an old backup after its certificate has expired.

## Reproducible offline checks

From the repository root, with a local JDK and the test-only `cryptography`
package available:

```sh
python3 -B -m unittest discover -s integrations/certificate-renewal/tests -p 'test_*.py' -v
python3 -B integrations/certificate-renewal/tests/test_independent_issuer_review.py
```

Production Python requires only the standard library plus existing OpenSSL;
the issuer additionally uses the installed Certbot/dns-cloudflare plugin.
Tests generate ephemeral keys/CA certificates and use temporary files; service
and network operations are mocked. The Java tests execute the compiled adapter
against real synthetic PKCS12 stores. No production credential or key is used.

Official references: [Certbot renewal and key reuse](https://eff-certbot.readthedocs.io/en/stable/using.html),
[Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/), and
[64-day certificate transition](https://letsencrypt.org/2026/10/07/64-day-certs/).
