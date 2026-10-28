# Germany CT250 MTA-STS certificate consumer

The inspected `mta-sts.the-grange.uk` vhost serves the same SAN set and existing
SPKI as `mx2.the-grange.uk`. Its copied certificate was due to expire on
25 November 2026, while the MX2 source had already been renewed to
26 January 2027. The existing Germany Proxmox host timer
`grange-mtasts-maintain.timer` copies both certificate and key nightly at 23:45.
The new consumer replaces that distribution job with a validated **public
certificate only** pull from CT280. It retains the key already on CT250.

This consumer does not change the four-MX issuer/publisher. Deploy `pem_consumer.py`
alongside the reviewed `renewal_common.py` and `mx_consumer.py` on CT250.
`mx_consumer.py` supplies the tested public-fetch/envelope validation functions;
the Xeams-specific routines are not invoked. Install
`config/consumer-germany-ct250-mtasts.json` as
`/etc/grange-certificate-renewal/consumer-mtasts.json`, root-owned and not
group/world writable. Create these private state directories:

```sh
install -d -m 0700 /var/lib/grange-certificate-renewal/mtasts
install -d -m 0700 /var/backups/grange-mtasts-tls-automatic
```

The config pins the existing key. The runtime additionally requires the
inventoried local CT250 IP `10.50.0.250`, fixed certificate/key paths under
`/data/custom_ssl/grange-mtasts`, and unchanged local vhost configuration.
CT250 is already in the publisher's exact source allowlist.

Run a plan and then the guarded application:

```sh
python3 -B /opt/grange-certificate-renewal/pem_consumer.py --config /etc/grange-certificate-renewal/consumer-mtasts.json
python3 -B /opt/grange-certificate-renewal/pem_consumer.py --config /etc/grange-certificate-renewal/consumer-mtasts.json --apply
```

This verifies the current loaded TLS certificate and MTA-STS policy, validates
the published replacement, backs up the public chain, replaces only that file
atomically with its existing owner/mode, runs `nginx -t`, reloads Nginx, and
checks the new expected TLS fingerprint plus an HTTP200 policy containing
`version: STSv1`. The private-key bytes and vhost configuration must remain
unchanged. Failure restores the verified original certificate and reloads it.
The consumer never stops or restarts Nginx. No ACME order is created here.

Install the provided `grange-mtasts-certificate-consumer.service` and `.timer`,
run `systemd-analyze verify`, reload systemd, then run the service once to test
its sandbox and inspect `health.json` under the private state directory.
Use the final service pinned in `DEPLOYMENT-DELTA-MANIFEST.json`: it includes
`AF_NETLINK` for local interface validation and
`ExecStartPre=/usr/bin/mkdir -p /tmp/nginx` for the tested native Nginx
configuration inside `PrivateTmp=true`. These are the two observed runtime
prerequisites; no sandbox setting needs to be removed.
After that succeeds, enable the timer, which checks hourly at minute20UTC.
Only **after** the new consumer has been verified should the operator on the
Germany Proxmox host save the old maintenance script/units and disable
`grange-mtasts-maintain.timer`. Leave its files/backups in place; do not delete
the rollback option. Confirm that the old service is not already running
before the final transition, so it cannot race a new pull.

The current old timer writes the same public source and key. During handover,
the consumer detects a concurrent file/config/key change and refuses to
overwrite it. Once the timer is disabled, future MX2 issuance is inherited
through the public publication and this hourly guarded reload.

Record the active/enabled timer, loaded certificate fingerprint/expiry,
unchanged SPKI/private-key hash, HTTP policy result and backup path in the
verification record. Do not call this endpoint automated until that live
handover is complete. Other CT102 MTA-STS/management certificates are separate
named Certbot lineages and use the local-lineage coordinator.
