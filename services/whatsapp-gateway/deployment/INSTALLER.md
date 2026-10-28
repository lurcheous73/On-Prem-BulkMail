# Debian 12 installer

The full repository includes `deployment/install-whatsapp-gateway.sh`. It installs
the gateway on Debian 12 x86-64 alongside an existing BulkMail installation. The
BulkMail upgrade must already have created `/etc/bulkmail/integrations.php`.

Run from the repository root:

```sh
sudo bash deployment/install-whatsapp-gateway.sh
```

The script installs the checksum-verified official Node **24.22.1** runtime under
`/opt/bulkmail-node-24.22.1`, without replacing the system's Node executable.
Gateway code goes under `/opt/bulkmail-whatsapp`; a systemd drop-in selects the
isolated Node executable by absolute path. A dedicated non-login user owns the
private `/var/lib/bulkmail-whatsapp` state directory.

The installer creates a random token locally and writes it to the root-only
`/etc/bulkmail-whatsapp.env` and the PHP-readable integrations file. The token is
never printed or passed on a command line. Existing SMS, identity and other
integration values are preserved. Both gateway connection and outbound delivery
remain disabled, and the PHP WhatsApp channel remains disabled. Starting the
local authenticated API does not connect to WhatsApp.

## Offline staging

Prepare a bundle on a machine with matching Linux x86-64 dependencies:

1. Fetch the official `node-v24.22.1-linux-x64.tar.xz` archive. The installer checks
   its hard-coded SHA256 before extracting it.
2. Run `npm ci --omit=dev --ignore-scripts` in the gateway source directory using
   the supported Node version, then include `node_modules` in the private staging
   bundle. Include `package.json` and `package-lock.json` unchanged.
3. Copy the repository/source bundle and Node archive to the staging CT.
4. Run:

   ```sh
   sudo bash deployment/install-whatsapp-gateway.sh \
     --source-dir /root/staging/On-Prem-BulkMail/services/whatsapp-gateway \
     --node-archive /root/staging/node-v24.22.1-linux-x64.tar.xz \
     --offline
   ```

Offline mode performs no downloads. The installed dependency graph is compared
with the lockfile, and imports of the actual Baileys, QR and locking packages are
tested without opening a WhatsApp socket. The authenticated health check uses
loopback and prints only a fixed success/failure status.

`--no-services` installs files without systemd reload, enable, start or health
checks. Normally omit it for the staging rehearsal so service startup is tested.

## Existing installations

The installer refuses an enabled configuration, nonstandard listener/state path,
or any existing auth credentials or halt markers. A previously active or linked
gateway needs an operator-reviewed upgrade; this script never clears its link.
It also refuses mismatched existing tokens unless `--rotate-token` is deliberately
provided. Token rotation is still refused for a previously active installation.

For an existing disabled installation, code, environment, integration config,
unit/drop-ins and state are backed up privately before replacement. If startup
or health validation fails, previous service files and service state are restored.
The gateway state directory is never deleted or overwritten by rollback. The
isolated verified runtime and dedicated service account may remain after a failed
installation; neither changes email delivery.

No firewall, router, mail unit, BulkMail user account or existing account password
is modified. Pairing and sending require the separate deliberate activation steps
in the gateway README.

Official runtime provenance:

- [Node 24.22.1 release post](https://nodejs.org/en/blog/release/v24.22.1)
- [Linux x64 archive](https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz)
- [Official checksum file](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt)

SHA256: `6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6`.
