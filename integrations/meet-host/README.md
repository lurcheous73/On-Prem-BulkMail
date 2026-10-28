# Meeting host CT400 portal sign-in

This adapter is for the existing **Canada** `meet.the-grange.uk/host/` application
in CT320. It wraps the reviewed Python standard-library HTTP handler. It does
not modify the Germany `meet2.the-grange.uk` service, local host password file,
meeting database, existing owner strings, Jitsi room configuration or mail relay.

## Sign-in flow

An unauthenticated visit to `/host/` performs a top-level redirect to the
BulkMail portal identity broker on `https://work.the-grange.uk:9443`. The work
portal's existing host cookie is available on that host. The broker verifies
it against CT400 and returns a single-use code to the exact callback:

`https://meet.the-grange.uk/host/auth/ct400/callback`

Meet binds the callback to a 120-second browser flow with state, an `__Host-`
Secure/HttpOnly pending cookie and a server-held PKCE verifier. It exchanges the
code over verified TLS using its private client secret. Redirects from the
exchange endpoint are rejected. Meet never receives the work portal's cookie,
password or reusable CT400 API token.

A verified CT400 GUID must have an explicit mapping in the private configuration.
Email or display-name similarity does not merge accounts. Existing local login
continues to work. Existing authenticated local sessions take precedence over
automatic portal login. A missing work session returns the user to a local
login page with a **Continue with work account** link, without a redirect loop.
Signing out stays on the login page until the user deliberately signs in again.

Portal sessions last at most 15 minutes. Removing a GUID mapping or disabling
the adapter invalidates its existing portal sessions on the next request.
Changes in CT400 account status are checked during the next portal exchange;
there is no promise of immediate global logout across services.

## Private configuration

Install the reviewed copy of `config.example.json` as
`/etc/grange-meet-ct400.json`, owned by `root:www-data`, mode `0640`.
Leave `enabled` false until the exact callback and matching secret are configured
in the BulkMail broker's `identity.sso_clients.meet-host` entry.

- `subjects`: explicit CT400 GUID to existing or new meeting host username.
- `additional_hosts`: additional usernames beginning `ct400-`, with verified
  `name` and `email`; each is always a standard host (`admin: false`).
- `broker_connect_address`: optional literal IPv4 or IPv6 address for the
  server-side code exchange. An omitted or empty value retains the original
  urllib transport. A nonempty address connects directly on the broker's
  existing port, 9443, while Host, TLS SNI and certificate verification continue
  to use `work.the-grange.uk`. Browser authorization URLs, the callback, issuer,
  state, PKCE and client-secret checks remain unchanged. The direct connection
  does not resolve the broker hostname or use environment proxies. Invalid
  addresses/types disable portal configuration instead of falling back to DNS;
  local host authentication remains available. Confirm reachability and trusted
  TLS from the meeting service before enrolling an address.
- Existing host profile dictionaries cannot be replaced by configuration.
- The existing `support` administrator cannot be mapped through this adapter.
- Invalid/missing configuration disables portal sign-in while preserving local
  host authentication.

The example GUIDs and account are synthetic. Populate the live mapping from the
verified CT400 directory. Preserve the existing `julie`, `debs`, and `dmh-admin`
owner identities for their explicitly verified people. A different existing
email must not be used as evidence to merge another account.

## Audit

Create `/var/lib/grange-meet-sso` with owner `www-data:www-data` and mode `0700`.
The service creates `audit.jsonl` there with mode `0600`. Events contain the
stable CT400 issuer/GUID, mapped meeting host name, authentication time and
event time. Host POST requests have an attempt event and a response event linked
by request ID. The HTTP status is recorded without claiming that it proves
delivery or successful business completion.

The audit does not contain portal cookies, codes, verifiers, secrets, passwords,
request bodies or invitation contents. A portal login or host POST does not
proceed if its initial audit cannot be written. Existing local host actions keep
their previous behavior. Configure normal private log retention operationally.

## Deployment

1. Back up `/opt/grange-meet-host/app.py`, its database consistently, the local
   host password file metadata/hash, service definition and relevant nginx
   configuration in a private root-owned directory. Record the original
   meeting-table contents internally for an after-install comparison.
2. Run `patch_app.py INPUT OUTPUT` against a copy of the live app. It requires
   the exact reviewed baseline SHA256
   `5b885603568bb2793f769bfc24dfeb6d25da560b20f6b1060805399d5c5e4c6b` and writes a new
   output file. It refuses unknown changes or an in-place overwrite. The only
   app changes are importing this adapter, wrapping `Handler` before startup,
   and restricting room deletion to the existing owner or existing local
   administrator. The deletion restriction is enforced in the SQL update.
3. Install `grange_ct400_sso.py` alongside `app.py`, root-owned and readable by
   the service. Install the private configuration and create the audit directory.
4. Make sure nginx forwards `/host/auth/ct400/` to the existing host application
   and does not require a separate basic-auth login first. Suppress access-log
   query strings for callback requests, or disable that location's access log.
   Application callback logs already omit the query string.
5. Atomically replace `app.py` with the reviewed patched copy. Restart only
   `grange-meet-host`; do not restart Jitsi, Prosody, the recorder or mail services.
   The baseline stores host login sessions only in process memory, so a restart
   requires those hosts to sign in again. Existing meetings and passwords remain.
6. Verify the local login form, automatic broker redirect, missing-work-login
   fallback, callback no-store/referrer headers, service health and unchanged
   original meeting records/password file. Complete an actual browser sign-in
   with an authorized work account before claiming that a real session was used.

Rollback restores the original `app.py` and restarts only its host service.
Keep the private audit and backups. No old meeting database should be restored
over later activity merely to roll back this adapter.

## Verification

`python3 integrations/meet-host/test_sso.py` runs 35 synthetic tests: 22 identity,
configuration and flow checks, eleven HTTP checks against the minimally patched
original handler, and two guarded patch checks. Set `MEET_BASELINE_PATH` to a private
reviewed source copy (default `/tmp/grange-meet-canada-baseline.py`). The original
customer application is not copied into this repository.

The tests use temporary databases, synthetic identities and a fake broker. They
do not use customer passwords, connect to CT400 or send invitations/messages.
The room-deletion regression verifies that a standard host cannot remove
another owner's room, while the existing administrator can. A delayed work
callback cannot overwrite a local sign-in completed while that flow was pending.

`python3 integrations/meet-host/test_broker_connect.py` adds nine loopback-only
tests with a disposable certificate authority and synthetic client values.
They verify the original Host/SNI, issuer, public callback and exchange payload;
absence of DNS/proxy use for a pin; rejection of trusted-but-wrong-name and
untrusted certificates before the secret is sent; redirect rejection; bounded
response size and fixed error messages; IPv6; invalid-address failure without
fallback; and unchanged urllib behavior when the option is omitted or empty.
No client secret, code or verifier is placed in a subprocess argument or log.
