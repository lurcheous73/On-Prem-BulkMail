# CT400 account links and audit attribution

The upgrade adds identity links alongside the existing BulkMail accounts. It does
not replace the `users` table, change any existing password hash, change existing
roles, rename Peter, transfer his address book, or rewrite old message ownership.
Peter remains the same local account (on the Derby installation, user ID 2).

## Configure

Add the `identity` section to the private `/etc/bulkmail/integrations.php` file;
see `deployment/integrations.php.example`. Keep this file outside the webroot,
owned by root and readable only by the application service group. Supply:

- `enabled`: literal boolean `true` when the connection is ready. Default `false`.
- `base_url`: the HTTPS origin of the existing ONLYOFFICE **Workspace** portal.
  This is not the separate DocSpace API or the mail-server container API.
- `directory_token`: an existing Workspace API token with access to read the
  intended people. Its lifecycle remains managed in CT400.
- `allow_http`: default `false`. Use HTTPS in production. The isolated fixture
  tests deliberately permit HTTP only to their temporary loopback server.
- `session_ttl`: optional CT400 login lifetime, default 3,600 seconds, bounded
  between 60 and 86,400 seconds. This does not change local-password sessions.

No CT400 credentials are present in source. The application does not generate a
portal administrator, alter CT400 settings, or copy directory passwords.

## Link Peter or another existing user

1. Sign in using an existing BulkMail administrator account.
2. Open **CT400 Accounts**, and look up the exact CT400 username or email.
3. Check the returned person's name, email and stable CT400 ID.
4. Select the correct **existing** BulkMail account from the list. Select Peter's
   existing account when linking Peter.
5. Optionally tick **Also allow this person to sign in with CT400 credentials**.
   An audit-only link does not automatically add a second login method.
6. Save. The server queries CT400 again and verifies the expected ID before it
   writes the link. Local accounts are never matched or merged automatically by
   email address.

The link is pinned to both the CT400 portal URL and its stable user ID. One CT400
identity cannot be linked to two local accounts. An established binding cannot
silently be replaced with a different person. A change of portal URL needs an
explicit, reviewed binding migration; it is not inferred to mean the same portal.

**Disable CT400 link** revokes the linked login and removes the link from future
audit snapshots. It retains the mapping record and all historic snapshots. It
does not disable or delete the local account. To re-enable the same binding,
look up the same CT400 person and link that existing account again.

## Add a new CT400 member

After a directory lookup, **Add a new account** is an explicit administrator
action. It creates a separate, non-administrator local account, with an empty
address book and a CT400 login link. No CT400 administrator role is inherited.
Existing username or email conflicts cause the action to stop and direct the
administrator to link the existing account. A duplicate external identity rolls
back the whole creation transaction.

The local password hash is created from a random secret that is immediately
discarded. There is no shared initial password. An administrator can deliberately
set a local password later using the existing Users workflow, if required.
Sender identities and any permitted domains must be assigned separately.

## Sign-in behavior

The existing login remains the default choice. The **Linked CT400 work account**
choice sends the entered username and password over the configured HTTPS
connection to `POST /api/2.0/authentication.json`, then verifies the returned token
with `GET /api/2.0/people/@self.json`. The token is sent in Workspace's raw
`Authorization` header. It is not a DocSpace Bearer-token integration.

For CT400 two-factor authentication, the optional code goes to
`POST /api/2.0/authentication/{code}.json`. Password-only challenge responses are
rejected. This component does not initiate an SMS challenge, disable MFA, or
provide an SSO bypass; use an already-issued code where the portal requires one.
The returned profile must be active, activated and a member, and have an active
administrator-approved local binding. No account is created during login.

Entered passwords and short-lived login tokens are not persisted in the session,
database, logs or audit details. A directory timeout or malformed response fails
the CT400 login without invoking the local password path. Users who choose their
existing local login never need CT400 to be available.

Each request checks whether a CT400-authenticated session still has the same
active local binding. Disabling its local link revokes that session on its next
request. The bounded CT400 session lifetime forces a fresh upstream verification.
Changes made only in CT400 (such as disabling a member) are enforced at the next
CT400 login, not by a continuous background directory synchronisation.

## Audit records

`user_identity_links` contains explicit verified mappings. `audit_identity`
captures a snapshot when a new `audit_log` entry is written:

- The local person who initiated the action and their linked CT400 ID.
- The local owner the action was performed for, and that owner's CT400 ID, when
  an authoritative owner is available.
- Whether the person used a local password or actually authenticated through
  CT400. A linked identity is not presented as proof of CT400 authentication.

An administrator acting for Peter remains the initiating person; Peter remains
the owner. Historic audit rows are not retroactively attributed using today's
links. The Audit page labels them as legacy records. Message campaigns separately
store actor and owner snapshots at queue time using `bm_identity_snapshot()`.

## Application integration

Load the integration configuration and this module before the login routes, then
call `bm_identity_schema($db)`. Its two `CREATE TABLE IF NOT EXISTS` operations
are additive and repeatable. Do not import a fresh database schema over live data.

Call `bm_identity_handle($db, $page)` after ordinary authentication; it handles
`identity_users` and `audit`. The login integration uses
`bm_identity_try_login($db, $username, $password, $code)` only for the explicit
CT400 option. Its return value includes `_ct400_id` and `_ct400_issuer` after
successful upstream verification. The session records `authentication_method`,
`authenticated_ct400_id`, `authenticated_ct400_issuer` and
`authenticated_ct400_at`. Call `bm_identity_validate_session($db)` on each request.

The `audit()` wrapper passes its newly inserted audit ID to
`bm_identity_record_audit($db, $auditId, $actorId, $action, $details, $ownerId)`.
New callers should pass the authorised owner explicitly. Compatibility handling
for existing email queue events reads the owner from the stored mailing record.

## Verification

Run `php tests/test-identity.php` and `python3 tests/identity-http.py`. They use
synthetic accounts and temporary SQLite databases only. The HTTP suite launches
a temporary loopback Workspace fixture and exercises actual app login and
account routes. Neither test contacts CT400 or sends messages. The tests check
Peter's complete row/hash/role preservation, data ownership, repeatable migration,
forged and duplicate links, cross-account access, CSRF, MFA challenge handling,
local login during an outage, session revocation and historical audit snapshots.

## Primary API references

- [Workspace authentication](https://api.onlyoffice.com/workspace/api-backend/get-started/passing-authentication/)
- [Authenticate a user](https://api.onlyoffice.com/workspace/api-backend/usage-api/authentication/authenticate-a-user)
- [Authenticate with a code](https://api.onlyoffice.com/workspace/api-backend/usage-api/authentication/authenticate-a-user-by-code)
- [Get the authenticated profile](https://api.onlyoffice.com/workspace/api-backend/usage-api/people/profiles/get-my-profile)
- [Get a profile by user name](https://api.onlyoffice.com/workspace/api-backend/usage-api/people/profiles/get-a-profile-by-user-name)

These references describe ONLYOFFICE Workspace. Live connection, credentials and
the customer's configured MFA flow still need an authorised smoke test before
enabling the integration for users.
