# Operations handover: 28 October 2026

CT400 account links and the meeting host sign-in adapter are enabled. The two
Grange MX certificates have been renewed and verified. **Peter's existing draft
recovery is complete:** 21 exact sent duplicates are retained in a recovery
folder, and all 48 Sent messages remain present. A successful normal staff
browser sign-in and the next ordinary user send remain to be observed.

This handover records the evidence in the
[identity activation record](../tests/verification/ct400-work-meet-20261028.json)
and the [mail sync and TLS record](../tests/verification/mail-sync-tls-20261028.json),
with the later [sign-in bootstrap investigation](../tests/verification/portal-bootstrap-20261028.json)
and [private sign-in routing record](../tests/verification/private-sso-routing-20261028.json).
It contains no private configuration, staff identifiers, credentials or backup
contents. The dated records carry the exact deployment revisions and checks.

## CT400 users and work portal sign-in

Seven active CT400 staff identities have verified BulkMail links and seven
verified meeting host mappings. BulkMail retains all five original user rows
exactly, including **Peter's original account, password and role**. Three
additional standard accounts bring its local total to eight. The local
administrator fallback remains available; pending and disabled directory
members were left unchanged. The comparison also preserved all 28 legacy data
tables and the email worker.

The meeting deployment at [meet.the-grange.uk/host/](https://meet.the-grange.uk/host/)
adds four standard host profiles while retaining its original meeting tables,
host password file, owner identities and local administrator. These account and
preservation results are recorded in the
[identity activation record](../tests/verification/ct400-work-meet-20261028.json).

Automatic work portal sign-in is deployed for linked identities. Live HTTPS and
an anonymous browser verified the meeting redirect flow, the fallback when a
work session is required, and the available work/local login controls. Positive
identity exchanges were tested with isolated fixtures. The user subsequently
reported that BulkMail and meeting sign-in were not working. **Successful reuse
of an actual staff login has not yet been observed.** No real messages or
invitations were sent by these checks. See the
[recorded browser verification limit](../tests/verification/ct400-work-meet-20261028.json).

### Request wait diagnosis and reviewed correction

Sanitized live access records show Safari reaching the BulkMail authorization
route and ending with nginx status 499, without the deployed broker or identity
diagnostic being reached. A controlled invalid-cookie API check completed with
HTTP 401 in 49 milliseconds. These observations do not establish why the real
browser abandoned its requests.

Before this correction, the common PHP entry point started its local session
before database/schema work and either broker handler. An isolated real PHP fixture reproduced the
authorization request waiting behind another request holding that same local
session lock. The independently reviewed correction skips `session_start` for
exactly `portal_sso_authorize` and `portal_sso_token`. Those handlers always exit
and retain their own portal-cookie or client authentication, redirect, state,
PKCE and revocation checks. Ordinary BulkMail session handling, existing local
logins and explicit logout suppression remain unchanged.

**The independently approved correction is deployed on CT300.** All three
reviewed source hashes were verified after installation, PHP lint passed, and
PHP-FPM was gracefully reloaded. No account data changed. All five new PHP
bootstrap cases passed, together with 205 existing identity, broker, diagnostic
and HTTP checks. New diagnostics distinguish ingress, session readiness,
database/schema readiness, broker dispatch and the auto-login decision. They
record elapsed time, fixed categories and cookie-presence booleans, excluding
URLs, credentials, session contents, identities and message bodies. The live
PHP configuration has automatic session startup disabled and uses the file
session handler, matching the tested lock mechanism. The source hashes, exact
test counts and browser-verification limit are in the
[bootstrap verification record](../tests/verification/portal-bootstrap-20261028.json).

The [native authentication source review](../tests/verification/onlyoffice-auth-path-20261028.json)
found no binding to the browser's IP, User-Agent or device headers, and no
dependency on another session cookie in the reviewed ONLYOFFICE cookie
verification path. Separate optional portal IP
restrictions are a configuration question, not evidence of such a token
binding. The broker lock correction removes a demonstrated unnecessary wait;
**a fresh staff browser attempt is still required to confirm the live result
and the cause of the earlier 499 responses remains unconfirmed.**

After deployment, a complete anonymous Meet redirect chain reached the login
fallback with HTTP 200, and the live Meet service authenticated its HTTPS
backchannel to BulkMail; a deliberately nonexistent authorization code was
correctly rejected. A later unattributed browser-shaped request also reached
the fallback, but carried neither a Work cookie nor a local session cookie
and its Meet callback had invalid state. Its browser identifier differed
from the earlier Safari requests. These checks confirm transport and
anonymous failure handling, not reuse of a signed-in staff session.

### Measured API delay and private routing

Later live requests supplied a correctly shaped Work cookie but spent
40,036–40,041 milliseconds in the portal API call, ending with cURL error 28
and no HTTP response. Session, database and schema startup took approximately
one millisecond. Five such waits were observed, and an unsuccessful home
request followed by the login-page redirect repeated the API call. Those failed
calls did not appear in Work's upstream access log. This identifies the API
transport wait as the measured bottleneck in these later requests; it does not
retrospectively prove the cause of every earlier Safari 499 response.

The live libcurl 7.88.1 uses asynchronous DNS. Its reviewed source can still
wait for a blocked resolver thread while cleaning up a timed-out request,
explaining how a four-second connection timeout and twelve-second total timeout
can be exceeded. An intermittent resolver or route failure is consistent with
the observations; a specific failing DNS server has not been established.

**The BulkMail private-route deployment was verified at 21:55:35 UTC.** Its
server-managed `identity.connect_address` setting selects the internal CT400
address while retaining the original Work HTTPS hostname, issuer, Host header,
SNI and certificate verification. Invalid routing settings fail closed and
redirects remain disabled. The controlled post-installation API check completed
in 34 milliseconds and the controlled PHP-FPM login-page probe in 58 milliseconds.
The latter recorded a 26-millisecond API response, including a 21-millisecond
TLS milestone, with the deliberately invalid cookie correctly rejected by
HTTP 401. No HTTP or certificate validation was bypassed.
Existing private settings and the reviewed source hashes were verified after
installation. This is transport and fallback verification; successful reuse of
a genuine staff browser session is still pending.

The change passed 202 focused and existing checks, including real local HTTPS
tests for IPv4 and IPv6, original Host/SNI preservation, certificate rejection,
proxy bypass only for a configured direct route, and credential-safe numeric
timing diagnostics. The independent reviewer reran 65 of those checks.

**The Meet private-backchannel deployment was verified at 21:59:25 UTC.** It uses
the existing private tunnel to BulkMail while retaining the original HTTPS
hostname and default certificate trust. The host application itself is
unchanged; only its adapter, optional private routing setting and host service
were updated or restarted. The service is active and its login page returns
HTTP 200. An actual service-user exchange authenticated the existing client
and correctly rejected a deliberately invalid authorization code with HTTP 400
`invalid_grant` in 369 milliseconds. The adapter passed independent source
review, 35 existing SSO/handler cases and nine real HTTPS cases. No staff code or
session was used, and a successful normal staff sign-in remains unverified.
Through 22:00 UTC, no actual staff API-verification or broker-exchange success
had been observed; these controlled timings do not measure staff browser latency.
Exact scope, hashes and
timings are in the [private routing verification record](../tests/verification/private-sso-routing-20261028.json).

Account binding and sign-in behavior are documented in
[CT400 accounts](CT400-ACCOUNTS.md) and the
[meeting adapter guide](../integrations/meet-host/README.md).

## Certificates and renewal ownership

**The 28-day automatic renewal policy is enabled and live-verified for all
four MX servers, Work/CT400 and its mail/BulkMail consumers, both Canadian
proxy lineages, and the Grange MTA-STS certificate consumer.** The actual
systemd jobs and their enabled, active timers were checked on the relevant
servers. Due certificates were issued and deployed; current MX certificates
that were not yet due passed the same consumer validation without another
order or unnecessary restart.

| Endpoint | Recorded result | Certificate expiry, UTC |
|---|---|---|
| `mx1.the-grange.uk` | Renewed and installed; 28-day automation enabled | 26 January 2027, 18:00:31 |
| `mx2.the-grange.uk` | Renewed and installed; 28-day automation enabled | 26 January 2027, 17:58:57 |
| `mx1.brimstonecottage.uk` Xeams | Valid and not yet due; 28-day automation enabled | 6 January 2027, 14:55:44 |
| `mx2.brimstonecottage.uk` Xeams | Valid and not yet due; 28-day automation enabled | 6 January 2027, 14:32:58 |
| `mx2.brimstonecottage.uk` public HTTPS / CT102 | Renewed and deployed; 28-day automation enabled | 26 January 2027, 19:53:02 |
| `mta-sts.brimstonecottage.uk` / CT102 | Renewed and deployed; 28-day automation enabled | 26 January 2027, 19:56:40 |
| `mta-sts.the-grange.uk` / CT250 | Renewed MX2 public chain deployed; automatic distribution enabled | 26 January 2027, 17:58:57 |
| `work.the-grange.uk` / CT400 | Renewed and deployed to all seven consumers; 28-day automation enabled | 26 January 2027, 20:24:24 |

The [TLS verification record](../tests/verification/mail-sync-tls-20261028.json)
confirms matching trusted certificates on all four private Xeams endpoints per
server: HTTPS 443, SMTP STARTTLS 25, SMTPS 465 and submission STARTTLS 587.
Independent public checks verified all twelve mail endpoints across the four
MX servers. Both renewed Grange certificates retain their original private
keys and DANE SPKI values; MX2 also retains its MTA-STS name. Protected backups
were created. All four actual consumer services completed successfully, their
appropriate primary/secondary timers are enabled and active, and all four
paired-MX health probes passed from their respective containers. The current
published certificates matched during activation, so those checks required no
additional Xeams restart.

### Automatic issuance and deployment

CT280 now performs the automatic four-MX issuance and publication. It uses
existing public CSRs with Cloudflare DNS validation for the Grange hosts and
HTTP validation through the existing proxy challenge routes for Brimstone.
The original MX private keys remain on their respective servers; distribution
carries public certificates only. A daily due check runs at 02:10 UTC with a
one-day look-ahead against the 28-day certificate-age deadline and a safeguard
for shorter certificate lifetimes. A separate hourly check at minute 45 handles
eligible retries with backoff. A deployment retry does not reset the issuance
age or place another order.

The final issuer correction also resumes a recorded interrupted attempt when
its failure counter was not yet incremented. Its guarded live source update
and read-only plan passed, and both issuer timers are enabled and active.
The earlier native certificate reminders remain as fallback; future routine
MX renewal no longer depends on a manual issuance/distribution run.

MX consumers validate certificate trust, names and the existing key binding,
keep protected backups, and verify the actual loaded TLS certificates after
activation. Primary and secondary deployment schedules are staggered, with a
paired-MX health check before an actual restart. The implementation and exact
reviewed deployment changes are recorded in the
[renewal guide](../integrations/certificate-renewal/README.md) and
[deployment delta](../integrations/certificate-renewal/DEPLOYMENT-DELTA.md).

CT250's actual service committed the new Grange MX2 public chain while
preserving its existing private key. Independent checks from Derby verified
the new public TLS certificate and an HTTP 200 MTA-STS policy. Its hourly
consumer timer is enabled and active. The old Germany-host certificate/key
copy timer was backed up, disabled and confirmed inactive after the new path
succeeded.

Both CT102 named lineages completed real certificate orders and guarded
deployment through their systemd services, retaining their existing keys and
SPKI values. Their four daily/retry timers are enabled and active. Only the
two replaced certificate-specific cron entries were backed up and commented.
The independent public TLS checks matched both new certificates; the separate
HTTP content limitation is recorded below.

### Work / CT400 renewal and mail TLS

The actual `grange-local-lineage@communityserver.service` completed a real
certificate order and guarded deployment successfully. The new Work
certificate retains the existing private key/SPKI and expires on
**26 January 2027 at 20:24:24 UTC**. The final read-only check verified all
seven consumers against the new leaf: Work HTTPS 443, BulkMail HTTPS 9443,
mail SMTP 25, SMTPS 465, submission 587, IMAPS 993 and POP3S 995. No deployment
or transaction remained pending. Independent public checks from Canada
verified the new certificate on both HTTPS ports, with Work returning HTTP
302 and BulkMail returning HTTP 200.

Both new daily/retry timers are enabled and active. The daily check runs at
02:20 UTC and the hourly retry at minute 35; the recorded certificate-age
deadline is **25 November 2026 at 20:24:25 UTC**, 28 days after the new
certificate's `notBefore`. Only after the new certificate and all consumer
checks passed were the old BulkMail synchronization timer, CT400 mail
synchronization timer and community-container Certbot timer disabled and
confirmed inactive. Their backup is retained. The earlier staging renewal
dry-run also passed; the live issuance and deployment now provide the final
acceptance evidence.

Dovecot's legacy DH parameters required a scoped repair before the strict mail
TLS checks could pass. The installed configuration, genuine startup template
and public DH parameter file were verified, and IMAPS/POP3S negotiated trusted
TLS 1.2 with **3072-bit DH**. The subsequent certificate deployment actually
restarted the same mail Docker container. A fresh native check after that
restart again verified both ports, the new Work leaf, one active Dovecot master,
regeneration disabled, and the exact installed file bytes, owners and modes.
The repair therefore survived the real certificate-driven restart. Recreating
the container requires the documented guarded enrollment/installation; that
separate operation was not exercised. See the
[Dovecot repair record](../integrations/dovecot-legacy-dh/README.md) and the
[TLS verification record](../tests/verification/mail-sync-tls-20261028.json)
for the exact hashes and protected transaction backup.

### Public management and policy HTTPS

Public management HTTPS follows separate routing. Earlier checks found the
Grange MX public HTTPS connections timed out and the public
`mx1.brimstonecottage.uk` endpoint rejected that SNI name; their private HTTPS
certificates were verified. Management exposure was preserved.

Public `mx2.brimstonecottage.uk` HTTPS terminates at the separate CT102 proxy,
with the newly renewed certificate in the table. Both that host and
`mta-sts.brimstonecottage.uk` passed independent public TLS verification, but
ordinary public HTTP probes returned **403**. Application content and the
Brimstone MTA-STS policy's public availability have therefore **not** been
verified. Direct GETs to the configured Xeams backend also returned 403 for
both the MTA-STS policy on port 80 and the BIMI SVG on port 5272, using their
configured Host headers and paths; neither response included a
`WWW-Authenticate` header. The denial is therefore reproducible at that backend
independently of the new frontend certificate paths. Its root cause and the
time it began have not been established. In contrast, the Grange MTA-STS
endpoint on CT250 passed its public TLS and HTTP 200 policy check. Keep these
content/route results separate from the successful certificate and SMTP checks
when assessing availability.
See `tls.public_management_https` and `tls.public_mail_policy_https` in the
[verification record](../tests/verification/mail-sync-tls-20261028.json).

## Mail sync deployment and completed draft recovery

The reviewed version 3 IMAP synchronization hotfix is deployed. The record reports 52
passing independent regression checks, 37 identical assembly-reference
comparisons, an unchanged core assembly, a healthy restarted IMAP sync service
and no assembly startup errors. The final read-only check verified the deployed
service hash, and the original NLog configuration was restored byte for byte.
**The next normal user send has not yet been observed.** Recreating or upgrading
the ONLYOFFICE Community Server container
requires reviewing/reapplying the compatible correction or verifying an
upstream fix. See the
[mail sync deployment record](../tests/verification/mail-sync-tls-20261028.json).

**Existing draft recovery is complete and the final read-only check passed.**
All 21 eligible Draft/Sent pairs passed fresh strict message-identity and ordered
MIME payload comparison. Each duplicate Draft was moved to
`Recovered sent drafts 2026-10-28`, its Sent original was retained, and normal
application synchronization was verified for that message before proceeding.
The private journal records 21 prepared, 21 move-verified and 21 portal-converged
entries, followed by completion.

| Final message location | Portal | IMAP count |
|---|---:|---:|
| Drafts retained | 10 | 11 |
| Sent retained | 48 | 48 |
| Recovered sent drafts | Import verified for all 21 | 21 |

The additional IMAP draft already existed without a portal row and was
preserved. All 10 previously unverified portal Draft rows were also preserved.
The recovery is reversible: the duplicates remain in the recovery folder.
No messages were resent or permanently deleted, and no SQL-only folder changes
were made. The bounded maintenance completed without errors; its activity
requests stopped and no maintenance process remained. See `draft_recovery` in the
[verification record](../tests/verification/mail-sync-tls-20261028.json).

## Remaining operational checks

- Observe an authorised staff browser already signed into the work portal
  opening BulkMail and the meeting host application, and confirm the mapped
  identity in both applications. Use the deployed fixed diagnostics if either
  request still fails.
- Observe the next normal user send to confirm the deployed mail sync behavior.
- Monitor the enabled 28-day certificate issuance/deployment timers and
  investigate the two CT102 HTTP 403 results reproduced at their Xeams backend
  before claiming that the affected application or MTA-STS policy content is
  publicly available.

The identity activation record also retains **SMS delivery disabled** and
**WhatsApp connection/delivery disabled**. Their service health does not record
enabled delivery. No messaging activation is claimed by this handover.
