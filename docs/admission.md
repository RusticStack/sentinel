# Registration and admission (A05)

Implemented in `sentinel-store::registration` and `sentinel admin policy|invite|account`, with append-only metadata migration **8**. Verified email identity, email invitations and the mail outbox ([below](#email-identity-and-email-invitations)) are `sentinel-store::email`, the `sentinel-mail` crate and migration **50**.

Four decisions are kept apart, because conflating them is how a CI system ends up granting compute to whoever clicked "install":

| Decision | Who makes it |
|---|---|
| An account exists | The deployment's registration policy, plus an invitation if one is required |
| The account is admitted | An invitation, or a platform admin approving a pending application |
| A namespace exists | A super admin, or — under policy — an approved account creating its own personal namespace |
| A forge installation belongs to a tenant | A platform admin, or — under policy — an admin of *that* tenant |

Authenticating is none of them. [Local login](local-authentication.md) and [GitHub sign-in](github-sign-in.md) establish who you are; this document is about whether that gets you anything.

## Registration policy

One row, super-admin controlled, audited, read inside the transaction that decides an application — so a policy change that commits while an application is in flight is the one that applies.

- **`invite-only`** (the default): an unspent, unexpired invitation is required. The invitation *is* the approval, so the account is active immediately.
- **`approval-required`**: anyone may apply. Without an invitation the account is created **pending** and waits for a decision.
- **`closed`**: no new accounts, invitation or not. Outstanding invitations do not survive closing — closed means closed, and they expire on their own. Everybody already admitted keeps signing in normally: closing registration is not a lockout of the people you already have.

Two further settings: `tenant_creation` (`super-admin-only` by default, or `approved-users`) and `installation_binding` (`tenant-admins` by default, or `super-admin-only`).

```sh
sentinel admin policy show --data-dir <PATH>
sentinel admin policy set --data-dir <PATH> --registration approval-required
```

## Pending, approved, rejected

`users.status` is pending (0), approved (1) or rejected (2), and a database trigger enforces that only an approved account can be `active`. That matters more than it sounds: `active` is the predicate every authorization query in [authorization](authorization.md) already joins on, so a pending account holds no session, no tenant data and no worker access **by construction**, not because each query remembered to ask.

A pending account may *hold* the credential it registered with — otherwise approving it would leave it with no way to sign in — but holding is not using: every authentication path still requires an active account. A rejected account keeps its username and identity claimed, so a rejected applicant cannot simply reapply, and its sessions, API credentials and OAuth grants are revoked in the same transaction as the rejection. Rejection is permanent — a rejected account can be neither approved nor reactivated — so rejecting an account that was already **approved** requires a recent [step-up](step-up.md), exactly like suspending it with `set_active`; refusing a pending application needs platform administration only.

```sh
sentinel admin account pending --data-dir <PATH>
sentinel admin account approve --data-dir <PATH> --user alice
sentinel admin account reject  --data-dir <PATH> --user alice
```

## Invitations

A 256-bit secret stored only as its digest, presented exactly once and delivered out of band — there is no mandatory mail server, and no way to show the link again. An invitation may bind, all optional:

- **A tenant and a role**, granted as membership on acceptance. Both or neither.
- **A verified identity** (`provider:subject`), so only the person holding that GitHub account can redeem it. A local applicant cannot redeem an identity-bound invitation, and neither can a different GitHub account.
- **A mailbox** (an email address), so the invitation is for one person and is redeemed only once that mailbox is verified: see [email invitations](#email-invitations).
- **An expiry**, 1 second to 30 days, 7 by default. There is no open-ended invitation.

Redemption is one-use and happens in the same transaction as the account it creates, so a lost race creates nothing. The terms are immutable, and a spent or revoked invitation never becomes unspent. A platform admin may invite to any tenant or to none; a tenant admin may invite only into the tenant they administer, and cannot mint a deployment-wide invitation.

An invitation delegates its creator's authority, so it is only as good as that authority is **at redemption**. The redeeming statement re-checks the creator in the same transaction: still an active account, and still a super admin or still an admin of the tenant the invitation grants membership of. Removing the creator's membership, suspending or rejecting the account, downgrading their role or demoting a super admin therefore voids every unspent invitation they minted — without any bookkeeping, and before anything is written — and the applicant sees the ordinary "invitation unusable" refusal. (Restoring the authority restores the invitation, if it has not expired.) Host-local invitations have no creator and carry the database file's authority.

```sh
sentinel admin invite create --data-dir <PATH> --tenant acme --role operator --expires-in 7d > invite
sentinel admin invite list --data-dir <PATH>
sentinel admin invite revoke --data-dir <PATH> --id inv_...
```

The secret is the only thing on stdout, as with [API credentials](api-credentials.md); the identifier and expiry go to stderr.

## Email identity and email invitations

An account may hold **one email address**. Holding is not proving: the address is a claim until a single-use token delivered to that mailbox is presented, and only a *verified* address does anything — it signs in, it matches an email-bound invitation, and it excludes every other account from verifying the same address. Migration **50** adds `users.email` and `users.email_verified_ms`, `email_verifications`, `mail_outbox` and `mail_settings`, and an `email` term on invitations.

**Addresses.** `sentinel-store::email::normalize` is the one place an address is compared: the local part is ASCII and lower-cased (1–64 bytes of RFC 5322 `atext` and dots, no leading, trailing or doubled dot), the domain is lower-cased and converted to punycode with UTS 46 under the STD3 rules (two or more labels, none empty or over 63 bytes, no hyphen at a label's edge, a last label that is not all digits, so `a@localhost`, `a@127.0.0.1` and `a@[::1]` are refused), and the whole is at most 254 bytes. An address that needs SMTPUTF8 in its local part is refused rather than mangled. `normalize_domain` is the same rule for a bare domain, so a deployment's allowed domains and an address's domain are one comparison: exact, never by suffix, never by subdomain. No error echoes the input.

**Uniqueness is among verified addresses.** A plain `UNIQUE` on a claimed address would let anyone claim a victim's address first and lock the owner out of registering it. So the unique index covers verified addresses only: several accounts may *claim* an address, the first to prove it owns it, and that proof clears the other accounts' claim (their pending links then refuse). A claim never signs in and never blocks anyone.

**Sign-up.** `POST /api/v1/register` (see [API](api.md)) creates an account by address and password when the [registration policy](#registration-policy) allows it: under `invite-only` an invitation is required, under `approval-required` the account waits as pending, under `closed` nothing is created. The account also gets a generated username (`user-` and twelve hex digits) so every local account has one; the address is its login identifier once verified. The answer is the same `202` for a new address, an address another account already verified and one that is merely claimed: whether an address has an account is not something the API tells. Policy refusals (`403`: closed, invitation needed, invitation unusable) say nothing about the address. Both paths pay the same password hash before the transaction, so timing does not tell them apart beyond the writer's small difference. Self-service sign-up draws on its own per-client admission budget (burst 5, one more per 20 s, 2 per second across clients) before anything is read or hashed.

**Sign-in.** `POST /api/v1/login` and `local_auth::login` take either a username or an address (an identifier with an `@` is an address; no username can hold one). An address signs in only when verified, an unknown or unverified one costs the same work as a wrong password, a rejected attempt never records the address, and the per-client guard keys on the canonical form so spelling variants are one account. Existing username accounts keep working unchanged and can add an address with `POST /api/v1/me/email`.

**Verification.** A token is 256 random bits stored only as its digest, valid for 24 hours, single-use, and tied to the address it was minted for. Minting a new one voids the account's earlier unused ones. `POST /api/v1/email/verify {token}` spends it: the address becomes the account's verified address (`EmailVerified` audit row) in the same transaction, and an unknown, spent, expired, voided or "verified elsewhere first" token is one `invalid_request`. A presented token is spent either way. Changing the address (`POST /me/email` again) **does not transfer trust**: the old verified address stays the account's identity until the new one is proved, and the new one does not sign in before. A resend (`POST /me/email/resend`, or `POST /email/resend {email}` for the "I never got it" form, always `202`) is limited to **5 links per account per hour** (the account is told with `429`; the unauthenticated form never is) and to **5 messages per recipient per hour** across every account and invitation, so the deployment cannot be used to bury a mailbox; the mail routes also draw on a per-client budget (burst 8, one more per 15 s).

**Delivery is a durable outbox, never inline.** The transaction that mints a token also writes the message to `mail_outbox` (at most 2,000 undelivered at once), and the `sentinel-mail` lane drains it on the single-writer pattern the [checks](checks.md) outbox uses: read a due batch, send with no store transaction open, write the outcome back, sleep on the commit notifier and the earliest retry. A transient failure (relay down, slow, misconfigured; an `AUTH` or `STARTTLS` refusal) is retried with backoff doubling from 30 s to 15 min, at most 8 attempts and never past the message's own expiry, and pauses the pass so a dead relay costs one connection per pause; a refusal of the message itself (`MAIL`/`RCPT`/`DATA` `5xx`) is recorded and not retried. A message that cannot be sent or opened is given up with an audit row (`mail-abandoned`, kind and reason, never the address). Because the message carries a one-time link, its **body is sealed with `master.key`** and **deleted the moment the row settles**: the link exists readable only between minting and handing over to the relay. A body sealed under a key later retired cannot be opened and is given up (a rotation window of a day at most). Tokens are digest-stored; only this short-lived queued body holds a readable link, and only when SMTP is configured and the master key exists.

**Without SMTP nobody is locked out.** Configure delivery in [`[mail]` or `SENTINEL_SMTP_*`](configuration.md#email-delivery); without it (or without a master key) nothing is queued and the verification and invitation links are minted by the host-local CLI, which prints them on stdout once and never logs them:

```sh
sentinel admin account email-link --data-dir <PATH> --user alice@example.com > link   # a fresh verification link
sentinel admin account email-link --data-dir <PATH> --user alice --email alice@example.com
sentinel admin account email-verify --data-dir <PATH> --user alice                       # the operator vouches for it
sentinel admin invite create --data-dir <PATH> --tenant acme --role reader --email bob@example.com
sentinel admin mail status --data-dir <PATH>                                              # delivery on/off, outbox counts
```

`--user` accepts a username, a `usr_` identifier or an address. `email-link` voids the account's earlier links and is audited as host-local. The controller records at every start whether it delivers mail (`mail_settings`), so a request queues a message only when a lane will drain it; the response tells the person which to expect (`"verification": "email"` or `"operator"`).

### Email invitations

`sentinel admin invite create --email` and `POST /api/v1/tenants/{slug}/invitations {email, role?, expires_in_secs?}` let an organization administrator invite a person by address to an **app-created** organization:

- The role is the invitation's term (default `reader`, the lowest) and the inviter must already administer the organization, checked live like every invitation; the creator's authority is re-checked at redemption, so removing, demoting or suspending the inviter voids their unspent invitations.
- A **GitHub-backed organization is refused** (`400`: its members come from GitHub): an organization is GitHub-backed when a GitHub App installation is bound to its tenant. The refusal holds at creation and again at redemption, whoever the inviter is, platform administrators included. A link-form invitation without an address is unchanged by this.
- An organization may create 50 email invitations per hour.
- With mail delivery the message is queued (`"delivery": "email"`) and no secret is shown; without it the response carries the one-time `token` for the inviter to pass on (`"delivery": "link"`). An administrator lists them (`GET`, never a secret) and revokes one of their own tenant's (`DELETE`; another tenant's is `not_found`).

Accepting needs the **mailbox proved**, in one of two ways, and never grants anything before it is:

1. **Verified address matching the invitation.** A signed-in account whose verified address is the invited one presents the secret (`POST /api/v1/invitations/accept {token}`) and joins at once.
2. **The link token plus verifying.** Anyone presenting the secret with that address — registering with it (`POST /register {…, invitation}`), or an existing account without a verified address accepting — gets the address as a claim and a verification link; the invitation rides on that link's token and is redeemed, with its membership, only when that token verifies exactly that address. A new account registered this way waits as **pending** (no session, no membership) until that proof, which is its admission, so a leaked link alone yields no active account; if the invitation is revoked or expires meanwhile the proof verifies the address and admits nothing. An applicant who proves a different address, or none (a GitHub or username applicant), is refused; an account holding a *different* verified address must change it first.

Redemption is one-use and race-safe: the invitation is spent in the same transaction that verifies the address and writes the membership, and an existing membership keeps its role. A link-form invitation (no address) is accepted by an existing account with the secret alone and still admits a new account at registration. Every step is audited: `invitation-created` (detail `email`), `email-verification-requested`, `email-verified`, `invitation-redeemed`.

The emailed links are `<public_url>/verify-email#token=<secret>` and `<public_url>/invitations/accept#token=<secret>` (the secret in the fragment, so it reaches no server log or `Referer`). The web interface does not yet have pages at those paths; until it does, a client posts the token to the API routes above.

## Who is deciding

Platform administration has two legitimate sources, and the audit trail tells them apart. `Authority::Credential { principal, stepped_up }` is an authenticated caller, checked live, carrying whether its session recently proved a second factor. `Authority::HostLocal` is an operator on the controller's own host, whose authority is the database file itself — the same authority that admits the first administrator. The host-local variant exists so `sentinel admin` does not have to fabricate a `Principal` for somebody who never authenticated, and every host-local decision is recorded as such.

## Installations

Seeing an installation is not trusting it. `record_installation` is trusted intake for webhook handling (G01–G02) and is idempotent, because deliveries repeat; the row it writes is **known, unbound and inactive**, resolving to no tenant. Installing the App on GitHub cannot create a tenant or allocate compute.

`bind_installation` is the decision that makes it usable, and requires administration of *that* tenant (or platform administration) plus the deployment's binding policy. An installation already bound elsewhere must be explicitly unbound first, so a repository's owner never changes underneath running work. Unbinding returns it to the known-but-inactive state rather than deleting it.

## Verification

`crates/sentinel-store/tests/registration.rs` covers the default invite-only policy refusing an uninvited application without creating an account; an invitation admitting exactly once, with replay, unknown and revoked secrets refused; expiry, revocation and lifetime bounds; tenant/role/identity binding, including a local applicant and a different GitHub account both refused; a pending account that cannot log in and cannot be issued a session even by the trusted path; approval making it work and a second approval failing; rejection revoking live sessions, refusing re-registration and resisting a raw `UPDATE` to reactivate; closing registration refusing invited and uninvited applicants alike while local login and GitHub sign-in keep working for existing accounts; policy, approval and rejection requiring platform scope rather than an ordinary session; a tenant admin inviting only into their own tenant; namespace creation refused under the default policy and allowed under `approved-users`, with one personal namespace per account and none for a tenant-scoped credential; installations remaining inactive until bound, idempotent re-delivery, rebinding requiring an unbind, and binding refused for a non-admin of that tenant or under the stricter policy; and audited decisions with bounded purging of spent invitations; an invitation dying with its inviter's membership, suspension, role downgrade and super-admin demotion (while a host-local one keeps working); and rejecting an approved account requiring step-up while a pending one does not.

The `sentinel admin policy|invite|account` surface was exercised end to end on Linux, including every refusal path and the host-local audit marking.

Email identity is covered by `crates/sentinel-store/tests/email_identity.rs` (canonical addresses and any-spelling sign-in; unverified claims not signing in; first-to-verify ownership and a claim blocking nobody; single-use, expiring, voided and digest-only tokens; a change not transferring trust; per-account and per-recipient limits; sealed outbox bodies, delivery, backoff and give-up; email invitations redeemed only on a verified mailbox, refused for a wrong address, a wrong applicant kind, a GitHub-backed organization and an unauthorized inviter; tenant-scoped revocation), `crates/sentinel-api/tests/email.rs` (identical answers for known and unknown addresses, policy refusals independent of the address, foreign `Origin` refused, the verify and resend routes, session and CSRF rules, invitations created, listed, revoked and accepted over HTTP) and `crates/sentinel-mail` (the SMTP client against a scripted relay: envelope and body, dot-stuffing, header injection, reply bounds, the STARTTLS no-downgrade rule, credentials file; the lane against a scripted transport). Their results are pending the verification VPS pass.

See [TODO.md](../TODO.md) for commands and results. Policy changes require a recent [step-up](step-up.md); tenant suspension and role revocation are A07.
