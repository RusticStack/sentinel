# External SSO

What an external identity provider would replace in Sentinel, what would have to be true before a deployment may trust one, and what is deliberately out of scope. **Not built**: this is the written design [the backlog](backlog.md) asked for. Its shape follows what already exists — a provider is a sign-in proof and nothing else — because the parts of the system that decide what a person may do are keyed by the person, not by the proof.

## What SSO replaces, and what it must not touch

[GitHub sign-in](github-sign-in.md) keeps three things apart: a **sign-in identity** (proof that a browser controls an account somewhere), a **Sentinel session** (issued only once that identity resolves to an admitted account), and an **application installation token** (repository access for jobs). SSO joins the first category only. It replaces neither the session model, nor admission, nor authorization.

So a provider replaces one sign-in proof, exactly as GitHub's does:

- **It does not replace the local password sign-in.** Bootstrap and `sentinel admin recover` are host-local and take the database file's authority ([local authentication](local-authentication.md)), so an operator is never locked out by an IdP outage or a misconfigured client — that break-glass path already exists and needs nothing built for it. A deployment may still disable password *sign-in* once SSO is configured, and the design says that is a settings decision with a stated consequence: the second factor and step-up then have no local password to fall back on, so `recover` remains the only way back.
- **It does not replace GitHub sign-in**, and it does not make GitHub sign-in redundant. GitHub's proof is also what binds an organization's membership ([GitHub-backed tenants](tenancy.md#github-backed-membership)); an SSO assertion carries no repository access and must never be read as if it did.
- **It does not touch admission.** Whether an authenticated person becomes an account, and with what membership, stays with [registration and admission](admission.md): invitations, approval, and the operator-owned domain auto-join rule. An IdP saying "this is Alice" is a proof of Alice; it is not a decision that Alice belongs anywhere.

## The provider key is already generic

`external_identities` is keyed by `(provider, subject)` — migration 4 — where `provider` is a short lowercase slug (at most 64 bytes of `a-z 0-9 - _`) and `subject` is the immutable provider identifier, never an email, login or display name. GitHub stores `provider = "github"` with the account's numeric id. A second provider is therefore **one more key in the same table**, not a new identity model: `oidc-acme`, `saml-example`. The credentials that would make that real:

- a configuration file beside `github-sign-in.json`, holding the issuer, client id, redirect URI and a client secret read from an operator-owned `0600` file, never from argv, an environment variable or the database ([configuration](configuration.md), [sealed storage](sealed-storage.md));
- a bounded outbound client with the discipline [GitHub sign-in](github-sign-in.md#bounds-and-configuration) already holds to: a ten-second timeout, bounded headers and body, no redirects, transport failures reported by kind and never with the URL, the secret in the body, and its own slot in the API's outbound pool;
- the pending-attempt table reused as it is: `sign_in_states` is already `(state digest, provider, redirect_to, expiry)`, single-use, ten minutes, and the callback requires the browser's own cookie to match the `state` parameter;
- **nothing new in the database for sign-in**, which is the point. A migration is only needed for what the session remembers (below).

## Verifying an assertion

The proof must establish one thing: that a browser controls a subject at a configured issuer, verified by that issuer's signature, and nothing else. For OIDC, an authorization-code flow with PKCE and a `nonce`, the ID token's signature checked against the issuer's JWKS with a pinned algorithm allowlist, and `iss`, `aud`, `exp`, `iat` and `nonce` all checked; the subject is `sub` scoped by `iss`. For SAML, a signed response *and* a signed assertion, with the XML signature wrapping attacks refused by validating the assertion the code actually reads rather than the first one in the document, and the digest algorithm pinned per provider.

**The issuer is part of the identity.** `provider` being a configured string is what makes `iss` implicit today, and that is only sound while one provider key names one issuer. An issuer that serves several directories can mint the same textual `sub` for different people, and only the issuer — plus the directory id, where the issuer exposes one — makes it unique. So the stored subject is issuer-scoped: `iss` plus `sub`, and the tenant/directory id when there is one, before a second directory is allowed to use the same provider key. Getting this wrong is an account takeover between two organizations that happen to use the same IdP, so it is a hard requirement, not a note.

A JWKS that cannot be read, a signature that does not verify, a key id the provider no longer publishes, and a clock inside the token's validity window are all **refusals**. Nothing falls back to a weaker check: an unreachable key set refuses sign-ins until it is readable again.

## An identity moving between providers

Memberships, grants, credentials and sessions all hang on `user_id`, and identities hang on `(provider, subject)`. That split is what makes a move survivable: the person keeps one account, and the provider changes underneath it.

- **A link is explicit.** `auth::link_verified_identity` is reached two ways: a person who already holds a session proving a second provider (the linking flow, whose intent is the authenticated session itself), and the creation of a brand-new account from a verified proof, which happens only for an applicant that already holds an invitation or an approval. It refuses a rejected account, and the database refuses to move a link between users (a trigger makes `external_identities` immutable). So "Alice signs in with GitHub, then adds her company's IdP" is: sign in one way, prove the other, link. Nothing about her roles changes, because roles were never attached to the proof.
- **An unlink is explicit and audited**, and unlinking the *derived-membership* provider (GitHub) still ends the memberships it derived, in the same transaction, exactly as today ([tenancy](tenancy.md#github-backed-membership)). An SSO provider derives no membership unless a deployment says so, and then the same rules apply.
- **Two accounts for one person is the failure to avoid**, and it is avoided by never creating a second account from an assertion that matches nobody: the default is `NoAccount`, the same answer GitHub sign-in gives an unlinked identity.

## Admission: what an SSO sign-in may admit

The default is exactly today's GitHub behaviour: **an SSO sign-in admits nobody**. It resolves only through an existing link; an unlinked identity gets one uniform "no active Sentinel account". An account is created by an invitation, by an approved application, or by the operator-owned domain auto-join rule.

That last one is the knob a deployment will want to turn for SSO, and it is deliberately an operator's, not a tenant's: a domain rule admits every *verified* mailbox of that domain and can create an organization administered by the first match, so a tenant-editable version would let any organization administrator claim a mail domain and admit its mailboxes without proof ([admission](admission.md#domain-auto-join)). SSO may extend where "verified" comes from — an assertion whose email the IdP marks verified — but the rule, its source of truth and the authority to change it do not move. A platform administrator is skipped by auto-join today and must stay skipped: an IdP claim must never be the way someone becomes a platform administrator.

## Security properties that must hold

These are the requirements; each one names the mechanism, because a property with no mechanism is a hope.

1. **No account takeover through an unverified email.** An email in an assertion links to, or signs in as, an existing account only when all of these hold: the assertion's signature verified, the provider states the address verified, the deployment's operator-owned rule allows that issuer and domain to match an existing account, and — if the matched account holds a local password or a second factor — that person proves it with a step-up in the same flow, so control of a mailbox alone never takes over an account that has more than a mailbox. Otherwise the address is metadata and the answer is `NoAccount`. Nothing ever matches on `preferred_username`, `name`, or a login: those are renameable, and the uniqueness rule that already governs local identity is that only a *verified* address is an identity, with one account able to verify one address ([admission](admission.md#email-identity-and-email-invitations)).
2. **No silent role elevation.** Platform administration (`PLATFORM_ADMIN`) and host-local authority are never derived from an assertion, a group, or a role claim. Tenant membership from directory groups is opt-in per tenant by an operator, is recorded as an operator-declared mapping (not a tenant setting) with step-up and an audit row, and grants at most the role the mapping names — `reader` unless the operator says otherwise — applied through the ordinary audited membership path, which means it moves the tenant's authorization epoch and cannot bypass the personal-namespace rules. A group that disappears downgrades on the next assertion, and a removal writes the ordinary tombstone so domain auto-join cannot undo it ([tenancy](tenancy.md#membership-and-grant-revocation)).
3. **The IdP is a trusted input, so a compromised IdP is a stated blast radius.** The page states it plainly: whoever administers the configured issuer can sign in as any linked person and, where group mapping is enabled, hand out the memberships the mapping names. That is why mapping is per tenant, opt-in, capped, and why nothing above `TENANT_ADMIN` can be reached through it.
4. **No identity is ever reassigned.** The `(provider, subject)` row is immutable and unique across the deployment; a second person presenting a subject someone else holds is refused, never merged.
5. **A refused assertion spends nothing and reveals nothing.** One uniform answer for unknown, unlinked, suspended and rejected; the pending state is spent at most once and only for its own provider; duplicated query parameters are refused rather than resolved; the destination is a same-site path, so a finished sign-in can never be an open redirect.
6. **Rate bounds, not retries.** The start route is limited per client as GitHub's is, the state table is bounded by its own expiry, and the outbound slot is one per provider kind so a slow IdP cannot make sign-in busy for everyone.

## What happens to existing sessions

**They stay.** Sessions are deployment-wide opaque secrets independent of the proof that minted them ([local authentication](local-authentication.md#sessions)); a person who signed in with a password yesterday keeps a valid session today, and enabling SSO revokes nothing.

What the design adds is provenance and one revocation path, both a schema change with the usual [compatibility](compatibility.md) decision:

- a session would record the provider it was issued under and the assertion's authentication instant, so [step-up](step-up.md) can require a *fresh* assertion for a proof that has one — an SSO session cannot satisfy a step-up with a stale `auth_time`, it redirects the browser through the IdP again;
- **provider-initiated logout** (an OIDC back-channel logout token, or a SAML single-logout message) would revoke that person's live sessions and nothing else: not memberships, not credentials, not grants. It is authenticated by the provider's own signature against the same key set, is idempotent, and a replay revokes nothing that is already gone. Without it, a session lives to its absolute deadline (seven days) whatever the IdP thinks — a stated limit, not an accident.

## What is deliberately not built

- **SCIM or any directory sync.** Accounts, memberships and removals are Sentinel's, created by the paths above. An IdP-driven provisioning protocol is a separate design with its own authority question (which tenant may a directory write to?).
- **IdP-initiated unsolicited assertions.** Only SP-initiated flows, because an unsolicited POST landing on a session is a login-CSRF shape Sentinel otherwise refuses everywhere ([local authentication](local-authentication.md#cookies-and-csrf)).
- **Per-tenant IdP configuration** in the first version: one issuer per deployment, configured by the operator. Multi-tenant issuers are handled by issuer-scoped subjects, not by tenants registering their own IdP — that would make each tenant administrator an authority over who can authenticate into the deployment.
- **Group-to-repository-grant mapping.** Groups may reach memberships at most; explicit repository grants stay a Sentinel decision.

## Constraints from the platform work

- The client secret is sealed or file-loaded like every other credential, and diagnostics echo no configuration; a log line names the provider key only.
- The redirect URI is one exact absolute HTTPS URL registered with the provider and derived from `public_url`, as GitHub's is; an enterprise IdP with an internal CA is a deployment choice already covered by the controller's own trust configuration.
- Audit rows name the provider, never the subject or the address, and a refused sign-in records the same shape as a refused GitHub sign-in.
- The web interface, the OAuth consent page and the device page each offer a configured sign-in method as a plain `GET` link; adding one changes no authorization surface, and an account that exists only through SSO can sign the CLI in through the same consent flow a GitHub-only account uses today ([OAuth](oauth.md)).

## Before implementation

1. **Name the IdP a real deployment uses.** The protocol work (OIDC first, SAML only if a named deployment needs it) follows from that answer, and the test fixtures — a loopback IdP shaped like the real one, as `sentinel_github::fake` is for GitHub — are built from it.
2. **Decide the auto-link rule.** Whether a verified assertion may match an existing account by address is an owner decision with a security trade: it is what makes a provider migration painless, and it is the one place where an IdP's claim becomes an account's identity.
3. **Decide whether directory groups derive membership at all.** If yes, the mapping is an operator-owned table with an audit event and a compatibility entry; if no, the page stays at "sign-in only" and the question of role elevation cannot arise.
4. **Decide what disabling password sign-in costs.** With SSO enforced, `recover` on the host is the only break-glass, and the deployment's second-factor story has to say so.

## What this page does not decide

Which protocol module the first provider needs beyond OIDC; whether an account may hold two SSO identities; whether a deployment may enforce SSO for one tenant and not another (the first version says no, since the issuer is deployment-wide).
