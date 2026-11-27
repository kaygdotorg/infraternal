# Password and infrastructure secrets manager: owner grill

**Job** J1311 · **Issue** [#609](https://git.kayg.org/kayg/infraternal/issues/609) · **Status** Research and design · **Decision owner** kayg

A replacement for 1Password has to fill a login on the owner's iPhone and
give a release job exactly the credential it needs. The phone can decrypt a
local vault after its owner unlocks it. A release job must authenticate and
get its own credential while the owner is offline. Build around those two
cases, with one place to manage access and two separate stores.

## 1. The work it has to do

| Day-to-day task | A replacement works when… |
|---|---|
| Sign in on Mac or iPhone | Safari on both and the owner's other Mac browser can fill a password for the right site. An iPhone app can use system AutoFill. A previously synced device fills offline after local unlock. |
| Use an SSH key | A Mac terminal can ask a local SSH signing service to sign without exporting the private key. An enrolled infraternal host continues to use its existing machine identity. |
| Run a release job | The job receives access scoped to the release it is performing and the time it needs. It never receives the personal vault or all release credentials. |
| Share one login | The owner shares a household login with one person. Both can fill it from their own devices, and an update is visible to both after sync. |
| Start a host service | A backup service can authenticate to its secret store without a person tapping a passkey. Removing that service's access stops issuance and renewals. A dynamic credential expires or is revoked at its issuer. |
| Recover after loss | With both devices gone, the owner can regain account access and decrypt a restored vault using an offline recovery kit. Workload recovery has its own runbook and credentials. |

## 2. What infraternal already gives us

- D151 defines client-held account keys and wraps for devices, supported
  passkeys and recovery. D154 G6 defines rotating group keys when access
  changes. The existing key-wrapping contract and code must be checked before
  reuse, especially device enrollment, cross-user wraps, and the handling of
  old vaults. D375 A2 allows OIDC sign-in. D333 scopes device API keys and
  keeps approval separate. D113 gives recovery from a fresh device a
  24-hour delay. [Decisions](../../DECISIONS.md) · [Key wrapping](../../contracts/keywrap.md)
- D168's deployment CA authenticates machines. Its signing key is available
  to the server when unlocked. D184's release key lives off the server and
  verifies releases via the pinned public key. Vault decryption, workload
  issuance and release signing need independent keys and recovery paths.
  [Decisions](../../DECISIONS.md) · [Remote infraternal agent contract](../../contracts/remote.md)
- D7 and D15 give the server and infraternal agent one static Rust binary
  with first-party plugins. D252's app roles, mesh access and host login
  access each have their own scope. Add explicit access to a vault or a
  workload secret instead of inheriting it from a host tag. D31, D277 and
  D334 put account invites and multi-user administration in the separate
  commercial repository. Household sharing needs an edition decision.
  [Decisions](../../DECISIONS.md) · [Architecture](../ARCHITECTURE.md)

---

## Q1. Which foundation should we prove?

**Recommendation.** Use the existing client-held account-key model for a
personal vault with item-level ciphertext sync. Use KDBX 4 as a portability
format and an early personal baseline. Connect separately deployed OpenBao
over its HTTP API for workload secrets. This gives the personal vault its
own trust boundary and avoids building a credential issuer.

| Option | What it offers | Cost and fit |
|---|---|---|
| **Client-encrypted personal records plus external OpenBao (recommended)** | Storage in the existing infraternal server, conflict checks per item, and a mature workload engine with path-scoped access. | New personal clients, sync, and a narrow connector. Operators who enable workload secrets own a second service, its seal, upgrades, audit, and restore. |
| KDBX 4 as the live personal store plus external OpenBao | KeePassXC on Mac and KeePassium on iPhone offer an existing route to personal autofill. Backups and handoff use a single file. | Sync and unlock cost scale with file size. Clients have to cope with simultaneous saves and divergent copies. Sharing needs a separate database per group with distinct unlock material. |
| OpenBao for both | One administrative service, versioned KV, fine-grained path ACLs, audit and issuer-backed leases. | The unsealed server processes plaintext for ordinary KV. Client-encrypting KV would still require building personal key distribution, search, sync, and autofill. |
| Native server for both, including workload issuance | One binary and direct control of every runtime dependency. | Own the seal, bootstrap, leasing, upstream connectors, revocation and recovery. Start this work only if the external operating cost proves unacceptable and the owner approves the larger scope. |
| SOPS + age-encrypted files for workloads | Small option for static Git-managed configuration. Access follows the recipients of the file key. | Each host receives a key and encrypted files. Changes and removals require distributing new files and changing exposed values. Issuance, lease renewal and audited reads would need a service. |

**Upstream facts and licenses.**

- OpenBao is a standalone Go service under MPL-2.0. Its encrypted storage
  barrier protects data at rest. Its path ACLs control which requests can run.
  KV v2 versions static values and the database engine can issue credentials
  with a lease. Transit can supply a cryptographic operation to a client.
  OpenBao's service boundary stays separate from the AGPL binary. Review
  the license and notices of any client dependency separately.
  [License](https://github.com/openbao/openbao/blob/main/LICENSE) · [Architecture](https://openbao.org/docs/internals/architecture/) · [Policies](https://openbao.org/docs/concepts/policies/) · [KV v2](https://openbao.org/docs/secrets/kv/kv-v2/) · [Database engine](https://openbao.org/docs/secrets/databases/) · [Transit](https://openbao.org/docs/secrets/transit/)
- KDBX 4.1 is a published encrypted and authenticated file format. A composite
  unlock secret can include a passphrase and key file. Its KDF parameters
  travel with the file, with Argon2id among the available choices. KeePass
  2.x is GPL-2.0-or-later. An independent
  implementation can use the specification. The MIT-licensed Rust
  `keepass-rs` parser is one candidate and labels writing experimental.
  Test interoperability, limits and error handling before choosing a library.
  KeePassXC supports a shared file workflow, including KeeShare groups,
  and individual client capabilities vary.
  [Format](https://keepass.info/help/kb/kdbx.html) · [KeePass license](https://keepass.info/help/v2/license.html) · [KeePass multi-user workflow](https://keepass.info/help/base/multiuser.html) · [KeePassXC guide](https://keepassxc.org/docs/KeePassXC_UserGuide) · [Rust candidate](https://github.com/sseemayer/keepass-rs)
- Bitwarden's official server has AGPL-3.0 and separately licensed commercial
  modules. Vaultwarden is an independent AGPL-3.0 Rust implementation of
  the Bitwarden client API. Both illustrate client-encrypted record sync
  with existing autofill clients. Maintaining compatibility would tie our
  protocol, identity flow and releases to those clients. Use both as design
  references. [Official license](https://github.com/bitwarden/server/blob/main/LICENSE.txt) · [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
- SOPS is MPL-2.0 and supports tools such as age or KMS to wrap data keys for
  encrypted config files. It is a useful comparison if host provisioning
  mostly reads static config from Git.
  [SOPS documentation](https://getsops.io/docs/) · [SOPS usage](https://github.com/getsops/sops)

## Q2. What runs where, and how do jobs and hosts get access?

**Recommendation.** Keep ciphertext sync in the server plugin and run
OpenBao on a selected infrastructure node as a separate service. Use the
existing infraternal agent for node management. A future “Run secrets here”
node capability can describe or supervise that service after a manual pilot
proves the install and restore path. Node placement and permission to read
secrets are independent.

| Option | Cost and consequence |
|---|---|
| **Explicit OpenBao endpoint and direct workload access (recommended)** | Deploy, seal, back up and upgrade a service. A workload reaches OpenBao over the mesh or an explicit TLS endpoint. Our server can manage references and show status without proxying secret values or holding a root token. |
| OpenBao supervised by the infraternal agent | One installation workflow for the owner. Adds upgrade verification, resource isolation, port ownership, seal handling and two independently restorable state stores. |
| Infraternal server brokers every secret read | Convenient for isolated networks. Makes the server a privileged deputy with access to values or issuing credentials, and couples workload startup to its availability. |

- **Release job.** Use a dedicated, scoped job identity, with workload OIDC
  where available or a narrowly scoped short-lived bootstrap credential.
  Bind identity to the repo, workflow and environment the issuer attests.
  The job may need a static upstream API token. In that case put a
  purpose-made token in its own KV path. Expiring the OpenBao login stops
  new reads. The upstream token stays valid until its issuer expires or
  rotates it. Deliver the value to the consuming process through a scoped
  helper, inherited file descriptor or restricted file, without logging it
  or sending it to AI chat, MCP output, shell history or argv.
  [OpenBao JWT/OIDC auth](https://openbao.org/docs/auth/jwt/) · [1Password service accounts](https://www.1password.dev/service-accounts)
- **Backup service.** Let a particular service on a particular host obtain
  its own workload identity. If OpenBao cert auth is used, validate a
  dedicated workload certificate or issuer and match explicit identities.
  Trust in the deployment CA alone would admit too many certificates.
  The host's infra identity can prove enrollment as part of bootstrap.
  Keep the CA's signing key in its existing role. OpenBao tokens also need
  a revocation path separate from the certificate that obtained them.
  [Certificate auth](https://openbao.org/docs/auth/cert/) · [Lease lifecycle](https://openbao.org/docs/concepts/lease/)
- **Database example.** Give the backup service its own narrowly privileged
  PostgreSQL account with a proposed 30-minute lease. Authenticate, request
  a credential, renew only as needed and shut down cleanly if it expires.
  Verify revoke and expiry against the database, including established
  sessions. For a restore, keep OpenBao snapshots and seal recovery material
  independently accessible. Test cold start when the CA or OpenBao is
  sealed, and ensure neither service needs a secret from the other to boot.
  [Database engine](https://openbao.org/docs/secrets/databases/) · [Seal architecture](https://openbao.org/docs/internals/architecture/) · [Raft operations](https://openbao.org/docs/commands/operator/raft/)

Record who requested which opaque secret or lease reference, when, and
whether it succeeded. Review audit settings and error paths for leakage.
Audit issuance and server actions. Offline password fills happen on the
device and do not create server evidence of use.
[OpenBao audit devices](https://openbao.org/docs/audit/)

## Q3. How should two people share a login?

**Recommendation.** Make “share this login with one person” create or use an
explicit shared vault. A vault can contain one item. Give each verified
member a wrap of the vault key and keep one current live item. Ask kayg
which edition hosts the second account before implementation. Under current
D277/D334, hosted invites and multi-user management go in the commercial
repo and the core operates independently.

| Option | Cost and consequence |
|---|---|
| **Shared vault key (recommended)** | One member wrap per vault. Use separate vaults for different readership. A new member can read all items in that vault. Membership changes require a new vault key and client-managed rotation. |
| Item key wrapped to each recipient's public key | Precise per-item access. Each item needs one wrap per recipient, plus key verification and rekeying of affected items. Useful if many items have different recipients. |
| Separate KDBX file shared through file sync | Works with compatible clients today. Both people need the file and its unlock material. They can keep old copies. An ACL change only affects further sync. Concurrent file saves depend on client and sync behavior. |
| Expiring recipient link | Good for a one-off handoff. Distribute an encrypted snapshot and its key in a link, with expiry and optional recipient verification on retrieval. Copies already retrieved remain usable and edits do not flow through. |

For 1,000 items with the same two members, a vault key needs two member wraps.
Per-item sharing needs 2,000 recipient wraps. That count excludes any keys
used inside the records. With a shared vault, removing one member still
requires re-encrypting up to 1,000 items before publishing the new epoch.

In the household example, the owner moves the streaming login to
“Household” and approves its member. The client verifies that person's key
via an authenticated pairing or an independent fingerprint check before
creating the first wrap. Pin the binding on both devices and require
confirmation for an unexpected key change. A key returned only by the sync
server would let that server substitute itself as the recipient. Bind item
identity, vault, version and key epoch into authenticated records. A
read-only member who holds a vault key can create ciphertext locally.
Server access checks enforce ordinary edits, and clients need authenticated
writer and membership records if they also distrust the server for integrity.

1Password documents user or group access to shared vault keys and a
separate encrypted snapshot link. Bitwarden's organization model wraps a
shared symmetric key for approved members. Bitwarden collections organize
access within that model. Neither reference implies retracting a password
after someone has read it.
[1Password security design](https://1password.com/files/1Password-White-Paper.pdf) · [1Password link sharing](https://support.1password.com/share-items-security/) · [Bitwarden whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)

## Q4. What does removing a person or a device revoke?

**Recommendation.** Cut online access immediately, then rotate the shared
vault key on an authorized device, and guide the owner through changing the
actual credentials at their issuers.

| Option | Cost and consequence |
|---|---|
| **Online cutoff plus key and credential rotation (recommended)** | More work when someone leaves. Future encrypted data can exclude the old key, and the upstream service can stop accepting the copied password or key. |
| Online cutoff alone | Simple, but a cached copy and any password already seen still work. |
| Change the upstream password only | Stops the old password when the issuer enforces it. Anyone retaining the vault key may still be able to read new data from a later leak. |

1. Revoke the person's membership and affected sessions at once. If no
   remaining authorized device is online, pause shared writes until a
   remaining member can perform the rekey.
2. Commit a new vault epoch with fresh key material, ciphertext and wraps
   for remaining members. Any per-item key previously available to the
   removed member must also change before encrypting new values with it.
   Retrying a failed rotation must keep access consistent. Reject stale
   writes from offline clients and check for rollback on sync and restore.
3. Treat anything previously readable as copied. Change the login
   password at the site and handle its active sessions and recovery codes.
   For a shared TOTP seed, re-enroll the factor. For an SSH key, remove the
   old public key at the target. A lost device that could read a vault may
   require the same steps after session and device wrap removal.

KDBX uses the same conceptual cutoff at file granularity. Remove sync
access, distribute a newly encrypted file under independent unlock material,
then rotate the real credentials. Past backups and snapshots remain
decryptable to anyone with the old unlock material.

## Q5. Who can unlock a personal vault? What survives device loss?

**Recommendation.** The personal sync server stores ciphertext and wrappers
only. Use separately installed, signed clients to decrypt personal data.
Use D151 account wraps, supported WebAuthn PRF and an offline recovery wrap
after checking the existing contract against the new use. Keep the sign-in
passkey in an independent provider or security key, with a recovery route
that works when this vault is unavailable.

| Option | Cost and consequence |
|---|---|
| **Client-only unlock with offline recovery (recommended)** | A supported passkey or enrolled device makes daily unlock easy. The owner must keep offline recovery material and a restorable vault backup. Losing both makes data recovery impossible. |
| Server-delivered web client unlocks the vault | Easy access from a new browser. A server compromise or malicious operator can change the code served at unlock and collect plaintext. D184 signs releases and does not authenticate each response from a compromised running server. |
| Explicit recovery escrow or an offline trusted person | Covers more loss cases. A decrypting escrow key widens who can obtain vault data. Escrow is a separate owner decision under D151 and D277; the personal baseline needs only the offline kit. |

- **Sign-in and decryption.** Passkeys prove who is signing in. Where PRF is
  supported the client can also derive a wrapping key, with release and
  workload key purposes kept separate. An enrolled device has its own wrap,
  unlocked locally. A fresh OIDC login needs approval from an existing
  device or recovery material to decrypt. Passkeys the vault might
  eventually store for other sites are a separate feature.
  [WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension) · [Key wrapping](../../contracts/keywrap.md)
- **Server boundary.** Encrypt titles, URLs, usernames, notes and attachments
  on the client and search on device. The sync service still observes
  account and membership IDs, ciphertext sizes, timing and item counts.
  It can withhold records. Authenticated records and pinned versions help
  clients detect substitution and rollback. A clean install needs a
  checkpoint from a trusted device or a verified backup record to tell a
  valid older snapshot from the latest one. An authorized device, malicious extension
  update or filled site can see the credentials it receives. OpenBao
  processes its own workload plaintext as described in Q1.
- **Recovery drill.** Restore ciphertext, membership state and envelopes
  from backup on a new server. With both Mac and iPhone gone, use the
  24-word kit offline for decryption and complete D113 account recovery
  from the replacement device. The account delay controls online takeover.
  Someone holding both the recovery words and a corresponding ciphertext
  backup can decrypt offline immediately. Enroll replacement devices,
  revoke old sessions and wraps, and test recovering a shared vault with a
  remaining member. Keep the kit and vault backup in separate locations.
  Store bootstrap access for backup storage outside the systems they
  restore. Record the newest version the restore is expected to contain.

## Q6. Which autofill clients make this a daily replacement?

**Recommendation.** Prove Mac Safari and the owner's other Mac browser,
plus iPhone system AutoFill, before migrating the personal vault. Use
KeePassXC and KeePassium as a baseline. Start with passwords and explicit
fill. Add third-party passkey storage, save prompts and wider browser
support after the core flows work.

| Option | Cost and consequence |
|---|---|
| **Mac browser extensions plus iOS Credential Provider (recommended)** | Requires independent signing and release channels, local unlock, encrypted cache, and a real-device extension proof. The iPhone extension fills Safari and supported apps via system AutoFill. |
| Existing KeePass clients with a synced KDBX file | Immediately relevant baseline across Mac and iPhone. Browser setup, file conflicts and shared unlock material remain user-visible. |
| PWA only or iPhone Safari extension only | PWA handles editing or copy/paste. An iPhone Safari extension can fill web pages, while system-wide app AutoFill requires the native Credential Provider entitlement. |

On Mac, use a Safari Web Extension packaged with an app and a Chromium
Manifest V3 extension if Chromium is the owner's second browser. Start with
an explicit gesture and minimal host permissions. Do the matching and
decryption in a trusted local context. Give a content script one selected
credential for the observed origin and frame, and recheck both after
navigation. Refuse cross-origin iframes by default. A local signing helper
for Mac SSH can serve a restricted `SSH_AUTH_SOCK` and ask for confirmation
where required. Test that a locked vault refuses signing and plan any SSH
forwarding separately.
[Safari extensions](https://developer.apple.com/safari/extensions/) · [Chrome activeTab](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab/) · [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging/) · [KeePassXC guide](https://keepassxc.org/docs/KeePassXC_UserGuide)

On iPhone, the containing app and extension need the AutoFill entitlement.
Keep encrypted data in shared app storage and protect its unwrap with the
device's key storage and user presence as required. If using Apple's
identity suggestion store, account for which label and site metadata the OS
retains. Fill from cache even when the extension is launched cold and the
mesh is unreachable. Prove biometric fallback, offline behavior, memory
pressure, and the signed build on a real device. The official APIs establish
feasibility. Extension budgets and distribution remain to be verified.
[Apple Credential Provider](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller) · [KeePassium AutoFill](https://support.keepassium.com/kb/autofill-setup-ios/)

## Q7. How do we migrate from 1Password?

**Recommendation.** Import a desktop 1PUX locally for personal data,
transfer passkeys through Apple Credential Exchange after proving support,
and reissue infrastructure credentials individually.

| Option | Cost and consequence |
|---|---|
| **Local 1PUX import plus passkey and workload cutovers (recommended)** | Richer import of fields and attachments. Needs a hardened archive parser and a typed migration report. Workload access is rebuilt deliberately by service. |
| CSV import | Smaller parser and quicker login-only pilot. Loses richer item types, custom fields and attachments. Passkeys need another route. |
| Convert via KeePassXC first | Gives an early KDBX baseline with an existing importer. Round-trip tests must show which fields and items survive two format conversions. |

1. First use a synthetic archive. Map login URLs and usernames, TOTP seeds,
   notes, SSH key fields, custom fields and attachments when present.
   Report counts by type, unsupported items, conflicts and failed mappings.
   Bound archive and attachment processing, reject path traversal, make a
   repeated import safe, and keep diagnostic output free of secret values.
2. On the Mac export 1PUX to local encrypted storage outside synced folders
   and backups. Import locally and upload only encrypted vault records.
   Delete the archive after verifying a restore and representative logins.
   Recreate collaborators explicitly after reviewing the imported private
   vault. Export structure is insufficient to recreate live permissions.
3. Desktop exports omit passkeys. 1Password on iOS 26+ exports through
   Credential Exchange to supported receivers, including supported passkeys.
   Test one passkey end to end with the receiving extension. Until that
   succeeds, use the existing provider to sign in and register a replacement
   at each site, then confirm the replacement before retiring the old one.
4. Move one job and one host at a time. Issue new scoped identities and
   secrets, run them while both paths can be recovered, and revoke old
   service credentials after confirming each cutover. Keep the issuer's
   read, write and rotation rights scoped to that workload.

[1Password export](https://support.1password.com/export/) · [1PUX format](https://support.1password.com/1pux-format/) · [Apple Credential Import](https://developer.apple.com/documentation/AuthenticationServices/ASCredentialImportManager) · [KeePassXC import](https://keepassxc.org/docs/KeePassXC_UserGuide)

---

## Decisions for the owner

| # | Question | Recommendation |
|---|---|---|
| Q1 | Foundation | Client-encrypted records for daily use, KDBX for portability and baseline, separate OpenBao for workloads. |
| Q2 | Node role and workload access | Start with an external TLS endpoint and distinct host/service/job identities. Consider node supervision after a restore drill. |
| Q3 | Sharing and edition | Shared vault including a one-item case. Keep managed invites in commercial code under the current decision. Decide whether to extend Community to one household recipient. |
| Q4 | Removal | Online cutoff, client-side vault key rotation, then rotate upstream credentials that could have been copied. |
| Q5 | Trust and recovery | Independently signed decrypting clients, offline recovery kit, no default escrow. Decide if web vault unlock is worth trusting server-delivered code. |
| Q6 | Daily client scope | Safari on Mac, confirm the second Mac browser, iPhone system Password AutoFill. Measure offline fill and local SSH signing before cutover. |
| Q7 | Import and retirement | Local 1PUX first, prove passkey transfer or re-register, reissue job and host tokens per workload. |

### Evidence to collect before choosing a foundation

- **Personal path.** Compare a real-device KDBX baseline with a thin
  ciphertext-record sync proof. Use the same synthetic 1,000-item vault,
  one attachment, and two devices. Report p50/p95 unlock-to-fill cold and
  warm, peak and idle RSS per client, sync bytes for one edit, and the
  outcome of conflicting offline edits. Exercise initial key verification,
  removal while a member is offline, and recovery from a restored backup.
- **Workload path.** Use one static release-token fixture and one dynamic
  PostgreSQL consumer. Measure authenticated fetch p50/p95 and idle RSS
  per OpenBao node, plus memory per active workload × the intended job
  count. Time lease issuance, renewal, issuer revocation, cold unseal and
  restore. Report idle load next to infraternal's own server and verify
  that neither audit nor caller output contains the fixture value.
- **Migration path.** Compare pre/post import counts for each fixture type,
  one attachment hash, one Credential Exchange passkey sign-in on a real
  iPhone, and the job and host cutovers above. Keep platform assumptions in
  the report until each case runs.

These are proposed test inputs and measurements. J1311 reports a design
and upstream evidence. Benchmarks and platform prototypes come after the
owner decides which paths to prove.
