<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Former slugs: keys -->
<!-- Role: the user-facing page "Keys and how long they last" (#302). Published at /docs/reference/keys/. It says what the code does today; where a decision is not built yet, a callout and the table say "planned". Reading aids used here: GitHub-style alerts, a [!WHY] reasoning block, [!FACTS] quick facts (the "?" preview), and [^n] citations (docs-extras.ts). -->
# Keys and how long they last

This page lists the keys, codes and certificates Infraternal uses, when each one expires, and what happens when something is offline.

## The short version

Most of these keys you never see. They renew by themselves while a host is online. The ones you handle yourself are your passkey, your recovery words, and the short codes that sign you in from a command line or add a host.

> [!NOTE] How to read the table
> **Works** means the version you are running does it today. **Planned** means the decision is made and it is not built yet.

### All keys at a glance

| Key | Lasts | Renewed | Today |
|---|---|---|---|
| Browser sign-in | 30 days | The server side slides with use; the browser's copy does not yet | Works, with one gap (see below) |
| Passkey | No expiry | Never | Works |
| Recovery words | No expiry | New words after each use | Works |
| First-owner setup code | 24 hours, one use | A new one at each server start, until an owner exists | Works |
| CLI sign-in code | 10 minutes, one use | Not renewable | Works |
| CLI sign-in API key | 30 days by default; configurable from 1 to 365 days | Renewed silently when used | Issued and stored; no CLI command uses it yet |
| Host join token | 15 minutes, one use | Not renewable | Works |
| `up` join code | 10 minutes, one use | Not renewable | Planned |
| Host certificate | 7 days | At half-life, 3.5 days | Works. Renewal after expiry is planned |
| Machine CA root | 10 years | Rollover is planned | Works. Expiry warnings are planned |
| WireGuard session keys | About 2 minutes | By WireGuard itself | Works |
| WireGuard static key | 7 days | Automatically, with overlap | Planned |
| Node identity key | 7 days | Automatically, signed by the old key | Planned |
| Mesh SSH person certificate | 24 hours | Silently, before it runs out | Planned |

> [!WHY] Why keys expire and rotate
> A key that never changes can be copied once and used for ever, and nobody would notice. A key that ends on its own makes a copied one useless after a short time, with nothing for you to do.
>
> Renewal happens while a host is online and in touch with the server, so a host you use never notices it. Only a host that stays away for longer than a key lasts has to be added again.
>
> Waiting for a key to expire is not the only protection. Removing a host cuts it off at once, even if it is offline, and recovering your account removes every passkey and every CLI sign-in key.

## Signing in

These are the keys that get you into Infraternal, and back in when something goes wrong.

### Browser sign-in

> [!FACTS]
> Lasts 30 days. Using Infraternal renews the server's copy. The cookie in your browser ends 30 days after you signed in.

When you sign in with a passkey, the server gives your browser a session that lasts 30 days. Using Infraternal keeps the server's copy alive: every use pushes its end 30 days forward.

> [!WARNING] Under review
> The cookie in your browser works differently today. It is written once, at sign-in, and ends 30 days after that, however often you use it. So a browser that has been signed in for 30 days asks you to sign in again, even if you used it yesterday. Making the cookie renew too is planned.

The session lives in the server's database and in that cookie, and nowhere else. While the server is offline nothing renews, and you can sign in again only once it is back. Destructive actions ask for a fresh passkey tap whatever the session says.

### Passkey

A passkey is a key pair on your device.[^webauthn] The private half never leaves your device, and Infraternal never sees it.

A passkey does not expire, and you can have two. It stops working when you remove it, or when a recovery replaces it. Signing in needs the server, so a passkey cannot be used while the server is offline.

![Maya Patel's account card, showing two passkeys, a recovery key that is set up, and four devices.](figure:account-card "Your account card counts your passkeys and says whether your recovery words are set up.")

### Recovery words

The 24 recovery words are your way back in when you lose your passkeys.[^bip39] They are shown once, when you create your account, and only you hold them: the server keeps a check value, not the words. They do not expire.

Starting a recovery from a device that is not signed in waits 24 hours, so that a stranger with stolen words cannot take over before you notice. Any signed-in device can cancel it, and a device already signed in to the same account skips the wait. After the wait you have until 48 hours after the start to finish.

> [!IMPORTANT] A recovery changes everything
> A finished recovery signs out every session, removes every passkey and API key, and gives you new words. So each set of words works once.

### First-owner setup code

When a server starts with no owner yet, it prints a one-time setup code in its log. You use it to create the first account.

The code lasts 24 hours and works once. It is not renewed while the server runs.

> [!TIP]
> If the code has run out, restart the server to get a new one. Once an owner exists, there is no setup code.

### CLI sign-in code

`infraternal sign-in <server>` shows a link and a short code. You approve it in a signed-in browser with a fresh passkey tap.

The code lasts 10 minutes and works once. If you are away from the browser, it simply expires and you start again.

### CLI sign-in API key

Approving a CLI sign-in gives that device an API key, kept in a file only your user can read. The default lifetime is **30 days without use**, configurable from **1 to 365 days** through the server's security settings API field `api_key_lifetime_days`.

The server renews a valid key silently when it is used, writing the renewal at most once per hour. The server's current lifetime setting applies on each check, including to existing keys, so shortening it can expire a key on its next use. Lengthening applies at the next successful renewal; it cannot bring an expired key back.

A key that expires needs `infraternal sign-in <server>` again. Revoking it in the app takes effect immediately; recovery removes all keys. Existing keys receive their first lifetime when the server is upgraded. Nothing renews while the CLI is offline or unused.

> [!WARNING] Under review
> No CLI command uses these stored sign-in keys yet. Sign-in issues and stores them; authenticated remote actions are planned. The Settings → Security control for the lifetime is planned too. Their expiry and renewal are enforced by the server whenever a caller uses a key.

## Adding and trusting hosts

These keys let a host join, and let the server and the host trust each other.

### Host join token

Adding a host by SSH gives the host a join token. It lasts 15 minutes and works once. A host that sends a faulty request does not use it up.

Adding the same host again replaces the token. If the 15 minutes pass, add the host again.

![Adding a Raspberry Pi: pick it from the list, continue, choose a user install, and watch the steps finish.](figure:add-machine+clip "Adding a machine. The join token it uses lasts 15 minutes and works once.")

### `up` join code

> [!WARNING] Not available yet
> The planned one-command install (`infraternal up <server>`) will use a join code that lasts 10 minutes and works once. Until it exists, the CLI sign-in code above is the only 10-minute code.

### Host certificate

> [!FACTS]
> Lasts 7 days. Renewed by itself at 3.5 days while the host is online. A host that stays offline for more than 7 days must be added again.

Every host proves who it is to the server with a certificate that lasts 7 days. The Infraternal agent on the host and the server renew it by themselves over their connection once half of the 7 days are gone, so a host that stays connected never sees it expire.

The host keeps the same private key across renewals. The key is stored on the host and never leaves it. If the machine certificate authority is locked when a renewal is due (see the next section), the renewal tries again every hour.

> [!CAUTION] A host that stays offline for more than 7 days
> Its certificate expires, and today it cannot renew itself. Add the host again with a new join token.

The planned change is that a host can renew for up to 90 days after expiry by proving it holds its key, unless it was removed.

### Machine CA root

The machine certificate authority (CA) signs every host certificate. Its root lasts 10 years. Its private key is stored encrypted on the server, and after each server restart it stays locked until an administrator unlocks it with their passkey.

While it is locked, running hosts keep working and renewals wait.

> [!WARNING] Under review
> No warnings before the root expires exist today. Planned: warnings at 365, 90, 30 and 7 days, and a tested rollover to a new root with an overlap.

## Between machines

These keys protect the traffic between your machines, and your SSH logins over the mesh.

### WireGuard session keys

Between two mesh nodes, WireGuard makes a new short-lived session key about every 2 minutes, by itself.[^wireguard] You do nothing.

If two nodes cannot reach each other, they have no session. A new one starts as soon as they can.

### WireGuard static key

Each mesh node has a long-lived WireGuard key that other nodes know it by. The decision is to replace it every 7 days (adjustable in Settings under Security), with an overlap of at least 2 minutes in which the old and the new key both work, so no connection drops.

This happens only while the host is online and can reach the server, and a key that may be compromised is replaced at once.

> [!WARNING] Under review
> This automatic rotation is not wired up yet. Today a node creates a new key each time it starts, and the key stays in memory. A mesh keeps working on its last known rules, with no time limit, when the server is offline.

### Node identity key

Each node also has an identity key. The decision is to replace it every 7 days, with the new key signed by the old one, and only while the node is online.

> [!WARNING] Under review
> Today the mesh has no separate identity key. A host's identity is its host certificate key, which stays the same when the certificate renews. The separate key is planned.

### Mesh SSH person certificate

Connecting to a host over the mesh with SSH will use a short certificate for you.[^ssh-certificates] It is valid for 24 hours by default (an administrator can set 1 to 24 hours), and it renews quietly in the background.

The key behind it is private to you. It is kept in the Secure Enclave or the TPM when your device has one, and otherwise only in memory. Renewal needs the server, so a certificate that runs out while you are offline is replaced when you are back online.

> [!WARNING] Planned
> This is not built yet. Today only the host's side of the check exists.

[^webauthn]: [Web Authentication, W3C Recommendation](https://www.w3.org/TR/webauthn-3/): how a browser makes and uses a passkey.
[^bip39]: [BIP-39, Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): the word list and format the recovery words follow.
[^wireguard]: [WireGuard: Next Generation Kernel Network Tunnel](https://www.wireguard.com/papers/wireguard.pdf), a session key is replaced after 120 seconds.
[^ssh-certificates]: [OpenSSH certificates](https://man.openbsd.org/ssh-keygen#CERTIFICATES): how a short certificate lets a host trust a key without a list of keys.

---

Behind this page: D24 and D25 (passkeys, recovery words), D26 (setup code), D27 (CLI keys), D28 (sessions), D113 (recovery delay), D133 (host certificates), D134 (removal), D166 (mesh keys), D168 (machine CA), D235 (mesh SSH certificates), D311 (CLI sign-in and one-command install). The lifetimes are the owner's decisions of 2026-11-01 on issues #269 (comment 72638), #285, #221 (question 6) and #263. What each key does today was checked against the code in #302.
