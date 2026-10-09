# Add-host flow: gaps in the provisioning contract

The add-host mockup now speaks `contracts/ssh-bootstrap.md` (branch `ssh-bootstrap`)
through `apps/tracer/src/provisioning-client.ts`, and the test double
(`apps/tracer/test/provisioning-double.ts`) implements the same requests and events.
This file lists what the UI wants that the contract does not give it. None of it is
invented in the double; each item says the exact field and why. Where the UI cannot
work without a field, it carries a fallback, named below.

## Wanted by the UI

1. **Per-step human text that matches a fixed vocabulary.** Contract: `message` is
   free human text and "clients must display the server's actual text". The UI shows
   exactly that, so the row's step label is whatever the server says. The double uses
   short phrases ("Checking the system", "Installing the agent", "Gathering host
   facts", "Connecting", "Ready", "Ready · root"). Wanted: the real server's `message`
   for each step stays a short present-participle phrase of under 30 characters,
   because it sits on one line beside a progress bar on a phone. Longer prose belongs
   in `log_tail`.

2. **Facts on the `done` event, for the window header and popover.** The check
   already collects OS, architecture, init, uid, sudo, user systemd and linger, but
   events carry only text. The UI wants on `done`:
   `host: { host_id, os: "ubuntu"|"debian"|..., os_name, os_version, architecture,
   uid, mode }`. Why: the new window's header shows the OS mark, name and version, and
   the popover shows architecture and mode. Today the UI falls back to the discovery
   inventory entry, which does not exist for a manually typed `user@host` (it shows
   "Linux", no architecture).

3. **The host id the new terminal belongs to.** `done` should carry `host_id` (the
   UUID bound after the check) so the window can open that host's terminal through
   the session router. Without it the UI cannot tell the canvas which host the new
   window is.

4. **A structured failure for the "what to do" copy.** `failure.kind` selects the
   title and next-step text in the UI, which is enough for six kinds. Wanted per kind
   that the UI cannot derive: `failure.phase` (which of check/install/facts/connect
   was running; today the UI keeps the last phase it saw) and, for `host-key` and
   `unsupported`, a field naming what was observed (the contract has `fingerprints`
   for host keys only; unsupported needs `reason: "no-systemd" | "arch" | "os"`).

5. **Queued versus started.** The server admits eight active hosts; the rest of a
   100-host batch have no event until a slot frees. The UI shows "Waiting" for a host
   with no events, which is indistinguishable from "the server never heard of it".
   Wanted: one `queued` step (or a `queued` event) per target at admission, with
   `queue_position`. The UI would then show "Waiting" only for queued hosts and could
   report a rejected target.

6. **A pasted credential becomes a reference how?** The credentials page lets the
   person paste a key or password and says it is encrypted with their passkey. The
   contract only accepts an opaque `credential` reference, and defines no request that
   turns pasted bytes into one (that is the vault adapter's job). Wanted: the vault
   request (path, body, response `{credential}`) so the UI can store the paste first
   and send the reference. Today the UI sends no credential, and the double refuses
   `nix-cache` regardless.

7. **Discovery and inventory.** The host list (names, sources, OS, "already added",
   "SSH ready" / "No answer" / "Blocked", root available) comes from a mock endpoint,
   `/__mock/proto/addhost`. The contract resolves `discovered` ids but defines no
   request that lists them. Wanted: a read-only listing with, per entry: `id`,
   `name`, `user`, `address`, `sources[]`, `os`, `architecture`, `added: boolean`,
   `reachability: "ready"|"no-answer"|"mesh-policy"` and `root_available`. The UI
   shows these before anything logs in, so they cannot come from the check.

8. **Retry after the socket is gone.** A closed socket cancels the batch and "a new
   socket cannot resume it". The UI keeps the socket open after a batch with failures
   so that the "Review" toast can still retry them. If the owner wants Review to
   outlive a page reload, a failed target must be retryable from a new socket
   (`retry` with the original address), or the UI must start a fresh batch for it.
   Open question for the contract, not a field.

9. **Upgrading to root later.** After a rootless install the host window offers
   "Root available" and "Install as root". The contract has `mode` only at `start`.
   Wanted: an `upgrade` command (or a statement that the person adds the host again)
   and a `root_available` fact on `done` so the pill can be hidden when sudo is
   missing.

10. **Root consent per target versus per batch.** The UI asks once for all selected
    hosts, then sends `mode: "root"` and `root_consent: true` on each host that offers
    passwordless sudo. That matches the contract, but it needs `sudo` known before
    `start`, which comes from discovery (item 7), not from the check.

11. **Typed hosts and ports.** The contract's `user@host[:port]` is enough. The UI
    cannot say, before `start`, whether a typed host is unreachable; the double
    therefore reports it as the usual `unreachable` failure after `check`.

## Double behaviour not in the contract

The double decides outcomes from the fixture, never from the request: `unreachable`
and `mesh-policy` fixtures fail after `check`, the refused-login fixture fails with
`auth`, and any retry of a failed target succeeds. The real server will decide these
itself. The double also fails `auth` after `check` (a real login happens during the
check as well), so the UI shows the same bar position for every failure.
