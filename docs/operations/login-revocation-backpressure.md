<!-- Explain bounded per-person revocation admission and authoritative replay. -->
# Login revocation backpressure and resync

The server is the source of truth for person access. A revocation remains
unconfirmed until the infraternal agent reports that its person refusal and
cleanup are durable. A transport failure or a busy security queue cannot confirm retirement.
A removal may acknowledge that the denial is recorded while cleanup is pending. The server retains the intent and
replays it when the host reconnects.

The infraternal agent reserves disk execution independently of ordinary saves.
It retains at most eighteen distinct accepted people per login registry;
duplicates share a receipt. When that queue is full, a new person receives a busy
reply before any intent, fence or descriptor is retained. The server keeps that
person blocked and waits to retry. There is no host-wide overflow latch and no
host marker to remove. Unrelated authorized people keep access.

Once the infraternal agent accepts a person, cancellation of the waiting caller
does not cancel that durable write. Storage failures reach the caller while the
bounded owner retries the accepted person. Operators should repair disk space,
permissions or storage health rather than remove refusal markers manually.

A freshly started infraternal agent begins without positive login grants. Missing
person refusal files alone never grant access. The trusted server resynchronizes
current authority; pending revocations use cleanup-only connections which cannot
publish a host or open terminals, restore people, or send plugin work. Only an
explicit server-authorized restoration may clear a durable person refusal.

Normal traffic is denied as soon as a server revocation is pending. Completing
retirement and acknowledging the revocation requires the durable host receipt;
while the host is unavailable, the operation stays pending rather than reporting
success after a finite retry budget.

The server commits a `remote_login_cleanup` row while fencing normal admission.
The row's unconfirmed state denies certificate admission, renewal and provisional
SSH access even after a server restart. The host's final retirement tombstone is
written only when a durable cleanup reply confirms that row. Cancelling an HTTP
request releases its waiter but leaves this database obligation in place.

Busy replies are retried cooperatively without a finite attempt budget. A lost
connection or the private connection's lifetime limit leaves the row pending for
the next authenticated reconnect. Cleanup connections carry only the named
person's revocation and cannot be used as normal host connections. A fresh
infraternal agent gets positive per-person authority only through trusted server
requests after this admission check; an absent local refusal file cannot grant
access on its own.

## What a removal reports

Removing an offline host returns `state: pending` with “revoked, cleanup pending”
after the server commits the denial and its delivery obligation. It does not wait
for that host to reconnect, time out, or turn the accepted denial into a 403.
The CLI reports pending; the canvas palette keeps the host listed as “removal pending”
without shell, removal or privilege actions. Normal host admission and renewal
are already refused. The host disappears from inventory only after its
infraternal agent confirms durable cleanup. A successful pending response means
that the server recorded denial, not that the host has finished cleanup.
The existing `host_cleanup` field describes the uninstall attempt, independently
of the durable login revocation receipt.

If setup installed the host and automatic uninstall could not be delivered, the
pending response includes its ownership-checked `manual` uninstall command in
both the status sentence and the structured field. The browser offers **Copy
command** while leaving the host listed as pending; human CLI output also prints
the command. Run it locally on the named host as root for a rootful installation,
or as the account that installed a rootless one. Bootstrap coordinates remain
stored until the host's durable cleanup receipt, so a pending removal does not
discard the installation information. Pending means that confirmation is still
outstanding; an already connected host need not reconnect to provide it.

The eight-slot removal pool covers the authorized commit, not the wait for an
offline host. Its durable outbox row retains the obligation across request
cancellation and server restart without retaining a removal task or permit.
Other hosts can therefore still be removed when many offline hosts are pending.

## Delivery bounds and expired certificates

Cleanup-only delivery admits eight active distinct hosts and at most sixteen
waiting distinct hosts. Each host has one claim across both populations, so a
host reconnecting repeatedly cannot consume another host's place. Waiting hosts
receive slots in FIFO order. Duplicate or full admission returns busy without
creating a cleanup actor; reconnect retries use the retained database row.
Cancellation releases a queued claim promptly. A delivery attempt lasts at most
300 seconds once admitted, after which an unconfirmed obligation remains for
reconnect. There is no retry budget that silently discards it.

On the next inventory read after all individually unrevoked leaf certificates
have expired, an undelivered removal is shown as `retired-unreachable`. The host
cannot authenticate to receive cleanup or renew its certificate. This status is
derived from the persisted certificate ledger, including after a server restart;
it does not forge a durable receipt or clear the pending denial. The host remains
listed with this terminal delivery outcome for the person and operators.

For `retired-unreachable`, remote cleanup cannot finish. An operator with local
access can remove the original installation using its ownership-checked uninstall
command. Returning the machine to service requires a fresh authorized enrollment
and an explicit authorized restoration of any refused person. No host-wide latch
or marker exists to recover, and unrelated hosts and people retain their access.
