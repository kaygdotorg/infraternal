<!-- Explain bounded per-person revocation admission and authoritative replay. -->
# Login revocation backpressure and resync

The server is the source of truth for person access. A revocation remains
unconfirmed until the infraternal agent reports that its person refusal and
cleanup are durable. A transport failure or a busy security queue must never
turn an unconfirmed revocation into success. The server retains the intent and
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
