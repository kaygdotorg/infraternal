<!-- D74 departure ordering fix, J850, issue #521. -->
# D74 departure ordering

J848's same-batch EOF/Resize regression exposed a delayed ownership release:
peer removal ran after all ready frames, so a later size report still saw the
departed typist as owner. Both the per-session shim and process-per-user reactor
now mark a departing peer detached and release its size before visiting the next
peer. Physical removal remains at the end of the pass, keeping poll indices
stable. Buffered-frame retirement and write failures follow the same ordering.

The release still checks all attached links. An already attached replacement
or shared link of the owning writer retains ownership. Reports before the
observed departure stay staged; the first report after the last owner link
leaves takes the size, and later reports cannot steal it. No staged report is
retroactively applied, as amended D74 says the next device reporting a size wins.

The real-socket/PTY regression is retained. Additional reactor coverage checks
reverse order, all three positions of an owner in a three-peer batch, a surviving
replacement/shared link, two departures of the same owner, and malformed buffered
input followed by another peer's Resize. The standalone wire proof also queues
EOF and reports while its own shim is stopped, so dispatch sees one ready batch.

The same-size resize/replay handler is unchanged. Ownership scans run on
observed departures; no scan is added to a healthy reconnect or resize. Forgejo
#521 records exact-head gates, repeated wire cases, geometry suites, mutations
and same-size reconnect measurements. Raw receipts live outside the checkout.
