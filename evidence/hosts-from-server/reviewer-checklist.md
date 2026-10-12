<!-- Author review of admitted-host data, authorization and lifecycle invariants, #194. -->
# Author review

- `remote_hosts`, `remote_certificates` and `remote_host_bootstrap` remain the only host records. No new library, transport, identity map or permission model was selected.
- The socket selects the account; request input cannot. Real SQLite tests include a second account's admitted host, tombstones, unredeemed invitations, and 1,001 rows with long destinations.
- UUIDs select host routing. Duplicate names cannot rebound a shell locally. Online state comes from the admitted actor's current census; offline records remain listed.
- SQL pages have item and byte limits; the client validates UUIDs, strings, booleans, cursor progress, uniqueness and the total host cap before atomic replacement.
- One coalesced watch source publishes durable admission/removal. Node observations belong to the generic plugin lifecycle; disabling it leaves no inventory worker or timer running. Subscription slots and epochs reject stale generations.
- Author review reproduced stale client admission after refusal and result delivery after authorization ended under outbound backpressure. Both have failing-before tests and fixes. Read, serialization and queue admission remain inside live socket authority.
- Socket-down guards prevent orphaned calls from being replayed on welcome; an offline-transition failing-before test covers that boundary.
- Already-open palettes refresh through the existing renderer, preserving query and selected identity; remote removal has a failing-before browser test.
- Welcome generations, disposal, complete snapshots and one adapter notification protect reconnect and paged reads. Browser functional proof uses fresh storage, 300 ms RTT, an offline row, UUID shell opening, reconnect and remote removal.
- No new UI component or style was added. The existing palette screenshot is attached for owner/designer judgment; no visual-quality claim is made.
- Decoder unit tests reject account selectors, arrays, malformed cursors and oversized input. The new existing-engine fuzz target compiles; no instrumented fuzz campaign is claimed.
- Only owned test fixtures and processes are created/retired. Owner live fixtures and unrelated services are untouched. No credentials are searched, serialized to evidence or passed in argv.
- Performance is measured on the named 4-vCPU perf VM under its shared lock, with prebuilt artifacts. Final raw gates and VM evidence are recorded separately from functional test diagnostics.
