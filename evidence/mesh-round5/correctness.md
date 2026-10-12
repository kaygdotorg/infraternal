<!-- Independent review regression reproduction and exact connection-state checks for #173, D242. -->
# Round 5 correctness

The production repair is two constant fresh-TCP checks on each frontend. Exact
connection retirement already selects the complete kernel object by initiating
tuple, observed ID and zone, removing its original and reply indexes. The new
checks require SYN before fresh TCP can be accepted, preventing loose tracking
from reclassifying a retired socket through still-permitted reverse access.
Established permitted streams retain their existing initiating-tuple checks.
No namespace-wide state removal, tracking setting, engine or dependency changes.

Source checkpoints: dev merge `c89fe001`, unchanged review regression import
`3b20429d`, nft repair `2b02a2d5`, compatibility repair `b6d51a7f`, contract/module
clarification `a1278216`. Every checkpoint is pushed on `mesh-policy-verify`.

The earlier independent MPVR-1/2/3 tests from `fd094729` were already imported
byte-identically by prior repair work. The four additional cases from
`a908499a` are imported unchanged; all four fail at their original refusal
assertion before repair and pass after repair. No test assertions were weakened.
The renderer count assertions account for and explicitly identify the two new
constant rules; existing acceptance/ownership/hook assertions remain.

| Functional evidence | Passed | Failed |
| --- | ---: | ---: |
| Expected before-repair reverse-state failures | 4 | 0 unexpected |
| Named kernel checks (earlier review, identity fences, recovery, reverse TCP) | 16 | 0 |
| Fresh-store authority withdrawal | 1 | 0 |
| Persistent-flow and exact connection-state assertions | 344 | 0 |
| Failed-journal original-ID preservation | 8 | 0 |
| Saved-intent recovery attempts | 20 | 0 |

Each named kernel case uses a fresh disposable user/network namespace. Dumps
and tuples remain in `reverse-state/`, `state-*/`, `rollback-*/`, and
`recovery-*/`; terminal output is limited to counts. `run-functional.sh` rebuilds
outside namespaces first so the configured compiler cache stays reachable.
The aggregate namespace reuse and isolated-cache compilation setup failures are
retained separately; neither is counted as a semantic before/after result.
All state campaigns run the same current source; allowed same-peer TCP/UDP and
unrelated underlay entries retain their exact IDs. Production authority entry-
point validation, perf-VM apply/last-receiver measurements and final fast output
are recorded in the completion evidence when those runs finish.

Reproduce with the pinned toolchain, umask 022, a private CARGO_TARGET_DIR under
`$HOME/.cache/codex-scratch/`, and the built `kernel_node` and
`connection_state_fixture` examples. Set MESH_EVIDENCE before running the named
kernel script. Run the existing state, rollback and recovery proof scripts in
separate namespaces for nft and `--nf-tables`. No owner live fixtures are used.
