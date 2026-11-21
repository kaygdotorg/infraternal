<!-- Records the origin and local scope of the decided SSH engine source. -->
# Pinned SSH engine

Published russh 0.65.2, upstream commit 56a999871aa134072e4f2a7395fe2de313870e21,
registry checksum 78229f06e4d96d83bea5f5133ad3b6e4b5f0ce22d8e31c1ff7243ec8e18d5ba1. Original licensing and
notices are retained. This is the D289 engine with ring, not a new engine.

Local changes (#221): opt-in manual receive credit, strict receive-window
accounting in that mode, and acknowledged credit updates dispatched independently
of blocked output. Defaults retain upstream behavior. Application code drops the
unused channel receiver and handles input through nonblocking callbacks.

A directly owned serve_stream future shares connection initialization without
using a detached background task; cancelling it drops the handler/attachments.

Regression tests live in crates/plugins/ssh/tests/mesh_flow.rs. Rebase these
changes or drop this copy when the engine provides an equivalent public API.

The rebase retains the local checked strict key-exchange sequence accounting
(including group exchange and optimistic startup), and retains upstream's new
authentication and parser checks. The upstream wasm32 clock still uses chrono
via russh-util 0.52.0 (#532).
