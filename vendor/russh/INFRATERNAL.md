<!-- Records the origin and local scope of the decided SSH engine source. -->
# Pinned SSH engine

Published russh 0.64.1, upstream commit e5d80a07dc554480b6ea3b2e14adfc190407b627,
registry checksum ba61e87b9ec9a39a59a6bbed4c0b8ff7fb07073405b24a767a1f2c8560ac8f58. Original licensing and
notices are retained. This is the D289 engine with ring, not a new engine.

Local changes (#221): opt-in manual receive credit, strict receive-window
accounting in that mode, and acknowledged credit updates dispatched independently
of blocked output. Defaults retain upstream behavior. Application code drops the
unused channel receiver and handles input through nonblocking callbacks.

A directly owned serve_stream future shares connection initialization without
using a detached background task; cancelling it drops the handler/attachments.

Regression tests live in crates/plugins/ssh/tests/mesh_flow.rs. Rebase these
changes or drop this copy when the engine provides an equivalent public API.
