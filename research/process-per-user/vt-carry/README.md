<!-- Role: explain the isolated parser-state checkpoint candidate and its validation [D270]. -->
This package evaluates bounded checkpoint access for the selected carry-parser
algorithm, pinned to vte 0.15.0. The MIT permission for that source remains in
LICENSE-MIT; the package is AGPL-3.0-only. Its workspace is independent of the
application, whose dependency graph retains the existing parser.

With the std feature, `export_checkpoint(max_osc_bytes)` records all parser
fields in a versioned format without raw pointers. The caller supplies its
existing OSC byte budget. `import_checkpoint` validates tags, ranges, grouped
parameters, incomplete UTF-8 and record exhaustion before returning a parser.
It preserves unused indices from older OSC values because future parser state
must remain exact. Serialization adds no buffer to a live parser.

The comparison tests resume every split of the sample corpus against the
existing dependency, then continue with additional input. They cover long
incomplete syntax, bounded storage, truncation, trailing bytes and changed
records. Run formatting, clippy and tests with this manifest explicitly;
application workspace checks do not select this candidate.

This API supplies the Rust carry state needed by D128. Whole-host replacement
also requires exact native terminal state, retained input/output state, every
PTY/listener/viewer descriptor, child ownership and the commit transaction.
Adoption remains an owner decision after measurements and review on #205.
