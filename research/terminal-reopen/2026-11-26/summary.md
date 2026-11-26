# Exact repaint on a same-size terminal reopen

J1270 · 2026-11-26 · base `98e6adda1080c9a991345f508efd6eb95c59c098` · [#521](https://git.kayg.org/kayg/infraternal/issues/521)

## Current replay policy

On this base, `ReadFrom` already attempts an exact Snapshot when a retained
backlog is **strictly greater than 1 MiB**. A refusal returns to raw replay.
A cursor older than the ring takes the existing recovery path. The proposed
change only matters when today's policy would choose raw replay and some of
the bytes it would replay predate a successful change in rows or columns.
The fixture compares the deployed selection, forced raw and forced exact
with the same exact-only fallback as #583. [#583](https://git.kayg.org/kayg/infraternal/issues/583)

## How often replay crosses a resize

The six checked-in PTY recordings deliberately exercise resizing during a
shell session. At each record boundary, model a new browser attaching from
cursor zero at the current size. Count the cut when an applied geometry
change follows some of the output that would be replayed.

| Recording | Sampled cuts | Changed sizes | Replay crosses a resize | More output since resize |
|---|---:|---:|---:|---:|
| Bash, one-line prompt | 348 | 4 | 185 | 181 |
| Bash, multiline prompt | 334 | 4 | 185 | 181 |
| Bash, long edits | 418 | 6 | 213 | 207 |
| Zsh, right prompt | 329 | 4 | 176 | 172 |
| Zsh, long edits | 420 | 6 | 214 | 208 |
| Fish | 401 | 4 | 227 | 223 |
| **Total** | **2,250** | **28** | **1,200** | **1,172** |

All 28 applied size changes follow output. At 1,172 of the 1,200 exposed
cuts (97.7%), at least one more PTY write has already arrived. A predicate
that checks whether the resize was the last event would miss those cuts.
Compare the attach cursor with the byte offset of the last applied
geometry change instead. The recordings supply an exposure count under a
resize-heavy workload. They provide no estimate of production reopen
frequency. The existing Snapshot counter tracks approximate outcomes and
does not provide a denominator for this case. [Corpus counts](https://git.kayg.org/kayg/infraternal/issues/521#issuecomment-105726)
