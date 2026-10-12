<!-- Records static artifact byte sizes and the unchanged production baseline for #195. -->
# Static build evidence

All artifacts are stripped static musl binaries on infraternal-dev. This is file
size evidence, not a runtime performance measurement.

| Artifact | Bytes | Frozen maximum | Result |
| --- | ---: | ---: | --- |
| Exact `5bf3f42e` x86_64 baseline | 20,329,648 | 16,404,816 | FAIL |
| Fixed x86_64 | 20,333,168 | 16,404,816 | FAIL |
| Fixed aarch64 | 18,112,240 | 13,817,816 | FAIL |

The fixed x86_64 artifact is 3,520 bytes larger than the exact production base,
which already exceeds the cap by 3,924,832 bytes. This job does not alter a budget
or decision. No fresh exact-base aarch64 comparison was made.

The gate verifies absence of PT_INTERP in both binaries. The native x86_64 key
memory diagnostic passes with an 8 MiB memlock limit; it does not claim native
aarch64 execution. Both legacy no-argument CLI stub checks return their expected
exit status and text. Full output is in `verify-fast-resume.txt`; the final
serialized head-gate summary is recorded on #195.
