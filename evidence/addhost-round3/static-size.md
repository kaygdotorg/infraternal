<!-- Static artifact sizes and unchanged historical caps for host provisioning round 3, #169. -->
# Static size

| Target | Repaired bytes | Historical maximum | Result |
| --- | ---: | ---: | --- |
| x86_64 musl | 20,132,112 | 16,404,816 | built, stripped static PIE, no PT_INTERP; cap exceeded |
| aarch64 musl | 17,943,200 | 13,817,816 | built, stripped static executable, no PT_INTERP; cap exceeded |

Independent review of original `9cdab5c7` measured 20,108,016 x86 bytes, already
above that cap. This repair adds 24,096 bytes. The reachable code adds owned
retirement transitions, SQL statements, fencing and startup recovery; new
regressions and observers are cfg(test). Cargo manifests, dependencies, default
features and release profile are unchanged. The snapshot retains the exact
historical cap and 262,144-byte allowance. D205's owner rule permits reported
feature growth; this is not a green size row or a budget increase.

Original-head ARM was not measured by the review dispatcher, which returned
at x86. No original ARM delta is claimed. The separate ARM build is required
because the same dispatcher stops at the x86 size check on the repaired head.
`arm-build-resume.log` has exit 0; `arm-static-check.log` has static/stripped/no
PT_INTERP proof and the unchanged failing cap check. The earlier capacity-ended
ARM build transcript is retained. Artifact SHA256 hashes are in
`static-artifacts-sha256.txt`.
