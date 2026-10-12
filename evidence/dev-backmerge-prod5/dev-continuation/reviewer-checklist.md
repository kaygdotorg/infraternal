<!-- Records the author integration checks for D250 round-4 reconciliation, #169. -->
# Continuation integration review

- Merge parents are the production-integrated `6b978074` branch and dev `53d7af1b`; preserve both histories and D256.
- The single add/add conflict retains every test function from both parents. Positive admission uses the existing signed-image fixture; fixed signature, immutable-inode and listener-refusal regressions run normally. Keep isolated fixture-root selection.
- Bootstrap uses the kernel-pinned running image for same-architecture payloads and SSH prompt helpers. Adjacent development payload lookup retains round-4 invocation handling. Production challenge/Start fresh, primary readiness exit and exact-owner durable retirement remain intact.
- SSH prompt identity remains exact inode plus source digest and direct registered parent; scopes remove the copied image and helper. No trust/permission prompt receives a credential.
- Anonymous infraternal agents launch shims directly through the existing audited signal/fd3 boundary. The real anonymous PTY oracle proves open/input/output without a shell resolving `/proc/self/exe` to the wrong image.
- Keep all signed replacement, same-PID recovery, PATH recovery, bootstrap, SSH and release test sets. No test deleted, assertion widened or new production ignore introduced.
- D243 checker is byte-for-byte identical to `6b978074`, including both maxima. D244 continues both provider checks after a size refusal; ARM runtime protection is not claimed on x86.
- Functional browser uses unique4977 and the existing optimized production harness. Captures are for independent review; no author visual verdict or physical-device proof.
- Original RTT probe runs under the VM208 shared lock. Functional gate durations are not accepted performance measurements.
- Push only `dev-backmerge-prod5`; no dev/main update, deployment, owner fixture mutation or issue closure.

Targeted results and raw transcripts are adjacent. Final exact-head `scripts/verify fast` output is retained locally and quoted verbatim on #169; its unchanged D243 size failure remains explicit.
