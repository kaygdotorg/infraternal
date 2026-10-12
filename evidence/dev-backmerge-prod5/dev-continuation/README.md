<!-- Records the D250 continuation merge, regression gates and reproducible evidence for #169. -->
# Dev continuation

Merge `5a4414a8` has parents `6b978074` and `53d7af1b` (current dev, round-4
release replacement and D256). Earlier production and Start fresh merges stay
in its ancestry. Push only this branch; no deployment or dev/main update.

The only conflict was the independently added replacement audit test module.
Every test function from both parents remains. Signed immutable fixtures and
fixed regression activation follow round 4; scratch-root isolation follows
this branch. No test dropped. Bootstrap, signed payload, SSH prompt, primary
readiness exit, Start fresh safeguards and durable retirement coexist.
D243's checker is byte-for-byte unchanged from `6b978074`; D244 still exercises
both static providers after a size failure. Incoming development/test SHA-256
optimization is retained; shipping release settings and size caps are unchanged.

## Targeted verification

- `native.log`: fmt, strict all-target Clippy and complete touched-package tests
  pass. CLI 75/0, server 413/0, shim 80/0; SSH and release suites pass, including
  signed admission, same-PID recovery, PATH recovery, prompt helper identity,
  bootstrap retirement, ownership and retained migration compatibility.
- `ownership-shell.log`: 16/16 real-filesystem cases, including SF-1 and
  refusal while a setup socket remains bound.
- `anonymous-pty.log`: real sealed-image infraternal agent opens a PTY and
  preserves input/output through the direct kernel executable and fd3 boundary.
- `browser.log`: 40/40 functional cases on unique port 4977. All original
  per-assertion deadlines retained; the inherited 120-second whole-case harness
  is unchanged. Production build with synthetic provisioning/canvas fixtures.
  Captures are attached under `captures/` for independent visual review; no
  physical iPhone or author visual-quality claim.
- `ts-serial.log`: compiler/checksums/build/transfer pass, 176 tracer tests,
  36 protocol tests/34,462 assertions, 134 streams/11,439 schedules and zero
  divergences. Critical gzip 295,019/307,200 and Brotli 245,740/256,000 bytes;
  deferred 49,757/51,200 and 43,935/45,056 bytes. Largest on-demand chunk
  15,854/20,480 gzip and 14,093/18,432 Brotli bytes.
- `ts.log` retains the initial unchanged 30-second differential timeout while
  Rust compilation shared its target directory. The unchanged replay passes;
  no timeout, assertion or #118 exemption changed.
- `perf-rtt-ready.log`: unchanged three-sample RTT probe on VM208 under the
  shared flock, four cores, recorded load 0.28/0.56/0.84. The wrapper requires
  both the PASS record and explicit remote exit zero; empty SSH output cannot
  silently pass. Non-RTT Python calls retain the existing Python 3.14 interpreter.

Raw transcripts are hashed in `artifact-hashes.txt`. Functional durations are
not performance evidence. Author checks: `reviewer-checklist.md`. No new
foundational engine, production feature or contract change is introduced.

## Exact-head repository gate

Run `scripts/verify fast` after the evidence commit, on the pushed branch head.
The complete final output is retained locally as `verify-fast-final.log` and
quoted verbatim on #169 with its head/hash. The known D243 caps remain
16,404,816 bytes x86 and 13,817,816 bytes ARM; any excess remains an explicit
failed gate, with both targets and the native x86 key-memory check exercised.
ARM runtime protection requires native ARM execution and is not claimed here.

Reproduce targeted commands with the adjacent gate scripts and owned private
HOME-cache targets. Bootstrap `scripts/auth-toolchain` for the job target first.
The final gate uses a real compact `b6` fixture root, never a scratch symlink.
Create the wrapper directory and copy `rtt-wrapper.sh` to its `python3` entry;
ship the unchanged `scripts/latency_proxy.py` and existing `perf-rtt.py` to this
job's VM directory before running `fast-gate.sh`. Only the RTT probe runs there.
Scratch build/fixture and VM inputs are removed after final evidence is recorded.
