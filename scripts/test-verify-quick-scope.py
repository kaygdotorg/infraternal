#!/usr/bin/env python3
"""Guard for `scripts/verify quick`: a cargo-fuzz package must never reach `cargo test` (#329).

The fuzz bins link libFuzzer's main, which never returns. `cargo test --workspace --bins` and
`-p infraternal-fuzz --bins` both run them despite `test = false`, so `quick` hung for 25 minutes.
This checks the pure selection logic in changed-scope.py without git or cargo. It is run by
`scripts/verify quick` itself, not by `fast`.
"""

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "verify.d" / "changed-scope.py"
spec = importlib.util.spec_from_file_location("changed_scope", SCRIPT)
changed_scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(changed_scope)

MEMBERS = {"fuzz": "infraternal-fuzz", "crates/plugins/ssh": "infraternal-plugin-ssh"}
FUZZ = {"fuzz"}


def lines(*paths):
    return changed_scope.scope(set(paths), MEMBERS, FUZZ)


# Editing a fuzz target selects `fuzz` (clippy only), never `package infraternal-fuzz`.
assert lines("fuzz/fuzz_targets/auth_cookie.rs") == ["fuzz", "exclude infraternal-fuzz"]
# A normal package is still selected, and the fuzz exclusion is always present for --workspace.
assert lines("crates/plugins/ssh/src/lib.rs") == [
    "package infraternal-plugin-ssh", "exclude infraternal-fuzz"]
# A root lockfile change selects the whole workspace, with the fuzz package excluded.
assert lines("Cargo.lock") == ["workspace", "exclude infraternal-fuzz"]
print("verify quick scope: fuzz packages are excluded from the test run; PASS")
