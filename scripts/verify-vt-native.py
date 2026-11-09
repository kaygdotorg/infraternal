"""Run public C behavioral probes with diagnostics retained in evidence files [40]."""
import argparse
import os
from pathlib import Path
import subprocess
from evidence_path import evidence_directory

root = Path(__file__).resolve().parent.parent
target_root = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
if not target_root.is_absolute():
    target_root = root / target_root
parser = argparse.ArgumentParser()
parser.add_argument("probe", choices=["mouse", "allocation"])
parser.add_argument("--library", type=Path)
parser.add_argument("--evidence", type=Path, default=evidence_directory("verify-vt-native"))
parser.add_argument("--build-dir", type=Path, default=target_root / "vt-probes")
args = parser.parse_args()
args.evidence.mkdir(parents=True, exist_ok=True)
# Select the most recent completed adapter build, never an in-progress archive.
lib = args.library or max((target_root / "debug/build").glob("infraternal-shim-*/out/native/lib/libghostty-vt.a"), key=lambda p: p.stat().st_mtime)
lib = lib.resolve()
cache = lib.parents[2]
source_dirs = [cache / "libghostty-vt-1.0.0", cache / "ghostty-source"]
include = next((path / "include" for path in source_dirs if (path / "include").is_dir()), None)
if include is None:
    raise SystemExit("native probe headers not found beside the built archive")
source = Path("crates/infraternal-shim/tests/native") / (args.probe + "_probe.c")
# Match scripts/build-vt: stage the checksum-pinned compiler even when the
# invoking dev shell has no Zig on PATH. Never substitute a host compiler.
subprocess.run([str(root / "scripts/auth-toolchain")], cwd=root, check=True)
zig = target_root / "auth-tools/zig/zig"
args.build_dir.mkdir(parents=True, exist_ok=True)
exe = args.build_dir / (args.probe + "-probe")
with (args.evidence / (args.probe + "-build.log")).open("w") as log:
    result = subprocess.run([str(zig), "cc", "-I", str(include), str(source), str(lib), "-lpthread", "-lm", "-ldl", "-o", str(exe)], stdout=log, stderr=log)
if result.returncode:
    raise SystemExit("native probe build FAIL")
failed = False
for step in (range(12) if args.probe == "allocation" else [None]):
    name = args.probe + ("-" + str(step) if step is not None else "")
    with (args.evidence / (name + ".log")).open("w") as log:
        command = [str(exe.resolve())] + ([] if step is None else [str(step)])
        result = subprocess.run(command, stdout=log, stderr=log, timeout=10)
    passed = result.returncode == 0
    failed |= not passed
    print(name + (" PASS" if passed else " FAIL"))
raise SystemExit(1 if failed else 0)
