#!/usr/bin/env python3
"""Prove shipping static artifacts survive isolated build roots and sccache [D243, #246]."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl")


def checked_output(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(command, cwd=cwd, env=env, text=True).strip()


def path_from_env(value: str | None, default: Path) -> Path:
    path = Path(value) if value else default
    return (ROOT / path).resolve() if not path.is_absolute() else path.resolve()


def copy_registry(source: Path, destination: Path) -> None:
    registry = source / "registry"
    if not registry.is_dir():
        raise RuntimeError(f"Cargo registry is missing: {registry}")
    destination.mkdir(parents=True, exist_ok=True)
    if not (destination / "registry").exists():
        subprocess.run(["cp", "-a", "--reflink=auto", str(registry), str(destination)], check=True)


def install_rustup_toolchain(destination_home: Path, env: dict[str, str]) -> None:
    compiler = Path(checked_output(["rustup", "which", "rustc"], cwd=ROOT, env=env))
    source_toolchain = compiler.parent.parent
    destination_toolchains = destination_home / "toolchains"
    destination_toolchains.mkdir(parents=True, exist_ok=True)
    destination_toolchain = destination_toolchains / source_toolchain.name
    if not destination_toolchain.exists():
        subprocess.run(
            ["cp", "-a", "--reflink=auto", str(source_toolchain), str(destination_toolchains)],
            check=True,
        )
    rustup_env = {**env, "RUSTUP_HOME": str(destination_home)}
    alternate_compiler = Path(checked_output(["rustup", "which", "rustc"], cwd=ROOT, env=rustup_env))
    if destination_home not in alternate_compiler.parents:
        raise RuntimeError(f"alternate Rustup home selected a compiler outside {destination_home}")


def run_logged(name: str, command: list[str], cwd: Path, env: dict[str, str], log: Path) -> None:
    with log.open("w", encoding="utf-8") as output:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, check=False)
    if result.returncode != 0:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        print(f"{name} failed; last build output:", file=sys.stderr)
        print("\n".join(lines[-80:]), file=sys.stderr)
        raise RuntimeError(f"{name} exited with {result.returncode}; log: {log}")


def make_sccache_observer(path: Path) -> None:
    path.write_text(
        "#!/usr/bin/env python3\n"
        '"""Capture remapped compile flags before forwarding to sccache."""\n'
        "import json, os, sys\n"
        "args = sys.argv[1:]\n"
        "compiler = args[0] if args else ''\n"
        "if compiler.endswith('.cargo/rustc.sh'):\n"
        "    capture = os.environ['INFRATER_SCCACHE_CAPTURE_RUST']\n"
        "elif compiler.endswith('.cargo/musl-cc-avx512.sh'):\n"
        "    capture = os.environ['INFRATER_SCCACHE_CAPTURE_NATIVE_X86']\n"
        "elif compiler.endswith('.cargo/musl-cc.sh'):\n"
        "    capture = os.environ['INFRATER_SCCACHE_CAPTURE_NATIVE_AARCH64']\n"
        "else:\n"
        "    capture = None\n"
        "if capture is not None:\n"
        "    # Cargo and native compiler probes run before build flags are available.\n"
        "    prefix = ('--remap-path-prefix=' if compiler.endswith('.cargo/rustc.sh')\n"
        "              else '-ffile-prefix-map=')\n"
        "    if not any(argument.startswith(prefix) for argument in args):\n"
        "        capture = None\n"
        "if capture is not None:\n"
        "    try:\n"
        "        fd = os.open(capture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
        "    except FileExistsError:\n"
        "        pass\n"
        "    else:\n"
        "        with os.fdopen(fd, 'w', encoding='utf-8') as output: json.dump(args, output); output.write('\\n')\n"
        "binary = os.environ['INFRATER_REAL_SCCACHE']\n"
        "os.execv(binary, [binary, *args])\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def registry_source_roots(cargo_home: Path) -> list[Path]:
    source = cargo_home / "registry" / "src"
    return sorted(path.resolve() for path in source.glob("*") if path.is_dir())


def executable_root(value: str | None) -> Path | None:
    if not value:
        return None
    words = shlex.split(value)
    if not words:
        return None
    resolved = shutil.which(words[0]) or words[0]
    return Path(resolved).resolve()


def add_path_root(roots: set[str], path: Path | None) -> None:
    if path is not None:
        roots.add(str(path.resolve()))


def artifact_roots(
    checkout: Path,
    cargo_home: Path,
    target_dir: Path,
    rustup_home: Path,
    sccache_dir: Path | None,
    rustc_wrapper: Path | None,
) -> set[str]:
    roots: set[str] = set()
    for path in (checkout, cargo_home, target_dir, rustup_home, sccache_dir, rustc_wrapper):
        add_path_root(roots, path)
    for path in registry_source_roots(cargo_home):
        add_path_root(roots, path)
    return roots


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def first_difference(left: bytes, right: bytes) -> int | None:
    for offset, (first, second) in enumerate(zip(left, right)):
        if first != second:
            return offset
    return None if len(left) == len(right) else min(len(left), len(right))


def section_lines(binary: Path) -> list[str]:
    output = checked_output(["readelf", "-W", "-S", str(binary)], cwd=ROOT)
    names = (".text ", ".rodata ", ".data ", ".comment ", ".note.infraternal")
    return [line.strip() for line in output.splitlines() if any(name in line for name in names)]


def main() -> int:
    home = Path.home()
    main_target = path_from_env(os.environ.get("CARGO_TARGET_DIR"), ROOT / "target")
    main_cargo = path_from_env(os.environ.get("CARGO_HOME"), home / ".cargo")
    main_rustup = path_from_env(os.environ.get("RUSTUP_HOME"), home / ".rustup")
    main_sccache = Path(os.environ["SCCACHE_DIR"]).resolve() if os.environ.get("SCCACHE_DIR") else None
    main_wrapper = executable_root(os.environ.get("RUSTC_WRAPPER"))
    main_binaries = {target: main_target / target / "release/infraternal" for target in TARGETS}
    missing = [str(binary) for binary in main_binaries.values() if not binary.is_file()]
    if missing:
        raise RuntimeError("main static artifacts are missing: " + ", ".join(missing))

    git_status = checked_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT)
    if git_status:
        raise RuntimeError("static reproducibility requires a clean checkout so the comparison worktree matches it")

    scratch_base = home / ".cache" / "codex-scratch"
    try:
        job_root = scratch_base / main_target.relative_to(scratch_base).parts[0]
    except (ValueError, IndexError):
        job_root = scratch_base / "infraternal-static-reproducibility"
    job_root.mkdir(parents=True, exist_ok=True)
    evidence = job_root / "evidence" / f"static-repro-{os.getpid()}"
    evidence.mkdir(parents=True)
    work_root = Path(tempfile.mkdtemp(prefix="static-repro-work-", dir=job_root))
    checkout = work_root / "long-root/with-a-distinct-and-deliberately-long-checkout-location/checkout-b"
    default_cargo = work_root / "cargo-home"
    default_rustup = work_root / "rustup-home"
    default_target = work_root / "target"
    alt_cargo = path_from_env(os.environ.get("INFRATER_STATIC_REPRO_CARGO_HOME"), default_cargo)
    alt_rustup = path_from_env(os.environ.get("INFRATER_STATIC_REPRO_RUSTUP_HOME"), default_rustup)
    alt_target = path_from_env(os.environ.get("INFRATER_STATIC_REPRO_TARGET_DIR"), default_target)
    real_sccache = shutil.which("sccache")

    def fail_before_worktree(message: str) -> None:
        shutil.rmtree(work_root, ignore_errors=True)
        raise RuntimeError(message)

    if not real_sccache:
        fail_before_worktree("sccache is required for the static cache-key reproducibility check")
    if any(path == main_path for path, main_path in (
        (alt_cargo, main_cargo), (alt_rustup, main_rustup), (alt_target, main_target)
    )):
        fail_before_worktree("alternate Cargo, Rustup and target roots must differ from the main build")
    if alt_target.exists() and any(alt_target.iterdir()):
        fail_before_worktree(f"alternate target directory must be empty: {alt_target}")

    checkout.parent.mkdir(parents=True, exist_ok=True)
    worktree_added = False
    try:
        head = checked_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
        subprocess.run(["git", "worktree", "add", "--detach", str(checkout), head], cwd=ROOT, check=True)
        worktree_added = True

        copy_registry(main_cargo, alt_cargo)
        if not alt_rustup.exists() or not (alt_rustup / "toolchains").exists():
            install_rustup_toolchain(alt_rustup, os.environ.copy())
        else:
            rustup_env = {**os.environ, "RUSTUP_HOME": str(alt_rustup)}
            selected = Path(checked_output(["rustup", "which", "rustc"], cwd=checkout, env=rustup_env))
            if alt_rustup not in selected.parents:
                raise RuntimeError(f"alternate Rustup home selected a compiler outside {alt_rustup}")

        alt_target.mkdir(parents=True, exist_ok=True)
        capture_rust = evidence / "sccache-rust-args.json"
        capture_native_x86 = evidence / "sccache-native-x86-args.json"
        capture_native_aarch64 = evidence / "sccache-native-aarch64-args.json"
        observer = work_root / "sccache"
        make_sccache_observer(observer)
        alt_env = os.environ.copy()
        alt_env.update({
            "CARGO_HOME": str(alt_cargo),
            "CARGO_TARGET_DIR": str(alt_target),
            "RUSTUP_HOME": str(alt_rustup),
            "SCCACHE_RECACHE": "1",
            "RUSTC_WRAPPER": str(observer),
            "INFRATER_REAL_SCCACHE": str(Path(real_sccache).resolve()),
            "INFRATER_SCCACHE_CAPTURE_RUST": str(capture_rust),
            "INFRATER_SCCACHE_CAPTURE_NATIVE_X86": str(capture_native_x86),
            "INFRATER_SCCACHE_CAPTURE_NATIVE_AARCH64": str(capture_native_aarch64),
        })

        environment_lines = [
            f"commit={head}", f"main_checkout={ROOT}", f"alternate_checkout={checkout}",
            f"main_CARGO_HOME={main_cargo}", f"alternate_CARGO_HOME={alt_cargo}",
            f"main_target={main_target}", f"alternate_target={alt_target}",
            f"main_RUSTUP_HOME={main_rustup}", f"alternate_RUSTUP_HOME={alt_rustup}",
            f"SCCACHE_DIR={main_sccache or 'inherited/default'}", "alternate_sccache_mode=forced-recache-through-shared-server",
            f"loadavg_start={Path('/proc/loadavg').read_text().splitlines()[0] if Path('/proc/loadavg').exists() else 'unavailable'}",
        ]
        (evidence / "environment.txt").write_text("\n".join(environment_lines) + "\n", encoding="utf-8")

        run_logged("alternate auth-toolchain", ["scripts/auth-toolchain"], checkout, alt_env, evidence / "auth-toolchain.log")
        for target in TARGETS:
            run_logged(
                f"alternate {target}",
                ["scripts/static-cargo", "build", "--locked", "--release", "--package", "infraternal", "--target", target],
                checkout,
                alt_env,
                evidence / f"{target}.log",
            )

        captures = {
            "Rust": capture_rust,
            "native x86_64": capture_native_x86,
            "native AArch64": capture_native_aarch64,
        }
        missing_captures = [name for name, path in captures.items() if not path.is_file()]
        if missing_captures:
            raise RuntimeError("sccache did not receive compiler invocations for: " + ", ".join(missing_captures))
        captured_args = {name: json.loads(path.read_text(encoding="utf-8")) for name, path in captures.items()}
        required_remaps = [
            f"--remap-path-prefix={checkout}=/infraternal",
            f"--remap-path-prefix={alt_cargo}=/cargo",
            f"--remap-path-prefix={alt_target}=/build",
            f"--remap-path-prefix={alt_rustup}=/rustup",
        ]
        source_roots = registry_source_roots(alt_cargo)
        native_remaps = [
            f"-ffile-prefix-map={checkout}=/infraternal",
            f"-ffile-prefix-map={alt_cargo}=/cargo",
            f"-ffile-prefix-map={alt_target}=/build",
        ]
        missing_remaps = [
            f"Rust: {flag}" for flag in required_remaps if flag not in captured_args["Rust"]
        ]
        registry_mappings_follow_cargo_home = False
        if not source_roots or not any(
            f"--remap-path-prefix={path}=/cargo" in captured_args["Rust"] for path in source_roots
        ):
            missing_remaps.append("Rust: a Cargo registry source-root remap")
        cargo_mapping = f"--remap-path-prefix={alt_cargo}=/cargo"
        if source_roots and cargo_mapping in captured_args["Rust"]:
            cargo_mapping_index = captured_args["Rust"].index(cargo_mapping)
            registry_mapping_indexes = [
                captured_args["Rust"].index(f"--remap-path-prefix={path}=/cargo")
                for path in source_roots
                if f"--remap-path-prefix={path}=/cargo" in captured_args["Rust"]
            ]
            registry_mappings_follow_cargo_home = bool(registry_mapping_indexes) and all(
                index > cargo_mapping_index for index in registry_mapping_indexes
            )
            if not registry_mappings_follow_cargo_home:
                missing_remaps.append("Rust: registry source-root remaps must follow CARGO_HOME")
        for label in ("native x86_64", "native AArch64"):
            missing_remaps.extend(
                f"{label}: {flag}" for flag in native_remaps if flag not in captured_args[label]
            )
            if not source_roots or not any(
                f"-ffile-prefix-map={path}=/cargo" in captured_args[label] for path in source_roots
            ):
                missing_remaps.append(f"{label}: a Cargo registry source-root remap")

        roots = artifact_roots(ROOT, main_cargo, main_target, main_rustup, main_sccache, main_wrapper)
        add_path_root(roots, Path(real_sccache))
        roots.update(artifact_roots(checkout, alt_cargo, alt_target, alt_rustup, main_sccache, observer))
        report = [
            *environment_lines,
            f"rust_sccache_remaps_visible={not any(item.startswith('Rust:') for item in missing_remaps)}",
            f"native_x86_sccache_remaps_visible={not any(item.startswith('native x86_64:') for item in missing_remaps)}",
            f"native_aarch64_sccache_remaps_visible={not any(item.startswith('native AArch64:') for item in missing_remaps)}",
            f"rust_registry_mappings_follow_cargo_home={registry_mappings_follow_cargo_home}",
        ]
        if missing_remaps:
            report.append("missing_sccache_remaps=" + ", ".join(missing_remaps))
        failed = bool(missing_remaps)
        for target in TARGETS:
            main_binary = main_binaries[target]
            alternate_binary = alt_target / target / "release/infraternal"
            first = main_binary.read_bytes()
            second = alternate_binary.read_bytes()
            equal = first == second
            report.extend([
                f"{target}: main_size={len(first)} alternate_size={len(second)} equal={equal}",
                f"{target}: main_sha256={sha256(first)} alternate_sha256={sha256(second)}",
            ])
            leaks = [(root, second.count(root.encode())) for root in sorted(roots, key=len, reverse=True) if second.count(root.encode())]
            if leaks:
                failed = True
                report.extend(f"{target}: embedded_path={root} count={count}" for root, count in leaks)
            if not equal:
                failed = True
                report.append(f"{target}: first_difference_offset={first_difference(first, second)}")
                report.extend(f"{target}: main_section={line}" for line in section_lines(main_binary))
                report.extend(f"{target}: alternate_section={line}" for line in section_lines(alternate_binary))
        (evidence / "report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
        print("\n".join(report))
        if failed:
            raise RuntimeError(f"static artifact reproducibility failed; evidence: {evidence}")
        print(f"static artifact reproducibility passed; evidence: {evidence}")
    finally:
        if worktree_added:
            result = subprocess.run(
                ["git", "worktree", "remove", "--force", str(checkout)], cwd=ROOT, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if result.returncode != 0:
                print(result.stderr, file=sys.stderr)
                raise RuntimeError(f"could not remove comparison worktree: {checkout}")
        shutil.rmtree(work_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as error:
        print(f"static reproducibility gate: {error}", file=sys.stderr)
        raise SystemExit(1)
