#!/usr/bin/env python3
"""Exercise the signed offline VT build recipe with local release-shaped inputs [#419]."""
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap


root = Path(__file__).resolve().parent.parent
version = "1.0.0"
source_name = f"libghostty-vt-{version}.tar.gz"
deps_name = f"libghostty-vt-{version}-deps.tar.gz"
public_key = "RWQlAjJC23149WL2sEpT/l0QKy7hMIFhYdQOFy0Z7z7PbneUgvlsnYcV"


def write_archive(path: Path, prefix: str, files: dict[str, str]) -> None:
    """Create a small tarball with the same top-level layout as a release asset."""
    with tarfile.open(path, "w:gz") as archive:
        for name, contents in files.items():
            data = contents.encode()
            entry = tarfile.TarInfo(f"{prefix}/{name}")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))


def sha256(path: Path) -> str:
    """Return the checksum the build recipe pins for one local fixture asset."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_fake_tools(bin_dir: Path) -> Path:
    """Install local curl/minisign doubles and a pinned Zig executable template."""
    bin_dir.mkdir(parents=True)
    (bin_dir / "curl").write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import os
            from pathlib import Path
            import shutil
            import sys

            args = sys.argv[1:]
            output = Path(args[args.index("-o") + 1])
            url = next(value for value in args if value.startswith("https://"))
            name = url.rsplit("/", 1)[1]
            shutil.copyfile(Path(os.environ["VT_FIXTURE_ASSETS"]) / name, output)
            if os.environ.get("VT_CORRUPT_SOURCE") == "1" and name == os.environ["VT_SOURCE_NAME"]:
                with output.open("ab") as stream:
                    stream.write(b"corrupt")
            with Path(os.environ["VT_CURL_LOG"]).open("a") as stream:
                stream.write(url + "\\n")
            """
        )
    )
    (bin_dir / "minisign").write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            if not args or args[0] != "-V":
                raise SystemExit("verification flag missing")

            def value(flag):
                try:
                    return args[args.index(flag) + 1]
                except (ValueError, IndexError):
                    raise SystemExit(f"argument missing: {flag}")

            public_key = value("-P")
            message = Path(value("-m"))
            signature = Path(value("-x"))
            expected = f"fixture signature for {message.name}\\n"
            if public_key != os.environ["VT_EXPECTED_PUBLIC_KEY"]:
                raise SystemExit("unexpected release verification key")
            if signature.read_text() != expected:
                raise SystemExit("signature did not match its asset")
            if os.environ.get("VT_REJECT_SIGNATURE") == "1":
                raise SystemExit("fixture signature rejected")
            with Path(os.environ["VT_MINISIGN_LOG"]).open("a") as stream:
                stream.write(json.dumps({
                    "public_key": public_key,
                    "message": str(message),
                    "signature": str(signature),
                }) + "\\n")
            """
        )
    )
    zig = bin_dir / "zig-template"
    zig.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]

            def record(value):
                with Path(os.environ["VT_ZIG_LOG"]).open("a") as stream:
                    stream.write(json.dumps(value) + "\\n")

            if args == ["version"]:
                record({"command": "version", "executable": sys.argv[0]})
                print("0.17.0")
                raise SystemExit(0)

            if not args or args[0] != "build":
                raise SystemExit("unexpected pinned compiler command")
            source = Path.cwd()
            system = Path(args[args.index("--system") + 1])
            prefix = Path(args[args.index("--prefix") + 1])
            global_cache = Path(os.environ["ZIG_GLOBAL_CACHE_DIR"])
            if not (source / "src/lib_vt.zig").is_file():
                raise SystemExit("signed source archive was not extracted")
            if not any(system.iterdir()):
                raise SystemExit("offline dependency archive was not extracted")
            if not global_cache.is_dir() or any(global_cache.iterdir()):
                raise SystemExit("offline Zig global cache must start empty")
            library = (source / "src/lib_vt.zig").read_text()
            if "infraternal_vt_snapshot" not in library:
                raise SystemExit("snapshot adapter was not wired into the library")
            if "-Demit-lib-vt=true" not in args or "-Demit-xcframework=false" not in args:
                raise SystemExit("VT library artifact selection is wrong")
            if not any(arg.startswith("-Dvt-features=") for arg in args):
                raise SystemExit("VT feature selection is missing")

            (prefix / "lib/pkgconfig").mkdir(parents=True)
            (prefix / "include/ghostty").mkdir(parents=True)
            (prefix / "lib/libghostty-vt.a").write_bytes(b"fixture static archive")
            (prefix / "lib/libghostty-vt.so").write_bytes(b"fixture shared library")
            (prefix / "lib/pkgconfig/libghostty-vt.pc").write_text("Name: libghostty-vt\\n")
            (prefix / "include/ghostty/vt.h").write_text("fixture header\\n")
            record({
                "command": "build",
                "executable": sys.argv[0],
                "args": args,
                "system": str(system),
                "prefix": str(prefix),
                "global_cache": str(global_cache),
            })
            """
        )
    )
    for executable in (bin_dir / "curl", bin_dir / "minisign", zig):
        executable.chmod(0o700)
    return zig


def make_fixture(base: Path) -> dict[str, Path]:
    """Build an isolated repository with signed-archive-shaped local assets."""
    repo = base / "repo"
    scripts = repo / "scripts"
    native = repo / "crates/infraternal-shim/native"
    scripts.mkdir(parents=True)
    native.mkdir(parents=True)
    for name in ("build-vt", "auth-toolchain", "patch-libghostty-vt.py", "zig.sha256"):
        shutil.copy2(root / "scripts" / name, scripts / name)
    shutil.copy2(root / "crates/infraternal-shim/native/snapshot.zig", native / "snapshot.zig")

    assets = base / "assets"
    assets.mkdir()
    source_archive = assets / source_name
    deps_archive = assets / deps_name
    write_archive(
        source_archive,
        f"libghostty-vt-{version}",
        {
            "LIB_VERSION": f"{version}\n",
            "src/lib_vt.zig": "// source fixture\n",
        },
    )
    write_archive(
        deps_archive,
        f"libghostty-vt-{version}-deps",
        {"fixture/dependency.zig": "// dependency fixture\n"},
    )
    source_signature = assets / f"{source_name}.minisig"
    deps_signature = assets / f"{deps_name}.minisig"
    source_signature.write_text(f"fixture signature for {source_name}\n")
    deps_signature.write_text(f"fixture signature for {deps_name}\n")
    pinned = (
        (source_archive, source_name),
        (source_signature, f"{source_name}.minisig"),
        (deps_archive, deps_name),
        (deps_signature, f"{deps_name}.minisig"),
    )
    (scripts / "libghostty-vt.sha256").write_text(
        "".join(f"{sha256(path)}  {name}\n" for path, name in pinned)
    )

    bin_dir = base / "bin"
    zig_template = write_fake_tools(bin_dir)
    return {
        "repo": repo,
        "assets": assets,
        "bin": bin_dir,
        "zig_template": zig_template,
        "target": base / "target",
        "outputs": base / "outputs",
        "curl_log": base / "curl.jsonl",
        "minisign_log": base / "minisign.jsonl",
        "zig_log": base / "zig.jsonl",
    }


def install_fake_zig(target: Path, template: Path) -> None:
    """Put the test-only compiler at the exact pinned-toolchain location."""
    executable = target / "auth-tools/zig/zig"
    executable.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(template, executable)
    executable.chmod(0o700)


def fixture_environment(fixture: dict[str, Path], target: Path) -> dict[str, str]:
    """Provide only local tools and assets to the real build script."""
    env = os.environ.copy()
    env.pop("INFRATERNAL_ZIG", None)
    env.update(
        {
            "PATH": f"{fixture['bin']}:/usr/bin:/bin",
            "CARGO_TARGET_DIR": str(target),
            "TARGET": "x86_64-unknown-linux-gnu",
            "PROFILE": "debug",
            "VT_FIXTURE_ASSETS": str(fixture["assets"]),
            "VT_SOURCE_NAME": source_name,
            "VT_EXPECTED_PUBLIC_KEY": public_key,
            "VT_CURL_LOG": str(fixture["curl_log"]),
            "VT_MINISIGN_LOG": str(fixture["minisign_log"]),
            "VT_ZIG_LOG": str(fixture["zig_log"]),
        }
    )
    return env


def run_build(
    fixture: dict[str, Path],
    label: str,
    features: dict[str, str] | None = None,
    target: Path | None = None,
    environment: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the real release recipe against local archives and selected test features."""
    target_root = target or fixture["target"]
    install_fake_zig(target_root, fixture["zig_template"])
    output = fixture["outputs"] / label
    output.mkdir(parents=True)
    env = fixture_environment(fixture, target_root)
    env.update(features or {})
    env.update(environment or {})
    result = subprocess.run(
        ["bash", str(fixture["repo"] / "scripts/build-vt"), str(output)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, output


def check_build_recipe() -> None:
    """Verify signed inputs, offline dependencies, artifacts and feature selection."""
    with tempfile.TemporaryDirectory(prefix="build-vt-fixture-") as temporary:
        fixture = make_fixture(Path(temporary))
        cases = (
            ("shipping", {}),
            ("mouse-probe", {"CARGO_FEATURE_VT_TEST_INPUT": "1"}),
        )
        for label, features in cases:
            result, output = run_build(fixture, label, features)
            assert result.returncode == 0, f"{label} build failed: {result.stderr}{result.stdout}"
            native = output / "native"
            assert native.is_symlink(), "Cargo output must link to the cached native prefix"
            native = native.resolve()
            assert (native / "lib/libghostty-vt.a").read_bytes() == b"fixture static archive"
            assert (native / "lib/libghostty-vt.so").read_bytes() == b"fixture shared library"
            static_link = native / "static-link"
            assert {path.name for path in static_link.iterdir()} == {"libghostty-vt.a"}, (
                "Rust's native link path must contain only the static archive"
            )
            assert (static_link / "libghostty-vt.a").resolve() == (
                native / "lib/libghostty-vt.a"
            ).resolve()
            assert (native / "lib/pkgconfig/libghostty-vt.pc").is_file()
            assert (native / "include/ghostty/vt.h").is_file()

        curl_urls = fixture["curl_log"].read_text().splitlines()
        expected_assets = {
            source_name,
            f"{source_name}.minisig",
            deps_name,
            f"{deps_name}.minisig",
        }
        assert len(curl_urls) == len(expected_assets), "the recipe should fetch each signed asset once"
        for url in curl_urls:
            assert url.startswith(
                f"https://release.files.ghostty.org/libghostty-vt/{version}/"
            ), f"unexpected release URL: {url}"
            assert url.rsplit("/", 1)[1] in expected_assets

        verifications = [
            json.loads(line) for line in fixture["minisign_log"].read_text().splitlines()
        ]
        assert len(verifications) == 4, "each build must verify both release archives"
        assert all(item["public_key"] == public_key for item in verifications)
        assert {
            Path(item["message"]).name for item in verifications
        } == {source_name, deps_name}
        assert all(
            Path(item["signature"]).name == f"{Path(item['message']).name}.minisig"
            for item in verifications
        )

        builds = [
            json.loads(line)
            for line in fixture["zig_log"].read_text().splitlines()
            if json.loads(line)["command"] == "build"
        ]
        assert len(builds) == 2, "both build variants must invoke the pinned compiler"
        feature_args = [
            next(arg for arg in build["args"] if arg.startswith("-Dvt-features="))
            for build in builds
        ]
        assert feature_args == [
            "-Dvt-features=-all",
            "-Dvt-features=-all,+input-encode",
        ]
        for build in builds:
            args = build["args"]
            assert args[0] == "build"
            assert args[args.index("-Demit-lib-vt=true")].endswith("true")
            assert args[args.index("-Demit-xcframework=false")].endswith("false")
            assert "--system" in args and Path(build["system"]).is_dir()
            assert "libghostty-vt-1.0.0-deps" in build["system"]
            assert Path(build["global_cache"]).is_dir()
            assert Path(build["executable"]).name == "zig"

        before_signatures = len(verifications)
        bad_target = Path(temporary) / "bad-checksum-target"
        bad_result, bad_output = run_build(
            fixture,
            "bad-checksum",
            target=bad_target,
            environment={"VT_CORRUPT_SOURCE": "1"},
        )
        assert bad_result.returncode != 0, "a checksum-mismatched source archive must fail closed"
        after_signatures = fixture["minisign_log"].read_text().splitlines()
        assert len(after_signatures) == before_signatures, "bad checksums must fail before signature verification"


def check_release_lz4_safety_patch() -> None:
    """Verify that shared-host restores receive safety checks and ordinary builds do not."""
    with tempfile.TemporaryDirectory() as temporary:
        source_root = Path(temporary)
        lz4 = source_root / "src/terminal/compress/lz4.zig"
        lz4.parent.mkdir(parents=True)
        lz4.write_text(
            """\
pub fn decompress(input: []const u8, output: []u8) DecompressError!usize {
    _ = input;
    _ = output;
}
fn copyMatch(output: []u8, op_: usize, offset: usize, match_len: usize) void {
    _ = output;
    _ = op_;
    _ = offset;
    _ = match_len;
}
inline fn readIntAt(comptime Int: type) Int {
    return 0;
}
inline fn writeIntAt(comptime Int: type) void {
    _ = Int;
}
inline fn copyIntAt(comptime Int: type) void {
    _ = Int;
}
"""
        )
        result = subprocess.run(
            [
                sys.executable,
                str(root / "scripts/patch-libghostty-vt.py"),
                str(source_root),
                "",
                "",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "@setRuntimeSafety(true);" not in lz4.read_text()
        patcher = runpy.run_path(str(root / "scripts/patch-libghostty-vt.py"))
        patcher["patch_lz4_safety"](source_root)
        assert lz4.read_text().count("@setRuntimeSafety(true);") == 5


check_build_recipe()
check_release_lz4_safety_patch()
print("PASS: signed offline inputs, pinned Zig, feature selection and static/shared artifacts")
print("PASS: bounded LZ4 safety patch remains conditional")
