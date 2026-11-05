#!/usr/bin/env python3
"""Compile a release consumer to prove D351 probes require explicit benchmark opt-in.

Run on the build VM through build-slot. Reuse CARGO_TARGET_DIR, keeping the
throwaway consumer and its lockfile outside the repository.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def no_product_enables_probes():
    """Fail if any other workspace manifest turns on `bench-probes`.

    The compile check below proves the feature gate works; this proves nothing
    that ships selects the feature, so the probe cannot reach a release binary
    through a dependency's feature list.
    """
    own = ROOT / 'crates/infraternal-agent/Cargo.toml'
    listed = subprocess.check_output(['git', 'ls-files', '-z', '*Cargo.toml'], cwd=ROOT).decode().split('\0')
    offenders = [path for path in filter(None, listed)
                 if ROOT / path != own and 'bench-probes' in (ROOT / path).read_text()]
    if offenders:
        raise SystemExit('bench-probes enabled outside its own crate: ' + ', '.join(offenders))
    print('no workspace manifest enables bench-probes')


def main():
    """Check both sides of the release feature boundary with real Rust compilation."""
    no_product_enables_probes()
    with tempfile.TemporaryDirectory(prefix='probe-gate-') as directory:
        source = Path(directory)
        (source / 'src').mkdir()
        (source / 'Cargo.toml').write_text(f'''[package]
name = "runtime-probe-consumer"
version = "0.0.0"
edition = "2024"
license = "AGPL-3.0-only"
[workspace]
[features]
probe = ["infraternal-agent/bench-probes"]
[dependencies]
infraternal-agent = {{ path = "{ROOT / 'crates/infraternal-agent'}", default-features = false }}
[patch.crates-io]
russh = {{ path = "{ROOT / 'vendor/russh'}" }}
russh-sftp = {{ path = "{ROOT / 'vendor/russh-sftp'}" }}
''')
        shutil.copyfile(ROOT / 'Cargo.lock', source / 'Cargo.lock')
        # The generic helper exists on every platform; constructing its future
        # checks the API without executing a runtime or touching the filesystem.
        (source / 'src/main.rs').write_text('''//! Release API boundary check.
use infraternal_agent::runtime_probe::during_slow_write;
/// Check that the explicitly selected release API is available.
fn main() {
    drop(during_slow_write(std::path::PathBuf::new(), async { Ok::<(), std::io::Error>(()) }));
}
''')
        environment = dict(os.environ, CARGO_TARGET_DIR=os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
        command = ['cargo', 'check', '--release', '--offline', '--manifest-path', str(source / 'Cargo.toml')]
        absent = subprocess.run(command, env=environment, capture_output=True, text=True)
        if absent.returncode == 0 or 'E0432' not in absent.stderr or 'could not find `runtime_probe`' not in absent.stderr:
            raise SystemExit('release probe exclusion FAILED\n' + absent.stdout + absent.stderr)
        print('release without benchmark feature: runtime_probe import rejected (E0432)')
        subprocess.run(command + ['--features', 'probe'], env=environment, check=True)
        print('release with explicit bench-probes: probe consumer compiled')


if __name__ == '__main__':
    main()
