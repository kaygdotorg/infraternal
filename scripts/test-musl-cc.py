#!/usr/bin/env python3
"""Exercise the pinned C wrappers' D244 and D264 policies for both musl targets."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
SCRATCH.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='wrapper-test-', dir=SCRATCH) as directory:
    tool = Path(directory) / 'auth-tools/zig/zig'
    tool.parent.mkdir(parents=True)
    tool.write_text('#!/usr/bin/env python3\nimport sys\nprint("\\n".join(sys.argv[1:]))\n')
    tool.chmod(0o755)
    for target, zig_target in (
        ('x86_64-unknown-linux-musl', 'x86_64-linux-musl'),
        ('aarch64-unknown-linux-musl', 'aarch64-linux-musl'),
    ):
        environment = dict(os.environ, CARGO_TARGET_DIR=directory, TARGET=target)
        retained = ['-DOPENSSL_NO_SECURE_MEMORY=1', '-DOTHER=1', '-O3', 'input with spaces.c']
        result = subprocess.run(
            [str(ROOT / '.cargo/musl-cc.sh'), f'--target={target}',
             '-DOPENSSL_NO_SECURE_MEMORY', *retained],
            env=environment, check=True, capture_output=True, text=True,
        )
        assert result.stdout.splitlines() == ['cc', '-target', zig_target,
            f'-ffile-prefix-map={ROOT}=/infraternal',
            f'-ffile-prefix-map={directory}=/build', *retained], target
        build_directories = [
            f'-DENGINESDIR="{directory}/native/install/lib/engines-3"',
            f'-DMODULESDIR="{directory}/native/install/lib/ossl-modules"',
        ]
        explicit = '-DMODULESDIR="/chosen/trusted-modules"'
        mismatched = f'-DMODULESDIR="{directory}/native/install/lib/engines-3"'
        result = subprocess.run(
            [str(ROOT / '.cargo/musl-cc.sh'), *build_directories, explicit, mismatched],
            env=environment, check=True, capture_output=True, text=True,
        )
        assert result.stdout.splitlines()[-4:] == [
            '-DENGINESDIR="/infraternal/build-only/engines-3"',
            '-DMODULESDIR="/infraternal/build-only/ossl-modules"', explicit, mismatched,
        ], 'build-only module paths depend on the checkout or target directory'
        result = subprocess.run(
            [str(ROOT / '.cargo/musl-cc.sh'), '--target=unowned-target'],
            env=environment, capture_output=True, text=True,
        )
        assert result.returncode != 0 and not result.stdout, target
        print(f'{target}: exact define removed; build directories remapped; explicit paths preserved; target override refused')

    source = Path(directory) / 'openssl-source'
    assembly = source / 'crypto/modes/asm/aes-gcm-avx512.pl'
    include = source / 'providers/implementations/ciphers/cipher_aes_gcm_hw_aesni.inc'
    assembly.parent.mkdir(parents=True)
    assembly.write_text('# pinned source marker\n')
    include.parent.mkdir(parents=True)
    include.write_text(
        '#include "cipher_aes_gcm_hw_vaes_avx512.inc"\n'
        'const PROV_GCM_HW *ossl_prov_aes_hw_gcm(size_t keybits);\n'
    )
    environment = dict(
        os.environ,
        CARGO_TARGET_DIR=directory,
        TARGET='x86_64-unknown-linux-musl',
    )
    arguments = [
        '--target=x86_64-unknown-linux-musl',
        '-DOPENSSL_NO_SECURE_MEMORY',
        '-O3',
        'cipher_aes_gcm_hw.c',
    ]
    for _ in range(2):
        result = subprocess.run(
            [str(ROOT / '.cargo/musl-cc-avx512.sh'), *arguments],
            cwd=source,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        assert result.stdout.splitlines() == [
            'cc', '-target', 'x86_64-linux-musl',
            f'-ffile-prefix-map={ROOT}=/infraternal',
            f'-ffile-prefix-map={directory}=/build', '-O3', 'cipher_aes_gcm_hw.c',
        ]
    patched = include.read_text()
    assert '#include "cipher_aes_gcm_hw_vaes_avx512.inc"' not in patched
    assert patched.count('D264: retain AES-NI and generic AES-GCM') == 1
    assert (source / '.infraternal-d264-avx512-gcm').read_text() == 'D264\n'
    print('x86_64 OpenSSL source: AVX-512 GCM dispatch removed idempotently')
