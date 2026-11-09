# libghostty-vt 1.0 size provenance (#419)

This record separates the original size-only baseline receipts from the
preserved performance binaries. Only artifacts with a source revision, build
recipe, and binary hash recorded together are used as a before/after pair.

## Rebuilt baseline

The clean baseline checkout is `origin/dev` at
`6ffe37e067d8fa7b090ea83c21b84b77937f76d9`, built on dev-02 with:

```sh
nix develop . -c scripts/auth-toolchain
nix develop . -c scripts/static-cargo build --locked --release --package infraternal --target <target>
```

The checkout was clean. Build inputs were recorded with the binary hashes:

| Input | SHA-256 |
| --- | --- |
| `scripts/static-cargo` | `13899f7c7e6870b5ab9a9c2a013f89400f0a579aff7eaf19fb8b08767da4bf0b` |
| `Cargo.lock` | `bc991b6d00ff74973b61b5d8593a948f90d72bf74e07e1f63f8fa73adb30a2e1` |
| `flake.lock` | `7182e465cf29c8b1c52de31e22d22cb00b57c67fb73f3935c90152080d9ddc9b` |

| Target | Bytes | Binary SHA-256 |
| --- | ---: | --- |
| `x86_64-unknown-linux-musl` | 27,659,664 | `8f1d1144f9490a82fa6827b8276dea743027e7e7dfb3b645ed8ca3c39679edf3` |
| `aarch64-unknown-linux-musl` | 24,893,280 | `d512e4ac722367ebcb61ea9f6aa1f1d0454bc28e19f681917ea316b1db5aa572` |

Receipt: `/home/claude/.cache/codex-scratch/J339-review-fixes/evidence/baseline-static-provenance.log`.

The earlier #419 size-only receipts recorded 27,662,256 / 24,905,984 bytes
for the same source revision, but did not preserve their binary hashes. The
fresh rebuild differs by 2,592 / 12,704 bytes. The old figures remain
historical measurements; this record uses the rebuilt, hashed artifacts for
direct comparisons.

## P2 branch build

The P2 branch build used clean source `5f96a8e61dd5067736585402669cf866185fe5a6`
on dev-02 with the same `scripts/static-cargo` recipe:

| Input | SHA-256 |
| --- | --- |
| `scripts/static-cargo` | `13899f7c7e6870b5ab9a9c2a013f89400f0a579aff7eaf19fb8b08767da4bf0b` |
| `Cargo.lock` | `3835a67d0a4e86a62d549a726d3ba057e8e64350ae501151de1ce59542b439e5` |
| `flake.lock` | `7643017deec35a2f9dd10a6b368db90fbe5134666e087ed6d8d7382f7fe6c626` |

| Target | Bytes | Binary SHA-256 |
| --- | ---: | --- |
| `x86_64-unknown-linux-musl` | 27,884,728 | `f79d9d1b644881a7d4cbd71896f1a9b20c0d0383bca8bc0991a7f2f3cd7ac230` |
| `aarch64-unknown-linux-musl` | 25,051,144 | `d6faa2a5a53a6a83238320ba5705e9ab6277911aa07a313fefe653655f9850c0` |

The rebuilt `6ffe37e0` baseline to P2 branch deltas are +225,064 bytes
(+0.81%) on x86_64 and +157,864 bytes (+0.63%) on aarch64. This is a whole
checkout comparison: the two commits have different Cargo and Nix lockfiles,
so these deltas are not attributed to the engine alone. The baseline build and
the P2 build ran on the same host with the same static-cargo recipe.

Receipt: `/home/claude/.cache/codex-scratch/J339-review-fixes/evidence/`.
The `p2-session-image-check.log` also records a successful build of the
private feature that compiles the no-op log sink.

## Direct P2 size-control comparison

I rebuilt the pre-P2 review head `17c9668e063f6533b7cb614c14aa7d52abe165e1`
and P2 head `5f96a8e61dd5067736585402669cf866185fe5a6` on dev-02 with the same
Zig 0.17.0 toolchain, `scripts/static-cargo` recipe and lockfiles. Both
checkouts were clean. The common inputs have identical hashes in both builds:

| Input | SHA-256 |
| --- | --- |
| `scripts/static-cargo` | `13899f7c7e6870b5ab9a9c2a013f89400f0a579aff7eaf19fb8b08767da4bf0b` |
| `Cargo.lock` | `3835a67d0a4e86a62d549a726d3ba057e8e64350ae501151de1ce59542b439e5` |
| `flake.lock` | `7643017deec35a2f9dd10a6b368db90fbe5134666e087ed6d8d7382f7fe6c626` |

| Target | Pre-P2 bytes | Pre-P2 binary SHA-256 | P2 bytes | P2 binary SHA-256 | Delta |
| --- | ---: | --- | ---: | --- | ---: |
| `x86_64-unknown-linux-musl` | 28,240,792 | `a83c742f3e2430566e98bf241cfc7e70fd7418a0dcff3201d6d08587c1a2c0bd` | 27,884,728 | `f79d9d1b644881a7d4cbd71896f1a9b20c0d0383bca8bc0991a7f2f3cd7ac230` | -356,064 (-1.26%) |
| `aarch64-unknown-linux-musl` | 25,388,760 | `fd965d1679fd1dca6b9604431ae9193483efab837527707239c4452f79a773a2` | 25,051,144 | `d6faa2a5a53a6a83238320ba5705e9ab6277911aa07a313fefe653655f9850c0` | -337,616 (-1.33%) |

The direct product pair measures the combined static effect of restoring
function and data section emission for final-link garbage collection and
removing the private `session-image` logger symbols. Both product builds
enable `session-image`, so this pair does not isolate the bytes saved by
sectioning from those saved by logger removal. The private-only archive check
confirms that those symbols are absent from that archive, but it is not a
separate product size measurement. The direct x86 pre-P2 rebuild is 3,712 bytes
larger than the older preserved `infraternal-after-final`; the latter's
recipe was not retained, so the reproducible pair above is used for the
before/after comparison.

Receipts: `/home/claude/.cache/codex-scratch/J339-review-fixes/evidence/`
(`pre-p2-static-*.log`, `pre-p2-infraternal-*`, and `p2-infraternal-*`).

## Preserved performance artifacts

The perf VM's `infraternal-baseline` is 27,773,808 bytes with SHA-256
`af2a3c054bb46e425deb6951c2a3799aa00416019ac3f897816acba11111ad2c`. Its
source revision and build recipe were not preserved with that file, so it is
not used as the baseline.

The old `infraternal-after-final` artifact is 28,237,080 bytes with SHA-256
`428c9987f2e9008b92f5b1d9faeb80b189585ea60e73d7aca2f37263128e72e3`. It
was built from review head `17c9668e063f6533b7cb614c14aa7d52abe165e1`; its
receipt is `verify-fast-final-17c9668.log` on compute01.

The old +574,824 / +483,288 byte deltas combine the historical size-only
baseline receipts with a different preserved final artifact. The direct
463,272 byte difference between the two preserved x86 files is also not a
valid engine attribution because the baseline's source and recipe are
unknown. Neither comparison is used to assign the libghostty-vt size cost.

The P2 branch's paired x86_64 and aarch64 sizes and hashes are recorded in
the final #419 verification comment and the matching build receipts.
