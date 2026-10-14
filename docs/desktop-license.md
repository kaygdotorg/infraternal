<!-- Role: AGPL dependency audit for the pinned macOS capture implementation [D204]. -->
# Desktop capture license audit

The selected `screencapturekit =11.0.0` crate is MIT OR Apache-2.0. Use its MIT
option with our AGPL-3.0-only plugin. Its published archive includes both
license texts and the Swift bridge source; that bridge is covered by the same
crate license. No source from a visual-reference site is used.

The enabled dependency closure adds `apple-cf 0.11.0`, `apple-metal 0.10.0`
(both MIT OR Apache-2.0), and `doom-fish-utils 0.4.1` (MIT OR Apache-2.0). Its queue/utility
closure reuses `crossbeam-queue` and `futures-util` (MIT OR Apache-2.0);
their existing `crossbeam-utils` (MIT OR Apache-2.0), `slab` (MIT),
`pin-project-lite` (MIT OR Apache-2.0) and futures crates (MIT OR Apache-2.0)
remain unchanged.
`apple-metal` also uses the existing `libc` dependency (MIT OR Apache-2.0).
Select MIT for each dual-license package. This closure adds no incompatible
license and no second version of an existing product dependency. The optional
async wrapper is off; macOS 14.2 APIs enable child-window/menu capture support.
Apple's frameworks are dynamically provided by the operating system, not
redistributed. Our native companion is AGPL-3.0-only alongside the Rust plugin.

The exact wrapper version is the one measured in #139 (D204). Both its source
and the graph must be checked again before any version upgrade. Verification
uses cargo-deny and cargo tree -d; the issue records the actual output.

Sources: published crate archives and LICENSE-MIT/LICENSE-APACHE files;
https://docs.rs/screencapturekit/11.0.0/screencapturekit/ ;
https://docs.rs/apple-cf/0.11.0/apple_cf/ ;
https://docs.rs/apple-metal/0.10.0/apple_metal/ ;
https://docs.rs/doom-fish-utils/0.4.1/doom_fish_utils/ .
