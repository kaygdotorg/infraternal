<!-- Immutable static binary-size attribution for D215 transport work, issue #129. -->
# D215 original binary-growth attribution

Immutable comparison: `a5f744fbc1d5e8966de46982b995d816e91baff5` → `515d371249d2809114133f9245a7947a3278d13c`. This measures the original transport lane; it does not include the later reviewed dataplane integration or round-two performance fixes. No production source was edited by this attribution task.

The historical shipping increase was **90,496 bytes** (20,614,656 → 20,705,152). Our same-toolchain unstripped rebuilds, processed identically with GNU `strip --strip-all`, increase **90,432 bytes** (20,616,408 → 20,706,840). The 64-byte delta difference is explicitly unreconciled. GNU strip rewrites the ELF; these sizes are not Cargo's shipping `strip=true` outputs. The historical independent review also differs from the author by 32 bytes. Use the paired measurements for attribution; do not substitute these binaries for the shipping gate.

## Method and immutable artifacts

- Rust 1.99.0, commit b940084d7eb6a299eb4bfeb8e34901bc051e7ac4, LLVM 23.1.1; cargo-bloat 0.12.1; GNU binutils strip 2.46.
- Target `x86_64-unknown-linux-musl`; default binary features, `--locked`; release opt-level 3, full LTO, one codegen unit, panic unwind. Only `CARGO_PROFILE_RELEASE_STRIP=false` differs from shipping, to retain names.
- Each source revision lives in its own detached scratch checkout. Shared scratch target was released after both binaries were copied to immutable revision-named files. Root did not build the mutable main worktree for this comparison.
- Pinned Zig 0.15.2; source archive checksum fb4b2f9ffa0af125983041fdbe4ef94d3fa79fb9f2d22b9c213c0e3847a866b6. Adapter and recipe SHA256 are identical at both revisions: snapshot.zig 5594ee4de305312390599734940ca03d3bbc4ac24bb648dc26db933e479ed19e; scripts/build-vt 31d638d41b058cd092212291f0878a824e62886e4e458a5e5c6a74cf3eb1d670. Cargo.lock and .cargo/config.toml are byte-identical. The verified ReleaseFast/baseline-CPU/x86musl native archive was reused under the new absolute-path-derived cache key; no build script changed.
- Cargo bloat command for each checkout:

```sh
CARGO_TARGET_DIR=/home/kayg/.cache/codex-scratch/mesh-agent-transport-round2/target \
CARGO_PROFILE_RELEASE_STRIP=false \
cargo bloat --locked --release --package infraternal --bin infraternal \
  --target x86_64-unknown-linux-musl --message-format json -n0
```

515 invocation was wrapped in `systemd-run --user --scope -p CPUWeight=10000`; build completed in 8m55s. Its recorded start/end load and compiler provenance are in bloat-515-provenance.txt. Baseline raw build log records 44m54s. Static builds are attribution work, not runtime benchmarks. No timing or capacity acceptance is inferred from build duration or shared-host load.

```sh
strip --strip-all -o <revision>-gnu-strip <revision>-unstripped
readelf -SW <revision>-unstripped
nm -CS --size-sort <revision>-unstripped
```

Unstripped sizes: 58,212,936 → 58,331,616 bytes. SHA256 baseline 1a0a1c0138d69941a33434b30177605f9a6b681bf1ba96237eb524dc1a2d7fde; original515 7c91d876411188bc2f02ffca9371f9e09d535325995c44b9d7d2c5089085730b. GNU-stripped515 is static PIE, stripped, with no PT_INTERP. Immutable binaries remain in job scratch. The exact raw Cargo-bloat JSON is retained as `bloat-a5f744fb.json.gz` and `bloat-515d3712.json.gz`; `bloat-evidence-manifest.json` records compressed/uncompressed hashes and sizes. Decompression was verified byte for byte before saving. The derived JSON retains section reconciliation and every nonzero item delta; compiler/load provenance and duplicate-symbol excerpts accompany it. Raw build logs are local evidence, with commands and results recorded on #129.

## Net crate attribution

Cargo-bloat crate attribution is a symbol heuristic under LTO; generic code is sometimes charged to std or to its caller. These are net changes, not sums of only added names. All nonzero crate rows follow.

| Crate | Baseline symbol bytes | Original515 symbol bytes | Delta bytes |
| --- | ---: | ---: | ---: |
| infraternal_agent | 324,438 | 349,534 | +25,096 |
| infraternal_plugin_remote | 46,892 | 60,654 | +13,762 |
| infraternal_server | 2,352,436 | 2,362,126 | +9,690 |
| std | 1,664,622 | 1,673,446 | +8,824 |
| serde_json | 186,276 | 190,334 | +4,058 |
| quinn | 71,646 | 75,265 | +3,619 |
| serde_core | 97,672 | 100,933 | +3,261 |
| infraternal_plugin_mesh | 466,374 | 468,888 | +2,514 |
| infraternal_plugin_api | 12,819 | 14,849 | +2,030 |
| quinn_proto | 441,718 | 443,131 | +1,413 |
| tokio | 317,619 | 318,702 | +1,083 |
| infraternal_protocol | 9,458 | 9,933 | +475 |
| bytes | 9,835 | 9,954 | +119 |
| sqlx_core | 179,558 | 179,573 | +15 |
| infraternal_plugin_host_facts | 27,868 | 27,876 | +8 |
| infraternal | 242,518 | 242,501 | -17 |

Net accounted symbol growth is **75,950 bytes**. Actual `.text` grows **76,736 bytes**: the remaining **786 bytes** are instruction alignment or code not assigned a reported function symbol. Baseline accounted symbols are 15,564,491 of 15,778,604 text bytes; original515 accounts 15,640,441 of 15,855,340.

## Items, offsets and functional justification

These families overlap the crate table and must not be added to it. Closure numbers and inlining boundaries change across revisions; a newly named function is not automatically wholly new code.

| Item or related family | Baseline bytes | Original515 bytes | Net bytes | Why it exists / offset |
| --- | ---: | ---: | ---: | --- |
| `server_path` supervisor/proof family | 0 | 44,632 | +44,632 | D215 candidate dial/proof while old path stays live, observed link status, retained-mesh restart, and fallback. Includes run closure18,245 and connect11,277 plus cancellation/drop state. |
| `remote_client::run_inner` family | 40,425 | 15,726 | -24,699 | Old monolithic dial/retry logic is replaced by that supervisor; ignoring this removal overstates supervisor growth. Combined supervisor + run_inner net19,933. |
| `quic_session` / `quic_session_on` family | 34,276 | 32,417 | -1,859 | Existing writer/session coordination is reused with proven stream/Receive support; renaming and new13741-byte session symbol do not mean13741 wholly additional bytes. |
| Remote router extraction plus `build_router_core` | 122,112 | 122,471 | +359 | New remote_router33,044 is almost completely offset by build_router_core shrinking32,685. Shared listener construction is not33KB duplicated code. |
| `remote_accept` family | 108,922 | 116,741 | +7,819 | One bounded authenticated pre-Hello Ping/Pong, recorded capabilities, additional destination classification, and existing durable certificate admission. Closure1→closure2 replacement offsets20,631 of its23,012-byte body. |
| `remote_link` family | 47,888 | 42,741 | -5,147 | Shared native/mux transport and proven greeting changes reduce existing transport glue; write_transport shrinks6,390 and pump1,990, offsetting new item names. |
| `RemoteListeners` family | 1,325 | 5,476 | +4,151 | Additional same-port listener lifecycle, shared admission limits, wildcard-address classification leases and owned cancellation. |
| NodeBridge `listen_server` family | 0 | 2,730 | +2,730 | Generic plugin listener capability; Mesh owns the lease rather than core hard-wiring a Mesh socket. |
| `client_config_with_liveness` | 0 | 5,922 | +5,922 | Common QUIC mTLS config with validated per-path timer inputs. The previous config was inlined into other bodies; this standalone size is not entirely incremental work. No new crypto engine/version. |
| TcpTls `Channel::write` and drop family | 5,498 | 12,528 | +7,030 | Extra candidate-proof call site retains a standalone asynchronous TLS write; much existing TLS write code shifts out of callers. `Transmit::send<TcpTls>` shrinks3,976. Not a new TLS implementation. |
| `run_channel` daemon generic family | 141,514 | 141,646 | +132 | Same122 symbol entries in both builds. No measured added daemon monomorphization family; attributing the90KB increase to this is unsupported. |
| ServerLink metadata-associated names | 0 | 6,862 | +6,862 | Typed actual transport status/reasons, serialization/deserialization and plugin compatibility. This includes generic serde costs also charged to serde/std. |
| Mesh Owner::node extraction plus plugin call | 30,959 | 31,797 | +838 | Standalone Owner::node3,973 offsets plugin call shrinking3,135; applied-address publication and status were added. |

The remaining crate-level changes include retained-input actor replay/splitting and full-Ack buffer release, watch/status ownership, generic serde expansion for optional coordinator server metadata and persistent-keepalive counters, and async drop/poll glue. This is new D128/D215 behavior with explicit state/cancellation requirements, not a dependency-version expansion. The `std`8,824-byte net row includes generic collection and future drop costs; `tokio`1,083, `quinn`3,619 and `quinn_proto`1,413 include newly reachable existing runtime/path/stat operations. Their version pins are unchanged.

Port policy adds explicit/ephemeral51820 exclusion, bounded reallocation,25-second persistent keepalive, and field-presence merging for multipart peer dumps. Original515 does **not** contain the separately reviewed translated-ingress firewall repair: firewall.rs/iptables.rs differ from this baseline only in test Config initializers. Thus this original90KB growth must not be charged to the later reviewed ingress/route-journal integration. The shipping test-only namespace proof feature and its large test fixtures do not activate with default features.

## Section reconciliation

| Section | Delta bytes |
| --- | ---: |
| .text | +76,736 |
| .gcc_except_table | +5,760 |
| .eh_frame | +7,240 |
| .eh_frame_hdr | +968 |
| .data.rel.ro | +1,408 |
| .relr.dyn | +24 |
| .rodata | 0 |
| Other listed file-backed alloc sections | 0 |
| Net listed file-backed alloc growth | +92,136 |
| File layout/alignment and stripping residual | -1,704 |
| GNU-strip file growth | +90,432 |

Unwind/exception growth is13,968 bytes. Release deliberately retains unwind so Tokio can isolate task panics; changing that is a foundational/profile decision requiring runtime evidence, not an acceptable attribution shortcut. `.relro_padding` NOBITS shrinks320 bytes and `.bss` is unchanged; neither is added file content. Symbol/debug sections explain the larger118,680-byte unstripped-file delta but are removed from the paired stripped outputs. No rodata increase was measured.

## Cleanup recommendations and limits

1. Keep the existing generic daemon dispatcher. It contributes only132 net bytes in this comparison; redesigning Channel to boxed dyn futures would add runtime/allocation costs without addressing the measured growth.
2. A targeted candidate experiment can call the existing `ControlChannel` enum from `prove_channel` for both QUIC and TCP instead of two concrete generic proof instantiations. Preserve the original authenticated stream and Receive through Hello. Proof bodies are inlined into11,277-byte connect; only two154-byte drop functions stand alone. Therefore no concrete byte saving is promised without a release rebuild and existing proof/coalesced-suffix tests plus latency validation.
3. `nm` confirms JSON BTreeMap clone_subtree has one2,279-byte symbol at baseline and two at515. Evidence names/addresses are in the duplicate-clone files. Same demangled name and size do not prove byte-identical code or removable behavior. A shared clone helper could be measured if this remains material; do not claim2,279 saved without identifying caller boundaries and a rebuild.
4. Retain the item-level functional costs above unless a measured cleanup preserves their behavior. No engine replacement, profile change, threshold waiver, or hypothetical savings is recommended. Round-two shipping growth must be measured separately after its final source state.

This evidence-only subtask does not run another workspace gate while the parent implementation is changing. The parent's required fresh `scripts/verify fast` output belongs to the final branch head; immutable original gate results remain historical evidence, not proof of round-two correctness.
