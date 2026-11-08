# GotaTun architecture study

**Job:** J201 · **Status:** research only · **Decision owner:** kayg

This study looks for architecture changes that can take the integrated GotaTun path past kernel WireGuard on loaded p99 and throughput, and past wireguard-go on throughput, while keeping its small idle footprint. It does not change a numbered decision or select a new foundational library.

## Current target and evidence

The current comparison supplied for this study is:

| Linux engine | Throughput, 1 / 8 flows | Loaded p99, 1 flow |
|---|---:|---:|
| Kernel WireGuard | 3.11 / 2.82 Gbit/s | 2.1 ms |
| wireguard-go | 4.93 / 4.92 Gbit/s | 38.9 ms |
| GotaTun fork | 3.01 / 2.67 Gbit/s | 6.1 ms |

The integrated GotaTun path is at 88–100% of kernel throughput, has no probe loss in the current comparison, and has an 8-flow loaded p99 about 3.5–4 times the kernel result. Its idle RSS is about 12 MiB across both ends. The current wireguard-go comparison reports 964 MiB after load. Those memory figures describe different phases, so they are not a same-state ratio; the paired hold below records both endpoints at the same phases. The goal is to shorten GotaTun's tail and raise throughput without losing its small idle footprint.

D346 makes GotaTun the Linux default once its integration branch merges, with kernel WireGuard as the explicit opt-out. D347 makes loaded p99 the first latency target. Performance parity remains a goal; the default switch does not lower it. D289 and D336 keep `ring` as the only crypto library unless kayg decides otherwise.

The table above is the owner's current reference, not a new D348-pinned hold. D348 says earlier unpinned results stay as history and must not be compared directly with new pinned results. The current perf VM has `AllowedCPUs=1-3` on `perf.slice` and reserves CPU0; its nested run scope cannot currently express a disjoint 0-1 / 2-3 split. J88i is checking whether a runtime-only widening and restoration can establish the requested two CPUs per endpoint without interference. No new hold counts until the effective masks, restoration and interference checks are proven. The existing J88h profile can rank hypotheses, but it is not a D348-pinned baseline.

J88h has already measured the stage bottleneck. In its tracer-only hold, the 8-flow RTT p99 was 17.0 ms. The TUN-to-encryption queue wait contributed 43% of tail excess, and encryption including batch mates contributed another 25%. A tail probe sat behind a median 2,634 packets; serial encryption cost about 4.3 µs per packet, implying a 2.56 Gbit/s ceiling for that build and hold. The TUN-to-buffer send stage was 0.005 ms p99 and `sendmmsg` was 0.61 ms p99 with no measured tail-excess share. Scheduler tracing also found 19.8 s of run-queue wait across a 14.3 s loaded phase and 23.5 thousand migrations. These are diagnostic measurements from a different, instrumented, unpinned hold, not replacement baseline numbers.

J88e raised the Linux TUN TX ring to 1,024 for devices GotaTun creates; this removed drops and lost probes in the paired hold, and the one-queue FIFO kept TCP order in the soak. If infraternal creates the device and passes it through `from_tun_device`, it must set `txqueuelen` to at least 1,024 for that increase to apply. TUN TSO/GRO, UDP batching/GSO/GRO and idle packet-pool release are also already integrated. J88g's sparse-first lane is not a kept baseline: its fixed version's 3% p99 change was inside run spread, throughput fell 2.2%, and the earlier version reordered TCP. J88h owns the bounded opportunistic batch, time-bounded queue, parallel crypto with ordered completion, TUN offload and two buffer-size-class candidates; its next planned cut is sojourn-bounded queueing after its current steps. This study does not duplicate or re-rank those cuts. Its roadmap starts with additional architecture seams and uses J88h's queue and crypto work as prerequisites.

## Reference data planes

### Linux kernel WireGuard

The kernel keeps bounded per-device encrypt/decrypt queues in `ptr_ring`; per-CPU crypto workers consume that work. On receive, crypto workers can finish packets out of order, so WireGuard also adds each packet to a per-peer previous-packet queue. The single consumer waits if the head packet is still being decrypted; once ready it validates the replay counter and passes the inner packet to `napi_gro_receive`. This combines parallel work with per-peer receive order. The code documents the multi-producer/single-consumer queue and the packet state explicitly in [`queueing.h`](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/queueing.h), [`queueing.c`](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/queueing.c), and [`receive.c`](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/receive.c).

NAPI processes packets in budgets rather than waking the stack for each packet. GRO then combines compatible packets for later stack work. The WireGuard integration paper describes the corresponding GSO/GRO path and the goal of retaining both single-flow and multi-flow performance ([WireGuard Linux integration techniques](https://www.wireguard.com/papers/wireguard-netdev22.pdf)). The `fq` qdisc is an underlay egress scheduler and pacer; it sees encrypted outer UDP flows. It cannot separate two inner flows carried to the same peer. See the [`fq` qdisc manual](https://man7.org/linux/man-pages/man8/tc-fq.8.html).

**Effect and cost.** The current local table is 3.11 / 2.82 Gbit/s and 2.1 ms loaded p99 at one flow. The separate `research/mesh-engines` measurements could not isolate kernel peer memory from shared kernel and network-stack allocations, so there is no defensible kernel per-peer number here. The per-CPU rings and workers are endpoint-wide, not a packet pool per peer; kernel memory must be measured from kernel accounting in a matching workload.

**Order, complexity and platform.** Per-peer RX order is protected even while decrypt work is parallel. The implementation depends on kernel networking internals, NAPI, GRO/GSO, qdiscs and kernel crypto. It is not a reusable userspace API and is Linux-only. GotaTun should copy the invariants that matter, not assume that its userspace worker queues inherit kernel ordering.

### wireguard-go, Tailscale and BoringTun

wireguard-go's Linux bind supports batches (its current source sets an ideal batch size of 128), and its Linux path uses UDP GRO/GSO and TUN offloads. Tailscale's engineering post reports a best-case 2.2× wireguard-go throughput gain from TSO, GRO and `sendmmsg`/`recvmmsg`, and up to 33% for Tailscale in its test setup. A separate post reports large UDP GSO/GRO gains for wireguard-go. Those are throughput results on their machines, not evidence of a p99 improvement in this benchmark: [TSO/GRO and `mmsg`](https://tailscale.com/blog/throughput-improvements), [UDP GSO/GRO](https://tailscale.com/blog/quic-udp-throughput).

A September 2026 Tailscale engineering post describes retaining packet offsets inside a large GRO read rather than copying each small packet into a 64 KiB buffer. It reports about 5% more speed in many configurations and describes stable per-stream userspace lanes; it does not quantify a multi-queue gain. Both ideas are relevant to GotaTun's superframes and flow ownership, but those numbers are not transferable without a hold: [buffer and queue work](https://tailscale.com/blog/making-tailscale-faster).

The separate `research/mesh-engines` study measured 37,614 B of incremental process RSS per wireguard-go peer at 1,000 peers and 20,017 B for GotaTun, per engine process. That workload is not the current two-end loaded comparison, which reports 964 MiB for wireguard-go after load; do not divide that aggregate by an unrelated peer count. BoringTun is a portable Rust userspace WireGuard implementation. Its pinned Linux CLI uses multiple TUN queues for concurrency, but the measured source snapshot used per-packet UDP I/O and had no TUN vnet-header offload or UDP GSO/GRO. See [BoringTun](https://github.com/cloudflare/boringtun), [its Linux TUN adapter](https://github.com/cloudflare/boringtun/blob/boringtun-cli-0.5.2/boringtun/src/device/tun_linux.rs), and [its UDP adapter](https://github.com/cloudflare/boringtun/blob/boringtun-cli-0.5.2/boringtun/src/device/udp_unix.rs).

The separate `research/mesh-engines` CLI run measured 18,760 B of incremental process RSS per BoringTun peer at 1,000 peers; it does not split that growth into protocol state, queue workers and packet buffers. The multi-queue setup does not by itself promise stable order if a flow changes queues. BoringTun demonstrates that its engine API can be shared between Linux and macOS, while its Linux TUN acceleration remains platform-specific. These measurements and designs do not predict how an integrated GotaTun path will behave.

These reference implementations show that batching and offload matter, but GotaTun already has TUN TSO/GRO, UDP `sendmmsg`/GSO and receive batching/GRO in the integration. J88h observes 19–23 KiB TUN reads and does not find the UDP send call in the 8-flow tail. Repeating the offload work has no expected gain to claim. The question now is how to keep queues shallow while using more crypto capacity.

### Linux TUN/UDP offloads and batched syscalls

**What it is.** TUN TSO/GSO lets the kernel hand userspace a large packet with segmentation metadata; the tunnel splits it before encrypting. GRO combines compatible received packets before TUN writes. UDP GSO sends a larger buffer as several encrypted UDP datagrams; UDP GRO receives multiple datagrams in one read. `sendmmsg` and `recvmmsg` send or receive a vector of messages per syscall. The Tailscale posts above report 2.2× best-case wireguard-go throughput for TSO/GRO plus mmsg and large additional UDP GSO/GRO gains in their own setups.

**GotaTun impact and memory.** These features are already integrated, so expected new throughput or p99 gain is zero without a regression in the existing implementation. They target syscalls per Gbit and throughput, not the J88h serial crypto queue. There is no per-peer persistent cost. Endpoint memory is the number of in-flight read batches times the maximum frame size and descriptor array; Linux can present up to about 64 KiB per TSO/GRO buffer, though J88h observed 19–23 KiB reads. Batch descriptors and packet buffers must have hard caps.

**Order, risk and platform.** TSO splitting and GRO coalescing preserve compatible flow order, but parsing vnet headers, checksums, segment sizes and fallback behavior must be correct. Waiting to fill a batch adds p99, so use packets already ready and flush promptly. These are Linux kernel features. macOS `utun` has no vnet header, TUN TSO/GRO or UDP GSO/GRO equivalent. Apple's `NEPacketTunnelFlow` can read and write packet arrays; a low-level `utun` adapter uses the `com.apple.net.utun_control` kernel control and a four-byte address-family prefix per packet. The [wireguard-go Darwin adapter](https://github.com/WireGuard/wireguard-go/blob/master/tun/tun_darwin.go) shows the prefix and one-packet-per-read behavior.

No new crypto or transport library is needed for Linux offloads; they use the existing TUN and UDP socket APIs. This is baseline code, not a new roadmap cut.

## Candidate designs

Effects below separate measured source results from estimates for GotaTun. When there is no comparable result, the size is explicitly unknown and must be decided by the R4b hold.

### Linux TUN multi-queue with stable flow steering

**What it is.** Attach several file descriptors to one TUN interface with `IFF_MULTI_QUEUE`, then let one reader/writer pair own each queue. Linux TUN keeps a flow-hash-to-queue table and can also use an eBPF steering program. In v6.12 the table has 1,024 buckets; the flow entry remembers a queue index. See the [TUN documentation](https://docs.kernel.org/networking/tuntap.html) and [v6.12 `tun.c`](https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c).

**Target and expected size.** Targets CPU/Gbit and throughput if one TUN reader or writer serializes enough traffic. A p99 gain is possible only if the TUN wakeup or one queue is a measured tail source. J88h's TUN read-to-buffer handoff is 0.005 ms p99 and 0% excess share, so the current profile does not justify predicting a large p99 gain. Linux supports this feature since 3.8; the source provides no transferable throughput number for this GotaTun workload. Expected effect: unknown until measured.

**Memory and ordering.** No per-peer allocation is required. Endpoint memory is `queue_count × (TUN queue state + bounded in-flight packet buffers)` plus the kernel's flow table; the flow table is device-wide. A stable flow-to-worker assignment keeps a flow on one FIFO. Do not assume Linux queue migration is order-safe: `tun.c` has a TODO about continuing to queue on the old queue until it drains. Keep mappings stable while active, or explicitly drain before remapping. J88g's two-lane attempt shows why this matters: one version caused 90,299 out-of-order receive segments; the fixed version improved p99 by only 3%, inside run spread, and reduced 8-flow throughput 2.2%, so it was rejected.

**Complexity, platform and foundation.** Medium/high: queue lifecycle, flow hashing, backpressure, one worker per queue, CPU mapping, and resize behavior all need coverage. Linux `IFF_MULTI_QUEUE` already exists, but J88e notes the current `tun` crate rejects more than one queue. A new TUN adapter or foundational library would be an owner decision after measuring options; do not choose one here. There is no equivalent `IFF_MULTI_QUEUE` or TSO/GRO interface on macOS. The macOS packet-tunnel API can return and accept packet arrays, but that is a separate adapter.

### Shared TSO/GRO frame with packet offsets

**What it is.** Keep the large TUN superframe in one backing buffer and describe its inner segments with offsets and lengths, rather than copying every segment into its own full-capacity buffer. Tailscale reports roughly 5% speed improvement in many configurations from this change, plus lower memory use for small packets in large reads ([recent engineering post](https://tailscale.com/blog/making-tailscale-faster)).

**Target and expected size.** Targets CPU/Gbit, memory and potentially throughput. The source's 5% result is a useful bound to test, not a forecast. It does not shorten a deep encryption queue by itself, so no independent loaded-p99 gain is expected. GotaTun already receives 19–23 KiB TUN reads; the test should first determine whether its deaggregation path copies packet payloads.

**Memory and ordering.** Per peer: zero fixed bytes. Per endpoint: one retained superframe for all its packet views, plus segment descriptors; peak backing memory is the count of batches still in crypto times the superframe size. Offset ranges preserve input order. The shared buffer cannot return to the pool until the last view completes. Parallel in-place AEAD must not create aliased mutable slices; either serialize mutation of each backing frame or give workers distinct writable buffers. A slow final segment can retain the whole frame and erase the RSS gain.

**Complexity, platform and foundation.** Medium: ownership and lifetime proof, no new crypto library. The same internal representation can work on macOS, but macOS `utun` has no Linux TSO/GRO superframes; the benefit there would come only from batching packet arrays.

### Worker placement and NUMA locality

**What it is.** Place TUN, crypto and UDP work on a small, measured set of CPUs and keep each flow's state and packet buffers near the worker that owns it. On a multi-socket host, allocate buffers local to that worker's NUMA node. This is a product scheduling experiment, separate from D348's benchmark cpusets, which pin both test endpoints for fairness.

**Target and expected size.** Targets loaded p99 and CPU/Gbit. J88h saw 19.8 seconds of run-queue wait and 23.5 thousand migrations in a 14.3 second phase; this makes scheduler contention a credible target, but the hold colocated two endpoints and is not a production topology. A recent WireGuard scalability study shows that threaded NAPI and improved placement materially change multi-tunnel throughput on 32-core gateways (about 13 to 48 Gbit/s with 16 tunnels); that result does not predict a single tunnel on a 2-CPU endpoint. See [the Netdev 0x18 paper](https://netdevconf.org/0x18/docs/netdev-0x18-paper23-talk-paper.pdf) and [the 2025 follow-up study](https://iris.polito.it/handle/11583/3002749). Expected GotaTun p99/throughput size: unknown; measure after the pinned baseline.

**Memory and ordering.** No per-peer memory. Endpoint cost is worker stacks, per-worker queues and any per-CPU buffer cache; do not create a thread per peer. Pinning a flow to one worker preserves order if its worker has a FIFO. Rebalancing flows across workers needs a drain or sequence fence. Poor placement can make p99 and throughput worse by pinning work to a busy CPU.

**Complexity, platform and foundation.** Low/medium on Linux if kept behind configuration; no new foundational library or kernel feature. macOS offers scheduling and QoS controls but not the same hard CPU-set contract, so treat CPU pinning as Linux-only and keep the portable scheduler independent of it. NUMA is relevant only on real multi-node hosts; the current four-vCPU perf VM cannot establish its gain.

### One fair scheduler for peers and inner flows

**What it is.** Put one scheduler before encryption. Use a FIFO per inner 5-tuple and a two-level policy: share service among peers, then among that peer's active flows. A deficit-round-robin or FQ scheduler can serve sparse flows promptly while limiting the service share of a bulk flow. Keep one arbitration point; do not add a second “sparse” queue that races the bulk queue.

**Target and expected size.** Targets p99 for interactive packets while a bulk transfer is active, plus fairness between peers. It is not expected to change the one-flow p99 because there is no competing flow to protect. RFC 8290 describes FQ-CoDel's per-flow queue isolation and delay control; that is an architectural basis, not a GotaTun throughput result ([RFC 8290](https://www.rfc-editor.org/rfc/rfc8290.html)). J88g's fixed idle-flow lane moved p50 but not p99 and failed its 2.2% throughput guard, which argues for measuring the one-scheduler design rather than restoring the lane.

**Memory and ordering.** Per-peer cost is active-flow metadata plus its bounded queued packets; endpoint cost is capped by `max_queued_bytes` plus per-flow state. Set limits for both active flows and bytes so churn cannot grow memory without bound. A single FIFO per flow preserves order. Crypto completion must preserve that order, as in the kernel's per-peer previous queue. Flow-key collisions can reduce fairness; fragments and IPv6 extension headers need a safe classification fallback.

**Complexity, platform and foundation.** Medium/high. No new kernel feature or foundational library is required. An internal parser and scheduler must be reviewed for malformed packets and per-flow state exhaustion. This design works on macOS because scheduling happens above the platform TUN adapter. The Linux `fq` qdisc alone is insufficient: it only sees the encrypted peer UDP tuple, not individual inner flows.

### TUN backpressure and sojourn AQM

**What it is.** Bound queues by residence time as well as packet count. On Linux, TUN's `IFF_BACKPRESSURE` can leave packets in the qdisc instead of dropping them when its userspace ring is full. A userspace queue can use CoDel-style sojourn tracking. The kernel TUN docs warn that backpressure requires a qdisc and can cost performance with multiple streams ([TUN qdisc backpressure](https://docs.kernel.org/networking/tuntap.html)).

**Target and expected size.** Targets p99 and memory by stopping a deep standing queue. J88h's model estimated a 5 ms target could reduce an approximately 3.6 MB standing queue to about 1.6 MB and give 8-flow p99 around 8.1 ms; a 2 ms target estimated around 7.0 ms. These are modelled values, not measured results. J88h ranked CoDel behind its batch cap because drops can lower TCP throughput, while a small queue cap may already remove most of the probe tail.

**Memory and ordering.** No per-peer static bytes for a single queue; memory is bounded by queued packet bytes. At 2.56 Gbit/s, 5 ms of queue is about 1.6 MB per direction before packet metadata. With per-flow scheduling, add one small state record per active flow. Dropping or marking a packet does not reorder survivors, but drops cause retransmits; loss-aware p99 counts any lost probe as infinite.

**Complexity, platform and foundation.** Medium. Linux `IFF_BACKPRESSURE` and qdiscs need no new library; an in-process AQM is portable. macOS has no Linux TUN qdisc or `IFF_BACKPRESSURE`; only the userspace queue design transfers. Do not add an AQM until the R4b hold shows the queue remains after the J88h batch work.

### ECN and L4S

**What it is.** ECN marks congestion in the IP header instead of dropping the packet. L4S combines ECN with a scalable congestion controller and a DualQ AQM; it is not just a different CoDel setting. Tunnel endpoints must propagate congestion indications correctly across outer and inner IP headers under [RFC 6040](https://www.rfc-editor.org/rfc/rfc6040.html) and [RFC 9601](https://www.rfc-editor.org/rfc/rfc9601.html). L4S requirements are in [RFC 9330](https://www.rfc-editor.org/rfc/rfc9330.html), [RFC 9331](https://www.rfc-editor.org/rfc/rfc9331.html) and [RFC 9332](https://www.rfc-editor.org/rfc/rfc9332.html).

**Target and expected size.** Targets queue delay and loss under congestion, with potential throughput benefit when senders respond to CE. No local GotaTun result quantifies it. A small userspace queue may mark CE on inner ECN-capable packets; outer-path CE must be correctly copied back during decapsulation. L4S cannot be assumed on arbitrary paths or clients, so its expected gain for this product is unknown.

**Memory and ordering.** ECN itself adds no per-peer state. AQM queue memory is the byte cap described above; a DualQ adds a second queue and classifier per endpoint. Marks preserve packet order. Incorrect ECN propagation can corrupt congestion behavior, and marking a Not-ECT packet is not valid.

**Complexity, platform and foundation.** High correctness risk, moderate CPU cost. No crypto library is needed, but this changes tunnel packet semantics and needs exact IPv4/IPv6 tests. Linux can use qdisc support. macOS needs userspace AQM and the same RFC behavior; no Linux L4S qdisc can be assumed.

### io_uring for TUN and UDP

**What it is.** Use a shared submission/completion ring to drive reads and writes, optionally with registered buffers, multishot receives and zero-copy sends. UDP sockets support multishot receive and registered/provided buffer patterns. `IORING_OP_SEND_ZC` can retain a registered send buffer until the completion notification. See the [io_uring manual pages](https://man7.org/linux/man-pages/man7/io_uring.7.html), [multishot operations](https://man7.org/linux/man-pages/man7/io_uring_multishot.7.html), [registered buffers](https://man7.org/linux/man-pages/man7/io_uring_registered_buffers.7.html), and [`send_zc`](https://man7.org/linux/man-pages/man3/io_uring_prep_send_zc.3.html).

**Target and expected size.** Targets syscall cost, wakeups and CPU/Gbit. There is no published result predicting a GotaTun gain. J88h already batches UDP syscalls and did not find `sendmmsg` in the tail; expected p99 gain is therefore small unless a new profile identifies syscall or wakeup cost. On TUN, basic async `read`/`write` and multishot read support depend on the exact file operations and kernel version; test Linux 6.12 directly. Do not assume socket-only `SEND_ZC` works on `/dev/net/tun`.

**Memory and ordering.** Per peer: none if buffers are shared. Endpoint memory is `registered_buffer_count × buffer_size` plus submission/completion rings. For example, 256 registered 4 KiB buffers reserve 1 MiB, before queue and ring metadata. Every send buffer remains owned until its completion notification. Each UDP socket remains ordered at the socket API, but multiple outstanding crypto or TUN completions still need per-flow sequence control.

**Complexity, platform and foundation.** High: cancellation, buffer lifetime, kernel-version feature checks, fallback paths and error completion. It is a transport/runtime foundation choice. Candidate Rust crates include [`io-uring`](https://crates.io/crates/io-uring) and [`tokio-uring`](https://crates.io/crates/tokio-uring); jobs may benchmark candidates but the owner must choose. No io_uring on macOS; keep the existing portable path as the fallback.

### AF_XDP

**What it is.** Bind an XDP socket to one NIC queue and exchange packet descriptors through memory-mapped fill, RX, TX and completion rings. UMEM is a registered pool of equal-sized frames. Zero-copy is available only when the NIC driver supports it; the kernel docs make driver feature discovery explicit ([AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html)).

**Target and expected size.** Targets CPU/Gbit and high-rate throughput by bypassing much of the normal socket path. No result transfers to GotaTun's current netns/veth R4b case. J88h points at crypto and queue age first, so AF_XDP has no credible p99 estimate until those costs fall. Expected GotaTun gain: unknown, and could be zero in copy mode.

**Memory and ordering.** No per-peer UMEM. Endpoint memory is `frame_count × frame_size` per UMEM plus descriptor rings per queue. A 4,096-frame, 2 KiB pool is 8 MiB before metadata, enough to erase the idle-memory margin if duplicated per endpoint or queue. One socket is tied to one device queue; one shared UMEM can serve multiple sockets. Preserve per-flow queue selection and FIFO order above those rings.

**Complexity, platform and foundation.** Very high: XDP program, privileged interface setup, driver capability checks, routing, checksum/segmentation, packet fragmentation, MTU/PMTU, network changes and fallback. This is a new Linux data plane and BPF/XDP library choice. Rust candidates include [`aya`](https://crates.io/crates/aya) and [`libbpf-rs`](https://crates.io/crates/libbpf-rs); the owner must select if the path is ever justified. No macOS equivalent. Do not pursue unless profiles show the NIC/socket path remains dominant after crypto work.

### `MSG_ZEROCOPY` on the UDP socket

**What it is.** Ask Linux to send from caller-owned pages without copying them into the socket buffer; reclaim the buffer after an error-queue completion. It applies to socket sends, not the TUN character device. The kernel says it is generally effective only for writes above about 10 KiB because page pinning and completion have their own cost ([kernel documentation](https://docs.kernel.org/networking/msg_zerocopy.html)).

**Target and expected size.** Targets CPU/Gbit and throughput, not queue residence. Individual encrypted packets are around MTU size, below the useful threshold, but GSO can combine many into one send. Test only if the actual UDP send size exceeds 10 KiB. J88h measured no sendmmsg tail-excess share, so expect no p99 gain. There is no transferable throughput number.

**Memory and ordering.** No fixed per-peer bytes. Endpoint memory is pages held until send completions, roughly the in-flight zerocopy bytes plus per-send completion bookkeeping; it may increase pool retention. Completion order is not a substitute for packet order, but UDP sends issued in order remain submitted in that order. Keep the existing sequence path around sends.

**Complexity, platform and foundation.** Medium: error-queue draining, pin limits, buffer lifetime, copy fallback and GSO interaction. No new library; requires Linux socket support and `SO_ZEROCOPY`. macOS has no compatible `MSG_ZEROCOPY` API.

### Multi-buffer SIMD ChaCha20-Poly1305

**What it is.** Encrypt several independent packets in SIMD lanes together. This is different from `ring` using SIMD within one packet, or from running separate `ring` calls on several CPU workers. `ring` exposes a one-message mutable buffer operation (`LessSafeKey::seal_in_place_separate_tag`), not a multi-message job API ([ring AEAD docs](https://docs.rs/ring/latest/ring/aead/struct.LessSafeKey.html)). Intel's [IPsec Multi-Buffer library](https://github.com/intel/intel-ipsec-mb) documents a ChaCha20-Poly1305 job API.

**Target and expected size.** Targets the largest throughput gap and CPU/Gbit. J88h's one serial crypto task measured about a 2.56 Gbit/s ceiling in its profile. Multi-buffer crypto could raise that ceiling, but the library's algorithm support alone does not give a GotaTun speedup estimate; do not transfer AES results or long-message crypto rates to WireGuard packet sizes. Batch waiting can increase p99, so the API must accept the packets already ready and must not wait to fill a vector batch. There is no expected gain number until a 64/512/1,380-byte packet microbenchmark and a full R4b hold.

**Memory and ordering.** Per-peer: no additional permanent queue if key state remains in the current ring path. Endpoint: one job manager and scratch/state per crypto worker, plus bounded in-flight packet buffers; measure exact resident bytes. Completion can be out of order and needs per-peer ordered release. Batch depth must be bounded to keep the 12 MiB idle target.

**Complexity, platform and foundation.** High correctness and build risk: extra cryptographic implementation, unsafe FFI, feature dispatch, side-channel review, vector tests, cross-builds and fallback. This is a second foundational crypto library, forbidden without an owner decision. D336 says to keep `ring` and optimize; D289 records the earlier AWS-LC option at about +2.68 MB. The recommendation is to first measure J88h's parallel `ring` calls; only if they fail the throughput target should the owner consider a separate multi-buffer library. Intel IPsec MB is an x86-oriented option; Apple Silicon and other supported architectures need separate measurements. macOS keeps `ring` unless the owner makes a cross-platform crypto choice.

### Bounded SPSC rings between stages

**What it is.** Replace a shared multi-producer channel with a bounded single-producer/single-consumer ring between two fixed stages. Linux AF_XDP uses this ownership model for its rings; the same model can reduce cache-line contention in an application queue.

**Target and expected size.** Targets handoff CPU/Gbit and wakeup delay, but not queue depth. J88h's TUN-to-buffer enqueue is 0.005 ms p99, while waiting behind packets is 10.83 ms. Replacing the channel alone has no expected p99 effect unless lock/wakeup cost appears in a fresh profile. Size: likely negligible at this queue stage; no measured GotaTun gain.

**Memory and ordering.** No per-peer bytes when rings are per stage or worker. Memory is `ring_slots × descriptor_size` plus the already-owned packet buffers; 256 16-byte descriptors are 4 KiB per ring. Do not copy payloads into the ring. A single producer and consumer naturally preserves ring order. Multiple producers need separate rings or a different algorithm; never quietly turn it into an unsafe shared queue.

**Complexity, platform and foundation.** Medium/high for lock-free memory ordering and shutdown. Rust's `forbid(unsafe_code)` means a custom ring may not be allowed in the integration crate. No kernel feature; if a new queue crate becomes necessary, benchmark it and bring the dependency choice to the owner. The design is portable to macOS.

### Busy polling

**What it is.** Keep polling a UDP socket's NAPI context briefly instead of sleeping and waiting for an interrupt/wakeup. Linux exposes `SO_BUSY_POLL` and `SO_PREFER_BUSY_POLL` for socket/NAPI polling ([NAPI documentation](https://docs.kernel.org/networking/napi.html)).

**Target and expected size.** Targets receive wakeup p99 for the outer UDP socket. It cannot shorten the 2,634-packet crypto wait. J88h measured a 2.74 ms p99 veth/socket/re-wakeup segment at 8 flows, 10% of excess share, so a small benefit is possible after crypto queueing is controlled. No transferable size; CPU/Gbit and idle CPU may worsen materially.

**Memory and ordering.** No per-peer memory; a short socket polling window and the existing receive buffers are endpoint-wide. It does not reorder packets. A busy poller can starve other work on the same core if placement is wrong.

**Complexity, platform and foundation.** Low/medium, but requires a NAPI-capable Linux socket/device path and careful CPU/power measurement. It does not apply to the TUN fd itself and has no matching macOS control. No new library.

### Timer wheel

**What it is.** Put many delayed actions into shared timer buckets rather than creating one timer and wakeup per packet or flow.

**Target and expected size.** It would target timer allocations and wakeups, not the measured crypto queue. In the examined fork, one device timer task loops over peers while timer state remains per peer; J88h did not identify timer work in the loaded tail. Expected p99 and throughput gain: zero until a profile says timers are hot.

**Memory and ordering.** Per timed peer or flow, one timer node and bucket link; endpoint memory is proportional to active timers, not queued packet bytes. Timers do not reorder packets, but expiration must not cancel packets already handed to crypto.

**Complexity, platform and foundation.** Low/medium if reusing the existing runtime timer; no new library is needed. A shared wheel can work on macOS. Do not build one as part of this performance roadmap without timer evidence.

## Ranked roadmap beyond J88h

J88h's existing bounded-batch cut remains the immediate prerequisite. Its later parallel-crypto cut is the best direct route to throughput, and must retain per-peer ordered completion. The independent cuts below are ranked by fit to the measured GotaTun gaps, implementation cost and risk.

### Shared R4b hold and keep rule

After J88i proves the D348 mask widening/restoration, change only one architecture choice per `perf-run --root` hold. Run kernel, control, candidate twice, control, kernel, using the same candidate binary for both samples and the same build host for control and candidate. Pin each endpoint plus its load and probe to a disjoint two-CPU set. Before counting the hold, prove the effective masks, restoration, no unrelated runnable work on the measured CPUs and control spread no worse than the unpinned harness. Record throughput at 1/8 flows, raw ICMP loss-aware p99 at 1/8 flows (each lost probe contributes infinite RTT before nearest-rank p99; at 3,600 probes, 37 or more losses makes p99 infinite), CPU seconds/Gbit, queue residence, drops/reorders/retransmits and RSS for both ends at idle, after load, after 15 seconds idle, and at 1,000 peers.

Each cut declares one primary target before its hold. Keep a latency cut only if its target p99 improves outside control spread, there is no loss or order regression, throughput stays within 3%, and the other tested p99 does not regress outside spread. Keep a throughput/CPU cut only if its target throughput or CPU/Gbit improves outside spread, both p99s do not regress outside spread, and it loses no probes. Keep a memory cut only if its target RSS improves outside spread and throughput/p99 do not regress outside spread. Every kept cut then passes a one-hour soak with TCP reorder, retransmits and TUN/UDP ring drops no worse than control. All cuts must return to about 12 MiB idle RSS across both ends 15 seconds after load; at 1,000 peers compare incremental process RSS per peer to a same-hold control and report it without an invented absolute threshold. The end goal is stricter than any one intermediate keep: exceed wireguard-go's 4.93 / 4.92 Gbit/s, beat kernel WireGuard's 2.1 ms one-flow loaded p99 with no loss, and retain the idle-memory guard.

| Rank | Cut and gap | Expected size and evidence | Independent keep rule |
|---|---|---|---|
| 1 | **Worker placement** after a valid D348 baseline. Assign TUN, crypto and UDP workers to tested CPUs and keep buffers local. Targets loaded p99 and CPU/Gbit. | No transferable percent. J88h measured 19.8 s run-queue wait in a 14.3 s phase. The 2025 threaded-NAPI study reports 13→48 Gbit/s for 16 tunnels on 32-core gateways but no single-tunnel gain; neither result predicts GotaTun here. | Keep only if p99 or CPU/Gbit improves outside spread, with no lost probes, no p99 regression at the other flow count and at most 3% throughput loss. Confirm on a production-like one-agent-per-host setup before defaulting placement. |
| 2 | **Per-peer and per-inner-flow FQ.** One scheduler, per-flow FIFO, byte cap. Targets interactive p99 under bulk traffic and peer fairness, not one-flow p99. | No source gives a GotaTun number. RFC 8290 supplies the design; J88g's sparse lane reordered TCP, while the fixed lane's 3% p99 change was within spread and throughput fell 2.2%. | Keep only if an interactive probe's 8-flow p99 improves outside spread at matched offered load, throughput loss stays within 3%, and the soak has no added reorder or retransmits. |
| 3 | **Shared TUN superframe with offsets.** Avoid copying each small segment into a separate full-capacity buffer. Targets memory and CPU/Gbit. | Tailscale reports about 5% speed improvement in many configurations; no local result and no expected standalone p99 win. | Keep only if bytes copied or CPU/Gbit falls outside spread, throughput does not fall over 3%, p99 does not regress, and the backing frame pool returns to the idle RSS guard after 15 seconds. |
| 4 | **Linux TUN multi-queue with stable flow mapping.** One reader/writer pair per queue, stable 5-tuple owner. Targets throughput and CPU/Gbit only if TUN service is a measured bottleneck; the current `tun` crate rejects multiple queues, so an adapter/library change may be required. | Unknown. Linux has `IFF_MULTI_QUEUE` and flow steering, but J88h measured a 0.005 ms TUN-to-buffer enqueue and 0% tail-excess share. | First require a new profile to show TUN service cost outside noise. Then keep only if throughput or CPU/Gbit improves outside spread, both p99s do not regress, flows stay on one FIFO until drained, and the soak adds no reorders or retransmits. |
| 5 | **Busy polling** the UDP socket briefly. Targets receive wakeup p99 after queue and crypto work is reduced. | No transferable gain. J88h measured a 2.74 ms veth/socket/wakeup p99 segment and 10% excess share in its instrumented 8-flow phase. | Keep only if raw p99 improves outside spread, no probes are lost, throughput stays within 3%, and CPU/Gbit and idle CPU remain within the declared budget. |
| 6 | **Bounded SPSC rings between stages**, only if a fresh profile finds channel contention. Targets handoff CPU/Gbit and wakeups. | No local gain: J88h measured a 0.005 ms TUN-to-buffer enqueue against 10.83 ms queued wait. | Skip unless lock/wakeup cost is measurable. If tested, keep only if handoff cost or CPU/Gbit improves outside spread with no p99, throughput, ordering or memory regression. |
| 7 | **UDP `MSG_ZEROCOPY`** only for GSO sends above 10 KiB. Targets CPU/Gbit. | Linux says zerocopy is generally worthwhile above about 10 KiB; the actual GotaTun send-size distribution is not yet reported, and J88h found no UDP-send p99 share. | First report send-size distribution. Keep only if enough sends exceed 10 KiB to lower CPU/Gbit outside spread, while p99 and throughput do not regress and completion backlog/RSS stay bounded. |
| 8 | **io_uring feasibility spike** for UDP and TUN separately. Targets syscalls, wakeups and CPU/Gbit. This is a measurement, not an approved product transport. | No transferable numerical result. Existing batch syscalls are present and not in the measured p99 tail. | Prototype only if a fresh profile shows syscall or wakeup cost. Keep as a candidate only with repeatable CPU/Gbit or p99 gain, bounded registered-buffer RSS, ordered completion and a working Linux 6.12 TUN path; then take the crate choice to the owner. |
| 9 | **ECN and L4S-style AQM**, after ordinary queue control. Targets p99 and loss under supported congestion paths. | RFCs define tunnel ECN propagation and DualQ; no GotaTun result, and arbitrary peers or underlays may not use ECN/L4S. | Measure against the same AQM without ECN using ECN-capable traffic. Keep only if loss-aware p99 improves at matched throughput, CE marks are valid and correctly propagated, and there are no order or correctness failures. |
| 10 | **AF_XDP feasibility spike**, only if the NIC path dominates after crypto and queue costs fall. Targets CPU/Gbit and throughput. | Unknown on our hardware; zero-copy requires driver support. A 4,096 × 2 KiB UMEM is 8 MiB per endpoint before metadata. | No product cut until hardware zero-copy is verified and the prototype beats the socket path outside spread, meets p99/order requirements and stays inside the idle-memory guard. The owner chooses the BPF/XDP stack first. |
| 11 | **Multi-buffer SIMD crypto**, only if parallel `ring` workers miss the throughput target. Targets throughput and CPU/Gbit, with p99 risk from batch wait. | No defensible speed estimate for WireGuard packet sizes. Intel IPsec MB has a ChaCha20-Poly1305 job API; `ring` exposes per-message calls, not a multi-message API. | First measure parallel `ring`. A second library needs owner approval. Compare 64/512/1,380-byte messages and full R4b p99/order/RSS; keep only if throughput improves outside spread, p99 does not regress, order is preserved and idle RSS stays within budget. |

Do not add a timer wheel unless timers appear in a new profile. Do not spend an R4b hold repeating TUN/UDP offload work already present. NUMA is a later host-scale study, not a four-vCPU VM cut. Busy polling, SPSC rings and ECN/L4S stay conditional on the stage or path evidence stated above.

### Optional quick probes

No perf-VM probe was run for this docs-only study. J88h already measured CPU headroom, queue residence and per-stage p99, and those results show the dominant crypto and run-queue costs. Kernel v6.12 source confirms TUN multi-queue and flow steering exist, while J88h shows the current TUN handoff is not the dominant tail. A TUN capability-only probe would not establish a performance gain; a candidate must be measured as its own pinned R4b cut. If one is run later, it must use the perf VM lock and finish in the foreground.

## Owner questions

These are foundational choices. The jobs can measure them; only the owner can choose.

1. **Should we authorize a measurement-only io_uring spike for TUN and UDP, and which Rust interface should it compare?** J88h measured 0.61 ms p99 for `sendmmsg` but no tail-excess share, so there is no current p99 case; a new profile must show syscall or wakeup cost. Benchmark TUN and UDP separately: registered-buffer and multishot support varies by operation and kernel, `SEND_ZC` is a socket operation, and 256 registered 4 KiB buffers reserve 1 MiB per endpoint before ring metadata. Completion lifetimes, order and bounded RSS need proof. macOS needs its existing `utun` adapter; `NEPacketTunnelFlow` exposes packet arrays for a Network Extension host. Candidate crates are `io-uring` and `tokio-uring`. **Recommendation:** defer product adoption; if a profile exposes syscall or wakeup cost, compare both interfaces on the affected path and bring the measured memory, correctness and CPU/Gbit results back before choosing a foundation.

2. **Should AF_XDP remain out of scope unless later profiling shows the NIC path dominates?** It replaces the normal Linux socket path, needs an XDP program, a supported driver and a large fixed UMEM pool, and has no macOS equivalent. Candidate Rust stacks include `aya` and `libbpf-rs`. **Recommendation:** defer. Crypto and queue residence dominate current evidence, and an 8 MiB pool per end conflicts with the idle-memory advantage. Revisit only after those stages are improved and hardware zero-copy is verified.

3. **If parallel `ring` does not meet throughput, may we benchmark a second crypto library for multi-buffer ChaCha20-Poly1305?** `ring` exposes one-message AEAD calls; Intel IPsec MB exposes a ChaCha20-Poly1305 job API, but adds a C library, unsafe FFI, architecture dispatch, build and validation work, and likely a separate ARM/Apple path. There is no directly comparable WireGuard-packet speed number yet. Per-peer state should remain unchanged, while each worker adds a library context and scratch memory; binary and RSS deltas must be measured. D289 and D336 keep `ring`. **Recommendation:** first measure parallel `ring`, which changes no library. If it misses the pinned 8-flow throughput target, ask for a separate opt-in library spike with correctness vectors, 64/512/1,380-byte microbenchmarks, RSS, binary size and x86_64/aarch64 results. Do not switch libraries in this job.

4. **If a profile shows TUN service is limiting, should we compare a multi-queue adapter with the current TUN library?** Linux `IFF_MULTI_QUEUE` has kernel support, but J88e records that the current `tun` crate rejects more than one queue; any replacement is a foundational packet-I/O choice. Each queue adds bounded buffers and a reader/writer pair, and queue remapping needs draining to preserve flow order. macOS keeps its separate `utun` adapter and has no Linux multi-queue TUN feature. **Recommendation:** defer while the measured TUN handoff remains 0.005 ms p99 with no tail-excess share. If a fresh profile shows TUN CPU or queueing is material, compare the current adapter with alternatives and bring per-queue RSS, throughput, p99, ordering and platform results to the owner before selecting a library.

## Sources

### Project evidence

- [#260, GotaTun comparison and architecture thread](https://git.kayg.org/kayg/infraternal/issues/260), including the [comparison table](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-77082), [J88e](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-77235), [J88g hold](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-77418) and [verdict](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-77775), [J88h profile](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-78349), and [D348 cpuset](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-78414) and [current J88h scope](https://git.kayg.org/kayg/infraternal/issues/260#issuecomment-78426) updates.
- [D163, D289, D331, D332, D336, D346, D347 and D348](../../DECISIONS.md): platform and crypto constraints, measurement policy, p99 priority and pinned R4b setup.
- [`research/mesh-engines/REPORT.md`](../../research/mesh-engines/REPORT.md): separate per-process memory measurements; kernel peer RSS was not isolatable.

### Primary implementation and platform sources

- Linux v6.12 [WireGuard queueing](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/queueing.h), [queue implementation](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/queueing.c), [receive path](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/receive.c), and [device path](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/device.c).
- Linux [TUN/TAP](https://docs.kernel.org/networking/tuntap.html) documentation and [v6.12 TUN source](https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c), [NAPI](https://docs.kernel.org/networking/napi.html), [network scaling](https://docs.kernel.org/networking/scaling.html), [segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html), [MSG_ZEROCOPY](https://docs.kernel.org/networking/msg_zerocopy.html), and [AF_XDP](https://docs.kernel.org/networking/af_xdp.html).
- [WireGuard Linux integration techniques](https://www.wireguard.com/papers/wireguard-netdev22.pdf), Barone et al., [Achieving Linear CPU Scaling in WireGuard with an Efficient Multi-tunnel Architecture](https://netdevconf.org/0x18/docs/netdev-0x18-paper23-talk-paper.pdf), and the [2025 threaded-NAPI follow-up](https://iris.polito.it/handle/11583/3002749).
- Tailscale engineering posts: [TSO/GRO and mmsg](https://tailscale.com/blog/throughput-improvements), [UDP GSO/GRO](https://tailscale.com/blog/quic-udp-throughput), and [buffer/queue memory work](https://tailscale.com/blog/making-tailscale-faster).
- [wireguard-go Linux batch API](https://github.com/WireGuard/wireguard-go/blob/master/conn/conn.go) and [BoringTun](https://github.com/cloudflare/boringtun) Linux TUN/UDP sources linked above.
- [`ring` AEAD API](https://docs.rs/ring/latest/ring/aead/struct.LessSafeKey.html), [Intel IPsec Multi-Buffer](https://github.com/intel/intel-ipsec-mb), and the Linux [io_uring](https://man7.org/linux/man-pages/man7/io_uring.7.html) manual pages.
- [RFC 8290, FQ-CoDel](https://www.rfc-editor.org/rfc/rfc8290.html), [RFC 6040, ECN tunnels](https://www.rfc-editor.org/rfc/rfc6040.html), [RFC 9330, L4S architecture](https://www.rfc-editor.org/rfc/rfc9330.html), [RFC 9331, L4S ECN](https://www.rfc-editor.org/rfc/rfc9331.html), and [RFC 9332, DualQ](https://www.rfc-editor.org/rfc/rfc9332.html).
- Apple [`NEPacketTunnelFlow`](https://developer.apple.com/documentation/networkextension/nepackettunnelflow?language=objc), which reads and writes packet arrays for a packet tunnel. macOS does not expose Linux TUN offloads, `IFF_MULTI_QUEUE`, NAPI, io_uring or AF_XDP through this interface.
- The [wireguard-go Darwin TUN adapter](https://github.com/WireGuard/wireguard-go/blob/master/tun/tun_darwin.go) for low-level `utun` control-socket setup, address-family framing and its packet read/write interface.
