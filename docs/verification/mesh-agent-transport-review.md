<!-- Author review checklist for mesh transport slice 2, #129. -->
# Author review

- Contract is additive: optional server role/path fields, legacy status remains readable, capability opt-in separates older infraternal agents.
- Foundational libraries unchanged: existing kernel WireGuard, Quinn/rustls, TCP/OpenSSL, SQLx and nft/iptables.
- Candidate identity uses the enrolled roots and TLS server name, current seven-day certificate, ordinary authority ledger and admitted fingerprint. No mesh address is authority. Exact nonce Pong precedes Hello and actor replacement.
- Losing/cancelled candidates own and retire endpoints/drivers; mesh coordinator owns additional listener leases. Component down clears proposal and proves fallback before retiring a live mesh session.
- Existing shim IDs, writer sequence and durable output offsets survive transport replacement; bounded retained input replays suffixes in legal frame sizes. Full buffer refuses more bytes.
- Retained TCP receive preserves coalesced stream IDs; native proof reuses its existing stream/decoder. Regression tests failed before decoder and advertisement fixes.
- Port allocation uses kernel port zero and validates the actual bound port, bounded retries and explicit 51820 refusal; public discovery receives the actual port. Every peer receives 25-second keepalive.
- Freshness uses authenticated, deduplicated QUIC frame counters; raw UDP cannot reset it. Watchers cancel with sessions. New fields reuse existing bounded protocol/JSON and netlink decoders and their fuzz targets; no new wire parser or foundational engine.
- Root proof refuses host network/mount namespaces, supplies a public fixture login in a private mount namespace, transfers private identity only by inherited zeroizing pipe and cleans node state on failure.
- Measurements distinguish 2 live nodes/1 PTY/1000 inventory from 1000 mutually authenticated transport pairs and 200 retained-input states. All run locally in CPUWeight10000 scopes, with load recorded. No external host or deployment.
- Performance acceptance remains subject to measured D41/PROCESS budgets; the host is shared and is not the pinned performance machine.
