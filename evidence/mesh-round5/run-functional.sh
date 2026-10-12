#!/usr/bin/env bash
# Run unchanged review assertions in separate disposable namespaces [242], #173.
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1
out="${MESH_EVIDENCE:?}"
# Compile on the build host: the disposable network namespace cannot reach
# the configured compiler cache. Enter it only to run immutable test artifacts.
cargo test --locked -p infraternal-plugin-mesh --all-features --all-targets --no-run > "$out/build.log" 2>&1 || exit 1
cargo build --locked -p infraternal-plugin-mesh --all-features --example kernel_node --example connection_state_fixture > "$out/fixtures-build.log" 2>&1 || exit 1
passed=0
failed=0
run_case() {
    local suite="$1" name="$2"
    if unshare -Urn cargo test --locked -p infraternal-plugin-mesh --all-features --test "$suite" "$name" -- --exact --ignored > "$out/$name.log" 2>&1 && rg -q '1 passed; 0 failed' "$out/$name.log"; then
        passed=$((passed+1))
    else
        failed=$((failed+1))
    fi
}
for frontend in nft nf_tables; do
    run_case review_authorized_reenrollment "${frontend}_authorized_reenrollment_reaches_the_live_node"
    if [[ "$frontend" == nft ]]; then marker=nft_marker_substring_is_not_table_ownership; else marker=nf_tables_marker_substring_is_not_chain_ownership; fi
    run_case review_firewall_marker "$marker"
    run_case authorized_local_binding "${frontend}_local_binding_and_address_recovery"
    run_case policy_snapshot_ordering "${frontend}_equal_version_conflicting_snapshot_is_refused"
    run_case policy_snapshot_ordering "${frontend}_snapshot_cannot_replace_local_node_identity"
    run_case policy_snapshot_ordering "${frontend}_split_snapshot_replay_requires_complete_identical_contents"
    for family in ipv4 ipv6; do
        run_case review_reverse_recreation "${frontend}_${family}_retired_tcp_stops_after_reverse_traffic"
    done
done
printf 'PASS=%s FAIL=%s\n' "$passed" "$failed"
[[ "$failed" == 0 ]]
