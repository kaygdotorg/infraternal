#!/usr/bin/env bash
# Run balanced apply samples and production change-to-refusal proofs on the authorized VM [242].
set -uo pipefail
cd /root/infraternal-bench/mesh-policy/round4-173
export PATH=/usr/sbin:/usr/bin:$PATH
mkdir -p results-final-fixed
passed=0
failed=0
for frontend in nft compat; do
    extra=()
    [[ "$frontend" == compat ]] && extra=(--nf-tables)
    for peers in 10 1000; do
        for rtt in 0 150; do
            for change in PeerRetirement RuleRemoval DefaultTightening; do
                case_name="${change}-${peers}-${rtt}-${frontend}"
                if unshare -Urn python3 mesh-revocation-proof.py --fixture "$PWD/head-kernel-node" --coordinator "$PWD/coordinator" --extra-members "$((peers-3))" --rtt-ms "$rtt" --change "$change" --evidence "results-final-fixed/$case_name" "${extra[@]}" > "results-final-fixed/$case_name.log" 2>&1; then
                    passed=$((passed+1))
                else
                    failed=$((failed+1))
                fi
            done
        done
        cohort=0
        for candidate in base head head base; do
            cohort=$((cohort+1))
            case_name="apply-${peers}-${frontend}-${cohort}-${candidate}"
            if unshare -Urn python3 mesh-policy-proof.py --fixture "$PWD/$candidate-kernel-node" --peers "$peers" --measure --apply-rounds 12 "${extra[@]}" > "results-final-fixed/$case_name.jsonl" 2>&1; then
                passed=$((passed+1))
            else
                failed=$((failed+1))
            fi
        done
    done
done
printf 'PASS=%s FAIL=%s\n' "$passed" "$failed"
[[ "$failed" == 0 ]]
