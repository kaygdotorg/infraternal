#!/usr/bin/env bash
# Resolve apply-cohort variance with reverse ordering; retain the first campaign [242], #173.
set -uo pipefail
cd /root/infraternal-bench/mesh-policy/round5
export PATH=/usr/sbin:/usr/bin:$PATH
mkdir -p apply-reverse
passed=0
failed=0
for frontend in nft compat; do
    extra=()
    [[ "$frontend" == compat ]] && extra=(--nf-tables)
    for peers in 10 1000; do
        cohort=0
        for candidate in head base base head; do
            cohort=$((cohort+1))
            case_name="apply-${peers}-${frontend}-${cohort}-${candidate}"
            if unshare -Urn python3 mesh-policy-proof.py --fixture "$PWD/$candidate-kernel-node" --peers "$peers" --measure --apply-rounds 36 "${extra[@]}" > "apply-reverse/$case_name.jsonl" 2>&1; then
                passed=$((passed+1))
            else
                failed=$((failed+1))
            fi
        done
    done
done
printf 'PASS=%s FAIL=%s\n' "$passed" "$failed"
[[ "$failed" == 0 ]]
