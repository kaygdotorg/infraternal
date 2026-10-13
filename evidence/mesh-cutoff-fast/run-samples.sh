#!/usr/bin/env bash
# Five disposable packet measurements per short locked run; no builds share the lock [256].
set -u
root=/root/infraternal-bench/mesh-cutoff-fast
variant=$1
backend=$2
first=$3
last=$4
flag=()
[[ "$backend" == compat ]] && flag=(--nf-tables)
failed=0
for sample in $(seq "$first" "$last"); do
 evidence="$root/final-$variant/$backend/$sample"
 [[ -f "$evidence/summary.json" ]] && continue
 mkdir -p "$evidence"
 unshare -Urn python3 "$root/mesh-revocation-proof.py" --fixture "$root/$variant-refusal-node" --coordinator "$root/$variant-refusal-coordinator" --stateful --extra-members 997 --rtt-ms 150 --change DefaultTightening --budget-ms 200 --evidence "$evidence" "${flag[@]}" > "$evidence/run.log" 2>&1
 sample_exit=$?
 printf '%s %s %s exit=%s\n' "$variant" "$backend" "$sample" "$sample_exit"
 [[ "$sample_exit" == 0 || "$sample_exit" == 1 && -f "$evidence/summary.json" ]] || exit 2
 [[ "$variant" != baseline && "$sample_exit" == 1 ]] && failed=1
done
exit "$failed"
