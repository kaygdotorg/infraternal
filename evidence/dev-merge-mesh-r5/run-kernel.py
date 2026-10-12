#!/usr/bin/env python3
"""Run immutable mesh regression executables in disposable namespaces, without compiler-cache access."""
import json, os, re, subprocess
from pathlib import Path
out = Path(__file__).resolve().parent
build = out / "kernel-rebuild.log"
with build.open("w") as log:
    subprocess.run(["cargo", "test", "--locked", "-p", "infraternal-plugin-mesh", "--all-features", "--all-targets", "--no-run"], stdout=log, stderr=subprocess.STDOUT, check=True)
artifacts = {}
for suite, path in re.findall(r"Executable tests/([^ ]+) \(([^)]+)\)", build.read_text()):
    artifacts[Path(suite).stem] = path
cases = []
for frontend in ("nft", "nf_tables"):
    cases.append(("review_authorized_reenrollment", frontend + "_authorized_reenrollment_reaches_the_live_node"))
    marker = "nft_marker_substring_is_not_table_ownership" if frontend == "nft" else "nf_tables_marker_substring_is_not_chain_ownership"
    cases.append(("review_firewall_marker", marker))
    cases.append(("authorized_local_binding", frontend + "_local_binding_and_address_recovery"))
    for suffix in ("equal_version_conflicting_snapshot_is_refused", "snapshot_cannot_replace_local_node_identity", "split_snapshot_replay_requires_complete_identical_contents"):
        cases.append(("policy_snapshot_ordering", frontend + "_" + suffix))
    for family in ("ipv4", "ipv6"):
        cases.append(("review_reverse_recreation", frontend + "_" + family + "_retired_tcp_stops_after_reverse_traffic"))
results = []
folder = out / "kernel-direct"
folder.mkdir(exist_ok=True)
for suite, name in cases:
    logpath = folder / (name + ".log")
    with logpath.open("w") as log:
        result = subprocess.run(["unshare", "-Urn", artifacts[suite], name, "--exact", "--ignored"], stdout=log, stderr=subprocess.STDOUT)
    passed = result.returncode == 0 and "1 passed; 0 failed" in logpath.read_text()
    results.append({"suite": suite, "case": name, "exit": result.returncode, "passed": passed})
(folder / "results.json").write_text(json.dumps(results, indent=2) + "\n")
print("PASS=" + str(sum(row["passed"] for row in results)) + " FAIL=" + str(sum(not row["passed"] for row in results)))
raise SystemExit(any(not row["passed"] for row in results))
