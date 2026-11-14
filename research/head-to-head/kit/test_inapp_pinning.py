#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""D348 for the in-app row: node B runs on side B's CPUs, not inside side A's scope (#260, J638).

`lib/mesh_ix.py` starts both infraternal nodes from one process sandboxed in side A,
so node B used to inherit side A's cpuset (J629: CPUs 1-2 at 95%, 3-4 idle).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parent


def run_adopt(root: Path, pid: str, cpus: str, *, allowed: dict[str, str], pinned: str = "1") -> subprocess.CompletedProcess[str]:
    """Source common.sh with a fake /proc and cgroup tree and call h2h_scope_adopt."""
    proc = root / "proc"
    cgroups = root / "cgroup"
    holder_cgroup = cgroups / "perf.slice/j88i-holder.scope"
    holder_cgroup.mkdir(parents=True, exist_ok=True)
    (holder_cgroup / "cgroup.procs").write_text("")
    (proc / "900").mkdir(parents=True, exist_ok=True)
    (proc / "900/cgroup").write_text("0::/perf.slice/j88i-holder.scope\n")
    for member, cpu_list in allowed.items():
        (proc / member / "task" / member).mkdir(parents=True, exist_ok=True)
        (proc / member / "status").write_text(f"Name:\tinfraternal\nCpus_allowed_list:\t{cpu_list}\n")
    results = root / "results/mesh-infraternal"
    results.mkdir(parents=True, exist_ok=True)
    script = (
        'source "$H2H_KIT/lib/common.sh"\n'
        # The holder scope is a real systemd scope on the VM; here it is PID 900.
        'h2h_scope_spawn() { printf -v "$1" %s 900; printf "spawn %s %s\\n" "$2" "${*:3}" >> "$ROOT/calls"; }\n'
        'h2h_scope_adopt "$PID" "$CPUS"\n'
    )
    environment = os.environ | {
        "H2H_KIT": str(KIT), "ROOT": str(root), "PID": pid, "CPUS": cpus,
        "H2H_CPUSET_PIN": pinned, "H2H_PROC_ROOT": str(proc), "H2H_CGROUP_ROOT": str(cgroups),
        "H2H_RESULTS": str(root / "results"), "H2H_CASE": "mesh-infraternal", "H2H_RUN": str(root),
    }
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=environment, check=False)


class InAppPinningTest(unittest.TestCase):
    def test_adopt_moves_the_process_tree_into_a_new_side_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-adopt-") as temporary:
            root = Path(temporary)
            (root / "proc/700/task/700").mkdir(parents=True)
            (root / "proc/700/task/700/children").write_text("701 \n")
            (root / "proc/701/task/701").mkdir(parents=True)
            (root / "proc/701/task/701/children").write_text("")
            result = run_adopt(root, "700", "3-4", allowed={"700": "3-4", "701": "3-4"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "calls").read_text(), "spawn 3-4 sleep infinity\n")
            procs = (root / "cgroup/perf.slice/j88i-holder.scope/cgroup.procs").read_text().split()
            self.assertEqual(procs, ["700", "701"])
            inventory = (root / "results/mesh-infraternal/cpuset-pids.tsv").read_text().splitlines()
            self.assertEqual(inventory, ["700\t3-4\tj88i-holder.scope", "701\t3-4\tj88i-holder.scope"])

    def test_adopt_fails_when_the_kernel_did_not_apply_the_side_mask(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-adopt-") as temporary:
            root = Path(temporary)
            (root / "proc/700/task/700").mkdir(parents=True)
            (root / "proc/700/task/700/children").write_text("")
            result = run_adopt(root, "700", "3-4", allowed={"700": "1-2"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("still allowed on 1-2", result.stderr)

    def test_adopt_is_a_no_op_unpinned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="j638-adopt-") as temporary:
            root = Path(temporary)
            result = run_adopt(root, "700", "3-4", allowed={}, pinned="0")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "calls").exists())

    def test_mesh_case_moves_node_b_to_side_b_before_measuring(self) -> None:
        mesh = (KIT / "cases/mesh.sh").read_text()
        starter = mesh.split("start_infraternal() {", 1)[1].split("\n}\n", 1)[0]
        # Node B is the second PID that mesh_ix.py reports; its side is B's namespace.
        self.assertIn('["pids"][1]', starter)
        self.assertIn('h2h_scope_adopt "$node_b" "$(h2h_cpu_mask_for_pid "$B_PID")"', starter)


if __name__ == "__main__":
    unittest.main()
