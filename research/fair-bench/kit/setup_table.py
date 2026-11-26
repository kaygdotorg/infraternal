#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1237 (#260, #580): turn the evidence folder of setup-only holds into one CSV and print medians.

    python3 -I setup_table.py <raw-dir> <hold>... --csv setup.csv

`<raw-dir>/<hold>/` is what `series.sh` writes on the control host. One line per row and run: the
time from the second node's start to the first reply through the tunnel (all stamps on the VMs' own
clocks) and, for the real-path row R, the stamps inside it, each as seconds after the second node's
`up` started: code printed, approval answered, `up` returned. `approval_window_s` is the span from
the printed code to the approval answer (the scripted owner standing in for a person).
"""
import argparse
import csv
import glob
import json
import os
import statistics
import sys

FIELDS = ["hold", "row", "run", "setup_s", "code_s", "approved_s", "up_returned_s", "approval_window_s"]


def stamps_of(path):
    """The `<name> <epoch>` lines and the approval answer of one node's `rp-stamps` file."""
    values, approve = {}, None
    for line in open(path).read().splitlines():
        if line.startswith("up."):
            name, value = line.split()[:2]
            values[name] = float(value)
        elif line.startswith("{"):
            approve = json.loads(line)
    return values, approve


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw")
    parser.add_argument("holds", nargs="+")
    parser.add_argument("--csv", required=True)
    args = parser.parse_args()
    rows = []
    for hold in args.holds:
        folder = os.path.join(args.raw, hold)
        for path in sorted(glob.glob(os.path.join(folder, "*.setup2"))):
            row, run = os.path.basename(path)[: -len(".setup2")].split(".")
            record = {"hold": hold, "row": row, "run": int(run), "setup_s": float(open(path).read())}
            if row == "R":
                # Node A (the second node) wrote the file whose host name is A's.
                node = glob.glob(os.path.join(folder, f"R.{run}.root@calternal-perf-01-*.rp-stamps"))[0]
                values, approve = stamps_of(node)
                assert approve and approve.get("ok"), f"{hold} R.{run}: approval did not succeed"
                start = values["up.start"]
                record.update(code_s=round(values["up.code"] - start, 3),
                              approved_s=round(values["up.approved"] - start, 3),
                              up_returned_s=round(values["up.end"] - start, 3),
                              approval_window_s=round(values["up.approved"] - values["up.code"], 3))
            rows.append(record)
    with open(args.csv, "w", newline="") as out:
        writer = csv.DictWriter(out, FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda r: (r["hold"], r["row"], r["run"])))
    for row in sorted({r["row"] for r in rows}):
        mine = [r for r in rows if r["row"] == row]
        for key in FIELDS[3:] + (["setup_less_approval"] if row == "R" else []):
            if key == "setup_less_approval":
                values = [round(r["setup_s"] - r["approval_window_s"], 3) for r in mine]
            else:
                values = [r[key] for r in mine if key in r]
            if values:
                print(f"{row} {key}: n={len(values)} median {statistics.median(values):.3f} "
                      f"range {min(values):.3f}-{max(values):.3f}")


if __name__ == "__main__":
    sys.exit(main())
