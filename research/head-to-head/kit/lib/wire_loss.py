#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compare the loss netem really applied to wire packets with the configured loss.

`mesh.sh` saves each direction's netem counters (`tc -s -j qdisc show`) before and
after a TCP sample. This reads the two snapshots per direction and reports packets
sent, packets dropped, the measured drop rate, and the average bytes per queued
packet. The last number shows whether netem was handed MTU-sized packets (about
1.4 KB) or GSO super-packets (many KB): with super-packets one drop removes a whole
batch of wire packets, so the drop count understates how much was really lost.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

# Above this many bytes per queued packet, the queue is being fed aggregated packets.
AGGREGATED_BYTES = 2000


def netem_counters(path: Path) -> dict[str, int] | None:
    """Return bytes, packets and drops of the netem qdisc in one `tc -s -j` snapshot."""
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and entry.get("kind") == "netem":
            return {key: int(entry.get(key, 0)) for key in ("bytes", "packets", "drops")}
    return None


def configured_loss_percent(loss: float, gemodel: str) -> float:
    """Average per-packet loss the netem arguments ask for.

    A gemodel string is `p r 1-h 1-k` in percent: the chain enters the bad state with
    probability p and leaves it with r, loses 1-h of packets in the bad state and 1-k
    in the good state, so the average is the stationary mix of the two.
    """
    if not gemodel.strip():
        return float(loss)
    values = [float(item.rstrip("%")) / 100 for item in gemodel.split()]
    enter, leave = values[0], values[1]
    loss_bad = values[2] if len(values) > 2 else 1.0
    loss_good = values[3] if len(values) > 3 else 0.0
    bad = enter / (enter + leave)
    return 100 * (bad * loss_bad + (1 - bad) * loss_good)


def direction(stem: Path, name: str, configured: float, bursty: bool) -> dict[str, Any]:
    """Summarize one direction from its before and after snapshots."""
    before = netem_counters(Path(f"{stem}-before-{name}.json"))
    after = netem_counters(Path(f"{stem}-after-{name}.json"))
    if before is None or after is None:
        return {"status": "unavailable"}
    sent = after["packets"] - before["packets"]
    dropped = after["drops"] - before["drops"]
    queued = sent + dropped
    byte_delta = after["bytes"] - before["bytes"]
    loss_pct = 100 * dropped / queued if queued > 0 else None
    average = byte_delta / sent if sent > 0 else None
    expected = configured / 100
    if loss_pct is None or queued == 0:
        agrees = None
    elif bursty:
        agrees = abs(loss_pct - configured) <= 0.25 * configured
    else:
        agrees = abs(loss_pct / 100 - expected) <= 4 * math.sqrt(expected * (1 - expected) / queued)
    return {
        "status": "measured",
        "queued_packets": queued,
        "sent_packets": sent,
        "dropped_packets": dropped,
        "measured_loss_percent": None if loss_pct is None else round(loss_pct, 4),
        "average_bytes_per_packet": None if average is None else round(average, 1),
        "aggregated_packets": None if average is None else average > AGGREGATED_BYTES,
        "matches_configured": agrees,
    }


def summarize(stem: Path, shaping: str, loss: float, gemodel: str) -> dict[str, Any]:
    """Build the per-direction wire-loss record for one TCP sample."""
    configured = configured_loss_percent(loss, gemodel)
    bursty = bool(gemodel.strip())
    return {
        "shaping": shaping,
        "configured_loss_percent": round(configured, 4),
        "ab": direction(stem, "ab", configured, bursty),
        "ba": direction(stem, "ba", configured, bursty),
    }


def main() -> int:
    """Write the wire-loss JSON for one sample."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stem", required=True, type=Path, help="path prefix of the before/after snapshot files")
    parser.add_argument("--shaping", required=True)
    parser.add_argument("--loss", type=float, default=0.0, help="configured loss percent")
    parser.add_argument("--gemodel", default="", help="netem gemodel arguments, if the loss is bursty")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    result = summarize(arguments.stem, arguments.shaping, arguments.loss, arguments.gemodel)
    arguments.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
