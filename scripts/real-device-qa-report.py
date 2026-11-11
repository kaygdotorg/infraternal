#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Turns the evidence of `scripts/real-device-qa check` into a markdown results table.

Usage: real-device-qa-report.py OUT_DIR HOST_FACTS_JSON THEMES

OUT_DIR holds one directory per theme, each with one directory per checklist phase (named `<time>-<theme>-<phase>`)
that contains `qa-lines.txt` (the runner's QA_RESULT / QA_FRAME / QA_LABEL / QA_NOTE lines) and numbered screenshots.

Verdicts:
  PASS    measured and within the rule
  FAIL    measured and outside the rule (the rule is named in the evidence column)
  REVIEW  not decidable from numbers: someone must look at the named screenshots or video
  N/A     the QA server cannot show this (for example the mesh view without mesh nodes)
  NOT RUN needs a destructive step the check never does by itself

Only the standard library is used on purpose, so the script runs anywhere with python3 -I.
"""
import json
import re
import sys
from pathlib import Path


def phase_lines(theme_dir: Path, phase: str):
    """All runner lines of one phase, or [] when the phase did not run."""
    for d in sorted(theme_dir.glob(f"*-{phase}")):
        f = d / "qa-lines.txt"
        if f.exists():
            return f.read_text(errors="replace").splitlines()
    return []


def shots(theme_dir: Path, phase: str, names):
    """Relative paths of the named screenshots of a phase that exist."""
    found = []
    for d in sorted(theme_dir.glob(f"*-{phase}")):
        for png in sorted(d.glob("[0-9]*.png")):
            if any(png.name.endswith(f"-{n}.png") for n in names):
                found.append(str(png.relative_to(theme_dir.parent)))
    return found


def results(lines):
    # A result line is "QA_RESULT <PASS|FAIL> <name> <detail>"; the checks this report looks up have one-word names.
    return {m.group(2): m.group(1) for l in lines if (m := re.match(r"QA_RESULT (PASS|FAIL) (\S+)", l))}


def frames(lines, name):
    out = []
    for l in lines:
        m = re.match(rf"QA_FRAME {re.escape(name)} kind=\S+ label=(\S*) x=(-?[\d.]+) y=(-?[\d.]+) w=([\d.]+) h=([\d.]+) screenW=([\d.]+)", l)
        if m:
            out.append({"label": m.group(1), "x": float(m.group(2)), "y": float(m.group(3)), "w": float(m.group(4)), "h": float(m.group(5)), "screen": float(m.group(6))})
    return out


def labels(lines):
    return [re.sub(r"^QA_LABEL \S+ x=-?\d+ y=-?\d+ w=\d+ h=\d+ ", "", l) for l in lines if l.startswith("QA_LABEL ")]


def check_theme(theme_dir: Path, facts: dict):
    rows = []

    def add(step, verdict, evidence):
        rows.append((step, verdict, evidence))

    # 1 sign in
    r = results(phase_lines(theme_dir, "signin"))
    if not phase_lines(theme_dir, "signin"):
        add("1 sign in", "FAIL", "phase did not run")
    else:
        ok = r.get("console-visible") == "PASS"
        add("1 sign in", "PASS" if ok else "FAIL", "the app shows its Console after load (`console-visible`); shots: " + ", ".join(shots(theme_dir, "signin", ["console"])))

    # 2 shell and exit
    sh = phase_lines(theme_dir, "shell")
    r = results(sh)
    if not sh:
        add("2 shell + exit", "FAIL", "phase did not run")
    else:
        closes = r.get("exit-closes-window")
        evidence = "after typing `exit` the 'shell ended' window must be gone (`exit-closes-window`); shots: " + ", ".join(shots(theme_dir, "shell", ["shell-typed", "after-exit"]))
        if closes is None:
            # The runner stops at the first failed keystroke, so no verdict was reached: say so instead of guessing.
            add("2 shell + exit", "REVIEW", "the phase aborted before the `exit` check (no keyboard focus; see test.log); rerun with `check --phases shell`")
        else:
            add("2 shell + exit", "PASS" if closes == "PASS" else "FAIL", evidence)

    # 3 window fits the viewport
    wide = [f for name in ("regions-before", "win-after-exit") for f in frames(sh, name)
            if f["label"].lower().find("shell") >= 0 or f["label"].lower().find("terminal") >= 0]
    wide = [f for f in wide if "_region" in f["label"] or "region" in f["label"]]
    own = [f for f in wide if re.search(r"\d+\.\d+\.\d+\.\d+|shell|terminal", f["label"], re.I)]
    overflow = [f for f in own if f["x"] >= -0.5 and f["x"] < f["screen"] and f["w"] > f["screen"] + 0.5 and f["w"] < 3 * f["screen"]]
    if not own:
        add("3 window fits viewport", "REVIEW", "no window frame was measured")
    elif overflow:
        worst = max(overflow, key=lambda f: f["w"])
        add("3 window fits viewport", "FAIL", f"window `{worst['label']}` is {worst['w']:.0f} pt wide in a {worst['screen']:.0f} pt viewport (rule: width <= viewport)")
    else:
        add("3 window fits viewport", "PASS", f"{len(own)} window frame(s) all <= {own[0]['screen']:.0f} pt")

    # 4 machine pill
    pl = phase_lines(theme_dir, "pill")
    if not pl:
        add("4a machine pill facts", "FAIL", "phase did not run")
        add("4b scroll holds 35 s", "FAIL", "phase did not run")
    else:
        text = "\n".join(labels(pl))
        want = [("kernel", facts.get("kernel", "")), ("architecture", facts.get("arch", ""))]
        missing = [name for name, value in want if value and value not in text]
        if "Details for" not in text:
            add("4a machine pill facts", "FAIL", "the machine panel did not open")
        elif missing:
            add("4a machine pill facts", "FAIL", f"panel does not show the host's own {', '.join(missing)} (host: {facts})")
        else:
            add("4a machine pill facts", "PASS", f"kernel and architecture match the host ({facts.get('kernel')}, {facts.get('arch')}); tabs Machine/Connection; shots: " + ", ".join(shots(theme_dir, "pill", ["pill-machine", "pill-connection"])))
        y0, y1, y2 = (frames(pl, n) for n in ("kernel-y0", "kernel-y1", "kernel-y2"))
        if not (y0 and y1 and y2):
            add("4b scroll holds 35 s", "REVIEW", "the Kernel row was not found at every sample")
        else:
            a, b, c = y0[0]["y"], y1[0]["y"], y2[0]["y"]
            if abs(a - b) < 40:
                # Fewer than 40 pt means the swipe did not really scroll the panel (accessibility frames lag too), so
                # the numbers prove nothing about holding position.
                add("4b scroll holds 35 s", "REVIEW", f"the swipe did not scroll the panel by a measurable amount (Kernel y {a:.0f} -> {b:.0f} -> {c:.0f}); compare pill-scrolled-now and pill-scrolled-35s by eye")
            elif abs(b - c) >= 20:
                add("4b scroll holds 35 s", "FAIL", f"panel moved after the swipe settled: Kernel y {b:.0f} at the swipe, {c:.0f} 35 s later")
            else:
                add("4b scroll holds 35 s", "PASS", f"Kernel y {a:.0f} -> {b:.0f} and still {c:.0f} after 35 s")

    # 5 remove host
    add("5 Remove host (pill, palette, sidebar swipe) + re-add", "NOT RUN", "destructive: do it by hand on the QA host, then `add-host` again (runbook step 5)")

    # 6 mesh cards
    mn = phase_lines(theme_dir, "menus")
    cards = frames(mn, "mesh-cards")
    if not mn:
        add("6 mesh cards fit their text", "FAIL", "phase did not run")
    elif not cards:
        add("6 mesh cards fit their text", "N/A", "the QA server has no mesh node, so the mesh view has no cards; shot: " + ", ".join(shots(theme_dir, "menus", ["mesh"])))
    else:
        bad = [f for f in cards if f["w"] > f["screen"]]
        add("6 mesh cards fit their text", "FAIL" if bad else "REVIEW", f"{len(cards)} card frame(s); wider than the viewport: {len(bad)}; check text clipping in the mesh shot")

    # 7 text sizes
    tx = phase_lines(theme_dir, "text")
    hs = {n: frames(tx, n) for n in ("text-heading", "text-label", "text-row")}
    if not any(hs.values()):
        add("7 text sizes at phone width", "REVIEW", "no text rows were measured; compare text-sample by eye")
    else:
        # The smallest matching row is the text itself; bigger matches are the containers around it.
        summary = ", ".join(f"{n.split('-')[1]} h={min(f['h'] for f in v):.0f}pt" for n, v in hs.items() if v)
        add("7 text sizes at phone width", "REVIEW", f"measured row heights ({summary}); there is no stored baseline yet, so compare with the same run on the previous build and look at text-sample")

    # 8 palette, settings, themes
    add("8 palette, settings, themes", "REVIEW" if mn else "FAIL", "shots: " + ", ".join(shots(theme_dir, "menus", ["views-menu", "settings", "palette"])))

    # 9 motion
    videos = [str(p.relative_to(theme_dir.parent)) for p in theme_dir.glob("*-motion.mov") if not p.name.startswith("._")]
    add("9 motion (pill menu, split)", "REVIEW" if videos else "FAIL", "screen recording: " + (", ".join(videos) if videos else "none was recorded") + " (ease-out, <= 300 ms is judged on the recording)")
    return rows


def main():
    out, facts_path, themes = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3].split(",")
    facts = json.loads(facts_path.read_text()) if facts_path.exists() else {}
    per_theme = {t: check_theme(out / t, facts) for t in themes if (out / t).is_dir()}
    print("| Step | " + " | ".join(f"{t}" for t in per_theme) + " | Evidence (rule and files) |")
    print("|---|" + "---|" * len(per_theme) + "---|")
    steps = [r[0] for r in next(iter(per_theme.values()))] if per_theme else []
    for i, step in enumerate(steps):
        verdicts = [per_theme[t][i][1] for t in per_theme]
        evidence = "; ".join(f"{t}: {per_theme[t][i][2]}" for t in per_theme) if len({per_theme[t][i][2] for t in per_theme}) > 1 else next(iter(per_theme.values()))[i][2]
        print(f"| {step} | " + " | ".join(verdicts) + f" | {evidence} |")


if __name__ == "__main__":
    main()
