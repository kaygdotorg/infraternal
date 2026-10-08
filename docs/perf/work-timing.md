<!-- Role: the work-timing table of the canvas preview's user operations, so later rounds can compare. -->
# Work timing of the preview's operations

Owner rule (TASTE.md, 'Work is instant, only the animation takes time'): the work of an operation, from the input
event to the finished DOM and state, is at most 16 ms (p95), with no long task (> 50 ms). 'Our work' is main-thread
script + style + layout time; 'whole task' adds commit and paint. Animations are off (reduced motion) so they do not
spread the work over frames. Measured with `bun apps/tracer/test/work-timing.ts` (`THROTTLE=4` for 4x CPU,
`ONLY=sidebar` for one operation) and profiled with `bun apps/tracer/test/work-trace.ts <operation>` (sampling profiler,
style recalcs and layouts per task, forced layouts).

Method for 'before' and 'after': a worktree at the commit before the round (72027e7) was served next to the current
tree and the two were run alternately, n = 14 per operation, on the same loaded machine (other sessions share it, so
4x numbers move by up to 40 % between runs; the 1x numbers are steady). Each cell is p50 / p95 ms.

## 4x CPU throttle

| operation | our work before | our work after | whole task before | whole task after | long tasks after |
|---|---|---|---|---|---|
| palette: open (Ctrl+K) | 49.2 / 203.1 | 21.9 / 58.2 | 99.4 / 266.3 | 63.0 / 121.4 | 0 |
| palette: filter (one keystroke) | 25.3 / 62.3 | 19.5 / 25.7 | 82.7 / 137.6 | 52.6 / 59.6 | 0 |
| theme switch (Enter on the row) | 52.3 / 69.7 | 44.1 / 74.3 | 138.8 / 207.1 | 126.8 / 180.9 | 2 |
| font switch, warm (Enter on the row) | 18.4 / 25.1 | 22.1 / 27.6 | 58.2 / 71.6 | 66.4 / 86.6 | 0 |
| font switch, cold (first selection; fetch excluded) | 33.0 / 93.6 | 42.4 / 124.3 | 135.5 / 293.1 | 194.2 / 343.5 | 0 |
| info popover: open (click pill) | 22.3 / 91.3 | 25.0 / 65.8 | 51.3 / 163.6 | 66.1 / 207.9 | 2 |
| info popover: switch tab | 24.9 / 46.3 | 29.7 / 51.9 | 77.0 / 132.3 | 92.6 / 120.0 | 0 |
| settings/about: open (gear) | 14.6 / 19.2 | 18.9 / 30.0 | 34.2 / 66.7 | 43.0 / 82.1 | 0 |
| lock/unlock (Ctrl+Shift+L) | 10.6 / 20.4 | 11.1 / 15.1 | 73.5 / 80.8 | 80.1 / 96.2 | 0 |
| sidebar: open | 35.6 / 45.0 | 12.7 / 20.1 | 98.4 / 116.6 | 44.7 / 61.6 | 0 |
| sidebar: close | 40.6 / 48.3 | 13.8 / 20.0 | 115.3 / 146.2 | 53.1 / 62.3 | 0 |
| window activation (click an inactive window) | 34.2 / 46.4 | 33.3 / 41.2 | 89.6 / 107.2 | 102.4 / 116.9 | 0 |
| window resize: commit (release after a drag) | 21.6 / 26.7 | 23.9 / 31.2 | 74.0 / 103.1 | 83.7 / 99.4 | 0 |

Earlier alternating rounds of the same comparison (n = 10, two rounds, 4x) measured window activation 49 to 53 ms before
and 25 to 29 after, sidebar open 39 to 41 before and 10 to 14 after, sidebar close 48 to 56 before and 12 to 16 after;
the single round above ran while the machine was busier, which is why its activation row shows no gain.

## 1x (no throttle)

| operation | our work before | our work after | whole task before | whole task after | long tasks after |
|---|---|---|---|---|---|
| palette: open (Ctrl+K) | 8.1 / 14.1 | 4.5 / 14.1 | 17.6 / 27.7 | 13.8 / 32.9 | 0 |
| palette: filter (one keystroke) | 3.0 / 4.4 | 3.2 / 5.1 | 8.8 / 11.4 | 9.0 / 13.7 | 0 |
| theme switch (Enter on the row) | 9.2 / 11.0 | 7.4 / 11.3 | 27.6 / 50.9 | 21.7 / 33.4 | 0 |
| font switch, warm (Enter on the row) | 4.5 / 5.1 | 3.4 / 4.7 | 14.9 / 16.6 | 11.5 / 13.7 | 0 |
| font switch, cold (first selection; fetch excluded) | 7.9 / 25.8 | 6.3 / 17.5 | 34.4 / 76.8 | 27.8 / 57.2 | 0 |
| info popover: open (click pill) | 6.0 / 19.4 | 3.9 / 11.5 | 13.7 / 35.6 | 10.5 / 23.6 | 0 |
| info popover: switch tab | 5.2 / 8.5 | 4.6 / 5.9 | 17.5 / 24.2 | 15.4 / 22.2 | 0 |
| settings/about: open (gear) | 2.4 / 4.4 | 2.0 / 4.0 | 5.7 / 27.9 | 5.3 / 11.9 | 0 |
| lock/unlock (Ctrl+Shift+L) | 2.2 / 5.0 | 2.1 / 2.5 | 13.5 / 17.3 | 12.8 / 30.5 | 0 |
| sidebar: open | 7.4 / 8.7 | 2.4 / 2.5 | 20.7 / 26.9 | 8.3 / 10.5 | 0 |
| sidebar: close | 8.2 / 11.0 | 2.9 / 3.6 | 25.4 / 31.6 | 10.4 / 13.0 | 0 |
| window activation (click an inactive window) | 6.6 / 9.3 | 4.6 / 7.0 | 19.2 / 23.7 | 15.6 / 19.0 | 0 |
| window resize: commit (release after a drag) | 4.6 / 5.7 | 4.6 / 5.7 | 17.5 / 27.9 | 16.7 / 18.7 | 0 |

## Changes of this round

- Sidebar open/close: windows no longer resize when the sidebar docks (no terminal re-measure and redraw); the test-double badge's `:has()` on the screen and the body is a script-set flag.
- Window activation: the host tree measures first and writes after (it forced a layout per section and per leaf); no `getAnimations()`.
- Palette open: fixed rows built once, the list filled while hidden, one layout for the focus, `content-visibility: auto` rows.
- Info popover: placed before it is attached; cells clone a parsed tick; no scroll reset unless scrolled.
- Theme and font switches: the terminal's recolour or re-measure runs in its own task after the interface; fonts preload on hover.

## What stays over 16 ms at 4x, and why

- Theme switch: one style recalculation of every element (about 350) as the colour tokens change, plus the terminal's own recolour of every retained row (renderer, foundation).
- Cold and warm font switch: the terminal re-measures its cells and redraws every row (renderer, foundation); the face fetch is excluded here.
- Window resize commit: the terminal's single refit on release (by design, once).
- Window activation, popover open, tab switch, palette filter: remaining style recalcs of the newly shown subtree and the terminal blur; each is within 1.3x of the budget at 4x and under it at 1x.
