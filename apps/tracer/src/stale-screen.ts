/**
 * Decides when a reattached terminal shows the "screen may be out of date" note (D309).
 *
 * After a terminal reattaches, the host replays the screen it kept. A program that can redraw (a
 * shell prompt, an editor) repaints at once because the attach carries a resize, so new output
 * follows the replay within about one round trip. A shell that cannot redraw stays silent, and the
 * replay is then the only picture there is, which may no longer match the program's own idea of its
 * screen. The wire carries no flag for this, so the client infers it from silence: the replay fence
 * (`terminal.replay_complete`) is the baseline, and the note appears only when no output past that
 * baseline has arrived once the wait has run out. Output that arrives first cancels the wait, so a
 * program that redraws never shows the note, not even for a frame. Output that arrives later clears
 * the note, because the screen is then live again.
 *
 * Silence only means "cannot redraw" when a repaint was actually expected. A program repaints because
 * its terminal changed size (SIGWINCH), so an idle shell reattached at the size it already had is
 * correctly silent and the host's replay is accurate: nothing to warn about. The replay fence reports
 * the size the replayed screen was captured at, before this attach's own Resize, and the wait starts
 * only when that differs from the size the attach sends. The client cannot remember the size itself:
 * another viewer may have resized the session since this one last looked (and a reload remembers
 * nothing). A server that does not report the size leaves the wait as it always was.
 *
 * This module only owns the state machine; the timer is injected so the cases are tested
 * without waiting, and the note element lives in `packages/ui/src/terminal-note.ts`.
 */

/** A terminal grid size in cells. */
export interface ScreenSize { cols: number; rows: number }

/**
 * The size a replay fence reports, or `undefined` when it does not (an older server) or the fields are
 * unusable. Both fields travel together as u16 cell counts of at least 1; anything else is treated as
 * absent, which keeps the old behaviour rather than trusting a half-formed size.
 */
export function replayedSize(notice: Record<string, unknown>): ScreenSize | undefined {
  const { cols, rows } = notice;
  const valid = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 65535;
  return valid(cols) && valid(rows) ? { cols, rows } : undefined;
}

/** Whether the attach changed the size the replay was captured at, so a running program is expected to repaint. */
export function repaintExpected(replayed: ScreenSize | undefined, attached: ScreenSize): boolean {
  return replayed === undefined || replayed.cols !== attached.cols || replayed.rows !== attached.rows;
}

/** The shortest wait: a local redraw arrives within a few milliseconds, a far host adds its round trip. */
export const STALE_WAIT_MIN_MS = 400;
/** The longest wait: past this a still-silent program is a program that does not redraw. */
export const STALE_WAIT_MAX_MS = 1500;

/** How long to wait after the replay has painted: the floor plus two round trips (redraw out, redraw back). */
export function staleWaitMs(roundTripMs: number | undefined): number {
  if (roundTripMs === undefined || !Number.isFinite(roundTripMs) || roundTripMs < 0) return STALE_WAIT_MIN_MS;
  return Math.min(STALE_WAIT_MAX_MS, Math.round(STALE_WAIT_MIN_MS + 2 * roundTripMs));
}

/** The timer the watch uses, injected so tests can run it without waiting. `after` returns a handle that `cancel` accepts. */
export interface StaleScreenScheduler {
  after(ms: number, run: () => void): unknown;
  cancel(handle: unknown): void;
}

/**
 * The state machine behind the "screen may be out of date" note. Create one per terminal with a `show` callback that
 * puts the note up (`true`) or takes it down (`false`). Call `begin` when a replay has painted, `output` for every
 * byte count that arrives afterwards, and `reset` when the screen is replaced or the link drops.
 */
export class StaleScreenWatch {
  /** The replay fence while the watch is running; `undefined` when it is idle. */
  private baseline: bigint | undefined;
  /** The pending timer, if the wait has not run out. */
  private handle: unknown;
  /** Whether the note is up now. */
  private shownNow = false;

  /** `show` is called with `true` when the note should appear and `false` when it should go. */
  constructor(private readonly show: (shown: boolean) => void, private readonly scheduler: StaleScreenScheduler) {}

  /** True while the note is up. */
  get shown(): boolean { return this.shownNow; }
  /** True between the replay painting and the first newer output (or the end of the wait with the note up). */
  get watching(): boolean { return this.baseline !== undefined; }

  /**
   * The replay of a reattached session has painted up to `fence`. `received` is how far output has
   * arrived by now: when it is already past the fence, the program redrew and there is nothing to say.
   * `replayed` is the size the replay was captured at and `attached` the size this attach sends; when
   * they are equal no repaint is coming, silence is correct, and the wait never starts.
   */
  begin(fence: bigint, received: bigint, waitMs: number, replayed: ScreenSize | undefined, attached: ScreenSize): void {
    this.reset();
    if (received > fence || !repaintExpected(replayed, attached)) return;
    this.baseline = fence;
    this.handle = this.scheduler.after(waitMs, () => {
      this.handle = undefined;
      if (this.baseline === undefined) return;
      this.shownNow = true;
      this.show(true);
    });
  }

  /** Output reached `received` bytes: anything past the baseline cancels the wait or clears the note. */
  output(received: bigint): void {
    if (this.baseline === undefined || received <= this.baseline) return;
    this.reset();
  }

  /** The screen is replaced or the link is gone: stop waiting and take the note down. */
  reset(): void {
    if (this.handle !== undefined) this.scheduler.cancel(this.handle);
    this.handle = undefined;
    this.baseline = undefined;
    if (this.shownNow) {
      this.shownNow = false;
      this.show(false);
    }
  }
}
