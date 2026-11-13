/** Measures synthetic terminal keydown-to-paint latency and forced-drop recovery. Loaded only by `?probe=1` pages (an on-demand module, D188). */
import type { TerminalClient, TerminalHooks, TerminalTraceHop } from "./terminal";

/** The characters the probe types, one after another. */
const KEY_SET = "abcdefghijklmnopqrstuvwxyz0123456789";
/** The most keys one run may send. */
const MAX_PROBE_KEYS = 5_000;
/** The shortest time a run waits for its echoes before giving up; longer runs wait 50 ms per key. */
const ECHO_TIMEOUT_MS = 15_000;
/**
 * A deadlock guard, not a latency budget: two minutes is over 70 times the 1700 ms worst-case bound at 300 ms RTT
 * plus jitter. It also leaves slow successes (including a minute-long reconnect) measured at their full duration.
 */
const RESUME_TIMEOUT_MS = 120_000;

/** One measured key (or the resume marker): its trace `id`, when it started, and the time at each stage it passed. */
interface ProbeSample {
  id: string | undefined;
  startedAt: number;
  kind: "key" | "resume";
  stages: Partial<Record<ProbeStage, number>>;
}

/** A point in a key's path: the keydown, the terminal's input callback, or a hop reported by the terminal. */
type ProbeStage = "keydown" | "onData" | TerminalTraceHop;

/** The stage times of one key, by trace id, for tests. */
export interface ProbeTraceSample {
  id: string;
  stages: Partial<Record<ProbeStage, number>>;
}

/** The stages that are reported as a span: a label with the stage the span starts and ends at. */
const BROWSER_HOPS: ReadonlyArray<readonly [string, ProbeStage, ProbeStage]> = [
  ["keydown → onData", "keydown", "onData"],
  ["onData → encode", "onData", "encode"],
  ["encode → ws.send", "encode", "wsSend"],
  ["ws.onmessage → decode", "wsMessage", "decode"],
  ["decode → term.write", "decode", "termWrite"],
  ["term.write → callback", "termWrite", "writeCallback"],
  ["callback → paint rAF", "writeCallback", "paint"],
];

/** The samples waiting for the same character to be painted, and the index of the next one to match. */
interface SampleQueue {
  samples: ProbeSample[];
  next: number;
}

/**
 * A test panel that measures how long a typed key takes to appear on screen, and how long a resumed connection takes
 * to show output. It types synthetic keys (never followed by Enter) and matches them to the painted echo. Create it with
 * the panel element, pass {@link PerformanceProbe.hooks} to the terminal, then call `bind` once the terminal exists.
 * It attaches only on `?probe=1`; normal terminal traffic does not keep probe state.
 */
export class PerformanceProbe {
  private terminal: TerminalClient | undefined;
  /** Samples waiting for their echo, by the character code that will be painted. */
  private readonly pending = new Map<number, SampleQueue>();
  /** Keydown-to-paint times in milliseconds for the current run. */
  private readonly latencies: number[] = [];
  /** Every sample of the current run, in order. */
  private readonly samples: ProbeSample[] = [];
  /** The same samples by trace id, so hops reported by the terminal find their key. */
  private readonly samplesById = new Map<string, ProbeSample>();
  private readonly countInput: HTMLInputElement;
  private readonly runButton: HTMLButtonElement;
  private readonly dropButton: HTMLButtonElement;
  private readonly copyButton: HTMLButtonElement;
  private readonly results: HTMLElement;
  private readonly message: HTMLElement;
  /** The character being sent now; the keydown listener only accepts this one. */
  private syntheticKey: string | undefined;
  private syntheticSample: ProbeSample | undefined;
  /** How many keys the current run will send. */
  private runTarget = 0;
  /** Whether a run is in progress. */
  private runActive = false;
  /** The run's overall timeout. */
  private timeout = 0;
  /** Fires 100 ms after the last output, marking the terminal as quiet. */
  private quietTimer = 0;
  private nextKeyTimer = 0;
  /** True when the terminal has been silent for 100 ms; runs only start then. */
  private quiet = false;
  /** When a forced socket drop began, until the first resumed echo is painted. */
  private resumeStartedAt: number | undefined;
  /** Whether the resume marker key has been sent for the current drop. */
  private resumeMarkerSent = false;
  /** The independent deadline covering both resumed attachment and the marker echo. */
  private resumeTimer = 0;
  /** A distinct printable marker per drop, so an expired echo cannot complete a later measurement. */
  private resumeMarker = "";
  /** How many leading marker bytes have painted; chunk boundaries need no buffering or per-byte allocation. */
  private resumeMatched = 0;
  /** The next marker number; it only advances when a new measurement starts. */
  private resumeNumber = 0;
  /** Failed samples remain counted across later successful drops and key runs, so they cannot disappear from a report. */
  private resumeFailures = 0;
  /** The latest failure's duration and reason, alongside the cumulative failure count. */
  private resumeFailure: string | undefined;
  /** How long the last resume took, in milliseconds. */
  private resumeDuration: number | undefined;
  /** The text of the last report, which the copy button copies. */
  private lastReport = "No probe has run yet.";

  /** Finds the panel's controls (`#probe-count`, `#probe-run`, `#probe-drop`, `#probe-copy`, `#probe-results`, `#probe-message`) and wires them. Throws if one is missing. */
  constructor(private readonly panel: HTMLElement, initialCount: number) {
    this.countInput = get<HTMLInputElement>(panel, "#probe-count");
    this.runButton = get<HTMLButtonElement>(panel, "#probe-run");
    this.dropButton = get<HTMLButtonElement>(panel, "#probe-drop");
    this.copyButton = get<HTMLButtonElement>(panel, "#probe-copy");
    this.results = get<HTMLElement>(panel, "#probe-results");
    this.message = get<HTMLElement>(panel, "#probe-message");
    this.countInput.value = String(initialCount);
    this.runButton.addEventListener("click", () => this.run());
    this.dropButton.addEventListener("click", () => this.forceDrop());
    this.copyButton.addEventListener("click", () => { void this.copyResults(); });
    document.addEventListener("keydown", this.onKeydown, true);
    this.runButton.disabled = true;
    this.dropButton.disabled = true;
  }

  /** The callbacks to give the terminal so the probe sees attach, disconnect, input, trace hops and painted output. */
  hooks(): TerminalHooks {
    return {
      onAttached: (resumed, terminal) => this.onAttached(resumed, terminal),
      onDisconnected: (forced) => this.onDisconnected(forced),
      onInput: (data, at, sequence) => this.onInput(data, at, sequence),
      onTrace: (id, hop, at) => this.onTrace(id, hop, at),
      onPaintedOutput: (bytes, at) => this.onPaintedOutput(bytes, at),
    };
  }

  /** Gives the probe the terminal it controls and updates the buttons. */
  bind(terminal: TerminalClient): void {
    this.terminal = terminal;
    this.syncButtons();
  }

  /** Cancels the timers and the keydown listener and forgets the samples. */
  dispose(): void {
    window.clearTimeout(this.timeout);
    window.clearTimeout(this.quietTimer);
    window.clearTimeout(this.resumeTimer);
    window.clearTimeout(this.nextKeyTimer);
    document.removeEventListener("keydown", this.onKeydown, true);
    this.pending.clear();
    this.samplesById.clear();
  }

  private readonly onKeydown = (event: KeyboardEvent): void => {
    if (!this.syntheticKey || event.key !== this.syntheticKey) return;
    const startedAt = performance.now();
    this.syntheticSample = {
      id: this.terminal?.inputSequence.toString(),
      startedAt,
      kind: "key",
      stages: { keydown: startedAt },
    };
    this.samples.push(this.syntheticSample);
    this.enqueue(event.key, this.syntheticSample);
    event.preventDefault();
  };

  /** Starts a run of the chosen number of keys (1 to 5000). Needs a connected terminal. */
  private run(): void {
    const terminal = this.terminal;
    const count = Number(this.countInput.value);
    if (!terminal?.isConnected) {
      this.message.textContent = "Connect the terminal before starting the probe.";
      return;
    }
    if (!Number.isInteger(count) || count < 1 || count > MAX_PROBE_KEYS) {
      this.message.textContent = `Choose between 1 and ${MAX_PROBE_KEYS} keys.`;
      return;
    }
    if (this.runActive || this.resumeStartedAt !== undefined) return;

    window.clearTimeout(this.timeout);
    window.clearTimeout(this.nextKeyTimer);
    this.pending.clear();
    this.latencies.length = 0;
    this.samples.length = 0;
    this.samplesById.clear();
    this.runTarget = count;
    this.runActive = true;
    this.resumeDuration = undefined;
    this.message.textContent = "Sending synthetic keys. They are not followed by Enter.";
    this.results.textContent = `Painted 0 / ${count}`;
    this.syncButtons();

    this.timeout = window.setTimeout(() => this.finishRun(true), Math.max(ECHO_TIMEOUT_MS, count * 50));
    this.sendNextKey();
  }

  /**
   * Drops the socket to measure how long the resume takes.
   *
   * One sample is one reconnect. The report shows "pending" (not the previous time) until this drop's marker echo is
   * painted, so a reader polling for `Time to resume: <n> ms` gets this drop's number, not the last one. The button
   * stays disabled until then (see `syncButtons`). Before both rules, a test that read the stale number clicked the
   * next drop while the marker was still in flight, and that marker's echo later ended a sample that spanned two
   * reconnects: 1432–1528 ms at a 300 ms round trip, where one reconnect takes 895–964 ms (#478).
   */
  private forceDrop(): void {
    if (!this.terminal?.isConnected) {
      this.message.textContent = "Connect the terminal before forcing a socket drop.";
      return;
    }
    if (this.resumeStartedAt !== undefined) {
      this.message.textContent = "Wait for the current resume to finish before dropping again.";
      return;
    }
    this.resumeStartedAt = performance.now();
    this.resumeDuration = undefined;
    this.resumeMarkerSent = false;
    this.resumeMarker = `~probe-${++this.resumeNumber}~`;
    this.resumeMatched = 0;
    this.resumeTimer = window.setTimeout(() => this.failResume(
      this.resumeMarkerSent ? "Timed out waiting for the marker echo." : "Timed out waiting for resumed attachment.",
    ), RESUME_TIMEOUT_MS);
    this.message.textContent = "Dropping the socket and measuring the first resumed echo…";
    this.renderReport();
    this.syncButtons();
    this.terminal.forceDrop();
  }

  /** Records an explicit failed sample and releases the measurement lock without losing earlier failures. */
  private failResume(reason: string): void {
    if (this.resumeStartedAt === undefined) return;
    this.resumeFailures += 1;
    this.resumeFailure = `${format(Math.max(0, performance.now() - this.resumeStartedAt))} ms: ${reason}`;
    this.clearResume();
    this.renderReport();
    this.message.textContent = `Resume failed: ${reason}`;
    this.syncButtons();
  }

  /** Cancels the deadline and forgets only the current marker and stopwatch, keeping recorded results intact. */
  private clearResume(): void {
    window.clearTimeout(this.resumeTimer);
    this.resumeTimer = 0;
    this.resumeStartedAt = undefined;
    this.resumeMarkerSent = false;
    this.resumeMarker = "";
    this.resumeMatched = 0;
  }

  /** Marks output busy on disconnect; forceDrop alone owns the measurement lifetime. */
  private onDisconnected(forced: boolean): void {
    this.quiet = false;
    window.clearTimeout(this.quietTimer);
    // Only forceDrop starts a sample; later disconnect notifications must not resurrect an expired measurement.
    if (forced) this.syncButtons();
  }

  /** After a resumed attach, types the unique marker whose complete painted echo ends the resume stopwatch. */
  private onAttached(resumed: boolean, terminal: TerminalClient): void {
    this.terminal = terminal;
    this.waitForOutputQuiet();
    if (resumed && this.resumeStartedAt !== undefined && !this.resumeMarkerSent) {
      this.resumeMarkerSent = true;
      try {
        terminal.injectInput(this.resumeMarker);
      } catch {
        this.failResume("The resumed terminal could not accept the probe marker.");
      }
    }
    this.syncButtons();
  }

  /** Matches painted bytes to waiting samples, records their latency and sends the next key when the previous ones are done. */
  private onPaintedOutput(bytes: Uint8Array, paintedAt: number): void {
    this.waitForOutputQuiet();
    this.matchResumeMarker(bytes, paintedAt);
    for (const byte of bytes) {
      const queue = this.pending.get(byte);
      if (!queue) continue;
      const sample = queue.samples[queue.next];
      if (!sample) {
        this.pending.delete(byte);
        continue;
      }
      queue.next += 1;
      if (queue.next >= queue.samples.length) this.pending.delete(byte);
      sample.stages.paint = paintedAt;
      const duration = Math.max(0, paintedAt - sample.startedAt);
      if (this.runActive) {
        this.latencies.push(duration);
        this.results.textContent = `Painted ${this.latencies.length} / ${this.runTarget}`;
        if (this.latencies.length >= this.runTarget) this.finishRun(false);
      }
    }
    if (this.runActive && this.latencies.length === this.samples.length) {
      this.nextKeyTimer = window.setTimeout(() => {
        this.nextKeyTimer = 0;
        this.sendNextKey();
      }, 0);
    }
  }

  /**
   * Matches this drop's marker across painted chunks without allocating per byte in the timing probe (P11).
   * Markers contain `~` only at their ends, so after a mismatch only a leading `~` can remain matched.
   */
  private matchResumeMarker(bytes: Uint8Array, paintedAt: number): void {
    if (this.resumeStartedAt === undefined || !this.resumeMarkerSent) return;
    for (const byte of bytes) {
      this.resumeMatched = byte === this.resumeMarker.charCodeAt(this.resumeMatched)
        ? this.resumeMatched + 1
        : byte === this.resumeMarker.charCodeAt(0) ? 1 : 0;
      if (this.resumeMatched !== this.resumeMarker.length) continue;
      this.resumeDuration = Math.max(0, paintedAt - this.resumeStartedAt);
      this.clearResume();
      this.renderReport();
      this.message.textContent = "Resume completed after the first echoed marker painted.";
      break;
    }
  }

  /** Queues a sample under the character it will paint. */
  private enqueue(key: string, sample: ProbeSample): void {
    const byte = key.charCodeAt(0);
    const queue = this.pending.get(byte) ?? { samples: [], next: 0 };
    queue.samples.push(sample);
    this.pending.set(byte, queue);
  }

  /** Attaches the byte-stream sequence as a stable key ID at Ghostty's onData boundary. */
  private onInput(data: string, at: number, sequence: bigint): boolean {
    const sample = this.syntheticSample;
    if (!sample || sample.kind !== "key" || data.length !== 1) return false;
    const id = sequence.toString();
    sample.id = id;
    sample.stages.onData = at;
    this.samplesById.set(id, sample);
    return true;
  }

  /** Records when the key with trace `id` reached `hop`. */
  private onTrace(id: string, hop: TerminalTraceHop, at: number): void {
    const sample = this.samplesById.get(id);
    if (sample) sample.stages[hop] = at;
  }

  /** Sends one key, then waits for its painted echo before measuring the next key. */
  private sendNextKey(): void {
    const terminal = this.terminal;
    if (!this.runActive || !terminal?.isConnected || this.samples.length >= this.runTarget) return;
    const key = KEY_SET[this.samples.length % KEY_SET.length];
    if (!key) return;
    this.syntheticKey = key;
    this.syntheticSample = undefined;
    document.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
    this.syntheticKey = undefined;
    if (!this.syntheticSample) {
      this.failRun("The browser did not deliver the synthetic keydown event.");
      return;
    }
    try {
      terminal.injectInput(key);
    } catch {
      this.syntheticSample = undefined;
      this.failRun("Terminal input is paused; wait for the server acknowledgement and try again.");
      return;
    }
    this.syntheticSample = undefined;
  }

  /** The trace id and stage times of every sample that got an id. */
  traceSamples(): ProbeTraceSample[] {
    return this.samples.flatMap((sample) => sample.id === undefined
      ? []
      : [{ id: sample.id, stages: { ...sample.stages } }]);
  }

  /** Ends the run (it completed or timed out) and shows the report. */
  private finishRun(timedOut: boolean): void {
    if (!this.runActive) return;
    this.runActive = false;
    window.clearTimeout(this.timeout);
    window.clearTimeout(this.nextKeyTimer);
    this.timeout = 0;
    this.renderReport();
    this.message.textContent = timedOut
      ? `Timed out after ${this.latencies.length} of ${this.runTarget} painted echoes.`
      : "Probe complete. Synthetic keys did not submit a command.";
    this.syncButtons();
  }

  /** Stops the run with `message` shown to the user. */
  private failRun(message: string): void {
    this.runActive = false;
    this.pending.clear();
    window.clearTimeout(this.timeout);
    window.clearTimeout(this.nextKeyTimer);
    this.timeout = 0;
    this.message.textContent = message;
    this.renderReport();
    this.syncButtons();
  }

  /** Writes the result text: key count, p50, p95 and p99 latency, the hop breakdown and the resume time. */
  private renderReport(): void {
    if (this.latencies.length === 0) {
      this.lastReport = this.resumeDuration === undefined
        ? (this.resumeStartedAt === undefined && this.resumeFailures > 0 ? "Time to resume: FAIL" : "No painted key echoes yet.")
        : `Time to resume: ${format(this.resumeDuration)} ms`;
      this.appendResumeFailures();
      this.results.textContent = this.lastReport;
      return;
    }
    const sorted = [...this.latencies].sort((left, right) => left - right);
    const resume = this.resumeDuration === undefined
      ? (this.resumeStartedAt === undefined && this.resumeFailures > 0 ? "FAIL" : "pending")
      : `${format(this.resumeDuration)} ms`;
    this.lastReport = [
      `Painted echoes: ${sorted.length} / ${this.runTarget}`,
      `p50: ${format(percentile(sorted, 0.5))} ms`,
      `p95: ${format(percentile(sorted, 0.95))} ms`,
      `p99: ${format(percentile(sorted, 0.99))} ms`,
      ...this.renderHopReport(),
      `Time to resume: ${resume}`,
    ].join("\n");
    this.appendResumeFailures();
    this.results.textContent = this.lastReport;
  }

  /** Keeps failed samples visible and copyable even after another measurement succeeds. */
  private appendResumeFailures(): void {
    if (this.resumeFailures === 0) return;
    this.lastReport += `\nResume samples: ${this.resumeFailures} FAIL\nLast failed resume: ${this.resumeFailure}`;
  }

  /** Copies the report to the clipboard, or tells the user to copy it by hand. */
  private async copyResults(): Promise<void> {
    this.renderReport();
    try {
      await navigator.clipboard.writeText(this.lastReport);
      this.message.textContent = "Results copied.";
    } catch {
      this.message.textContent = "Clipboard unavailable. Select the results and copy them.";
    }
  }

  /**
   * Enables the run and drop buttons only when the terminal is connected, quiet, no run is active and no forced drop
   * is still waiting for its resumed echo (a key or a second drop then would land inside that resume's sample).
   */
  private syncButtons(): void {
    const connected = this.terminal?.isConnected === true;
    const busy = !connected || !this.quiet || this.runActive || this.resumeStartedAt !== undefined;
    this.runButton.disabled = busy;
    this.dropButton.disabled = busy;
  }

  /** Marks the terminal busy now and quiet again after 100 ms without output. */
  private waitForOutputQuiet(): void {
    this.quiet = false;
    window.clearTimeout(this.quietTimer);
    this.syncButtons();
    this.quietTimer = window.setTimeout(() => {
      this.quietTimer = 0;
      this.quiet = true;
      this.syncButtons();
    }, 100);
  }

  /** One line per stage span of {@link BROWSER_HOPS} (and the socket send-to-message span) with its p50 and p99 time, for spans that have samples. */
  private renderHopReport(): string[] {
    const lines: string[] = [];
    for (const [label, from, to] of BROWSER_HOPS) {
      const durations = this.samples.flatMap((sample) => {
        const start = sample.stages[from];
        const end = sample.stages[to];
        return sample.kind === "key" && start !== undefined && end !== undefined
          ? [Math.max(0, end - start)]
          : [];
      }).sort((left, right) => left - right);
      if (durations.length === 0) continue;
      lines.push(`${label}: p50 ${format(percentile(durations, 0.5))} ms, p99 ${format(percentile(durations, 0.99))} ms`);
    }
    const sendToMessage = this.samples.flatMap((sample) => {
      const start = sample.stages.wsSend;
      const end = sample.stages.wsMessage;
      return sample.kind === "key" && start !== undefined && end !== undefined
        ? [Math.max(0, end - start)]
        : [];
    }).sort((left, right) => left - right);
    if (sendToMessage.length > 0) {
      lines.push(`ws.send → ws.onmessage: p50 ${format(percentile(sendToMessage, 0.5))} ms, p99 ${format(percentile(sendToMessage, 0.99))} ms (includes the double and both local socket legs)`);
    }
    return lines;
  }
}

/** The value at fraction `percentileValue` (0 to 1) of an ascending list; 0 for an empty list. */
function percentile(sorted: number[], percentileValue: number): number {
  const rank = Math.max(0, Math.ceil(sorted.length * percentileValue) - 1);
  return sorted[rank] ?? 0;
}

/** A number with two decimals. */
function format(value: number): string {
  return value.toFixed(2);
}

/** The element matching `selector` in `root`; throws a readable error if the panel lacks it. */
function get<ElementType extends HTMLElement>(root: HTMLElement, selector: string): ElementType {
  const element = root.querySelector<ElementType>(selector);
  if (!element) throw new Error(`Probe control is missing: ${selector}`);
  return element;
}
