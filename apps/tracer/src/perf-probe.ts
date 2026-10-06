/** Measures synthetic terminal keydown-to-paint latency and forced-drop recovery. */
import type { TerminalClient, TerminalHooks, TerminalTraceHop } from "./terminal";

const KEY_SET = "abcdefghijklmnopqrstuvwxyz0123456789";
const MAX_PROBE_KEYS = 5_000;
const ECHO_TIMEOUT_MS = 15_000;

interface ProbeSample {
  id: string | undefined;
  startedAt: number;
  kind: "key" | "resume";
  stages: Partial<Record<ProbeStage, number>>;
}

type ProbeStage = "keydown" | "onData" | TerminalTraceHop;

export interface ProbeTraceSample {
  id: string;
  stages: Partial<Record<ProbeStage, number>>;
}

const BROWSER_HOPS: ReadonlyArray<readonly [string, ProbeStage, ProbeStage]> = [
  ["keydown → onData", "keydown", "onData"],
  ["onData → encode", "onData", "encode"],
  ["encode → ws.send", "encode", "wsSend"],
  ["ws.onmessage → decode", "wsMessage", "decode"],
  ["decode → term.write", "decode", "termWrite"],
  ["term.write → callback", "termWrite", "writeCallback"],
  ["callback → paint rAF", "writeCallback", "paint"],
];

interface SampleQueue {
  samples: ProbeSample[];
  next: number;
}

/** Attaches only on `?probe=1`; normal terminal traffic does not keep probe state. */
export class PerformanceProbe {
  private terminal: TerminalClient | undefined;
  private readonly pending = new Map<number, SampleQueue>();
  private readonly latencies: number[] = [];
  private readonly samples: ProbeSample[] = [];
  private readonly samplesById = new Map<string, ProbeSample>();
  private readonly countInput: HTMLInputElement;
  private readonly runButton: HTMLButtonElement;
  private readonly dropButton: HTMLButtonElement;
  private readonly copyButton: HTMLButtonElement;
  private readonly results: HTMLElement;
  private readonly message: HTMLElement;
  private syntheticKey: string | undefined;
  private syntheticSample: ProbeSample | undefined;
  private runTarget = 0;
  private runActive = false;
  private timeout = 0;
  private quietTimer = 0;
  private nextKeyTimer = 0;
  private quiet = false;
  private resumeStartedAt: number | undefined;
  private resumeMarkerSent = false;
  private resumeDuration: number | undefined;
  private lastReport = "No probe has run yet.";

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

  hooks(): TerminalHooks {
    return {
      onAttached: (resumed, terminal) => this.onAttached(resumed, terminal),
      onDisconnected: (forced) => this.onDisconnected(forced),
      onInput: (data, at, sequence) => this.onInput(data, at, sequence),
      onTrace: (id, hop, at) => this.onTrace(id, hop, at),
      onPaintedOutput: (bytes, at) => this.onPaintedOutput(bytes, at),
    };
  }

  bind(terminal: TerminalClient): void {
    this.terminal = terminal;
    this.syncButtons();
  }

  dispose(): void {
    window.clearTimeout(this.timeout);
    window.clearTimeout(this.quietTimer);
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
    if (this.runActive) return;

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

  private forceDrop(): void {
    if (!this.terminal?.isConnected) {
      this.message.textContent = "Connect the terminal before forcing a socket drop.";
      return;
    }
    this.resumeStartedAt = performance.now();
    this.resumeDuration = undefined;
    this.resumeMarkerSent = false;
    this.message.textContent = "Dropping the socket and measuring the first resumed echo…";
    this.terminal.forceDrop();
  }

  private onDisconnected(forced: boolean): void {
    this.quiet = false;
    window.clearTimeout(this.quietTimer);
    if (forced) {
      this.resumeStartedAt ??= performance.now();
      this.resumeMarkerSent = false;
      this.syncButtons();
    }
  }

  private onAttached(resumed: boolean, terminal: TerminalClient): void {
    this.terminal = terminal;
    this.waitForOutputQuiet();
    if (resumed && this.resumeStartedAt !== undefined && !this.resumeMarkerSent) {
      this.resumeMarkerSent = true;
      const sample: ProbeSample = { id: undefined, startedAt: this.resumeStartedAt, kind: "resume", stages: {} };
      this.enqueue("~", sample);
      try {
        terminal.injectInput("~");
      } catch {
        this.message.textContent = "The resumed terminal could not accept the probe marker.";
      }
    }
    this.syncButtons();
  }

  private onPaintedOutput(bytes: Uint8Array, paintedAt: number): void {
    this.waitForOutputQuiet();
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
      if (sample.kind === "resume") {
        this.resumeDuration = duration;
        this.resumeStartedAt = undefined;
        this.renderReport();
        this.message.textContent = "Resume completed after the first echoed marker painted.";
      } else if (this.runActive) {
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

  traceSamples(): ProbeTraceSample[] {
    return this.samples.flatMap((sample) => sample.id === undefined
      ? []
      : [{ id: sample.id, stages: { ...sample.stages } }]);
  }

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

  private renderReport(): void {
    if (this.latencies.length === 0) {
      this.lastReport = this.resumeDuration === undefined
        ? "No painted key echoes yet."
        : `Time to resume: ${format(this.resumeDuration)} ms`;
      this.results.textContent = this.lastReport;
      return;
    }
    const sorted = [...this.latencies].sort((left, right) => left - right);
    const resume = this.resumeDuration === undefined ? "pending" : `${format(this.resumeDuration)} ms`;
    this.lastReport = [
      `Painted echoes: ${sorted.length} / ${this.runTarget}`,
      `p50: ${format(percentile(sorted, 0.5))} ms`,
      `p95: ${format(percentile(sorted, 0.95))} ms`,
      `p99: ${format(percentile(sorted, 0.99))} ms`,
      ...this.renderHopReport(),
      `Time to resume: ${resume}`,
    ].join("\n");
    this.results.textContent = this.lastReport;
  }

  private async copyResults(): Promise<void> {
    this.renderReport();
    try {
      await navigator.clipboard.writeText(this.lastReport);
      this.message.textContent = "Results copied.";
    } catch {
      this.message.textContent = "Clipboard unavailable. Select the results and copy them.";
    }
  }

  private syncButtons(): void {
    const connected = this.terminal?.isConnected === true;
    this.runButton.disabled = !connected || !this.quiet || this.runActive;
    this.dropButton.disabled = !connected || !this.quiet || this.runActive;
  }

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

function percentile(sorted: number[], percentileValue: number): number {
  const rank = Math.max(0, Math.ceil(sorted.length * percentileValue) - 1);
  return sorted[rank] ?? 0;
}

function format(value: number): string {
  return value.toFixed(2);
}

function get<ElementType extends HTMLElement>(root: HTMLElement, selector: string): ElementType {
  const element = root.querySelector<ElementType>(selector);
  if (!element) throw new Error(`Probe control is missing: ${selector}`);
  return element;
}
