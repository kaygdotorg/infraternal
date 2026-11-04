// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The clickable "switch to the Infraternal Multiplexer?" mockup (D315, #251). Mock only; reached with
 * `?mock=1&proto=clusters&startup-demo=1&fixture=none` (add `&mux=zellij` for the other name, `&manual=1` for a startup
 * line Infraternal cannot edit).
 *
 * It runs the product's own notice (`createStartupHints`, the shared toast, the shared confirmation) against a
 * pretend `terminal.startup` service: a startup file held in memory, with the same rules as the real helper
 * (nothing is written without `confirmed`, undo needs the exact line). The live terminal on the canvas prints what a
 * shell would show, so ✓ and Restore visibly change the file. ? opens this server's own `/docs/terminal/multiplexer/` (built from `docs/user/20-terminal/10-multiplexer.md`).
 * The palette (⌘K) has "Mockup: ask again", because answering the question uses it up for the host, as in the product.
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { createStartupHints, multiplexerName, type StartupHints } from "../sessions/startup-hints";

/** The session id the demo's notice talks about. */
const SESSION = "0123456789abcdef0123456789abcdef";
/** The startup file the demo edits. */
const FILE = ".zshrc";

/** Where the demo prints what a shell would show. */
interface Output { write(text: string): void }
/** The running demo. `start` asks the question, `replay` asks it again, `entries` are its palette rows. */
export interface StartupDemo {
  /** Waits for the live terminal, prints the shell start, then asks the question like the product does. */
  start(): void;
  entries(): PaletteEntry[];
  replay(): void;
  readonly hints: StartupHints;
  dispose(): void;
}

/** Prints onto the live terminal's screen (not through the wire); losing a write only loses a decoration. */
const terminalOutput: Output = {
  write(text) {
    const double = (window as unknown as { __tracerTestDouble?: { writeText(text: string): Promise<void> } }).__tracerTestDouble;
    void double?.writeText(text).catch(() => {});
  },
};

/** Builds the demo from the page's query (`mux=zellij`, `manual=1`). `out` is where the shell output goes; by default the live terminal's screen. */
export function createStartupDemo(core: CoreScreen, query: URLSearchParams, out: Output = terminalOutput): StartupDemo {
  const multiplexer = query.get("mux") === "zellij" ? "zellij" : "tmux";
  const command = multiplexer === "zellij" ? "exec zellij attach --create main" : "exec tmux new-session -s main";
  const original = `  ${command}`;
  const guard = `[ -n "$INFRATERNAL_SESSION" ] || ${command}`;
  const manual = query.get("manual") === "1";
  let line = original;
  let shown = false;
  let enabled = true;
  const proposal = { file: FILE, line: 2, original, guard, fingerprint: "mock-fingerprint", multiplexer };
  const prompt = "$ ";
  const grep = (): void => out.write(`grep -n ${multiplexer} ~/${FILE}\r\n3:${line}\r\n${prompt}`);

  const service = {
    isWelcomed: false,
    onWelcome: () => () => {},
    async call(_action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
      await new Promise((resolve) => setTimeout(resolve, 80));
      switch (input.op) {
        case "get": return { global_enabled: enabled, host_override: null, enabled };
        case "set": enabled = input.enabled === true; return { saved: true };
        case "inspect":
          if (!enabled || shown) return { multiplexer: null };
          shown = true;
          return manual ? { multiplexer } : { multiplexer, proposal };
        case "apply":
        case "undo": {
          if (input.confirmed !== true) throw new Error("not confirmed");
          const from = input.op === "apply" ? original : `  ${guard}`;
          if (line !== from) throw new Error("the line is not as expected");
          line = input.op === "apply" ? `  ${guard}` : original;
          grep();
          return { saved: true };
        }
        default: throw new Error("unknown operation");
      }
    },
  };
  const hints = createStartupHints(service, core.toast);
  const timers = new Set<number>();
  const later = (run: () => void, ms: number): void => { const id = window.setTimeout(() => { timers.delete(id); run(); }, ms); timers.add(id); };

  const ask = (): void => { void hints.inspect(SESSION, undefined, "web01"); };
  const shellStart = (): void => {
    out.write(`source ~/${FILE}\r\n${multiplexerName(multiplexer)} server started (pretend)\r\n${prompt}`);
  };
  const whenTerminalReady = (run: () => void): void => {
    let tries = 0;
    const poll = window.setInterval(() => {
      const double = (window as unknown as { __tracerTestDouble?: { isConnected(): boolean } }).__tracerTestDouble;
      if (double?.isConnected() || ++tries > 100) { window.clearInterval(poll); timers.delete(poll); later(run, 400); }
    }, 100);
    timers.add(poll);
  };
  return {
    hints,
    start() { whenTerminalReady(() => { shellStart(); later(ask, 700); }); },
    entries: () => [{ group: "Mockup", glyph: "◇", label: "Mockup: ask to switch again", hint: "the Infraternal Multiplexer question", action: "proto:startup:replay" }],
    replay() {
      line = original;
      shown = false;
      core.toast.dismiss();
      shellStart();
      later(ask, 500);
    },
    dispose() { for (const id of timers) { window.clearTimeout(id); window.clearInterval(id); } timers.clear(); hints.dispose(); },
  };
}
