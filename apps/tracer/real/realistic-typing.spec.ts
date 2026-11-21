/**
 * The D375 rows for what a person typing actually sees (#569 finding 2, #447, D375): overlapping human keystrokes into
 * a real shell, through the production server, behind an emulated round trip, with no test double anywhere.
 *
 * The older rows type one synthetic key at a time and wait for each echo, against a double that repeats every byte
 * back. That cannot show the cases a typist hits: a second key sent before the first echo returns, a shell that
 * redraws instead of echoing, a predicted letter drawn one cell short. This spec closes that gap:
 *
 * - The production `infraternal` binary and tracer, a real PTY, and the account's real `bash` or `zsh`, started by
 *   typing `exec …` into the session (`-f`/`--norc` so no profile changes what the line looks like).
 * - The fixture's TLS bridge adds `REAL_ONE_WAY_MS` in each direction. It delays in user space, so nothing on the
 *   machine changes: no namespace, no route, no `tc` (a namespace would be needed only for kernel-level loss).
 * - Real, trusted key events from `page.keyboard`, timed by J1079's recipe: the key lists of its recorded traces
 *   (`typing-model.ts`) with a person's irregular gaps, so keys overlap at 300 ms.
 * - The probe's typing recorder (`PerformanceProbe.startHumanRecording`) stamps every key, every output region
 *   (socket message to paint, directly) and every change of the prediction overlay.
 *
 * Each repetition types the line, waits for its echoes, presses Enter (the line is an `echo`) and waits for quiet, so one run gives a
 * p99 over more than 100 keys. Every (trace, prediction on/off) pair is its own server and page.
 *
 * Rows printed at the end (`METRIC name=d375_real_*`, read by `scripts/latency_targets.py`):
 * - `real_paint_after_ws`: socket message to paint, p99 over all output regions (the browser's share, a gated row);
 * - `real_echo_shell`: key to the host's echo painted, prediction off, against the round trip plus two frames;
 * - `real_typed_letter`: key to the letter in its own cell, prediction on, with the counts of wrong cells.
 * Also one `METRIC name=realistic_typing …` line per run with its raw numbers. The old rows keep running beside these.
 *
 * Run with `scripts/verify latency`, or by hand with `INFRATERNAL_BIN` set and the tracer built. `REAL_ONE_WAY_MS`
 * is the one-way delay (150 is the 300 ms round trip), `REALISTIC_REPEATS` the lines per run (default 7),
 * `REALISTIC_TRACES` a comma list of trace names to run. It measures; run it on a quiet machine.
 */
import { expect, test, type Page } from "playwright/test";
import { d375Row, FRAME_MS, latencyDisplay } from "../test/latency-targets";
import { personName, startRealServer, type RealServer } from "./server";
import { humanGaps, paintAfterMessage, percentile, scoreRepetition, TRACES, type RecordedKey, type RecordedOutput, type RecordedOverlay, type TypingTrace } from "./typing-model";

/** One-way delay the bridge adds; the round trip is twice this. */
const ONE_WAY_MS = Number(process.env.REAL_ONE_WAY_MS ?? 150);
/** The round trip the rows are measured at. */
const RTT_MS = ONE_WAY_MS * 2;
/** How many times each trace's line is typed per run: 7 lines of 16 keys is over 100 keys. */
const REPEATS = Number(process.env.REALISTIC_REPEATS ?? 7);
/** The traces to run, by name; default all four. */
const SELECTED = (process.env.REALISTIC_TRACES ?? "").split(",").filter(Boolean);
/** D375 row 2: the real echo may take the round trip plus two frames (16.7 ms). */
const ECHO_TARGET_MS = RTT_MS + 2 * FRAME_MS;
/** How long the terminal must stay silent before a line is considered finished. */
const QUIET_MS = 700;

test.describe.configure({ mode: "serial" });

/** What one run measured, kept for the closing rows. */
interface RunResult {
  trace: string;
  predict: boolean;
  paintAfterWs: number[];
  felt: number[];
  wrongCells: number;
  predictedKeys: number;
  scoredKeys: number;
}
const results: RunResult[] = [];

/** Resolves after `ms` milliseconds. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Signs in to a fresh server with a software passkey and opens the probe page with its first terminal. */
async function openProbePage(server: RealServer, page: Page, predict: boolean): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(`${server.origin}/?theme=ink&bg=none&probe=1${predict ? "&predict=1" : ""}`);
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("realistic_typing"));
  await page.locator("#setup-display-name").fill("Realistic typing");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".terminal-host").first().waitFor();
}

/** Waits until the terminal has painted something and then stayed silent for `QUIET_MS`. */
async function waitQuiet(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate((quietMs) => {
    const last = window.__tracerPerformanceProbe?.human.lastPaintedAt() ?? 0;
    return last > 0 && performance.now() - last >= quietMs;
  }, QUIET_MS), { timeout: 60_000, intervals: [100] }).toBe(true);
}

/**
 * Types `keys` with `gaps` (milliseconds before each key) on an absolute schedule, so a slow key press does not push
 * every later key back. Real, trusted key events.
 */
async function typeLike(page: Page, keys: string[], gaps: number[]): Promise<void> {
  const start = performance.now();
  let due = 0;
  for (const [index, key] of keys.entries()) {
    due += gaps[index] ?? 0;
    const wait = start + due - performance.now();
    if (wait > 0) await sleep(wait);
    await page.keyboard.press(key);
  }
}

/** Starts `shell` inside the session so the line is typed into a known prompt; resets the recorder afterwards. */
async function startShell(page: Page, shell: TypingTrace["shell"]): Promise<void> {
  const command = shell === "bash"
    ? "exec env PS1='$ ' bash --norc --noprofile -i"
    : "exec env PROMPT='$ ' zsh -f -i";
  await page.locator(".terminal-host").first().click();
  await page.evaluate(() => window.__tracerPerformanceProbe?.human.start());
  await page.keyboard.type(command);
  await page.keyboard.press("Enter");
  await waitQuiet(page);
  await page.evaluate(() => { window.__tracerPerformanceProbe?.human.stop(); window.__tracerPerformanceProbe?.human.start(); });
}

/** Types one trace `REPEATS` times and returns what the recorder saw, with the column each line started in. */
async function typeRepetitions(page: Page, trace: TypingTrace): Promise<{ startColumns: number[] }> {
  const startColumns: number[] = [];
  const printable = trace.keys.filter((key) => key.length === 1).length;
  let typed = 0;
  for (let repetition = 0; repetition < REPEATS; repetition += 1) {
    startColumns.push(await page.evaluate(() => window.__tracerPerformanceProbe?.human.cursorColumn() ?? 0));
    await typeLike(page, trace.keys, humanGaps(trace.keys.length, 1000 + repetition * 17 + trace.name.length));
    typed += printable;
    // Every typed letter's own echo must have painted before the line is cleared; a stuck one fails the run.
    await expect.poll(() => page.evaluate((count) => {
      const trace = window.__tracerPerformanceProbe?.human.trace();
      return trace ? trace.keys.filter((key) => key.key.length === 1 && key.echoPaintedAt !== undefined).length >= count : false;
    }, typed), { timeout: 30_000, intervals: [100] }).toBe(true);
    await waitQuiet(page);
    // Enter runs the line (an echo) and brings a fresh prompt, as a person's next line starts.
    await page.keyboard.press("Enter");
    await waitQuiet(page);
  }
  return { startColumns };
}

for (const trace of TRACES.filter((candidate) => SELECTED.length === 0 || SELECTED.includes(candidate.name))) {
  for (const predict of [false, true]) {
    test(`${trace.name} typed with overlapping keys, prediction ${predict ? "on" : "off"}`, async ({ browser }) => {
      test.setTimeout(600_000);
      const server = await startRealServer({ latencyMs: ONE_WAY_MS });
      const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 } });
      const page = await context.newPage();
      try {
        await openProbePage(server, page, predict);
        await expect.poll(() => server.bridges.some((bridge) => !bridge.closed && bridge.attached.size > 0), { timeout: 30_000 }).toBe(true);
        // sleep: the login shell's own startup output has no end marker; give it a moment before the first poll for quiet.
        await sleep(1_000);
        await startShell(page, trace.shell);
        const { startColumns } = await typeRepetitions(page, trace);
        const recorded = await page.evaluate(() => window.__tracerPerformanceProbe!.human.trace());
        const keys: RecordedKey[] = recorded.keys;
        const overlay: RecordedOverlay[] = recorded.overlay;
        const outputs: RecordedOutput[] = recorded.outputs;
        const printable = keys.filter((key) => key.key.length === 1);
        const plain = trace.keys.every((key) => key.length === 1);
        const perLine = trace.keys.filter((key) => key.length === 1).length;
        let felt: number[] = [];
        let wrongCells = 0;
        let predictedKeys = 0;
        if (plain) {
          // Plain lines have a known cell for every key, so a drawn letter can be checked against it.
          for (let line = 0; line < REPEATS; line += 1) {
            const lineKeys = printable.slice(line * perLine, (line + 1) * perLine);
            // The line's frames run from its first key to the next line's first key (the overlay clears in between).
            const lineStart = lineKeys[0]?.keydownAt ?? 0;
            const nextStart = printable[(line + 1) * perLine]?.keydownAt ?? Number.POSITIVE_INFINITY;
            const scored = scoreRepetition(lineKeys, overlay.filter((frame) => frame.at >= lineStart && frame.at < nextStart), startColumns[line] ?? 0);
            felt = felt.concat(scored.felt);
            wrongCells += scored.wrongCells;
            predictedKeys += scored.predictedFirst.filter(Boolean).length;
          }
        } else {
          // With Backspace the final cell of a letter is not simply its position; the letter's own echo is the measure.
          felt = printable.map((key) => (key.echoPaintedAt === undefined ? Number.NaN : key.echoPaintedAt - key.keydownAt));
          if (predict) {
            predictedKeys = printable.filter((key) => key.predictedAt !== undefined && (key.echoPaintedAt === undefined || key.predictedAt <= key.echoPaintedAt)).length;
          }
        }
        const paint = paintAfterMessage(outputs);
        results.push({ trace: trace.name, predict, paintAfterWs: paint, felt, wrongCells, predictedKeys, scoredKeys: printable.length });
        console.log(
          `METRIC name=realistic_typing trace=${trace.name} predict=${predict ? 1 : 0} rtt_ms=${RTT_MS} display=${latencyDisplay()} ` +
          `keys=${printable.length} predicted_keys=${predictedKeys} wrong_cells=${wrongCells} predictor=${JSON.stringify(recorded.predictor ?? null).replaceAll(" ", "")} ` +
          `felt_p50_ms=${percentile(felt, 0.5).toFixed(2)} felt_p99_ms=${percentile(felt, 0.99).toFixed(2)} ` +
          `paint_after_ws_n=${paint.length} paint_after_ws_p50_ms=${percentile(paint, 0.5).toFixed(2)} paint_after_ws_p99_ms=${percentile(paint, 0.99).toFixed(2)}`,
        );
        expect(printable.length).toBe(perLine * REPEATS);
      } finally {
        await context.close();
        await server.dispose();
      }
    });
  }
}

/** Prints the closing rows from every run above. It asserts nothing about speed: the report at the end of `scripts/verify latency` gates. */
test("realistic typing rows", () => {
  const paint = results.flatMap((run) => run.paintAfterWs);
  const echo = results.filter((run) => !run.predict).flatMap((run) => run.felt);
  const typed = results.filter((run) => run.predict).flatMap((run) => run.felt);
  const wrong = results.filter((run) => run.predict).reduce((sum, run) => sum + run.wrongCells, 0);
  const predicted = results.filter((run) => run.predict).reduce((sum, run) => sum + run.predictedKeys, 0);
  const typedKeys = results.filter((run) => run.predict).reduce((sum, run) => sum + run.scoredKeys, 0);
  const traces = [...new Set(results.map((run) => run.trace))].join(",");
  const source = "real-server-real-shell-tracer-production-build";
  console.log(d375Row({
    key: "real_paint_after_ws", source, n: paint.length, value: percentile(paint, 0.99), unit: "ms", target: FRAME_MS,
    extra: `p50_ms=${percentile(paint, 0.5).toFixed(2)} traces=${traces} rtt_ms=${RTT_MS}`,
  }).line);
  console.log(d375Row({
    key: "real_echo_shell", source, n: echo.filter(Number.isFinite).length, value: percentile(echo, 0.99), unit: "ms",
    target: ECHO_TARGET_MS, extra: `p50_ms=${percentile(echo, 0.5).toFixed(2)} traces=${traces} rtt_ms=${RTT_MS}`,
  }).line);
  console.log(d375Row({
    key: "real_typed_letter", source, n: typed.filter(Number.isFinite).length, value: percentile(typed, 0.99), unit: "ms",
    target: FRAME_MS, reportOnly: true,
    extra: `p50_ms=${percentile(typed, 0.5).toFixed(2)} wrong_cells=${wrong} predicted_keys=${predicted} typed_keys=${typedKeys} traces=${traces} rtt_ms=${RTT_MS}`,
  }).line);
  expect(results.length).toBeGreaterThan(0);
});
