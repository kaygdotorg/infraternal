/** Independent #257 regression: restored terminals can join a shared socket after its open event. */
import { expect, test } from "bun:test";
import { TerminalClient } from "../src/terminal";
import { StaleScreenWatch } from "../src/stale-screen";
import type { StreamHandler } from "../src/connection";

for (const socketOpenedFirst of [false, true]) for (const scenario of [
  { name: "resized", captured: { cols: 80, rows: 24 }, shown: true },
  { name: "same-size", captured: { cols: 120, rows: 40 }, shown: false },
  { name: "legacy", captured: undefined, shown: true },
]) test(`a ${scenario.name} silent restore decides its note watch when socketOpenedFirst=${socketOpenedFirst}`, () => {
  let expire: (() => void) | undefined;
  const changes: boolean[] = [];
  const watch = new StaleScreenWatch((shown) => changes.push(shown), {
    after: (_ms, run) => { expire = run; return 1; }, cancel: () => { expire = undefined; },
  });
  // This uses the production stream callbacks and painted-fence handler. A shared socket's
  // openStream calls only onWelcome when it was already welcomed before the renderer registered.
  const client = Object.assign(Object.create(TerminalClient.prototype), {
    closed: false, sessionGone: false, sessionId: new Uint8Array(16),
    connectionIsResume: false, attached: true, attachmentConfirmed: false,
    lastOutSeq: 10n, receivedOutSeq: 10n, replayResponseFence: 10n,
    replayCapturedSize: scenario.captured, lastSize: { cols: 120, rows: 40 },
    staleWatch: watch, config: { hooks: {}, status: { textContent: "Catching up…" } },
    conn: { streamAttached: () => {} },
    cancelStreamRetry: () => {}, tryAttach: () => {}, resendUnacknowledgedInput: () => {},
    startPings: () => {}, setStatus: () => {},
  }) as { streamHandler(): StreamHandler; releaseReplayResponsesAfterPaint(): void };
  const handler = client.streamHandler();
  if (!socketOpenedFirst) handler.onSocketOpen(false);
  handler.onWelcome(true);
  client.releaseReplayResponsesAfterPaint();
  expire?.();
  expect(changes).toEqual(scenario.shown ? [true] : []);
  watch.output(11n);
  expect(changes).toEqual(scenario.shown ? [true, false] : []);
});
