/**
 * Test double of the owner's Updates controls (#211, S5; `?mock=1&proto=clusters&updates=1`). It decides nothing the real server
 * will: it holds one scripted state and plays the few transitions the buttons cause (check, update now, roll back), so every
 * message of the Updates window, and the Inbox item can be reached and photographed. Times are taken from now, so
 * "2 hours ago" is always two hours before the day the double is opened.
 */
import type { Channel, UpdateFacts, UpdateHistoryEntry, UpdatesSource } from "../../updates/source";

const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;

/** One state to reach from the palette. */
export interface UpdatesScenario { id: string; label: string; hint: string; facts: (now: number) => UpdateFacts }

const lostSince = (version: string, when: string): string =>
  `Everything saved since ${version} was installed ${when} is lost: new keys, shares, devices and settings changes. Terminal sessions stay open.`;

const history = (now: number): UpdateHistoryEntry[] => [
  { version: "0.4.2", from: "0.4.1", outcome: "applied", at: now - 2 * HOUR },
  { version: "0.4.1", from: "0.4.0", outcome: "applied", at: now - 2 * DAY },
  { version: "0.4.0", from: "0.3.9", outcome: "rolled-back", at: now - 5 * DAY, reason: "It did not pass its health check within 2 minutes." },
  { version: "0.3.9", from: "0.3.8", outcome: "applied", at: now - 9 * DAY },
];

const base = (now: number, over: Partial<UpdateFacts>): UpdateFacts => ({
  state: { kind: "current" }, running: "0.4.2", channel: "stable", quietMinutes: 5, checkedAt: now - 2 * MIN, history: history(now),
  rollback: { available: true, to: "0.4.1", lost: lostSince("0.4.2", "2 hours ago"), since: now - 2 * HOUR }, ...over,
});

export const UPDATE_SCENARIOS: UpdatesScenario[] = [
  { id: "current", label: "up to date", hint: "tick · Check now · Roll back available", facts: (n) => base(n, {}) },
  { id: "checking", label: "checking", hint: "turning arc · every button waits", facts: (n) => base(n, { state: { kind: "checking" } }) },
  { id: "downloading", label: "downloading", hint: "0.5.0 at 62%", facts: (n) => base(n, { state: { kind: "downloading", version: "0.5.0", percent: 62 } }) },
  { id: "ready", label: "ready, waiting for a quiet moment", hint: "Inbox item · Update now", facts: (n) => base(n, { state: { kind: "ready", version: "0.5.0" } }) },
  { id: "switching", label: "installing", hint: "sessions stay open", facts: (n) => base(n, { state: { kind: "applying", version: "0.5.0", phase: "switching" } }) },
  { id: "trial", label: "checking the new version", hint: "the two-minute health check", facts: (n) => base(n, { state: { kind: "applying", version: "0.5.0", phase: "checking" } }) },
  { id: "undone-health", label: "undone: failed its check", hint: "rolled back by itself, with the reason", facts: (n) => base(n, {
    state: { kind: "rolled-back", version: "0.5.0", reason: "It did not pass its health check within 2 minutes, so 0.4.2 is running again. Anything saved in those 2 minutes was lost." },
    history: [{ version: "0.5.0", from: "0.4.2", outcome: "rolled-back", at: n - 6 * MIN, reason: "It did not pass its health check within 2 minutes." }, ...history(n)],
    rollback: { available: false } }) },
  { id: "undone-owner", label: "undone: rolled back by you", hint: "manual Roll back", facts: (n) => base(n, {
    running: "0.4.1", state: { kind: "rolled-back", version: "0.4.2", reason: "You rolled it back, so 0.4.1 is running again. What was saved since 0.4.2 was installed is lost." },
    history: [{ version: "0.4.2", from: "0.4.1", outcome: "rolled-back", at: n - 3 * MIN, reason: "You rolled it back." }, ...history(n).slice(1)],
    rollback: { available: false } }) },
  { id: "failed", label: "failed: signature did not verify", hint: "nothing changed", facts: (n) => base(n, { state: { kind: "failed", reason: "The download of 0.5.0 did not match its signature." },
    history: [{ version: "0.5.0", from: "0.4.2", outcome: "failed", at: n - 4 * MIN, reason: "The download did not match its signature." }, ...history(n)] }) },
  { id: "offline", label: "offline", hint: "cannot reach the release server", facts: (n) => base(n, { state: { kind: "offline", reason: "The release server did not answer. It tries again in 15 minutes." }, checkedAt: n - 3 * HOUR }) },
  { id: "no-release", label: "no release yet", hint: "a fresh channel with nothing published", facts: (n) => base(n, { channel: "edge", running: "0.4.2-edge.1", state: { kind: "offline", reason: "The edge channel has no release yet." }, history: [], rollback: { available: false }, checkedAt: n - MIN }) },
  { id: "never", label: "never checked", hint: "first minutes after the server started", facts: (n) => base(n, { state: { kind: "never" }, checkedAt: undefined, history: [], rollback: { available: false } }) },
  { id: "edge", label: "channel: edge", hint: "Edge selected, up to date", facts: (n) => base(n, { channel: "edge", running: "0.4.3-edge.18", rollback: { available: true, to: "0.4.3-edge.17", lost: lostSince("0.4.3-edge.18", "40 minutes ago"), since: n - 40 * MIN },
    history: [{ version: "0.4.3-edge.18", from: "0.4.3-edge.17", outcome: "applied", at: n - 40 * MIN }, { version: "0.4.3-edge.17", from: "0.4.3-edge.16", outcome: "applied", at: n - 3 * HOUR }] }) },
  { id: "aged", label: "installed 3 days ago", hint: "up to date · Roll back no longer offered (24 h)", facts: (n) => base(n, { running: "0.4.2",
    rollback: { available: true, to: "0.4.1", lost: lostSince("0.4.2", "3 days ago"), since: n - 3 * DAY },
    history: history(n).map((e, i) => (i === 0 ? { ...e, at: n - 3 * DAY } : e)) }) },
  { id: "off", label: "automatic updates off", hint: "not available on this server, with the reason", facts: (n) => base(n, { state: { kind: "off", reason: "This server does not run as root, so it cannot replace its own program." }, checkedAt: undefined, history: [], rollback: { available: false } }) },
  { id: "long", label: "long history, long version", hint: "worst case wrapping", facts: (n) => base(n, { running: "0.12.104-edge.3-rc.2+build.20261121.3f9c2ab", state: { kind: "ready", version: "0.12.105-edge.3-rc.2+build.20261121.9ad41c0" },
    history: Array.from({ length: 12 }, (_, i): UpdateHistoryEntry => ({ version: `0.12.${104 - i}-edge.3`, from: `0.12.${103 - i}-edge.3`, outcome: i === 3 ? "failed" : "applied", at: n - (i + 1) * DAY, ...(i === 3 ? { reason: "The new version could not open the database copy, which is read-only on this volume. Nothing was changed." } : {}) })) }) },
];

const wait = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

export interface UpdatesDouble extends UpdatesSource {
  setScenario(id: string): void;
  /** Whether the next call is refused as if the sign-in were stale (the specs and the review use it). */
  refuseNext(sentence: string | undefined): void;
}

export function createUpdatesDouble(initial = "current"): UpdatesDouble {
  const find = (id: string): UpdatesScenario => UPDATE_SCENARIOS.find((s) => s.id === id) ?? UPDATE_SCENARIOS[0]!;
  let state = find(initial).facts(Date.now());
  let refusal: string | undefined;
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const run of listeners) run(); };
  const set = (next: Partial<UpdateFacts>): void => { state = { ...state, ...next }; emit(); };
  const guard = (): void => { if (refusal) { const r = refusal; refusal = undefined; throw new Error(r); } };

  return {
    facts: () => state,
    setScenario(id) { state = find(id).facts(Date.now()); emit(); },
    refuseNext(sentence) { refusal = sentence; },
    async check() {
      guard();
      set({ state: { kind: "checking" } });
      await wait(900);
      set({ state: { kind: "current" }, checkedAt: Date.now() });
    },
    async apply() {
      guard();
      if (state.state.kind !== "ready") throw new Error("Nothing is waiting to be installed.");
      const to = state.state.version, from = state.running;
      set({ state: { kind: "applying", version: to, phase: "switching" } });
      await wait(1200);
      set({ state: { kind: "applying", version: to, phase: "checking" } });
      await wait(1800);
      const entry: UpdateHistoryEntry = { version: to, from, outcome: "applied", at: Date.now() };
      set({ state: { kind: "current" }, running: to, checkedAt: Date.now(), history: [entry, ...state.history], rollback: { available: true, to: from, lost: lostSince(to, "just now"), since: Date.now() } });
    },
    async rollback() {
      guard();
      if (!state.rollback.available) throw new Error("No earlier version is kept.");
      const to = state.rollback.to, from = state.running;
      set({ state: { kind: "applying", version: to, phase: "switching" } });
      await wait(1500);
      const entry: UpdateHistoryEntry = { version: from, from: to, outcome: "rolled-back", at: Date.now(), reason: "You rolled it back." };
      set({ running: to, state: { kind: "rolled-back", version: from, reason: `You rolled it back, so ${to} is running again. What was saved since ${from} was installed is lost.` }, history: [entry, ...state.history], rollback: { available: false } });
    },
    async setChannel(channel: Channel) { guard(); await wait(150); set({ channel }); },
    async setQuietMinutes(minutes) { guard(); await wait(150); set({ quietMinutes: minutes }); },
    onChange(run) { listeners.add(run); return () => { listeners.delete(run); }; },
  };
}
