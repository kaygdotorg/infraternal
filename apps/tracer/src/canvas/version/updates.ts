/**
 * The Updates row's behaviour (#216), as plain logic so every state can be tested without a screen.
 *
 * One row, one value, one default action (owner, 2026-11-01: "there should be one Updates key and it should automatically
 * show if any host is lagging"; "tapping the value should check for updates across all hosts in parallel"):
 *
 *   Up to date  ──press──▶  Checking for updates…  ──▶  Up to date
 *                                                   ──▶  2 updates available — proceed?  ──press──▶  Updating 2…  ──▶  (checks again)
 *                                                   ──▶  Couldn't check — try again
 *
 * - Pressing a value that asks "proceed?" proceeds; pressing any other state checks. The value is the whole conversation.
 * - Lag shows by itself: a host whose reported version differs from this server's counts as an update the moment the
 *   facts say so, with no check. A host that has not reported a version is unknown, never behind.
 * - A check asks the server and every host together (`checkFleet`), so its length is the slowest host's, not the sum.
 * - The turning arc stays at least `MIN_BUSY_MS` so the change is seen even when the answer is instant.
 *
 * Nothing here touches the page: `VersionPanel` paints what `view()` says.
 */
import type { CheckResult, HostVersion, Target, VersionFacts, VersionSource } from "./source";
import { UpdatesUnavailable } from "./source";

/** What the row says: the settled state, or the work in progress. */
export type Fleet =
  | { kind: "unknown" }
  | { kind: "current" }
  | { kind: "available"; targets: Target[] }
  | { kind: "failed"; reason: string }
  | { kind: "checking" }
  | { kind: "updating"; targets: Target[] };

/** The shortest time the spinner shows. Long enough to read "Checking for updates…", short enough to never feel slow. */
export const MIN_BUSY_MS = 700;

/** Hosts whose reported version is known and differs from this server's. */
export function lagging(facts: Pick<VersionFacts, "version" | "hosts">): Target[] {
  return facts.hosts
    .filter((host): host is HostVersion & { version: string } => host.version !== undefined && host.version !== facts.version)
    .map((host) => ({ name: host.name, from: host.version, to: facts.version }));
}

/** Merges two target lists by name, the first list winning. */
const union = (first: Target[], second: Target[]): Target[] => [...first, ...second.filter((t) => !first.some((f) => f.name === t.name))];

/** The state the row shows now: a settled answer, with whatever lag the facts already show added to it. */
export function effective(settled: Fleet, facts: Pick<VersionFacts, "version" | "hosts">): Fleet {
  if (settled.kind === "checking" || settled.kind === "updating" || settled.kind === "failed") return settled;
  const behind = lagging(facts);
  if (settled.kind === "available") return { kind: "available", targets: union(settled.targets, behind) };
  return behind.length ? { kind: "available", targets: behind } : settled;
}

export interface FleetController {
  /** The state to paint now. */
  view(): Fleet;
  /** The last state that was not work in progress (what the pill shows while a check runs). */
  settled(): Fleet;
  /** What a press does now. */
  action(): "check" | "proceed";
  /** Presses the row. Resolves when the work it started has settled. A press during work does nothing. */
  press(): Promise<void>;
  onChange(run: () => void): () => void;
  dispose(): void;
}

export interface FleetOptions {
  source: VersionSource;
  /** Shown to the person once, in plain words, when something they asked for could not be done. */
  say?(message: string): void;
  /** Injected so a test never waits. Default: a timer. */
  sleep?(ms: number): Promise<void>;
  minBusyMs?: number;
}

export function createFleetController(options: FleetOptions): FleetController {
  const { source } = options;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => { window.setTimeout(resolve, ms); }));
  const minBusy = options.minBusyMs ?? MIN_BUSY_MS;
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const run of listeners) run(); };

  let settled: Fleet = source.facts().updates;
  let busy: Fleet | undefined;
  let disposed = false;

  const view = (): Fleet => effective(busy ?? settled, source.facts());
  const settle = (next: Fleet): void => { settled = next; busy = undefined; if (!disposed) emit(); };
  const work = (state: Fleet): void => { busy = state; if (!disposed) emit(); };

  /** Asks, and keeps the spinner for at least `minBusy`. */
  const ask = async (): Promise<Fleet> => {
    const started = Promise.all([
      source.check().then((result): Fleet => result, (error: unknown): Fleet => ({
        kind: "failed",
        reason: error instanceof UpdatesUnavailable ? error.message : "The check did not finish. Try again in a moment.",
      })),
      sleep(minBusy),
    ]);
    return (await started)[0];
  };

  const check = async (): Promise<void> => {
    work({ kind: "checking" });
    settle(await ask());
  };

  const proceed = async (targets: Target[]): Promise<void> => {
    if (!source.proceed) { settle({ kind: "failed", reason: "Updating is not available in this build yet." }); return; }
    work({ kind: "updating", targets });
    try {
      await Promise.all([source.proceed(targets), sleep(minBusy)]);
    } catch {
      options.say?.("The update did not start. Nothing was changed.");
      settle({ kind: "available", targets });
      return;
    }
    // The hosts report their new version on their own; checking again tells whether anything is still behind.
    work({ kind: "checking" });
    settle(await ask());
  };

  // The source's retained update state is the truth: when it changes (a new answer arrived from elsewhere, an update finished)
  // the row follows it; a change that leaves the retained state as it was (the licence, a host's version) keeps what a
  // press here found.
  let seen = JSON.stringify(source.facts().updates);
  const stop = source.onChange(() => {
    if (disposed) return;
    const now = JSON.stringify(source.facts().updates);
    if (now !== seen) { seen = now; if (!busy) settled = source.facts().updates; }
    emit();
  });

  return {
    view,
    settled: () => effective(settled, source.facts()),
    action: () => (view().kind === "available" ? "proceed" : "check"),
    async press() {
      if (busy) return;
      const now = view();
      if (now.kind === "available") await proceed(now.targets); else await check();
    },
    onChange(run) { listeners.add(run); return () => { listeners.delete(run); }; },
    dispose() { disposed = true; listeners.clear(); stop(); },
  };
}

/**
 * Checks every target together: all probes start before any answers, and the result waits for the slowest one. A probe that
 * fails counts as "could not be checked", and one failure makes the whole answer "failed" rather than quietly leaving a
 * host out. For a source that has to ask each host itself; a server that already knows all versions needs one call instead.
 */
export async function checkFleet(names: string[], probe: (name: string) => Promise<Target | null>): Promise<CheckResult> {
  const answers = await Promise.allSettled(names.map((name) => probe(name)));
  const failed = answers.find((a): a is PromiseRejectedResult => a.status === "rejected");
  if (failed) return { kind: "failed", reason: failed.reason instanceof Error ? failed.reason.message : "A host did not answer." };
  const targets = answers.flatMap((a) => (a.status === "fulfilled" && a.value ? [a.value] : []));
  return targets.length ? { kind: "available", targets } : { kind: "current" };
}
