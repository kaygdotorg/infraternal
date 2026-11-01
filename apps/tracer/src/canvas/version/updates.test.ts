import { describe, expect, test } from "bun:test";
import type { CheckResult, Target, VersionFacts, VersionSource } from "./source";
import { UpdatesUnavailable } from "./source";
import { checkFleet, createFleetController, effective, lagging } from "./updates";

const server = (to: string): Target => ({ name: "this server", server: true, from: "1.0.0", to });
const facts = (over: Partial<VersionFacts> = {}): VersionFacts => ({
  version: "1.0.0", copy: "1.0.0-abc", hosts: [], licence: { tier: "community" }, updates: { kind: "unknown" }, ...over,
});

/** A source whose check and proceed the test resolves by hand. */
function source(initial: VersionFacts, behaviour: { check?: () => Promise<CheckResult>; proceed?: (t: Target[]) => Promise<void> } = {}): VersionSource & { set(f: VersionFacts): void; checks: number } {
  let now = initial;
  const listeners = new Set<() => void>();
  const out = {
    checks: 0,
    facts: () => now,
    check: () => { out.checks++; return behaviour.check ? behaviour.check() : Promise.resolve<CheckResult>({ kind: "current" }); },
    ...(behaviour.proceed ? { proceed: behaviour.proceed } : {}),
    onChange: (run: () => void) => { listeners.add(run); return () => { listeners.delete(run); }; },
    set(f: VersionFacts) { now = f; for (const run of listeners) run(); },
  };
  return out;
}

const instant = (): Promise<void> => Promise.resolve();

describe("lag shows by itself", () => {
  test("a host whose version differs from the server's is an update; an unknown version never is", () => {
    const f = facts({ hosts: [{ name: "a", version: "0.9.0" }, { name: "b", version: "1.0.0" }, { name: "c", version: undefined }] });
    expect(lagging(f).map((t) => t.name)).toEqual(["a"]);
    expect(effective({ kind: "current" }, f)).toEqual({ kind: "available", targets: [{ name: "a", from: "0.9.0", to: "1.0.0" }] });
  });

  test("no lag leaves the settled state alone; work in progress and failures are never replaced", () => {
    const f = facts({ hosts: [{ name: "a", version: "0.9.0" }] });
    expect(effective({ kind: "checking" }, f).kind).toBe("checking");
    expect(effective({ kind: "failed", reason: "x" }, f).kind).toBe("failed");
    expect(effective({ kind: "current" }, facts()).kind).toBe("current");
    expect(effective({ kind: "unknown" }, facts()).kind).toBe("unknown");
  });

  test("a check's targets and the lagging hosts are merged by name", () => {
    const f = facts({ hosts: [{ name: "a", version: "0.9.0" }] });
    const view = effective({ kind: "available", targets: [server("1.1.0"), { name: "a", from: "0.9.0", to: "1.1.0" }] }, f);
    expect(view.kind === "available" && view.targets.map((t) => t.name)).toEqual(["this server", "a"]);
  });
});

describe("the Updates value is the whole conversation", () => {
  test("a press on 'Up to date' checks, shows the spinner, and settles", async () => {
    const s = source(facts({ updates: { kind: "current" } }));
    const c = createFleetController({ source: s, sleep: instant });
    const seen: string[] = [];
    c.onChange(() => seen.push(c.view().kind));
    expect(c.action()).toBe("check");
    await c.press();
    expect(seen).toEqual(["checking", "current"]);
    expect(s.checks).toBe(1);
  });

  test("a check that finds updates asks 'proceed?', and a second press proceeds then checks again", async () => {
    let proceeded: Target[] = [];
    let found: CheckResult = { kind: "available", targets: [server("1.1.0")] };
    const s = source(facts(), { check: () => Promise.resolve(found), proceed: (t) => { proceeded = t; found = { kind: "current" }; return Promise.resolve(); } });
    const c = createFleetController({ source: s, sleep: instant });
    await c.press();
    expect(c.view().kind).toBe("available");
    expect(c.action()).toBe("proceed");
    const seen: string[] = [];
    c.onChange(() => seen.push(c.view().kind));
    await c.press();
    expect(proceeded.map((t) => t.name)).toEqual(["this server"]);
    expect(seen).toEqual(["updating", "checking", "current"]);
  });

  test("lag that is already known is answered by one press: proceed, no check first", async () => {
    let proceeded = 0;
    const s = source(facts({ hosts: [{ name: "a", version: "0.9.0" }] }), { proceed: () => { proceeded++; return Promise.resolve(); } });
    const c = createFleetController({ source: s, sleep: instant });
    expect(c.action()).toBe("proceed");
    await c.press();
    expect(proceeded).toBe(1);
  });

  test("a press while work runs does nothing", async () => {
    let release!: () => void;
    const s = source(facts(), { check: () => new Promise<CheckResult>((resolve) => { release = () => resolve({ kind: "current" }); }) });
    const c = createFleetController({ source: s, sleep: instant });
    const first = c.press();
    await c.press();
    expect(s.checks).toBe(1);
    release();
    await first;
    expect(c.view().kind).toBe("current");
  });

  test("a source that cannot check says why, in its own words; any other failure is a plain sentence", async () => {
    const a = createFleetController({ source: source(facts(), { check: () => Promise.reject(new UpdatesUnavailable()) }), sleep: instant });
    await a.press();
    expect(a.view()).toEqual({ kind: "failed", reason: "Checking for updates is not available in this build yet." });
    const b = createFleetController({ source: source(facts(), { check: () => Promise.reject(new Error("socket 10.0.0.4:7 reset")) }), sleep: instant });
    await b.press();
    const view = b.view();
    expect(view.kind === "failed" && view.reason).toBe("The check did not finish. Try again in a moment.");
  });

  test("a source with no way to update never offers it as done; the failure is kept for the person to read", async () => {
    const s = source(facts({ hosts: [{ name: "a", version: "0.9.0" }] }));
    const c = createFleetController({ source: s, sleep: instant });
    await c.press();
    const view = c.view();
    // The host still lags, so the row asks again; the failure reason is kept on the settled state.
    expect(view.kind).toBe("failed");
  });

  test("an update that does not start leaves the choice where it was and says so once", async () => {
    const said: string[] = [];
    const s = source(facts({ hosts: [{ name: "a", version: "0.9.0" }] }), { proceed: () => Promise.reject(new Error("no")) });
    const c = createFleetController({ source: s, sleep: instant, say: (m) => said.push(m) });
    await c.press();
    expect(c.view().kind).toBe("available");
    expect(said).toEqual(["The update did not start. Nothing was changed."]);
  });

  test("the spinner stays at least as long as asked, even when the answer is instant", async () => {
    const waits: number[] = [];
    const c = createFleetController({ source: source(facts()), sleep: (ms) => { waits.push(ms); return Promise.resolve(); }, minBusyMs: 700 });
    await c.press();
    expect(waits).toEqual([700]);
  });
});

describe("the source is the truth about what it retains", () => {
  test("a new retained update state replaces what the row showed; an unrelated change keeps what a press found", async () => {
    const s = source(facts({ updates: { kind: "current" } }));
    const c = createFleetController({ source: s, sleep: instant });
    s.set(facts({ updates: { kind: "unknown" } }));
    expect(c.view().kind).toBe("unknown");
    await c.press();
    expect(c.view().kind).toBe("current");
    s.set(facts({ updates: { kind: "unknown" }, licence: { tier: "team" } }));
    expect(c.view().kind).toBe("current");
  });
});

describe("checkFleet asks every host together", () => {
  test("every probe has started before any has answered", async () => {
    const started: string[] = [];
    const releases: Array<() => void> = [];
    const probe = (name: string): Promise<Target | null> => { started.push(name); return new Promise((resolve) => { releases.push(() => resolve(null)); }); };
    const done = checkFleet(["a", "b", "c", "d"], probe);
    await Promise.resolve();
    expect(started).toEqual(["a", "b", "c", "d"]);
    for (const release of releases) release();
    expect(await done).toEqual({ kind: "current" });
  });

  test("the answer lists exactly the targets that need an update", async () => {
    const result = await checkFleet(["a", "b"], (name) => Promise.resolve(name === "b" ? { name, from: "0.9", to: "1.0" } : null));
    expect(result).toEqual({ kind: "available", targets: [{ name: "b", from: "0.9", to: "1.0" }] });
  });

  test("one host that cannot answer makes the whole answer a failure instead of leaving it out", async () => {
    const result = await checkFleet(["a", "b"], (name) => name === "a" ? Promise.reject(new Error("a did not answer")) : Promise.resolve(null));
    expect(result).toEqual({ kind: "failed", reason: "a did not answer" });
  });
});
