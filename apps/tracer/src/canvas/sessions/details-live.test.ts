/** Verifies live host-facts presentation and disabled-plugin lifecycle boundaries (D126/D198). */
import { expect, spyOn, test } from "bun:test";
import { ActionRefused, type MuxConnection } from "../../connection";
import type { WinRec } from "../context";
import { createLiveDetails } from "./details-live.on-demand";

test("a refused host facts action stops its recurring timer", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const timers = new Map<number, () => void>();
  let nextTimer = 1;
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    setTimeout(callback: () => void): number {
      const id = nextTimer++;
      timers.set(id, callback);
      return id;
    },
    clearTimeout(id: number): void { timers.delete(id); },
  } });
  let stop = (): void => {};
  let calls = 0;
  try {
    // Model the actual Result(ok=false) emitted for a disabled or build-removed plugin.
    const connection = {
      isWelcomed: true,
      call: async (): Promise<Record<string, unknown>> => {
        calls++;
        throw new ActionRefused(undefined, "action unavailable");
      },
    } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "local" }, connection, roundTrip: () => undefined });
    const rec = { model: { id: "window-1", kind: "terminal", host: "local" } } as unknown as WinRec;
    stop = source.open!(rec, () => {});
    // Flush the read's rejected call and finally block without advancing a real clock.
    await Promise.resolve();
    await Promise.resolve();
    expect(calls).toBe(1);
    expect(timers.size).toBe(0);
  } finally {
    stop();
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
});

// A valid read must feed the existing operating-system mark, as well as the System row (D126).
test("a detected operating system supplies the live popover mark", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    setTimeout: (): number => 1, clearTimeout: (): void => {},
  } });
  Object.defineProperty(globalThis, "location", { configurable: true, value: { hostname: "example.invalid", protocol: "https:" } });
  let stop = (): void => {};
  try {
    const connection = {
      isWelcomed: true, isOpen: true,
      call: async (): Promise<Record<string, unknown>> => ({
        os: "Debian GNU/Linux", version: "13", kernel: "6.12", architecture: "x86_64",
        logicalCpus: 8, executionUid: 1000, mode: "embedded", engines: [],
      }),
    } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "build-01" }, connection, roundTrip: () => undefined });
    const rec = { model: { id: "window-1", kind: "terminal", host: "build-01" } } as unknown as WinRec;
    stop = source.open!(rec, () => {});
    await Promise.resolve();
    await Promise.resolve();
    const facts = source.facts(rec)!;
    // Establish that the response decoded and became visible before checking its header metadata.
    expect(facts.sections[0]!.rows.find((row) => row.key === "System")?.value).toBe("Debian GNU/Linux 13");
    expect(facts.os).toBe("debian");
  } finally {
    stop();
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
    if (originalLocation) Object.defineProperty(globalThis, "location", originalLocation);
    else Reflect.deleteProperty(globalThis, "location");
  }
});

/** Runs `body` with the browser globals the live details source reads (timers, the page's own address). */
async function withPage(body: (timers: Map<number, () => void>) => Promise<void>): Promise<void> {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
  const timers = new Map<number, () => void>();
  let nextTimer = 0;
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    setTimeout: (callback: () => void): number => { timers.set(++nextTimer, callback); return nextTimer; },
    clearTimeout: (id: number): void => { timers.delete(id); },
  } });
  Object.defineProperty(globalThis, "location", { configurable: true, value: { hostname: "server.example.invalid", protocol: "https:" } });
  try { await body(timers); } finally {
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow); else Reflect.deleteProperty(globalThis, "window");
    if (originalLocation) Object.defineProperty(globalThis, "location", originalLocation); else Reflect.deleteProperty(globalThis, "location");
  }
}

/** What the server's own agent reports. */
const SERVER_FACTS = { os: "AlmaLinux", version: "10.2", kernel: "6.12", architecture: "x86_64", cpuModel: "Intel N100", logicalCpus: 4, executionUid: 0, mode: "embedded", engines: [] };
/** What an added host's agent reports: every field differs from the server's. */
const WORKER_FACTS = { os: "Debian GNU/Linux", version: "13", kernel: "6.12.5", architecture: "aarch64", cpuModel: "Neoverse N1", logicalCpus: 8, executionUid: 1000, mode: "remote", engines: [] };
/** The admitted id of the added host in these specs. */
const WORKER_ID = "11111111-1111-4111-8111-111111111111";
/** The value of the row named `key` in the selected details section, or undefined when it is absent. */
const row = (facts: ReturnType<ReturnType<typeof createLiveDetails>["facts"]>, key: string, section = "host"): string | undefined => facts!.sections.find((tab) => tab.id === section)?.rows.find((r) => r.key === key)?.value;

// #410: a window's details describe the window's own host. The server's machine answers only for the server's own windows.
test("two hosts' details differ: each window reads and shows its own host's system, CPU, address and kind", async () => {
  await withPage(async () => {
    const asked: Array<[string, Record<string, unknown>]> = [];
    const connection = {
      isWelcomed: true, isOpen: true,
      call: async (action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> => {
        asked.push([action, input]);
        return action === "remote.host.facts" ? WORKER_FACTS : SERVER_FACTS;
      },
    } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "server" }, connection, roundTrip: () => undefined });
    const own = { model: { id: "w-own", kind: "terminal", host: "server" } } as unknown as WinRec;
    const added = { model: { id: "w-added", kind: "terminal", host: "worker", hostId: WORKER_ID, user: "operator", address: "operator@worker.lan" } } as unknown as WinRec;
    const stops = [source.open!(own, () => {}), source.open!(added, () => {})];
    for (let i = 0; i < 8; i++) await Promise.resolve();
    const server = source.facts(own)!, worker = source.facts(added)!;
    expect(asked).toContainEqual(["host.facts.read", { includeLive: true }]);
    expect(asked).toContainEqual(["remote.host.facts", { host_id: WORKER_ID }]);
    expect(row(server, "System")).toBe("AlmaLinux 10.2");
    expect(row(server, "CPU")).toBe("4 logical cores · Intel N100");
    expect(row(server, "Address", "connection")).toBe("server.example.invalid");
    expect(row(server, "Infraternal agent")).toBe("Embedded · root");
    expect(row(worker, "System")).toBe("Debian GNU/Linux 13");
    expect(row(worker, "CPU")).toBe("8 logical cores · Neoverse N1");
    expect(row(worker, "Address", "connection")).toBe("operator@worker.lan");
    expect(row(worker, "Infraternal agent")).toBe("Remote · user");
    expect(worker.os).toBe("debian");
    for (const stop of stops) stop();
  });
});

// #410: when the host cannot answer, the panel says so and never falls back to the server's machine.
test("an offline or not-yet-read host says so in plain words and never shows the server's facts", async () => {
  await withPage(async () => {
    let answer: () => Promise<Record<string, unknown>> = async () => { throw new ActionRefused(undefined, "host offline"); };
    const connection = { isWelcomed: true, isOpen: true, call: (action: string): Promise<Record<string, unknown>> => action === "remote.host.facts" ? answer() : Promise.resolve(SERVER_FACTS) } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "server" }, connection, roundTrip: () => undefined });
    const added = { model: { id: "w-added", kind: "terminal", host: "worker", hostId: WORKER_ID, address: "operator@worker.lan" } } as unknown as WinRec;
    // Before any answer: not known yet.
    answer = () => new Promise(() => {});
    const stop = source.open!(added, () => {});
    let facts = source.facts(added)!;
    expect(row(facts, "System")).toBe("Not known yet");
    // Waiting rows hold their place with "Reading…" so the panel keeps one height when the facts land (#500, J528).
    expect(row(facts, "CPU")).toBe("Reading…");
    expect(facts.loading).toBe(true);
    expect(JSON.stringify(facts)).not.toContain("AlmaLinux");
    stop();
    // Refused as offline.
    answer = async () => { throw new ActionRefused(undefined, "host offline"); };
    // Another window of the same host: reads are spaced per window, so a fresh id reads at once.
    const again = { model: { ...added.model, id: "w-added-2" } } as unknown as WinRec;
    const stop2 = source.open!(again, () => {});
    for (let i = 0; i < 8; i++) await Promise.resolve();
    facts = source.facts(again)!;
    expect(row(facts, "System")).toBe("Can't be read while this machine is offline");
    expect(facts.sections[1]!.rows.find((r) => r.key === "Status")?.value).toContain("Offline");
    expect(JSON.stringify(facts)).not.toContain("AlmaLinux");
    expect(JSON.stringify(facts)).not.toContain("Intel N100");
    expect(row(facts, "Address", "connection")).toBe("operator@worker.lan");
    stop2();
  });
});

/** Regression: a shared-layout update can retarget a stable window id. */
test("retargeting one open window must not show the previous host's cached facts", async () => {
  await withPage(async () => {
    const asked: Array<[string, Record<string, unknown>]> = [];
    const connection = { isWelcomed: true, isOpen: true, call: async (action: string, input: Record<string, unknown>) => {
      asked.push([action, input]); return WORKER_FACTS;
    } } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "server" }, connection, roundTrip: () => undefined });
    const rec = { model: { id: "stable-window", kind: "terminal", host: "worker", hostId: WORKER_ID } } as unknown as WinRec;
    const stop = source.open!(rec, () => {});
    for (let i=0; i<8; i++) await Promise.resolve();
    expect(row(source.facts(rec), "Architecture")).toBe("aarch64");
    // model/reconcile.ts keeps rec.model and replaces its hostId in place for a shared-layout retarget.
    Object.assign(rec.model, { host: "different-host", hostId: "22222222-2222-4222-8222-222222222222" });
    const shown = source.facts(rec);
    expect(row(shown, "System")).toBe("Not known yet");
    expect(asked.at(-1)).toEqual(["remote.host.facts", { host_id: "22222222-2222-4222-8222-222222222222" }]);
    stop();
    expect(row(shown, "Architecture")).not.toBe("aarch64");
  });
});

/** A late read or refusal belongs to the old host even when the window id remains stable. */
for (const stale of ["success", "offline", "refused"] as const) test(`retargeted polling ignores an old host's ${stale} while the new host is pending`, async () => {
  await withPage(async (timers) => {
    const asked: string[] = [];
    let resolveOld!: (value: Record<string, unknown>) => void;
    let rejectOld!: (reason: unknown) => void;
    let resolveNew!: (value: Record<string, unknown>) => void;
    const connection = { isWelcomed: true, isOpen: true, call: (_action: string, input: Record<string, unknown>) => {
      asked.push(input.host_id as string);
      return input.host_id === WORKER_ID
        ? new Promise<Record<string, unknown>>((resolve, reject) => { resolveOld = resolve; rejectOld = reject; })
        : new Promise<Record<string, unknown>>((resolve) => { resolveNew = resolve; });
    } } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "server" }, connection, roundTrip: () => undefined });
    const rec = { model: { id: "stable", kind: "terminal", host: "worker", hostId: WORKER_ID } } as unknown as WinRec;
    const stop = source.open!(rec, () => {});
    try {
      Object.assign(rec.model, { host: "new", hostId: "22222222-2222-4222-8222-222222222222" });
      // The scheduled poll observes the model even if the panel has not rendered again yet.
      const tick = timers.values().next().value!;
      timers.clear(); tick();
      expect(asked).toEqual([WORKER_ID, "22222222-2222-4222-8222-222222222222"]);
      if (stale === "success") resolveOld(WORKER_FACTS);
      else rejectOld(new ActionRefused(undefined, stale === "offline" ? "host offline" : "host unavailable"));
      for (let i = 0; i < 8; i++) await Promise.resolve();
      expect(row(source.facts(rec), "System")).toBe("Not known yet");
      expect(timers.size).toBe(1);
      resolveNew(SERVER_FACTS);
      for (let i = 0; i < 8; i++) await Promise.resolve();
      expect(row(source.facts(rec), "Architecture")).toBe("x86_64");
      expect(row(source.facts(rec), "System")).toBe("AlmaLinux 10.2");
    } finally { stop(); }
    expect(timers.size).toBe(0);
  });
});

/** Bounded server admission is temporary; it must not permanently stop a visible host's poll. */
test("a busy host read retries and then displays that host's facts", async () => {
  await withPage(async (timers) => {
    const clock = spyOn(performance, "now").mockReturnValue(0);
    let calls = 0;
    const connection = { isWelcomed: true, isOpen: true, call: async () => {
      if (++calls === 1) throw new ActionRefused(undefined, "host busy");
      return WORKER_FACTS;
    } } as unknown as MuxConnection;
    const source = createLiveDetails({ host: { name: "server" }, connection, roundTrip: () => undefined });
    const rec = { model: { id: "busy", kind: "terminal", host: "worker", hostId: WORKER_ID } } as unknown as WinRec;
    const stop = source.open!(rec, () => {});
    try {
      for (let i = 0; i < 8; i++) await Promise.resolve();
      expect(row(source.facts(rec), "System")).toBe("Not known yet");
      expect(timers.size).toBe(1);
      clock.mockReturnValue(1_000);
      const tick = timers.values().next().value!;
      timers.clear(); tick();
      for (let i = 0; i < 8; i++) await Promise.resolve();
      expect(row(source.facts(rec), "Architecture")).toBe("aarch64");
      expect(calls).toBe(2);
    } finally { stop(); clock.mockRestore(); }
  });
});
