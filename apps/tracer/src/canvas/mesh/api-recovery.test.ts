/** Guards Mesh watch ownership across refresh failures and synchronous refusals (#229). */
import { expect, test } from "bun:test";
import { createMeshApi } from "./api";
import type { MeshTransport, Snapshot } from "./protocol";

const raw = { revision: 1, nodes: [], tags: [], grants: [] };
const prime: Snapshot = { rev: 0, access: { view: true, manageGrants: false }, nodes: [], tags: {}, grants: [] };
const settle = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

/** Deterministic browser timer ownership without real retry delays or a DOM. */
function timers(): () => void {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  let serial = 0;
  const pending = new Set<number>();
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    setTimeout: () => { const id = ++serial; pending.add(id); return id; },
    clearTimeout: (id: number) => pending.delete(id),
  } });
  return () => { if (prior) Object.defineProperty(globalThis, "window", prior); else Reflect.deleteProperty(globalThis, "window"); };
}

test("failed watch refreshes retain one subscription through retry and release it on disposal", async () => {
  const restore = timers();
  const watches = new Set<(event: Record<string, unknown>) => void>();
  let refuse = true;
  const transport: MeshTransport = {
    call: () => refuse ? Promise.reject(new Error("connection lost")) : Promise.resolve(raw),
    onReady: () => () => {},
    subscribe: (_topic, listener) => { watches.add(listener); return () => { watches.delete(listener); }; },
  };
  const source = createMeshApi({transport, prime});
  try {
    for (let revision = 2; revision <= 5; revision++) {
      for (const watch of [...watches]) watch({type: "changed", revision});
      await settle();
      expect(source.status()).toBe("error");
      expect(watches.size).toBe(1);
      refuse = false;
      source.retry();
      await settle();
      expect(source.status()).toBe("ready");
      expect(watches.size).toBe(1);
      refuse = true;
    }
  } finally { source.dispose(); restore(); }
  expect(watches.size).toBe(0);
});

test("a synchronous subscription refusal leaves retry able to install a new watch", async () => {
  const restore = timers();
  let active = 0, attempts = 0;
  const transport: MeshTransport = {
    call: () => Promise.resolve(raw),
    onReady: () => () => {},
    subscribe: (_topic, listener) => {
      active++;
      if (++attempts === 1) listener({type: "error", error: "mesh unavailable"});
      return () => { active--; };
    },
  };
  const source = createMeshApi({transport, prime});
  try {
    expect(source.status()).toBe("error");
    source.retry();
    await settle();
    expect(source.status()).toBe("ready");
    expect(attempts).toBe(2);
    expect(active).toBe(1);
  } finally { source.dispose(); restore(); }
  expect(active).toBe(0);
});
