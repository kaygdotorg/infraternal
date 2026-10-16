/** Checks retry request counts over a logical two-minute outage without a wall-clock benchmark (#229). */
import { expect, test } from "bun:test";
import { createMeshApi } from "./api";
import type { Snapshot } from "./protocol";

test("a retained watch outage bounds retry requests over two logical minutes", async () => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "window");
  const pending = new Map<number, {due: number; run: () => void}>();
  let now = 0, serial = 0, calls = 0, watches = 0;
  let deliver: ((event: Record<string, unknown>) => void) | undefined;
  Object.defineProperty(globalThis, "window", { configurable: true, value: {
    setTimeout: (run: () => void, delay: number) => {
      const id = ++serial;
      pending.set(id, {due: now + delay, run});
      return id;
    },
    clearTimeout: (id: number) => pending.delete(id),
  }});
  const settle = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };
  const prime: Snapshot = {rev: 0, access: {view: true, manageGrants: false}, nodes: [], tags: {}, grants: []};
  const source = createMeshApi({prime, transport: {
    call: () => { calls++; return Promise.reject(new Error("connection lost")); },
    onReady: () => () => {},
    subscribe: (_topic, listener) => { watches++; deliver = listener; return () => { watches--; }; },
  }});
  try {
    deliver!({type: "changed", revision: 1});
    await settle();
    for (;;) {
      const next = [...pending.entries()].sort((a, b) => a[1].due - b[1].due)[0];
      if (!next || next[1].due > 120_000) break;
      now = next[1].due;
      pending.delete(next[0]);
      next[1].run();
      await settle();
    }
    expect(calls).toBe(7); // Original failed refresh plus six backoff retries.
    expect(watches).toBe(1);
    expect(source.status()).toBe("error");
  } finally {
    source.dispose();
    if (previous) Object.defineProperty(globalThis, "window", previous);
    else Reflect.deleteProperty(globalThis, "window");
  }
  expect(pending.size).toBe(0);
  expect(watches).toBe(0);
});
