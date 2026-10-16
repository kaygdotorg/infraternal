/** Guards Mesh watch ownership across refresh failures and synchronous refusals (#229). */
import { expect, test } from "bun:test";
import { createMeshApi } from "./api";
import { ActionRefused, type MeshTransport, type Snapshot } from "./protocol";

const raw = { revision: 1, nodes: [], tags: [], grants: [] };
const prime: Snapshot = { rev: 0, access: { view: true, manageGrants: false }, nodes: [], tags: {}, grants: [] };
const settle = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

/** Deterministic browser timer ownership without real retry delays or a DOM. */
function timers(pending = new Set<number>()): () => void {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "window");
  let serial = 0;
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


test("a pushed recovery cancels the scheduled retry", async () => {
  const pending = new Set<number>();
  const restore = timers(pending);
  let deliver: ((event: Record<string, unknown>) => void) | undefined;
  const transport: MeshTransport = {
    call: () => Promise.reject(new Error("connection lost")),
    onReady: () => () => {},
    subscribe: (_topic, listener) => { deliver = listener; return () => {}; },
  };
  const source = createMeshApi({transport, prime});
  try {
    deliver!({type: "changed", revision: 1});
    await settle();
    expect(source.status()).toBe("error");
    expect(pending.size).toBe(1);
    deliver!({type: "resync", snapshot: raw});
    expect(source.status()).toBe("ready");
    expect(pending.size).toBe(0);
  } finally { source.dispose(); restore(); }
});

test("a pushed recovery supersedes an outstanding retry failure", async () => {
  const pending = new Set<number>();
  const restore = timers(pending);
  let deliver: ((event: Record<string, unknown>) => void) | undefined;
  let rejectRetry: ((reason: Error) => void) | undefined;
  let retrying = false;
  const source = createMeshApi({prime, transport: {
    call: () => retrying
      ? new Promise((_resolve, reject) => { rejectRetry = reject; })
      : Promise.reject(new Error("connection lost")),
    onReady: () => () => {},
    subscribe: (_topic, listener) => { deliver = listener; return () => {}; },
  }});
  try {
    deliver!({type: "changed", revision: 1});
    await settle();
    expect(source.status()).toBe("error");
    retrying = true;
    source.retry();
    await settle();
    deliver!({type: "resync", snapshot: {...raw, revision: 2}});
    expect(source.status()).toBe("ready");
    rejectRetry!(new Error("connection lost"));
    await settle();
    expect(source.status()).toBe("ready");
    expect(pending.size).toBe(0);
  } finally { source.dispose(); restore(); }
});

for (const [revision, accepted] of [[1, false], [3, true]] as const)
  test(`a retry snapshot at revision ${revision} is ordered against a pushed recovery`, async () => {
    const restore = timers();
    let deliver: ((event: Record<string, unknown>) => void) | undefined;
    let resolveRetry: ((value: Record<string, unknown>) => void) | undefined;
    let retrying = false;
    const source = createMeshApi({prime, transport: {
      call: () => retrying
        ? new Promise(resolve => { resolveRetry = resolve; })
        : Promise.reject(new Error("connection lost")),
      onReady: () => () => {},
      subscribe: (_topic, listener) => { deliver = listener; return () => {}; },
    }});
    try {
      deliver!({type: "changed", revision: 1});
      await settle();
      retrying = true;
      source.retry();
      await settle();
      deliver!({type: "resync", snapshot: {...raw, revision: 2}});
      resolveRetry!({...raw, revision, nodes: [{node: {id: 1, host: "retry-host", tags: []}}]});
      await settle();
      expect(source.status()).toBe("ready");
      expect(source.data().nodes.has("retry-host")).toBe(accepted);
    } finally { source.dispose(); restore(); }
  });

test("a pushed liveness expiry supersedes an equal-revision retry snapshot", async () => {
  const restore = timers();
  let deliver: ((event: Record<string, unknown>) => void) | undefined;
  let resolveRetry: ((value: Record<string, unknown>) => void) | undefined;
  let retrying = false;
  const source = createMeshApi({prime, transport: {
    call: () => retrying
      ? new Promise(resolve => { resolveRetry = resolve; })
      : Promise.reject(new Error("connection lost")),
    onReady: () => () => {},
    subscribe: (_topic, listener) => { deliver = listener; return () => {}; },
  }});
  try {
    deliver!({type: "changed", revision: 1});
    await settle();
    retrying = true;
    source.retry();
    await settle();
    const node = {node: {id: 1, host: "peer", tags: []}};
    deliver!({type: "resync", snapshot: {...raw, revision: 2, nodes: [{...node, live: false}]}});
    resolveRetry!({...raw, revision: 2, nodes: [{...node, live: true}]});
    await settle();
    expect(source.data().nodes.get("peer")?.state).toBe("offline");
  } finally { source.dispose(); restore(); }
});

test("a forbidden withdrawal cancels retry work from the retained watch", async () => {
  const pending = new Set<number>();
  const restore = timers(pending);
  let deliver: ((event: Record<string, unknown>) => void) | undefined;
  const source = createMeshApi({prime, transport: {
    call: () => Promise.reject(new Error("connection lost")),
    onReady: () => () => {},
    subscribe: (_topic, listener) => { deliver = listener; return () => {}; },
  }});
  try {
    deliver!({type: "changed", revision: 1});
    await settle();
    expect(source.status()).toBe("error");
    expect(pending.size).toBe(1);
    deliver!({type: "error", error: "forbidden"});
    expect(source.status()).toBe("unavailable");
    expect(pending.size).toBe(0);
  } finally { source.dispose(); restore(); }
});

test("a withdrawn view ignores an earlier outstanding retry result", async () => {
  const restore = timers();
  let deliver: ((event: Record<string, unknown>) => void) | undefined;
  let resolveRetry: ((value: Record<string, unknown>) => void) | undefined;
  let retrying = false;
  const source = createMeshApi({prime, transport: {
    call: () => retrying
      ? new Promise(resolve => { resolveRetry = resolve; })
      : Promise.reject(new Error("connection lost")),
    onReady: () => () => {},
    subscribe: (_topic, listener) => { deliver = listener; return () => {}; },
  }});
  try {
    deliver!({type: "changed", revision: 1});
    await settle();
    retrying = true;
    source.retry();
    await settle();
    deliver!({type: "error", error: "forbidden"});
    expect(source.status()).toBe("unavailable");
    expect(source.canView()).toBe(false);
    resolveRetry!({...raw, revision: 2});
    await settle();
    expect(source.status()).toBe("unavailable");
    expect(source.canView()).toBe(false);
  } finally { source.dispose(); restore(); }
});

// Closed sockets, liveness deadlines and JSON decoding reject the same pending
// call promise. The source must distinguish these failures from access refusal.
for (const [label, answer, status] of [
  ["closed transport", () => Promise.reject(new Error("connection lost")), "error"],
  ["liveness deadline", () => Promise.reject(new Error("connection timed out")), "error"],
  ["unreadable JSON", () => Promise.reject(new SyntaxError("invalid JSON")), "error"],
  ["unavailable storage", () => Promise.reject(new ActionRefused("refused", "mesh unavailable")), "error"],
  ["forbidden action", () => Promise.reject(new ActionRefused("refused", "forbidden")), "unavailable"],
  ["invalid stored host", () => Promise.resolve({...raw, nodes: [{node: {id: 1, host: "", tags: []}}]}), "error"],
] as const) test(`initial Mesh list handles ${label}`, async () => {
  const pending = new Set<number>();
  const restore = timers(pending);
  let watches = 0;
  const source = createMeshApi({transport: {
    call: answer,
    onReady: listener => { listener(); return () => {}; },
    subscribe: () => { watches++; return () => { watches--; }; },
  }});
  try {
    await settle();
    expect(source.status()).toBe(status);
    expect(watches).toBe(0);
    expect(pending.size).toBe(status === "error" ? 1 : 0);
  } finally { source.dispose(); restore(); }
  expect(pending.size).toBe(0);
});

for (const reason of ["forbidden", "mesh unavailable", "plugin unavailable"] as const)
  test(`Mesh watch withdrawal handles ${reason}`, () => {
    const pending = new Set<number>();
    const restore = timers(pending);
    let watches = 0;
    let deliver: ((event: Record<string, unknown>) => void) | undefined;
    const source = createMeshApi({prime, transport: {
      call: () => Promise.resolve(raw),
      onReady: () => () => {},
      subscribe: (_topic, listener) => { watches++; deliver = listener; return () => { watches--; }; },
    }});
    try {
      // Wire fields cannot claim that a withdrawn subscription is still active.
      deliver!({type: "error", error: reason, subscriptionActive: true});
      expect(watches).toBe(0);
      expect(source.status()).toBe(reason === "forbidden" ? "unavailable" : "error");
      expect(pending.size).toBe(reason === "forbidden" ? 0 : 1);
    } finally { source.dispose(); restore(); }
    expect(pending.size).toBe(0);
  });
