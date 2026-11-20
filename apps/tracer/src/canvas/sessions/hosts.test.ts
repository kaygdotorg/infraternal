/** Proves admitted-host synchronization is independent of storage, deduplicated, and fenced across welcomes. */
import { afterAll, expect, test } from "bun:test";
import { syncAdmittedHosts } from "./hosts";
import type { HostEntry } from "./adapter";
import { ensureHostMarks } from "../../../../../packages/ui/src/host-icons";

/** Host discovery loads artwork asynchronously even when this fixture draws no SVG elements. */
const previousDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
Object.defineProperty(globalThis, "document", { configurable: true, value: { querySelectorAll: () => [] } });
afterAll(async () => {
  // Keep the DOM available until the real artwork import has finished, then restore the next suite's environment.
  await ensureHostMarks(["debian"]);
  if (previousDocument) Object.defineProperty(globalThis, "document", previousDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

const id = "11111111-2222-3333-4444-555555555555";
const row = { id, name: "worker", user: "operator", os: "Debian GNU/Linux", address: "operator@worker", online: false };
/** Build a complete paged inventory connection with controlled invalidations. */
function fixture(initial: Record<string, unknown> = row) {
  const hosts = new Map<string, HostEntry>();
  let ready = () => {}, event = (_value: Record<string, unknown>) => {};
  let response: Record<string, unknown> = { hosts: [initial], next: null };
  let reads = 0, subs = 0;
  const stop = syncAdmittedHosts({
    call: async () => { reads++; return response; },
    onWelcome: (listener) => { ready = listener; listener(); return () => {}; },
    subscribe: (_filter, listener) => { subs++; event = listener; return () => {}; },
  }, { replaceHosts: (entries) => { hosts.clear(); for (const entry of entries) hosts.set(entry.id, entry); } });
  return { hosts, ready: () => ready(), event: () => event({ type: "changed" }), set: (value: Record<string, unknown>) => { response = value; }, reads: () => reads, subs: () => subs, stop };
}
const settle = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
test("fresh storage lists an offline host added by another browser", async () => {
  const f = fixture(); await settle();
  expect([...f.hosts.values()]).toEqual([{ ...row, os: "debian" }]);
  expect(f.subs()).toBe(1); f.stop();
});
test("every welcome reconciles without duplicate subscriptions or hosts", async () => {
  const f = fixture(); await settle(); f.ready(); await settle();
  expect(f.hosts.size).toBe(1); expect(f.reads()).toBe(2); expect(f.subs()).toBe(1); f.stop();
});
test("a removal in another browser withdraws the host", async () => {
  const f = fixture(); await settle(); f.set({ hosts: [], next: null }); f.event(); await settle();
  expect(f.hosts.size).toBe(0); f.stop();
});
test("a malformed page cannot partially replace the authoritative inventory", async () => {
  const f = fixture(); await settle(); f.set({ hosts: [{ ...row, id: "wrong" }], next: null }); f.event(); await settle();
  expect(f.hosts.size).toBe(1); f.stop();
});

test("a socket-authority refusal withdraws previously admitted hosts", async () => {
  const { ActionRefused } = await import("../../connection");
  let welcome = () => {}, denied = false;
  let entries: HostEntry[] = [];
  const stop = syncAdmittedHosts({
    call: async () => { if (denied) throw new ActionRefused(); return { hosts: [row], next: null }; },
    onWelcome: (listener) => { welcome = listener; listener(); return () => {}; },
    subscribe: () => () => {},
  }, { replaceHosts: (hosts) => { entries = hosts; } });
  await settle(); expect(entries).toHaveLength(1);
  denied = true; welcome(); await settle(); expect(entries).toHaveLength(0); stop();
});

test("an invalidated read cannot enqueue an unsent call while the socket is down", async () => {
  let connected = true, calls = 0, event = (_value: Record<string, unknown>) => {}, welcome = () => {};
  let rejectRead: ((reason: Error) => void) | undefined;
  let entries: HostEntry[] = [];
  const stop = syncAdmittedHosts({
    get isWelcomed() { return connected; },
    call: async () => {
      calls++;
      if (calls === 2) return await new Promise<Record<string, unknown>>((_resolve, reject) => { rejectRead = reject; });
      if (!connected) return await new Promise<Record<string, unknown>>(() => {});
      return { hosts: calls === 1 ? [row] : [], next: null };
    },
    onWelcome: (listener) => { welcome = listener; listener(); return () => {}; },
    subscribe: (_filter, listener) => { event = listener; return () => {}; },
  }, { replaceHosts: (hosts) => { entries = hosts; } });
  await settle(); event({ type: "changed" }); await settle(); event({ type: "changed" });
  connected = false; rejectRead?.(new Error("drop")); await settle();
  expect(calls).toBe(2);
  connected = true; welcome(); await settle(); expect(entries).toHaveLength(0); stop();
});

/** Cleanup status must survive page validation, including reconnect after expiry. */
test("pending removals retain their server cleanup status", async () => {
  const f = fixture({ ...row, os: undefined }); await settle();
  for (const state of ["pending", "retired-unreachable"]) {
    f.set({ hosts: [{ ...row, os: undefined, state }], next: null }); f.event(); await settle();
    expect(f.hosts.get(id)).toMatchObject({ id, state, online: false });
  }
  f.set({ hosts: [], next: null }); f.event(); await settle();
  expect(f.hosts.size).toBe(0); f.stop();
});
