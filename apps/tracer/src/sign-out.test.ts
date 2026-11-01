/** Logout completions belong to the initiating screen lifetime, including a later sign-in before an old reply (D312). */
import { expect, test } from "bun:test";
import { registerSignOut, signOut } from "./sign-out";
import { registerAccountWork } from "./account-lifetime";

test("a late successful logout cannot forget or announce revocation for a newer signed-in screen", async () => {
  const original = globalThis.fetch; let respond!: (value: Response) => void;
  globalThis.fetch = Object.assign(() => new Promise<Response>((resolve) => { respond = resolve; }), { preconnect: original.preconnect });
  let epoch = 1, forgotten = 0, announced = 0, disposed = 0;
  // The lifetime callback is optional for screens without asynchronous replacement.
  registerSignOut(() => { forgotten++; }, () => "a", () => {}, () => { announced++; }, () => epoch);
  const old = signOut(); epoch++;
  const off = registerAccountWork("a", { pause() {}, dispose() { disposed++; } });
  try {
    respond(new Response(null, { status: 204 })); const error = await old.then(() => undefined, (error: unknown) => error);
    expect(forgotten).toBe(0); expect(announced).toBe(0); expect(disposed).toBe(0); expect(error).toBeUndefined();
  } finally { off(); globalThis.fetch = original; registerSignOut(() => {}, () => undefined); }
});
test("a late failed logout does not thaw the replacement screen", async () => {
  const original = globalThis.fetch; let respond!: (value: Response) => void;
  globalThis.fetch = Object.assign(() => new Promise<Response>((resolve) => { respond = resolve; }), { preconnect: original.preconnect });
  let epoch = 1; const freezes: boolean[] = [];
  registerSignOut(() => {}, () => "a", (value: boolean) => freezes.push(value), () => {}, () => epoch);
  const old = signOut(); epoch++;
  try {
    respond(new Response(null, { status: 503 })); await expect(old).rejects.toThrow(); expect(freezes).toEqual([true]);
  } finally { globalThis.fetch = original; registerSignOut(() => {}, () => undefined); }
});
test("new screen logout has its own request and old completion cannot clear its deduplication", async () => {
  const original = globalThis.fetch, replies: Array<(value: Response) => void> = [];
  globalThis.fetch = Object.assign(() => new Promise<Response>((resolve) => replies.push(resolve)), { preconnect: original.preconnect });
  let epoch = 1; const freezes: boolean[] = [];
  registerSignOut(() => {}, () => "a", (value) => freezes.push(value), () => {}, () => epoch);
  const old = signOut(); void old.catch(() => {}); epoch++;
  const current = signOut(); void current.catch(() => {});
  try {
    expect(replies).toHaveLength(2); expect(signOut()).toBe(current);
    replies[0]!(new Response(null, { status: 503 })); await expect(old).rejects.toThrow();
    expect(signOut()).toBe(current); expect(freezes).toEqual([true, true]);
    replies[1]!(new Response(null, { status: 503 })); await expect(current).rejects.toThrow();
    expect(freezes).toEqual([true, true, false]);
  } finally {
    for (const reply of replies) reply(new Response(null, { status: 503 })); await Promise.allSettled([old, current]);
    globalThis.fetch = original; registerSignOut(() => {}, () => undefined);
  }
});
test("default lifetime still deduplicates one failed logout and restores its screen", async () => {
  const original = globalThis.fetch; let reply!: (value: Response) => void; const freezes: boolean[] = [];
  globalThis.fetch = Object.assign(() => new Promise<Response>((resolve) => { reply = resolve; }), { preconnect: original.preconnect });
  registerSignOut(() => {}, () => undefined, (value) => freezes.push(value));
  const pending = signOut();
  try {
    expect(signOut()).toBe(pending); reply(new Response(null, { status: 503 }));
    await expect(pending).rejects.toThrow(); expect(freezes).toEqual([true, false]);
  } finally { globalThis.fetch = original; registerSignOut(() => {}, () => undefined); }
});
