/** Account reads are deferred, deduplicated and fenced to this screen's authenticated lifetime (#224). */
import { expect, test } from "bun:test";
import { identityModel } from "./model";

test("setup facts are fetched only on demand and do not imply recovery verification", async () => {
  const originalFetch = globalThis.fetch;
  let requests = 0, changes = 0;
  globalThis.fetch = (async () => {
    requests++;
    return Response.json({ user_id: "one", session_incarnation: "current", passkeys: 1, recovery_set_up: true });
  }) as unknown as typeof fetch;
  try {
    const model = identityModel({ name: "Person", username: "person" }, "one", "current");
    const off = model.onChange(() => { changes++; });
    expect(requests).toBe(0);
    expect(model.person().passkeys).toBeUndefined();
    await Promise.all([model.refresh!(), model.refresh!()]);
    expect(requests).toBe(1);
    expect(changes).toBe(1);
    expect(model.person().passkeys).toBe(1);
    expect(model.person().recovery).toEqual({ setUp: true });
    off();
    await model.refresh!();
    expect(requests).toBe(2);
    expect(changes).toBe(1);
  } finally { globalThis.fetch = originalFetch; }
});

for (const state of ["unavailable", "other-user", "other-lifetime", "invalid-count"] as const) {
  test(`summary ${state} leaves facts unknown and permits a retry`, async () => {
    const originalFetch = globalThis.fetch;
    let retry = false, changes = 0;
    globalThis.fetch = (async () => Response.json({
      user_id: !retry && state === "other-user" ? "two" : "one",
      session_incarnation: !retry && state === "other-lifetime" ? "old" : "current",
      passkeys: !retry && state === "invalid-count" ? -1 : 2, recovery_set_up: true,
    }, { status: !retry && state === "unavailable" ? 503 : 200 })) as unknown as typeof fetch;
    try {
      const model = identityModel({ name: "Person", username: "person" }, "one", "current");
      model.onChange(() => { changes++; });
      await model.refresh!();
      expect(model.person().passkeys).toBeUndefined();
      expect(model.person().recovery).toBeUndefined();
      expect(changes).toBe(0);
      retry = true;
      await model.refresh!();
      expect(model.person().passkeys).toBe(2);
      expect(changes).toBe(1);
    } finally { globalThis.fetch = originalFetch; }
  });
}
