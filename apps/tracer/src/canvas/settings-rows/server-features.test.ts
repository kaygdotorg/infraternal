// SPDX-License-Identifier: AGPL-3.0-only
/** The App Windows switch reads and writes the server's own `desktop` feature switch, asking for a passkey once (#146). */
import { expect, test } from "bun:test";
import { appWindowsBacking, SWITCH_REFUSED, type FeatureLink } from "./server-features";

/** A fake connection: `plugins.list` answers `listed`, and `plugins.set_enabled` refuses until a passkey was confirmed when `fresh` is false. */
function fakeLink(listed: unknown, fresh: boolean): FeatureLink & { sets: unknown[]; confirms: number } {
  let confirmed = fresh;
  const link = {
    sets: [] as unknown[],
    confirms: 0,
    call: async (actionId: string, input: Record<string, unknown>) => {
      if (actionId === "plugins.list") return listed as Record<string, unknown>;
      if (!confirmed) throw new Error("not permitted");
      link.sets.push(input);
      return input;
    },
    confirmAndReconnect: async () => { link.confirms += 1; confirmed = true; },
  };
  return link;
}

test("the switch shows the server's desktop feature state, and nothing for a build without it", async () => {
  const on = { plugins: [{ descriptor: { id: "canvas" }, enabled: true }, { descriptor: { id: "desktop" }, enabled: false }] };
  expect(await appWindowsBacking(fakeLink(on, true)).read()).toBe(false);
  expect(await appWindowsBacking(fakeLink({ plugins: [] }, true)).read()).toBeUndefined();
});

test("a fresh owner switches it at once; an older sign-in confirms with a passkey once", async () => {
  const fresh = fakeLink({ plugins: [] }, true);
  expect(await appWindowsBacking(fresh).write(false)).toBeUndefined();
  expect(fresh.sets).toEqual([{ plugin: "desktop", enabled: false }]);
  expect(fresh.confirms).toBe(0);
  const stale = fakeLink({ plugins: [] }, false);
  expect(await appWindowsBacking(stale).write(true)).toBeUndefined();
  expect(stale.confirms).toBe(1);
  expect(stale.sets).toEqual([{ plugin: "desktop", enabled: true }]);
});

test("a second refusal is final and the row says so", async () => {
  const link = fakeLink({ plugins: [] }, false);
  link.confirmAndReconnect = async () => { link.confirms += 1; };
  expect(await appWindowsBacking(link).write(true)).toBe(SWITCH_REFUSED);
  expect(link.confirms).toBe(1);
});
