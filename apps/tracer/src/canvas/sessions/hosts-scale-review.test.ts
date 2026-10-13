/** Verifies account inventory remains discoverable beyond the live transport registry bound (#194, D170). */
import { expect, test } from "bun:test";
import { syncAdmittedHosts } from "./hosts";
import type { HostEntry } from "./adapter";

test.each([10_000, 10_001])("a fresh browser discovers %i admitted offline hosts from complete bounded pages", async (count) => {
  const id = (serial: number): string => `00000000-0000-0000-0000-${serial.toString(16).padStart(12, "0")}`;
  let entries: HostEntry[] = [], calls = 0;
  const stop = syncAdmittedHosts({
    call: async (_action, input) => {
      calls++;
      const after = typeof input.after === "string" ? Number.parseInt(input.after.slice(-12), 16) : 0;
      const last = Math.min(count, after + 128);
      return {
        hosts: Array.from({ length: last - after }, (_, offset) => ({ id: id(after + offset + 1), name: `offline-${after + offset + 1}`, online: false })),
        next: last < count ? id(last) : null,
      };
    },
    onWelcome: (listener) => { listener(); return () => {}; },
    subscribe: () => () => {},
  }, { replaceHosts: (hosts) => { entries = hosts; } });
  // Resolve every page and final publication without a wall-clock timing assertion.
  for (let microtask = 0; microtask < 200; microtask++) await Promise.resolve();
  stop();
  expect(calls).toBe(79);
  expect(entries).toHaveLength(count);
});
