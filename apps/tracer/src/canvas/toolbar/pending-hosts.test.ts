/** Pending host removal stays visible in the existing palette without offering access. */
import { expect, test } from "bun:test";
import { hostEntries } from "./palette-hosts.on-demand";
import type { Ctx } from "../context";

/** An undelivered cleanup is status, never another removal or access action. */
test("denied hosts remain listed as pending or retired-unreachable", () => {
  for (const state of ["pending", "retired-unreachable"]) {
    const cx = { adapters: { sessions: { hosts: () => [{ id: "11111111-2222-3333-4444-555555555555", name: "worker", state }] }, hostRemoval: { label: () => "Remove host" } }, views: new Map() } as unknown as Ctx;
    const entries = hostEntries(cx);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.label).toBe("worker");
    expect(entries[0]?.hint).toContain(state === "pending" ? "pending" : "retired-unreachable");
    expect(entries[0]?.action).toBeUndefined();
  }
});

/** Only the owner-capable adapter offers Forget, and only for an unreachable retirement. */
test("forget is offered only for retired-unreachable hosts to their owner", () => {
  for (const state of ["pending", "retired-unreachable"]) {
    for (const owner of [false, true]) {
      const cx = { adapters: { sessions: { hosts: () => [{ id: "11111111-2222-3333-4444-555555555555", name: "worker", state }] }, hostRemoval: { label: () => owner ? "Remove host" : undefined, forget: () => {} } }, views: new Map() } as unknown as Ctx;
      const entries = hostEntries(cx);
      expect(entries).toHaveLength(1);
      expect(entries[0]?.action).toBe(owner && state === "retired-unreachable" ? "canvas:forgethost:11111111-2222-3333-4444-555555555555" : undefined);
      if (owner && state === "retired-unreachable") {
        expect(entries[0]?.glyph).toBe("×");
        expect(entries[0]?.hint).toBe("unreachable");
      }
    }
  }
});
