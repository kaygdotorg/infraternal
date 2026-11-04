/**
 * Mockup sharing: the test double's `/__mock/shares` transport behind the `SharingAdapter` interface. A person who
 * can receive polls it while signed in as them.
 */
import type { ViewModel } from "../model/types";
import { GROUPS, PEOPLE, usernameOf } from "./data";
import type { IncomingShare, SharingAdapter } from "../sharing/adapter";
import { allowedHosts, type MockWorld } from "./world";

/** Makes the sharing adapter over the test double's `/__mock/shares` endpoints. It polls every 1.5 seconds, and only while the signed-in role is "asha", the one who receives. */
export function createMockSharing(world: MockWorld): SharingAdapter {
  const me = (): string => usernameOf(world.role);
  return {
    me,
    directory: () => ({ people: PEOPLE, groups: GROUPS }),
    canPublish: () => world.role === "operator",
    allowedHosts: () => allowedHosts(world.role),
    async send(message) {
      const r = await fetch("/__mock/shares", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ from: me(), ...message }) });
      return (await r.json()) as { id: string };
    },
    async update(id, key, snapshot: ViewModel) {
      await fetch("/__mock/shares/update", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id, key, snapshot }) });
    },
    subscribe(listener) {
      const poll = async (): Promise<void> => {
        if (world.role !== "asha") return;
        try { listener(((await (await fetch(`/__mock/shares?for=${me()}`, { credentials: "same-origin" })).json()) as { shares: IncomingShare[] }).shares); } catch { /* the double may be restarting */ }
      };
      const timer = window.setInterval(() => { void poll(); }, 1500);
      void poll();
      return () => window.clearInterval(timer);
    },
  };
}
