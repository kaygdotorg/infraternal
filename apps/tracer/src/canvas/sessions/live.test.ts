/** Remote routing survives labels, splits and restored sessions without falling back to the embedded host. */
import { expect, test } from "bun:test";
import type { CoreScreen } from "../../core-screen";
import type { MuxConnection } from "../../connection";
const previousMatchMedia = globalThis.matchMedia;
globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
const { createLiveSessions } = await import("./live");
if (previousMatchMedia) globalThis.matchMedia = previousMatchMedia;
else Reflect.deleteProperty(globalThis, "matchMedia");

const id = "11111111-2222-3333-4444-555555555555";
const service = () => createLiveSessions({ core: {} as CoreScreen, connection: {} as MuxConnection, host: { name: "server", user: "owner" } });
test("an enrolled host opens by UUID and splits keep that authority", () => {
  const sessions = service();
  sessions.registerHost({ id, name: "worker", user: "operator", os: "debian" });
  const model = sessions.open(id);
  expect(model.hostId).toBe(id);
  expect(model.host).toBe("worker");
  expect(model.user).toBe("operator");
  expect(sessions.open(model.host, { from: model }).hostId).toBe(id);
  expect(sessions.open("worker", { session: "session" }).hostId).toBe(id);
  sessions.dispose();
});
test("unknown and ambiguous labels never open an embedded shell", () => {
  const sessions = service();
  expect(sessions.open("missing").noAccess).toBe(true);
  sessions.registerHost({ id, name: "server" });
  expect(sessions.open("server").noAccess).toBe(true);
  expect(sessions.open(id).hostId).toBe(id);
  sessions.dispose();
});

test("removed hosts disappear from inventory and cannot route a new shell", () => {
  const sessions = service();
  sessions.registerHost({ id, name: "worker" });
  sessions.forgetHost(id);
  expect(sessions.hosts().map((host) => host.id)).toEqual(["embedded"]);
  expect(sessions.open(id).noAccess).toBe(true);
  expect(sessions.open("worker").noAccess).toBe(true);
  sessions.dispose();
});

test("an authoritative host snapshot replaces admission with one notification", () => {
  const sessions = service();
  sessions.registerHost({ id, name: "worker" });
  let notifications = 0;
  sessions.onChange(() => { notifications++; });
  const replacement = "66666666-2222-3333-4444-555555555555";
  expect(sessions.replaceHosts([{ id: replacement, name: "worker", online: false }])).toEqual([id]);
  expect(notifications).toBe(1);
  expect(sessions.open(id).noAccess).toBe(true);
  expect(sessions.open(replacement).hostId).toBe(replacement);
  expect(() => sessions.replaceHosts([{ id: replacement, name: "worker" }, { id: replacement, name: "duplicate" }])).toThrow();
  expect(sessions.hosts()).toHaveLength(2);
  sessions.dispose();
});

test("the embedded inventory identity still opens locally beside an equally named remote", () => {
  const sessions = service();
  sessions.registerHost({ id, name: "server" });
  const embedded = sessions.open("embedded");
  expect(embedded.host).toBe("server");
  expect(embedded.hostId).toBeUndefined();
  expect(embedded.noAccess).not.toBe(true);
  expect(sessions.open(embedded.host, { from: embedded }).noAccess).not.toBe(true);
  expect(sessions.open(id).hostId).toBe(id);
  sessions.dispose();
});
