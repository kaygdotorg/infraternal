/** An ended shell on a remote host must leave the inventory's session list at once, not at the next reload (#510). */
import { expect, test } from "bun:test";
import { createLiveInventory } from "./live-inventory";
import { reportShellExit } from "./exit-report";

test("a shell that exits on a remote host is no longer listed as a session", () => {
  const inventory = createLiveInventory({ accountId: "exit-remote", host: "server" });
  const remote = "22222222-2222-4222-8222-222222222222";
  const session = "33333333-3333-4333-8333-333333333333";
  inventory.attach(remote, session, { name: "shell" });
  expect(inventory.list(remote).map((record) => record.id)).toEqual([session]);
  reportShellExit(inventory.gone, remote, session, 0);
  expect(inventory.list(remote)).toEqual([]);
  expect(inventory.get(remote, session)?.state).toBe("exited");
  inventory.dispose();
});

test("a window with no session id reports nothing", () => {
  let calls = 0;
  reportShellExit(() => { calls++; }, "host", undefined, 0);
  expect(calls).toBe(0);
});
