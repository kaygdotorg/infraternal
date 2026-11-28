/**
 * The owner's Inbox reports of what a revoked person left behind (D356, D398): how a report becomes an Inbox line, when
 * the page says so aloud, what Dismiss does, and what a refusal ends. The server writes the sentences; these tests prove
 * the page draws them whole (the D367 coverage boundary included) and rewords nothing.
 */
import { afterEach, beforeEach, expect, mock, test } from "bun:test";
import type { InboxItem } from "../../../../packages/ui/src/inbox";
import type { CoreScreen } from "../core-screen";

/** What each source last published to the (stand-in) Inbox card. */
const published = new Map<string, readonly InboxItem[]>();
/** The stand-in Inbox card: it only records what each source published. */
const inbox = { set: (source: string, items: readonly InboxItem[]) => { published.set(source, items); }, count: () => 0, dispose: () => {} };
mock.module("./inbox-host", () => ({ inboxFor: () => inbox, existingInbox: () => inbox }));
const { AccessReportError, accessReportItem, accessReportTitle, createAccessReportInbox } = await import("./access-left.on-demand");
/** One waiting report, as the server words it. */
type Entry = import("./access-left.on-demand").AccessReportEntry;

/** The clean report's sentence, D364's root checks and D367's coverage boundary included. */
const SENTENCE = "No changes found in the 214 places we watch (SSH keys, cron and at jobs, user services, shell startup files) since 14 Nov 2026, 09:12 UTC. They had no root access through sudo, doas, polkit or admin groups. Access outside these checks isn't covered.";
/** A changed report for build-01 with one planted key; `over` changes what a test needs. */
const entry = (over: Partial<Entry> = {}): Entry => ({
  host_id: "6f1d0a52-7c3e-4b8a-9d21-0a5e4c7b1f30", host: "build-01", person_id: "0b2f6f4e-8d0a-4f43-9a8a-3f2f5f0c1a01", person_name: "Dana", recorded_at: 1,
  outcome: "changed", headline: "These access files changed on the host since the person's logins were granted.",
  lines: ["Account deploy: changed since the grant.", "  ~/.ssh/authorized_keys", "    + ssh-ed25519 AAAAplanted dana@laptop"], ...over,
});

/** The browser globals the source touches, as inert stand-ins (the unit suite has no DOM). */
beforeEach(() => {
  published.clear();
  const target = { addEventListener() {}, removeEventListener() {} };
  Object.assign(globalThis, {
    window: { ...target, setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout, setInterval: globalThis.setInterval, clearInterval: globalThis.clearInterval },
    document: { ...target, visibilityState: "visible" },
  });
});
afterEach(() => {
  delete (globalThis as { window?: unknown }).window;
  delete (globalThis as { document?: unknown }).document;
});

/** The first line the source published, the way a person reads the card. */
function firstItem(): InboxItem {
  const item = published.get("access-left")?.[0];
  if (item === undefined) throw new Error("the Inbox has no access-left line");
  return item;
}

/** Press the first line's first action, like a person tapping Dismiss. */
function pressFirstAction(): void {
  const action = firstItem().actions[0];
  if (action === undefined) throw new Error("the line has no action");
  action.run();
}

/** A core with a toast that records what it said. */
function fakeCore(): { core: CoreScreen; said: string[] } {
  const said: string[] = [];
  const core = { toast: { show: (options: { message: string }) => { said.push(options.message); return "t"; }, dismiss: () => {} } } as unknown as CoreScreen;
  return { core, said };
}

test("a changed report is one line: host first, the sentence as the body, the files and lines as the details", () => {
  const item = accessReportItem(entry(), () => {});
  expect(item.title).toBe("build-01: access left behind");
  expect(item.body).toBe("Dana was revoked here and the host stayed. These access files changed on the host since the person's logins were granted.");
  expect(item.details).toEqual(entry().lines);
  expect(item.actions.map((action) => action.label)).toEqual(["Dismiss"]);
  expect(item.id).toBe("access-left:6f1d0a52-7c3e-4b8a-9d21-0a5e4c7b1f30:0b2f6f4e-8d0a-4f43-9a8a-3f2f5f0c1a01");
});

test("a clean report keeps D364's root checks and D367's coverage boundary, and is never worded as unchanged", () => {
  const clean = entry({ outcome: "unchanged", headline: SENTENCE, lines: [`Account deploy: ${SENTENCE}`] });
  const item = accessReportItem(clean, () => {});
  expect(item.title).toBe("build-01: no changes found");
  expect(item.body).toContain("No changes found in the 214 places we watch");
  expect(item.body).toContain("They had no root access through sudo, doas, polkit or admin groups.");
  expect(item.body.endsWith("Access outside these checks isn't covered.")).toBe(true);
  expect(`${item.title} ${item.body}`.toLowerCase()).not.toContain("unchanged");
});

test("a report that could not check says so, and a removed person is still told apart", () => {
  const unchecked = entry({ outcome: "not_checked", person_name: null, headline: "The host's access files were not fully checked; see why below." });
  expect(accessReportTitle(unchecked)).toBe("build-01: not fully checked");
  expect(accessReportItem(unchecked, () => {}).body.startsWith("A revoked person was revoked here")).toBe(true);
});

test("what waited before the page opened is shown without a toast; a report that arrives later is said once", async () => {
  const { core, said } = fakeCore();
  let waiting = [entry()];
  const service = { list: async () => ({ reports: waiting, more: 0 }), dismiss: async () => {} };
  const source = createAccessReportInbox(core, service);
  await source.refresh();
  expect(published.get("access-left")?.length).toBe(1);
  expect(said).toEqual([]);
  waiting = [entry(), entry({ host_id: "a3b8c1d4-2e5f-4a6b-8c7d-9e0f1a2b3c4d", host: "web-02" })];
  await source.refresh();
  expect(published.get("access-left")?.length).toBe(2);
  expect(said).toEqual(["Dana left access behind on web-02. See the list in your Inbox."]);
  await source.refresh();
  expect(said.length).toBe(1);
  source.dispose();
  expect(published.get("access-left")).toEqual([]);
});

test("Dismiss takes the line away at once and tells the server; a failed dismissal brings it back with a message", async () => {
  const { core, said } = fakeCore();
  const calls: string[] = [];
  let fail = false;
  let waiting = [entry()];
  const service = {
    list: async () => ({ reports: waiting, more: 0 }),
    dismiss: async (host: string, person: string) => { calls.push(`${host}/${person}`); if (fail) throw new AccessReportError("no", 500); waiting = []; },
  };
  const source = createAccessReportInbox(core, service);
  await source.refresh();
  fail = true;
  pressFirstAction();
  expect(published.get("access-left")).toEqual([]);
  await new Promise((resolve) => setTimeout(resolve, 0));
  await source.refresh();
  expect(calls).toEqual(["6f1d0a52-7c3e-4b8a-9d21-0a5e4c7b1f30/0b2f6f4e-8d0a-4f43-9a8a-3f2f5f0c1a01"]);
  expect(said).toContain("Couldn't dismiss this report. Check your connection and try again.");
  expect(published.get("access-left")?.length).toBe(1);
  fail = false;
  pressFirstAction();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(published.get("access-left")).toEqual([]);
  source.dispose();
});

test("a refusal (not the owner) withdraws every line and ends the asking; a failed fetch keeps what is shown", async () => {
  const { core } = fakeCore();
  let asked = 0;
  let outcome: "ok" | "down" | "refused" = "ok";
  const service = {
    list: async () => {
      asked += 1;
      if (outcome === "down") throw new AccessReportError("down", 503);
      if (outcome === "refused") throw new AccessReportError("no", 403);
      return { reports: [entry()], more: 0 };
    },
    dismiss: async () => {},
  };
  const source = createAccessReportInbox(core, service);
  await source.refresh();
  outcome = "down";
  await source.refresh();
  expect(published.get("access-left")?.length).toBe(1);
  outcome = "refused";
  await source.refresh();
  expect(published.get("access-left")).toEqual([]);
  const before = asked;
  await source.refresh();
  expect(asked).toBe(before);
  source.dispose();
});
