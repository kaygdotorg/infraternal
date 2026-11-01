/** A pinned session name reaches the account's open devices, never another account (#293). */
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol, settled, windows } from "./layout-devices";
import { cache, watchLayout } from "./layout-observer";
import { startRealServer, type RealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";
import { documentWindows } from "../src/canvas/model/schema";

test.use({ actionTimeout: 10_000 });

/** Seed a separate fixture account; session capabilities stay in memory and stdin. */
async function otherAccount(server: RealServer, context: BrowserContext): Promise<void> {
  const token = randomBytes(32).toString("base64url"), user = randomUUID();
  const digest = createHash("sha256").update(token).digest("base64url");
  const child = spawn("python3", ["-c", `import json,sqlite3,sys,time
v=json.load(sys.stdin)
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'Rename peer',0,'unused','rename_peer','Rename peer')",(v['user'],))
 db.execute("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'test',?,?,1)",(v['digest'],v['user'],int(time.time())+3600,int(time.time())))
`, server.dataDir + "/infraternal.sqlite"], { stdio: ["pipe", "ignore", "ignore"] });
  const ended = once(child, "exit"); child.stdin.end(JSON.stringify({ user, digest }));
  expect((await ended)[0]).toBe(0);
  await context.addCookies([{ name: "__Host-infraternal", value: token, url: server.origin, secure: true, httpOnly: true, sameSite: "Strict" }]);
}

const openSessions = async (page: Page): Promise<void> => {
  await windows(page).first().getByRole("button", { name: "Sessions", exact: true }).click();
  await expect(page.locator(".cl-sx-name").first()).toBeVisible();
};

test("session rename and pin reach an active peer without leaking to another account", async ({ browser }) => {
  const server = await startRealServer({ timedControls: true });
  const contexts = await Promise.all(Array.from({ length: 3 }, () => browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true })));
  const [first, second, stranger] = contexts as [BrowserContext, BrowserContext, BrowserContext];
  const evidence = tracerEvidencePath("session-rename-sync");
  await mkdir(evidence, { recursive: true });
  try {
    const a = watchLayout(await first.newPage()); await enrol(a, server);
    await second.addCookies(await first.cookies());
    const b = watchLayout(await second.newPage()); await b.goto(server.origin + "/?theme=ink&bg=none");
    await expect(windows(b)).toHaveCount(1); await settled(b);
    await otherAccount(server, stranger);
    const c = watchLayout(await stranger.newPage());
    const foreignEvents: string[] = [], peerEvents: string[] = [];
    for (const [page, events] of [[b, peerEvents], [c, foreignEvents]] as const) page.on("websocket", (socket) => {
      const decoder = new WebSocketFrameDecoder();
      socket.on("framereceived", ({ payload }) => {
        if (typeof payload !== "string") decoder.feed(new Uint8Array(payload), (_stream, frame) => {
          if (frame.type === "Event") events.push(new TextDecoder().decode(frame.eventJson));
        });
      });
    });
    // Reconnect B after installing the wire observer, then leave both canvases active.
    await b.reload(); await settled(b);
    await c.goto(server.origin + "/?theme=ink&bg=none"); await settled(c);
    await expect.poll(async () => documentWindows((await cache(c)).canonical).filter((w) => w.target.type === "session").length).toBe(1);
    await settled(c);
    const foreignBefore = (await cache(c)).canonical;
    await openSessions(a); await openSessions(b);
    expect(await b.evaluate(() => document.visibilityState)).toBe("visible");
    const name = "pinned rename gjpqy";
    await a.locator(".cl-sx-row").first().hover();
    await a.locator('.cl-sx-act[data-act="rename"]').first().click();
    await a.getByRole("textbox", { name: "Session name", exact: true }).fill(name);
    const started = Date.now();
    await a.getByRole("textbox", { name: "Session name", exact: true }).press("Enter");
    await expect(a.locator(".cl-sx-name").first()).toHaveText(name);
    let latencyMs = 0;
    try {
      await expect(b.locator(".cl-sx-name").first()).toHaveText(name, { timeout: 2000 });
      await expect(windows(b).first().locator(".ui-window-pill")).toContainText(name);
      await expect(b.locator(".cl-sx-pin").first()).toBeVisible();
      latencyMs = Date.now() - started;
      expect(latencyMs).toBeLessThan(2000);
    } finally {
      await a.screenshot({ path: `${evidence}/device-a.png` });
      await b.screenshot({ path: `${evidence}/device-b.png` });
      await writeFile(`${evidence}/result.json`, JSON.stringify({ latencyMs, elapsedMs: Date.now() - started, peerEvents, foreignEvents, peerName: await b.locator(".cl-sx-name").first().textContent() }, null, 2));
    }
    expect(foreignEvents.some((event) => event.includes(name))).toBe(false);
    expect((await cache(c)).canonical).toEqual(foreignBefore);
    await expect(c.getByText(name, { exact: true })).toHaveCount(0);
    // The pin survives a fresh page and subsequent layout paints on either device.
    await b.reload(); await settled(b); await openSessions(b);
    await expect(b.locator(".cl-sx-name").first()).toHaveText(name);
    await expect(b.locator(".cl-sx-pin").first()).toBeVisible();
  } finally { await Promise.allSettled(contexts.map((context) => context.close())); await server.dispose(); }
});
