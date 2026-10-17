/**
 * In Chromium, with the shipped renderer: a terminal opened after another one closed, and a terminal reset for a
 * session switch, start blank (#241). The tracer opens one renderer per window and frees it when the window closes;
 * `Terminal.reset()` frees and recreates the WASM terminal (session switch, new shell, unresumed reconnect). Neither
 * may show the screen of the terminal that was freed before it.
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test } from "playwright/test";

const RENDERER = resolve(import.meta.dirname, "../vendor/ghostty-web/dist/ghostty-web.js");
const ORIGIN = "http://renderer.test";

test.beforeEach(async ({ page }) => {
  const renderer = await readFile(RENDERER);
  await page.route(`${ORIGIN}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/ghostty-web.js") return route.fulfill({ body: renderer, contentType: "text/javascript" });
    return route.fulfill({ body: "<!doctype html><meta charset=utf-8><div id=a style='width:640px;height:384px'></div><div id=b style='width:640px;height:384px'></div>", contentType: "text/html" });
  });
  await page.goto(`${ORIGIN}/`);
  await page.evaluate(async () => {
    const { init, Terminal } = await import(`${location.origin}/ghostty-web.js`);
    await init();
    const text = (terminal: InstanceType<typeof Terminal>): string[] => {
      const buffer = terminal.buffer.active;
      const rows: string[] = [];
      for (let row = 0; row < buffer.length; row += 1) rows.push(buffer.getLine(row)?.translateToString(true) ?? "");
      return rows.filter(Boolean);
    };
    const written = (terminal: InstanceType<typeof Terminal>, data: string): Promise<void> => new Promise((done) => terminal.write(data, done));
    Object.assign(window, { rendererProbe: { Terminal, text, written } });
  });
});

test("a window opened after another closed starts with an empty screen", async ({ page }) => {
  const rows = await page.evaluate(async () => {
    const { Terminal, text, written } = (window as unknown as { rendererProbe: any }).rendererProbe;
    const closed = new Terminal({ cols: 80, rows: 24 });
    closed.open(document.getElementById("a"));
    await written(closed, "shim-test% whoami\r\nfrom-the-closed-session\r\n");
    if (!text(closed).includes("from-the-closed-session")) throw new Error("the first terminal did not paint");
    closed.dispose();
    const opened = new Terminal({ cols: 80, rows: 24 });
    opened.open(document.getElementById("b"));
    return text(opened);
  });
  expect(rows).toEqual([]);
});

test("a terminal reset for another session starts with an empty screen", async ({ page }) => {
  const rows = await page.evaluate(async () => {
    const { Terminal, text, written } = (window as unknown as { rendererProbe: any }).rendererProbe;
    const terminal = new Terminal({ cols: 80, rows: 24 });
    terminal.open(document.getElementById("a"));
    await written(terminal, "root@host:~# whoami\r\nroot\r\n");
    terminal.reset();
    return text(terminal);
  });
  expect(rows).toEqual([]);
});
