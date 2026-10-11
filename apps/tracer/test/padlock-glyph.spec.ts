/**
 * Candidates for the glyph of the phone toolbar's input lock (#164): the control that keeps the focused terminal in view and
 * sends it the keystrokes. It must read as that, not as a generic padlock and not as the window chrome's "Lock input".
 * This spec only renders: each candidate, off and on, on a sheet and in the real toolbar (the button's glyph swapped in
 * place) at 393x852 in ink and paper. It changes no product code and asserts nothing about the default.
 */
import { expect, test } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = resolve(import.meta.dirname, "../captures/padlock-glyph");

/** Inner SVG markup on the toolbar's 24 px grid, drawn with the toolbar's 1.75 stroke. `off` and `on` are the two states. */
const CANDIDATES: Array<{ id: string; name: string; why: string; off: string; on: string }> = [
  { id: "current", name: "Now: open and shut padlock", why: "what production shows", off: '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V7.5a3.5 3.5 0 0 1 6.6-1.6"/>', on: '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>' },
  {
    id: "a-held-prompt", name: "A: prompt held in corner brackets", why: "corner brackets open when off and close into the window when on, around a prompt: this terminal is held and takes the keys",
    off: '<path d="M4 9V6a2 2 0 0 1 2-2h3M15 4h3a2 2 0 0 1 2 2v3M20 15v3a2 2 0 0 1-2 2h-3M9 20H6a2 2 0 0 1-2-2v-3"/><path d="m8.5 10.5 3 1.5-3 1.5M13 14h3"/>',
    on: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="m8.5 10.5 3 1.5-3 1.5M13 14h3"/>',
  },
  {
    id: "b-keys-under-window", name: "B: window with its keys", why: "a window and a row of keys under it: the keys go to this window; on, the keys are filled and the window closes over them",
    off: '<rect x="4" y="3.5" width="16" height="10" rx="2.5"/><path d="M7 17.5h.01M10 17.5h.01M13 17.5h.01M16 17.5h.01M8.5 20.5h7"/>',
    on: '<rect x="4" y="3.5" width="16" height="10" rx="2.5"/><path d="m8 7 2.5 1.5L8 10M12.5 10.5H16"/><path d="M7 17.5h.01M10 17.5h.01M13 17.5h.01M16 17.5h.01M8.5 20.5h7" stroke-width="2.6"/>',
  },
  {
    id: "c-pinned-window", name: "C: window with a pin", why: "a pushpin lifted over the window when off and pressed in when on: this window stays where it is, in view",
    off: '<rect x="4" y="9" width="16" height="11" rx="3"/><path d="m8.5 13 2.5 1.5L8.5 16M13 16.5h3"/><path d="M12 6V2.5M9.5 2.5h5"/>',
    on: '<rect x="4" y="9" width="16" height="11" rx="3"/><path d="m8.5 13 2.5 1.5L8.5 16M13 16.5h3"/><path d="M12 9V5.5M9.5 5.5h5"/>',
  },
  {
    id: "d-caret-captured", name: "D: caret in a frame with guides", why: "a text caret held in the middle of a frame by guides from every edge: the input is captured here; off, the guides stand back",
    off: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M12 8.5v7M10 8.5h4M10 15.5h4"/>',
    on: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M12 4v4.5M12 15.5V20M4 12h5M15 12h5"/><path d="M12 8.5v7M10 8.5h4M10 15.5h4"/>',
  },
];

const svg = (inner: string): string => `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

for (const theme of ["ink", "paper"] as const) {
  test(`input lock glyph candidates, ${theme}: a sheet and the real toolbar at 393x852`, async ({ browser }) => {
    test.setTimeout(120_000);
    await mkdir(captures, { recursive: true });
    const context = await browser.newContext({ viewport: { width: 393, height: 852 }, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });
    const page = await context.newPage();
    await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
    await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
    await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
    await page.waitForTimeout(1800);

    // The real toolbar: swap the input lock's glyph and state in place, then take the capsule.
    const tray = (await page.locator(".keytray").boundingBox())!;
    for (const c of CANDIDATES) for (const state of ["off", "on"] as const) {
      await page.evaluate(({ inner, on }) => {
        const b = document.querySelector<HTMLElement>("[data-cv='input-lock']")!;
        b.removeAttribute("data-disabled"); b.setAttribute("aria-disabled", "false");
        b.dataset.pressed = String(on); b.setAttribute("aria-pressed", String(on));
        b.querySelector("svg")!.innerHTML = inner;
      }, { inner: c[state], on: state === "on" });
      await page.waitForTimeout(260);
      await page.screenshot({ path: `${captures}/${c.id}-${state}-${theme}-toolbar.png`, clip: { x: tray.x - 4, y: tray.y - 4, width: tray.width + 8, height: tray.height + 8 } });
    }

    // The sheet: every candidate, off and on, at the toolbar's size with its selection circle, with a line on what it says.
    const cell = (inner: string, on: boolean): string => `<span style="display:grid;place-items:center;width:48px;height:48px;position:relative"><span style="position:absolute;inset:5px;border-radius:50%;background:${on ? "var(--accent-soft)" : "transparent"}"></span><span style="position:relative;display:grid;color:${on ? "var(--accent)" : "var(--fg)"}">${svg(inner)}</span></span>`;
    const rows = CANDIDATES.map((c) => `<div style="display:grid;grid-template-columns:auto 1fr;gap:12px;align-items:center;padding:8px 10px;border:1px solid var(--overlay-line);border-radius:18px"><div style="display:flex;gap:2px">${cell(c.off, false)}${cell(c.on, true)}</div><div><div style="font-weight:600">${c.name}</div><div style="color:var(--fg-3)">${c.why}</div></div></div>`).join("");
    await page.evaluate((html) => {
      const sheet = document.createElement("div");
      sheet.style.cssText = "position:fixed;inset:0;z-index:99;background:var(--bg);color:var(--fg);padding:18px 14px;display:grid;gap:12px;align-content:start;font:12px/1.4 var(--font-ui)";
      sheet.innerHTML = html;
      document.body.append(sheet);
    }, rows);
    await page.waitForTimeout(250);
    await page.screenshot({ path: `${captures}/candidates-${theme}.png` });
    await context.close();
  });
}
