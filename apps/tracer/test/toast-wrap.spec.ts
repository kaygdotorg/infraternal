// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Toasts that wrap (#104, owner 2026-11-21: "we need to multi-line toasts prettier").
 *
 * One layout rule serves every toast (packages/ui/styles.css, toast.ts `fit`), so this spec shows one toast for each shape a real
 * message can take (mark or glyph, one or two actions, dismiss button, choices, count) with the product's own wording, at
 * 1440x900 and 393x852, in Ink and Paper, on the production build. It measures what a person sees:
 *   - the mark and the close button are centred on the FIRST line of text, whatever the number of lines;
 *   - actions share the first row only when the message fits on one line beside them, otherwise they sit under the text;
 *   - the last line is never a lone word (balanced lines), and the card hugs its text (no empty strip on the right);
 *   - the card stays inside the screen with its own inset, and no toast is taller than its text needs.
 * Each case also writes a screenshot named by `TOAST_SHOTS_LABEL` (before or after) into the evidence directory, so the same
 * spec produces the before/after pairs. The measurements are skipped for a "before" run: they describe the fixed layout.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { motionSettled } from "./motion";

declare global { interface Window { __toast?: { dismiss(...id: [string?]): void; show(value: Record<string, unknown>): string } } }

/** Names the output folder (before or after); the same spec produces both sets of screenshots. */
const LABEL = process.env.TOAST_SHOTS_LABEL ?? "after";
/** Where this run writes its screenshots. */
const OUT = tracerEvidencePath("toast-wrap", LABEL);
/** The measurements describe the fixed layout, so a "before" run only takes screenshots. */
const MEASURE = LABEL !== "before";

/** Icon bodies as the product draws them (packages/ui/src/icons.ts); the spec cannot import them into the page. */
const TERMINAL = '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 10 3 2-3 2M13 14h4"/>';
/** The info mark. */
const INFO = '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 7.8v.01"/>';
/** The lock. */
const LOCK = '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>';
/** The tick for a choice. */
const CHECK = '<path d="m5 12.5 4.5 4.5L19 7.5"/>';
/** The cross for a choice. */
const X = '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>';
/** The question mark for a choice. */
const HELP = '<circle cx="12" cy="12" r="8.5"/><path d="M9.7 9.7a2.4 2.4 0 1 1 3.4 2.2c-.7.4-1.1.9-1.1 1.7M12 16.8v.01"/>';

/** One toast as a caller can ask for it: wording, tone, icon, buttons, choices and how often it repeats. */
interface Shape { id: string; message: string; tone?: "error"; icon?: string; dismissible?: boolean; action?: string; secondary?: string; choices?: boolean; repeat?: number }

/** One toast per layout the product can produce, with real wording. */
const SHAPES: Shape[] = [
  { id: "one-line", message: "Session keeps running", action: "Reopen" },
  { id: "error-rootless", message: "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.", tone: "error", dismissible: false },
  { id: "error-two-lines", message: "Could not change the startup file. It may have changed; try again.", tone: "error" },
  { id: "info-memory", message: "build-01 is low on memory (512 MiB free, 1 session running). Close sessions you no longer need.", icon: INFO },
  { id: "ai-note", message: "Claude opened edge-shell on edge-arm: \"Checking why the apt timer failed.\"", icon: TERMINAL, dismissible: true, action: "Close window" },
  { id: "two-actions", message: "build-01 starts tmux when a shell opens, which stacks a second session manager inside this one.", icon: TERMINAL, dismissible: true, action: "Add guard line", secondary: "Copy line" },
  { id: "removal-copy", message: "edge-arm: access revoked. It uninstalls infraternal as soon as it connects. If it never comes back, copy the command and run it there.", icon: INFO, dismissible: true, action: "Copy command" },
  { id: "restore", message: "Switched. tmux no longer starts in Infraternal terminals (changed ~/.zshrc).", dismissible: true, action: "Restore ~/.zshrc" },
  { id: "locked", message: "Host connections are locked. Unlock them to open shells on your hosts.", icon: LOCK, dismissible: true, action: "Unlock" },
  { id: "choices", message: "tmux started automatically. Would you like to switch to the Infraternal Multiplexer instead?", icon: TERMINAL, choices: true },
  { id: "shared-with-you", message: "Alex shared Console, Mesh and Settings layouts with you", action: "Open" },
  { id: "count", message: "That layout change was not saved. The saved layout is back.", tone: "error", repeat: 3 },
];

/** Opens the production mock in a theme and clears the welcome notices, so each case starts with an empty stack. */
async function open(page: Page, theme: "ink" | "paper"): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForFunction(() => Boolean(window.__toast));
  await page.evaluate(() => window.__toast!.dismiss());
  await expect(page.locator(".ui-toast")).toHaveCount(0);
}

/** Shows one toast with the product wording and waits until its card is open and still. */
async function show(page: Page, s: Shape): Promise<void> {
  await page.evaluate(({ s: shape, icons }) => {
    const value: Record<string, unknown> = { message: shape.message, duration: 0, key: shape.id };
    if (shape.tone) value.tone = shape.tone;
    if (shape.icon) value.icon = shape.icon;
    if (shape.dismissible) value.dismissible = true;
    if (shape.action) value.action = { label: shape.action, onSelect() {} };
    if (shape.secondary) value.secondaryAction = { label: shape.secondary, onSelect() {} };
    if (shape.choices) value.iconActions = [
      { label: "Switch", icon: icons.CHECK, onSelect() {} },
      { label: "Keep as is", icon: icons.X, onSelect() {} },
      { label: "About", icon: icons.HELP, keepOpen: true, onSelect() {} },
    ];
    for (let n = 0; n < (shape.repeat ?? 1); n++) window.__toast!.show(value);
  }, { s, icons: { CHECK, X, HELP } });
  await expect(page.locator(".ui-toast")).toHaveCount(1);
  await expect(page.locator(".ui-toast")).toHaveAttribute("data-open", "true");
  await motionSettled(page);
  // The tick draws itself in; measure and photograph the finished card.
  // sleep: the tick draws itself in with no signal to wait for; measure and photograph the finished card.
  await page.waitForTimeout(700);
}

/** What a person sees of one card, in CSS pixels: the first text line, the mark, the close button, the last line and the actions. */
async function geometry(page: Page) {
  return page.evaluate(() => {
    const card = document.querySelector<HTMLElement>(".ui-toast")!;
    const label = card.querySelector<HTMLElement>(".ui-toast-message")!;
    const range = document.createRange();
    range.selectNodeContents(label);
    // One box per line: the rectangles of a line share a top (rounded), so group by it.
    const lines = new Map<number, { left: number; right: number; top: number; bottom: number }>();
    for (const r of range.getClientRects()) {
      const key = Math.round(r.top / 4);
      const prev = lines.get(key);
      lines.set(key, { left: Math.min(prev?.left ?? r.left, r.left), right: Math.max(prev?.right ?? r.right, r.right), top: Math.min(prev?.top ?? r.top, r.top), bottom: Math.max(prev?.bottom ?? r.bottom, r.bottom) });
    }
    const rows = [...lines.values()].sort((a, b) => a.top - b.top);
    const visible = (el: Element | null): HTMLElement | null => (el instanceof HTMLElement && !el.hidden && el.getClientRects().length ? el : null);
    const mark = visible(card.querySelector(".ui-toast-marker")) ?? visible(card.querySelector(".ui-toast-glyph"));
    const close = visible(card.querySelector(".ui-toast-close"));
    const actions = visible(card.querySelector(".ui-toast-actions")) ?? visible(card.querySelector(".ui-toast-icons"));
    const mid = (r: DOMRect | { top: number; bottom: number }): number => (r.top + r.bottom) / 2;
    const c = card.getBoundingClientRect();
    // The control slot in pixels (it is in rem), and the card's own padding and border.
    const probe = document.createElement("div");
    probe.style.cssText = "height:var(--ui-toast-ctl);position:absolute;visibility:hidden";
    card.append(probe);
    const slot = probe.getBoundingClientRect().height;
    probe.remove();
    const cs = getComputedStyle(card);
    const chrome = ["paddingTop", "paddingBottom", "borderTopWidth", "borderBottomWidth"].reduce((sum, k) => sum + Number.parseFloat(cs[k as "paddingTop"]), 0);
    const first = rows[0]!, last = rows[rows.length - 1]!;
    const widest = Math.max(...rows.map((r) => r.right - r.left));
    const lineHeight = Number.parseFloat(getComputedStyle(label).lineHeight);
    return {
      lines: rows.length,
      lineHeight,
      firstMid: mid(first),
      markMid: mark ? mid(mark.getBoundingClientRect()) : null,
      closeMid: close ? mid(close.getBoundingClientRect()) : null,
      lastWidth: last.right - last.left,
      widest,
      textRight: Math.max(...rows.map((r) => r.right)),
      labelRight: label.getBoundingClientRect().right,
      actionsTop: actions ? actions.getBoundingClientRect().top : null,
      labelBottom: label.getBoundingClientRect().bottom,
      slot, chrome,
      cardLeft: c.left, cardRight: c.right, cardWidth: c.width, cardHeight: c.height,
      stacked: card.dataset.stacked,
      innerWidth: window.innerWidth,
    };
  });
}

for (const phone of [false, true]) {
  for (const theme of ["ink", "paper"] as const) {
    test.describe(`${phone ? "phone 393x852 @3x" : "desktop 1440x900 @2x"} ${theme}`, () => {
      test.use({ viewport: phone ? { width: 393, height: 852 } : { width: 1440, height: 900 }, deviceScaleFactor: phone ? 3 : 2, hasTouch: phone, isMobile: phone, colorScheme: theme === "ink" ? "dark" : "light" });

      for (const shape of SHAPES) {
        test(`${shape.id}`, async ({ page }) => {
          await open(page, theme);
          await show(page, shape);
          // The card itself, with room around it for the shadow and some of what lies behind it.
          const box = (await page.locator(".ui-toast").boundingBox())!;
          const vp = page.viewportSize()!;
          const x = Math.max(0, box.x - 24), y = Math.max(0, box.y - 32);
          const clip = { x, y, width: Math.min(vp.width - x, box.width + 48), height: Math.min(vp.height - y, box.height + 64) };
          await page.screenshot({ path: `${OUT}/${phone ? "phone" : "desktop"}-${theme}-${shape.id}.png`, clip });
          if (!MEASURE) return;

          const g = await geometry(page);
          const tag = JSON.stringify(g);
          // The mark and the close button centre on the first line (±1 px), however many lines follow.
          if (g.markMid !== null) expect(Math.abs(g.markMid - g.firstMid), `mark vs first line: ${tag}`).toBeLessThanOrEqual(1);
          if (g.closeMid !== null) expect(Math.abs(g.closeMid - g.firstMid), `close vs first line: ${tag}`).toBeLessThanOrEqual(1);
          // Actions: beside the text only when it is one line; under it otherwise.
          if (g.actionsTop !== null && g.stacked === "true") expect(g.actionsTop, `stacked actions under the text: ${tag}`).toBeGreaterThanOrEqual(g.labelBottom - 1);
          if (g.actionsTop !== null && g.stacked !== "true") expect(g.lines, `beside actions mean one line: ${tag}`).toBe(1);
          // Wrapped text: no lone last word, and the box hugs the longest line (within a couple of pixels).
          if (g.lines > 1) {
            expect(g.lastWidth, `last line is not an orphan: ${tag}`).toBeGreaterThanOrEqual(g.widest * 0.4);
            expect(g.labelRight - g.textRight, `no empty strip right of the text: ${tag}`).toBeLessThanOrEqual(3);
          }
          // Inside the screen, with at least the stack's own inset on both sides.
          expect(g.cardLeft, tag).toBeGreaterThanOrEqual(11.5);
          expect(g.innerWidth - g.cardRight, tag).toBeGreaterThanOrEqual(11.5);
          // A card is never taller than its lines, the control slot and the padding need: no slack under a multi-line text.
          const expected = (g.stacked === "true" ? g.slot : 0) + Math.max(g.slot, g.lines * g.lineHeight + (g.slot - g.lineHeight)) + g.chrome;
          expect(Math.abs(g.cardHeight - expected), `card height ${g.cardHeight} vs ${expected}: ${tag}`).toBeLessThanOrEqual(2.5);
        });
      }
    });
  }
}
