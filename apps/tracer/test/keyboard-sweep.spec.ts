/**
 * The guard for "keyboard opens instantly" (#427): nothing a keyboard shortcut or a palette row starts may keep animating.
 *
 * The rule lives in one place (input-source.ts: `markMotion` and `triggeredByKeyboard()`), but each opener has to call it. This sweep
 * is what makes the coverage hold by construction instead of by review: it finds the shortcuts and the palette rows itself, so a
 * shortcut or row added tomorrow is swept without anyone remembering to add it here.
 *
 * - Chords: the `?` panel lists every registered shortcut for this platform; each chord is pressed on a fresh clusters mockup.
 * - Palette rows: the palette lists every action; for each, open it with the chord, type the row's label, then press Enter.
 *
 * What counts as still animating, at least three animation frames after the key (the first two are the instant change itself): a
 * running CSS transition or script animation (`getAnimations()`, CSS keyframe animations aside), or an inline `transform`,
 * `clip-path` or `opacity` that is still being rewritten (which is what every spring does). Whatever was already moving while the
 * page sat idle (a connection pulse, a cursor) is measured first and ignored. A failure names the label and the element.
 */
import { expect, test, type Page } from "playwright/test";

const OPEN = "/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none&sessions=1";
/** The palette chord on the (non-Mac) test browser. */
const PALETTE = "Control+Shift+K";
/** What the sweep leaves out, with the reason; keep it short, every entry is a hole in the guard. */
const SKIP_LABEL = /^(Reload|Sign out of every device)/i;

/** One finding: what was still moving and where. */
type Finding = string;

/**
 * Loads a fresh clusters mockup with a second terminal window active (so window actions and the session manager have a target),
 * and installs the watcher in the page.
 */
async function fresh(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(OPEN);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: let the mockup's opening motion finish before the camera is sent to the Console view
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string, instant?: boolean): void } }).__tracerClusters.flyView("console", true));
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } })));
  // sleep: the new window is placed and the opening motion of the page is over, before the idle baseline is taken
  await page.waitForTimeout(1500);
  await page.evaluate(() => {
    type Seen = Map<string, Set<number>>;
    const w = window as unknown as { __sw: { phase: "idle" | "key"; frame: number; keyFrame: number; idle: Seen; key: Seen } };
    const sw = w.__sw = { phase: "idle", frame: 0, keyFrame: 0, idle: new Map(), key: new Map() };
    const name = (el: Element | null): string => el ? `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}.${el.className.toString().split(" ").filter(Boolean).slice(0, 2).join(".")}` : "?";
    const note = (what: string, el: Element | null): void => {
      const seen = sw.phase === "idle" ? sw.idle : sw.key;
      const signature = `${what} on ${name(el)}`;
      if (!seen.has(signature)) seen.set(signature, new Set());
      seen.get(signature)!.add(sw.frame);
    };
    const PROPS = ["transform", "clip-path", "opacity"];
    new MutationObserver((records) => {
      for (const record of records) {
        const el = record.target as HTMLElement;
        const before = document.createElement("div");
        before.style.cssText = record.oldValue ?? "";
        for (const prop of PROPS) if (before.style.getPropertyValue(prop) !== el.style.getPropertyValue(prop)) note(`style ${prop}`, el);
      }
    }).observe(document.documentElement, { attributes: true, attributeFilter: ["style"], attributeOldValue: true, subtree: true });
    const tick = (): void => {
      sw.frame++;
      for (const animation of document.getAnimations()) {
        if (animation instanceof CSSAnimation || animation.playState !== "running") continue;
        const target = (animation.effect as KeyframeEffect | null)?.target ?? null;
        note(animation instanceof CSSTransition ? `transition ${animation.transitionProperty}` : "animation", target);
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  // sleep: about ten frames of idle, recorded as the ambient baseline
  await page.waitForTimeout(250);
}

/** Switches the watcher to the key phase, runs `act`, waits for the motion to show, and returns what kept moving. */
async function sweep(page: Page, act: () => Promise<void>): Promise<Finding[]> {
  await page.evaluate(() => { const sw = (window as unknown as { __sw: { phase: string; frame: number; keyFrame: number } }).__sw; sw.phase = "key"; sw.keyFrame = sw.frame; });
  await act();
  // sleep: long enough for a 130 to 300 ms animation to be caught in the frames after the third
  await page.waitForTimeout(450);
  return page.evaluate(() => {
    const sw = (window as unknown as { __sw: { keyFrame: number; idle: Map<string, Set<number>>; key: Map<string, Set<number>> } }).__sw;
    const found: string[] = [];
    for (const [signature, frames] of sw.key) {
      if (sw.idle.has(signature)) continue;
      const late = [...frames].filter((f) => f >= sw.keyFrame + 3);
      if (late.length) found.push(`${signature} (still moving in ${late.length} frames from ${late[0]! - sw.keyFrame} frames after the key)`);
    }
    return found;
  });
}

/** The pressable chords of the `?` panel: its rows' first run of key caps, as Playwright key names. */
async function chordsOfPanel(page: Page): Promise<Array<{ label: string; key: string }>> {
  // Ctrl+Shift+/ works from inside a focused terminal, where a bare "?" is typed into the shell.
  await page.keyboard.press("Control+Shift+/");
  await expect(page.locator(".ui-shortcuts")).toBeVisible();
  const rows = await page.locator(".ui-shortcuts-row").evaluateAll((nodes) => nodes.map((row) => ({
    label: row.querySelector(".ui-shortcuts-label")?.textContent ?? "",
    caps: [...row.querySelectorAll("kbd:not(.ui-shortcuts-alt)")].map((kbd) => kbd.textContent ?? ""),
  })));
  await page.keyboard.press("Escape");
  const names: Record<string, string> = { Ctrl: "Control", Esc: "Escape", "←": "ArrowLeft", "→": "ArrowRight", "↑": "ArrowUp", "↓": "ArrowDown", "↩": "Enter" };
  const chords: Array<{ label: string; key: string }> = [];
  for (const row of rows) {
    const caps = row.caps.map((cap) => names[cap] ?? cap);
    // Patterns and pointer entries ("Ctrl+Shift+1–3", "Scroll", "Alt+click") are not one pressable chord.
    if (!caps.length || caps.some((cap) => /[–]|click|Scroll/i.test(cap)) || /^Show these shortcuts$|^Close the open panel$/.test(row.label)) continue;
    chords.push({ label: row.label, key: caps.join("+") });
  }
  return chords;
}

test("no shortcut leaves anything animating three frames after the key", async ({ page }) => {
  test.setTimeout(600_000);
  await fresh(page);
  const chords = await chordsOfPanel(page);
  expect(chords.length, "the panel lists the registered chords").toBeGreaterThan(10);
  const failures: string[] = [];
  for (const { label, key } of chords) {
    await fresh(page);
    const found = await sweep(page, () => page.keyboard.press(key));
    if (found.length) failures.push(`${label} (${key}): ${found.join("; ")}`);
  }
  expect(failures, `chords that kept animating:\n${failures.join("\n")}`).toEqual([]);
});

test("no palette row leaves anything animating three frames after Enter", async ({ page }) => {
  test.setTimeout(1_800_000);
  await fresh(page);
  await page.keyboard.press(PALETTE);
  await expect(page.locator("#palette")).toBeVisible();
  // One row per family of actions (theme:*, font:*, canvas:settings:*, ...): the rows of a family run the same code, and the sweep reloads the page for each.
  const rows = await page.locator("#palette-results .result").evaluateAll((nodes) => nodes.map((node) => ({ label: node.querySelector(".result-label")?.textContent?.trim() ?? "", action: (node as HTMLElement).dataset.action ?? "" })));
  const families = new Map<string, string>();
  for (const { label, action } of rows) {
    if (!label || SKIP_LABEL.test(label)) continue;
    const family = action.includes(":") ? action.slice(0, action.lastIndexOf(":")) : action || label;
    if (!families.has(family)) families.set(family, label);
  }
  const labels = [...families.values()];
  expect(labels.length, "the palette lists its actions").toBeGreaterThan(8);
  const failures: string[] = [];
  for (const label of labels) {
    await fresh(page);
    await page.keyboard.press(PALETTE);
    await page.keyboard.type(label, { delay: 0 });
    await expect(page.locator("#palette-results .result").first()).toBeVisible();
    // sleep: the filtered list is rendered and the palette's own open has finished, so only the Enter is measured
    await page.waitForTimeout(300);
    const found = await sweep(page, () => page.keyboard.press("Enter"));
    if (found.length) failures.push(`${label}: ${found.join("; ")}`);
  }
  expect(failures, `palette rows that kept animating:\n${failures.join("\n")}`).toEqual([]);
});
