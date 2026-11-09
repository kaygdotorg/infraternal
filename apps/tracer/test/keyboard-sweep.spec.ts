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
 * What counts as still animating: something that is still being seen moving 50 ms after the key and has been seen for 60 ms or more
 * from its first frame (an instant change finishes within a frame or two, under 60 ms even at 20 frames a second; the time is
 * measured, not counted in frames, so a slow host that draws a 120 ms fade in three frames still fails it): a running CSS transition of open or close geometry or a script animation (`getAnimations()`,
 * CSS keyframe animations aside), or an inline `transform`, `clip-path` or `opacity` that is still being rewritten (which is what every
 * spring does). Whatever was already moving while the page sat idle (a connection pulse, a cursor) is measured first and ignored. A
 * failure names the label and the element.
 *
 * Runs at a desktop and a phone size (`SWEEP_SIZE=desktop`, `phone` or the default `both`). The Escape chord is checked for an effect:
 * a chord that changes nothing would pass for the wrong reason.
 */
import { expect, test, type Page } from "playwright/test";

/** The page the sweep boots: the Console scene with sessions. */
const OPEN = "/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none&sessions=1";
/** The two sizes the sweep runs at: a desktop window and a phone. */
const SIZES = [{ name: "1440x900", width: 1440, height: 900 }, { name: "393x852", width: 393, height: 852 }].filter((size) => {
  const want = process.env.SWEEP_SIZE ?? "both";
  return want === "both" || (want === "desktop" ? size.width > 1000 : size.width < 1000);
});
/** The palette chord on the (non-Mac) test browser. */
const PALETTE = "Control+Shift+K";
/**
 * Palette rows the sweep leaves out, with the reason; keep it short, every entry is a hole in the guard. Reload and Sign out of every
 * device navigate the page or ask the same confirmation as Sign out; the Mockup: rows run the test mockup's scripted scenes, which move
 * on their own timers by design.
 */
const SKIP_LABEL = /^(Reload|Sign out of every device|Mockup:)/i;
/**
 * Elements whose motion is not a response to the key: the test double's badge (a test-only label that dims while the palette is open)
 * the terminal cursor's blink, which starts when a terminal takes focus, and a window's connection indicator, which morphs when the
 * connection state changes (a network event that happens to follow the key, not a response to it).
 */
const NOT_PRODUCT = /#test-double-badge|terminal-cursor-layer|ui-conn-g/;

/** A palette family of this many rows or fewer is swept row by row (nine fonts, four card levels); a larger one (the themes) takes one row. */
const FAMILY_ALL = 10;

/** One finding: what was still moving and where. */
type Finding = string;

/**
 * Loads a fresh clusters mockup with a second terminal window active (so window actions and the session manager have a target),
 * and installs the watcher in the page.
 */
async function fresh(page: Page, size: { width: number; height: number }): Promise<void> {
  await page.setViewportSize({ width: size.width, height: size.height });
  await page.goto(OPEN);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: let the mockup's opening motion finish before the camera is sent to the Console view
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string, instant?: boolean): void } }).__tracerClusters.flyView("console", true));
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } })));
  // sleep: the new window is placed and the opening motion of the page is over, before the idle baseline is taken
  await page.waitForTimeout(1500);
  await page.evaluate(() => {
    type Seen = Map<string, number[]>;
    const w = window as unknown as { __sw: { phase: "idle" | "key"; now: number; keyTime: number; idle: Seen; key: Seen } };
    const sw = w.__sw = { phase: "idle", now: performance.now(), keyTime: 0, idle: new Map(), key: new Map() };
    const name = (el: Element | null): string => el ? `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}.${(el.getAttribute("class") ?? "").split(" ").filter(Boolean).slice(0, 2).join(".")}` : "?";
    const note = (what: string, el: Element | null): void => {
      const seen = sw.phase === "idle" ? sw.idle : sw.key;
      const signature = `${what} on ${name(el)}`;
      if (!seen.has(signature)) seen.set(signature, []);
      seen.get(signature)!.push(sw.now);
    };
    const PROPS = ["transform", "clip-path", "opacity"];
    const GEOMETRY = new Set(["opacity", "transform", "translate", "scale", "clip-path", "height", "width", "max-height", "top", "left", "inset", "filter", "grid-template-rows"]);
    new MutationObserver((records) => {
      for (const record of records) {
        const el = record.target as HTMLElement;
        const before = document.createElement("div");
        before.style.cssText = record.oldValue ?? "";
        for (const prop of PROPS) if (before.style.getPropertyValue(prop) !== el.style.getPropertyValue(prop)) note(`style ${prop}`, el);
      }
    }).observe(document.documentElement, { attributes: true, attributeFilter: ["style"], attributeOldValue: true, subtree: true });
    const tick = (): void => {
      sw.now = performance.now();
      for (const animation of document.getAnimations()) {
        if (animation instanceof CSSAnimation || animation.playState !== "running") continue;
        const target = (animation.effect as KeyframeEffect | null)?.target ?? null;
        // A colour tint (a focus ring, a hover) is not open or close motion; the stepping and lock fades have their own specs.
        if (animation instanceof CSSTransition && !GEOMETRY.has(animation.transitionProperty)) continue;
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
  await page.evaluate(() => { const sw = (window as unknown as { __sw: { phase: string; now: number; keyTime: number } }).__sw; sw.phase = "key"; sw.keyTime = performance.now(); });
  await act();
  // sleep: long enough for a 130 to 340 ms animation to be caught well after its first frames, even on a slow host
  await page.waitForTimeout(700);
  const found = await page.evaluate(() => {
    const sw = (window as unknown as { __sw: { keyTime: number; idle: Map<string, number[]>; key: Map<string, number[]> } }).__sw;
    const found: string[] = [];
    for (const [signature, times] of sw.key) {
      if (sw.idle.has(signature)) continue;
      // An instant change, even one that came after some code had loaded, lasts a frame or two (under 60 ms even at 20 frames a second).
      // Motion is still being seen 50 ms after the key and has been seen for 60 ms or more from its first frame: a 120 ms fade qualifies.
      const first = times[0]!, last = times[times.length - 1]!;
      if (last >= sw.keyTime + 50 && last - first >= 60) found.push(`${signature} (moving from ${Math.round(first - sw.keyTime)} ms to ${Math.round(last - sw.keyTime)} ms after the key)`);
    }
    return found;
  });
  return found.filter((finding) => !NOT_PRODUCT.test(finding));
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

for (const size of SIZES) {
  test.describe(size.name, () => {
    test("no shortcut leaves anything animating after the key", async ({ page }) => {
      test.setTimeout(900_000);
      await fresh(page, size);
      const chords = await chordsOfPanel(page);
      expect(chords.length, "the panel lists the registered chords").toBeGreaterThan(10);
      const failures: string[] = [];
      for (const { label, key } of chords) {
        await fresh(page, size);
        const isOverview = /^All views/.test(label);
        // Escape goes to the overview only from outside a terminal and with no popover open (the first Escape closes a popover, the
        // Console scene opens one); the sweep gets there first, presses the chord, and checks that it arrived.
        if (isOverview) {
          if (await page.locator(".ui-anchored-popover").count()) {
            await page.keyboard.press("Escape");
            // sleep: the popover is closed and its anchor has taken focus back before the chord under test is pressed
            await page.waitForTimeout(400);
          }
          await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
        }
        const found = await sweep(page, () => page.keyboard.press(key));
        if (isOverview) {
          const zoom = await page.locator(".cl-world").getAttribute("data-zoom");
          if (zoom !== "out") failures.push(`${label} (${key}): the chord did not reach the overview (data-zoom is "${zoom}"), so it proved nothing`);
        }
        if (found.length) failures.push(`${label} (${key}): ${found.join("; ")}`);
      }
      expect(failures, `chords that kept animating:\n${failures.join("\n")}`).toEqual([]);
    });

    test("Enter on the window's Sessions button leaves nothing animating", async ({ page }) => {
      test.setTimeout(300_000);
      await fresh(page, size);
      const button = page.locator('.ui-window[data-active] [data-action="sessions"]').first();
      // The button is in the active window's header; on a phone the header may hold it in a menu, and the test is then about the desktop.
      test.skip(await button.count() === 0 || !(await button.isVisible()), "the Sessions button is not on this header");
      await button.focus();
      const found = await sweep(page, () => page.keyboard.press("Enter"));
      expect(found, `Sessions button, Enter:\n${found.join("\n")}`).toEqual([]);
    });

    test("no palette row leaves anything animating after Enter", async ({ page }) => {
      test.setTimeout(2_400_000);
      await fresh(page, size);
      await page.keyboard.press(PALETTE);
      await expect(page.locator("#palette")).toBeVisible();
      // Every row is swept except the rows of a large argument family, which run the same code with a different argument: theme:*,
      // canvas:settings:*, canvas:view:* ... take one row each. A family of FAMILY_ALL rows or fewer (the fonts, the card
      // levels) is swept whole: each row changes a different selection in a pane behind the palette, and the one that moves is not
      // always the one sampled. The canvas verbs (canvas:close, canvas:overview, canvas:sessions, ...) are different code each.
      const rows = await page.locator("#palette-results .result").evaluateAll((nodes) => nodes.map((node) => ({ label: node.querySelector(".result-label")?.textContent?.trim() ?? "", action: (node as HTMLElement).dataset.action ?? "" })));
      const familyOf = (action: string, label: string): string => {
        const colons = action.split(":").length - 1;
        return colons >= 2 ? action.slice(0, action.lastIndexOf(":")) : colons === 1 && !action.startsWith("canvas:") ? action.slice(0, action.indexOf(":")) : action || label;
      };
      const members = new Map<string, Array<{ label: string; action: string }>>();
      for (const { label, action } of rows) {
        if (!label || SKIP_LABEL.test(label)) continue;
        const family = familyOf(action, label);
        members.set(family, [...(members.get(family) ?? []), { label, action }]);
      }
      const targets = [...members.values()].flatMap((list) => (list.length <= FAMILY_ALL ? list : [list[0]!]));
      expect(targets.length, "the palette lists its actions").toBeGreaterThan(14);
      expect(targets.filter((target) => target.action.startsWith("font:")).length, "every font row is swept").toBe(rows.filter((row) => row.action.startsWith("font:")).length);
      const failures: string[] = [];
      for (const { label, action } of targets) {
        await fresh(page, size);
        await page.keyboard.press(PALETTE);
        await page.keyboard.type(label, { delay: 0 });
        await expect(page.locator("#palette-results .result").first()).toBeVisible();
        // sleep: the filtered list is rendered and the palette's own open has finished, so only the Enter is measured
        await page.waitForTimeout(300);
        // The label can match another row first ("Ink" matches a settings row whose action ends in add-link): walk down to the wanted
        // row, and fail the row if it cannot be selected, rather than pressing Enter on the wrong one.
        const actions = await page.locator("#palette-results .result").evaluateAll((nodes) => nodes.map((node) => (node as HTMLElement).dataset.action ?? ""));
        const at = actions.indexOf(action);
        if (at < 0) { failures.push(`${label}: the row ${action} is not in the list the label filters to`); continue; }
        for (let step = 0; step < at; step++) await page.keyboard.press("ArrowDown");
        const chosen = await page.locator('#palette-results .result[aria-selected="true"]').getAttribute("data-action");
        if (chosen !== action) { failures.push(`${label}: Enter would press ${chosen}, not ${action}`); continue; }
        const found = await sweep(page, () => page.keyboard.press("Enter"));
        if (found.length) failures.push(`${label} (${action}): ${found.join("; ")}`);
      }
      expect(failures, `palette rows that kept animating:\n${failures.join("\n")}`).toEqual([]);
    });
  });
}
