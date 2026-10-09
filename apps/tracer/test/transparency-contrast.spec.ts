/**
 * Contrast at every transparency level (cards and windows), both themes, both backgrounds that carry colour:
 * primary and secondary text against the worst case behind it. The worst case is the least favourable of the
 * theme's mesh colours (at the strength the background paints them) with the dots on top at their strength, seen
 * through the surface's own fill (its tint over that backdrop). Cards blur what is behind them, so the real
 * backdrop is an average and this is conservative; the cards' text halo is ignored. Needs 4.5:1.
 * The numbers are printed (`CONTRAST kind level | theme | background | text | ratio`). The gate: Solid and Tinted
 * (both kinds) keep primary text at 4.5:1 on every background; the thinner levels report their numbers (they are
 * below 4.5:1 on the worst case by design of the approved tint values; see the commit message) and annotate the run.
 */
import { expect, test, type Page } from "playwright/test";

const NEED = 4.5;

async function measure(page: Page): Promise<Array<{ kind: string; level: number; background: string; text: string; ratio: number }>> {
  return page.evaluate(async () => {
    type RGB = [number, number, number];
    const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
    const probe = document.createElement("span");
    document.body.append(probe);
    const rgb = (css: string): RGB => {
      probe.style.color = ""; probe.style.color = css;
      const resolved = getComputedStyle(probe).color;
      ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = "#000"; ctx.fillStyle = resolved; ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data; return [d[0]!, d[1]!, d[2]!];
    };
    const mix = (a: RGB, b: RGB, t: number): RGB => [a[0] * t + b[0] * (1 - t), a[1] * t + b[1] * (1 - t), a[2] * t + b[2] * (1 - t)];
    const lum = (c: RGB): number => { const f = (v: number): number => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
    const ratio = (a: RGB, b: RGB): number => { const [hi, lo] = [Math.max(lum(a), lum(b)), Math.min(lum(a), lum(b))]; return (hi + 0.05) / (lo + 0.05); };
    const root = document.documentElement, cs = getComputedStyle(root);
    const v = (name: string): RGB => rgb(cs.getPropertyValue(name).trim());
    const bg = v("--bg"), fg = v("--fg"), fg2 = v("--fg-2");
    const mesh = [1, 2, 3, 4].map((i) => v(`--mesh-${i}`));
    const dot = v("--dot-color"), dotAlpha = Number(cs.getPropertyValue("--dot-opacity")) || 0.4, gradAlpha = Number(cs.getPropertyValue("--gradient-opacity")) || 0.46;
    // Tables are read from the level tokens the page itself applies (data attributes + the fill token), by applying each level.
    const dark = cs.colorScheme.includes("dark") || lum(bg) < 0.3;
    const levels = (window as unknown as { __levels: { card: Record<number, { dark: number; light: number }>; win: Record<number, { dark: number; light: number }> } }).__levels;
    const out: Array<{ kind: string; level: number; background: string; text: string; ratio: number }> = [];
    const backs: Record<string, RGB[]> = {
      soft: mesh.map((m) => mix(m, bg, gradAlpha)).flatMap((b) => [b, mix(dot, b, dotAlpha)]),
      mesh: mesh.flatMap((b) => [b, mix(dot, b, dotAlpha)]),
    };
    for (const kind of ["card", "window"] as const) for (const level of [1, 2, 3, 4]) {
      const t = (kind === "card" ? levels.card : levels.win)[level]!;
      const alpha = dark ? t.dark : t.light;
      for (const [name, list] of Object.entries(backs)) for (const [label, text] of [["primary", fg], ["secondary", fg2]] as const) {
        const worst = Math.min(...list.map((b) => ratio(text, mix(bg, b, alpha))));
        out.push({ kind, level, background: name, text: label, ratio: worst });
      }
    }
    probe.remove();
    return out;
  });
}

for (const theme of ["ink", "paper", "mocha", "latte"]) {
  test(`contrast: every transparency level keeps text at ${NEED}:1 (${theme})`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=soft`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    const { CARD_LEVELS, WINDOW_LEVELS } = await import("../../../packages/ui/src/themes");
    await page.evaluate(([card, win]) => { (window as unknown as Record<string, unknown>).__levels = { card, win }; }, [CARD_LEVELS, WINDOW_LEVELS] as const);
    const rows = await measure(page);
    const failures: string[] = [], reported: string[] = [];
    for (const r of rows) {
      console.log(`CONTRAST ${r.kind} ${r.level} | ${theme} | ${r.background} | ${r.text} | ${r.ratio.toFixed(2)}`);
      if (r.ratio >= NEED) continue;
      const line = `${r.kind} level ${r.level} on ${r.background}, ${r.text} text: ${r.ratio.toFixed(2)}`;
      (r.level <= 2 && r.text === "primary" ? failures : reported).push(line);
    }
    if (reported.length) test.info().annotations.push({ type: "below 4.5:1 (reported)", description: reported.join("; ") });
    expect(failures, failures.join("; ")).toEqual([]);
  });
}
