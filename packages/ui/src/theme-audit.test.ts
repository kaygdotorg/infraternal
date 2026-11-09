// SPDX-License-Identifier: AGPL-3.0-only
/** D365 is a gate: every text colour in every scheme passes, and palette repair only moves lightness. */
import { expect, test } from "bun:test";
import { hexToOklab } from "./color";
import { auditTheme, cardSurface, contrast, luminance, repair, rolesOf } from "./theme-audit";
import { THEMES } from "./themes";
import { gradientsFor, sampleGradientBackdrop, toned } from "../../../apps/tracer/src/canvas/themes/gradients";

test("every colour scheme passes the D365 contrast audit", () => {
  for (const [id, theme] of Object.entries(THEMES)) {
    expect(auditTheme(theme).map((f) => `${f.role} ${f.colour} ${f.ratio.toFixed(2)}<${f.need}`), id).toEqual([]);
  }
});

test("the built-in gradient sampler covers each recipe and its rendered endpoints", () => {
  const theme = THEMES.paper!;
  const gradients = gradientsFor(theme);
  expect(gradients.map(({ id }) => id).sort()).toEqual(["aurora", "dusk", "ember", "haze", "horizon", "lagoon", "meadow", "orchid", "sunrise"]);
  const aurora = sampleGradientBackdrop(theme, "aurora", 100);
  expect(aurora.find(({ xPercent, yPercent }) => xPercent === 15 && yPercent === 20)?.colour).toBe(toned(theme, theme.accent));
  const horizon = sampleGradientBackdrop(theme, "horizon", 100);
  expect(horizon[0]?.colour).toBe(theme.bg);
  expect(horizon.at(-1)?.colour).toBe(toned(theme, theme.accent));
});

test("every text role reaches its D365 contrast line at the worst sampled point of every built-in gradient", () => {
  const failures: string[] = [];
  for (const [id, theme] of Object.entries(THEMES)) {
    for (const { id: gradientId } of gradientsFor(theme)) {
      const samples = sampleGradientBackdrop(theme, gradientId);
      const backgrounds = samples.map((sample) => ({ sample, luminance: luminance(sample.colour) }));
      for (const { role, colour: foreground, need } of rolesOf(theme)) {
        const foregroundLuminance = luminance(foreground);
        let worst = { ratio: Number.POSITIVE_INFINITY, colour: "", xPercent: 0, yPercent: 0 };
        for (const { sample, luminance: backgroundLuminance } of backgrounds) {
          const high = Math.max(foregroundLuminance, backgroundLuminance), low = Math.min(foregroundLuminance, backgroundLuminance);
          const ratio = (high + 0.05) / (low + 0.05);
          if (ratio < worst.ratio) worst = { ratio, colour: sample.colour, xPercent: sample.xPercent, yPercent: sample.yPercent };
        }
        if (worst.ratio < need) failures.push(`${id}: ${role} ${foreground} over ${gradientId} at ${worst.xPercent}%,${worst.yPercent}% ${worst.colour} ${worst.ratio.toFixed(2)}<${need}`);
      }
    }
  }
  expect({ count: failures.length, examples: failures.slice(0, 8) }).toEqual({ count: 0, examples: [] });
});

test("every text token reaches 4.5:1 on its theme surface, and primary text keeps 7:1", () => {
  const failures: string[] = [];
  for (const [id, theme] of Object.entries(THEMES)) {
    const surfaces = [theme.bg, cardSurface(theme)];
    for (const [role, colour, need] of [
      ["fg", theme.fg, 7], ["fg2", theme.fg2, 4.5], ["fg3", theme.fg3, 4.5],
      ["accent", theme.accent, 4.5], ["ok", theme.ok, 4.5], ["danger", theme.ansi[1], 4.5], ["warn", theme.ansi[3], 4.5],
    ] as const) {
      for (const surface of surfaces) {
        const ratio = contrast(colour, surface);
        if (ratio < need) failures.push(`${id}: ${role} ${colour} on ${surface} ${ratio.toFixed(2)}<${need}`);
      }
    }
    for (const [table, colours] of [["ansi", theme.ansi], ["bright", theme.bright]] as const) {
      for (const [slot, colour] of colours.entries()) {
        const ratio = contrast(colour, theme.bg);
        if (ratio < 4.5) failures.push(`${id}: ${table} ${slot} ${colour} on ${theme.bg} ${ratio.toFixed(2)}<4.5`);
      }
    }
  }
  expect(failures).toEqual([]);
});

test("every scheme has the eight ANSI colours twice, #rrggbb everywhere, and a name that is its own", () => {
  const names = new Set<string>();
  for (const [id, theme] of Object.entries(THEMES)) {
    expect(theme.ansi, id).toHaveLength(8);
    expect(theme.bright, id).toHaveLength(8);
    for (const c of [theme.bg, theme.fg, theme.fg2, theme.fg3, theme.accent, theme.ok, ...theme.ansi, ...theme.bright]) expect(c, id).toMatch(/^#[0-9a-f]{6}$/);
    expect(names.has(theme.name), `${id}: ${theme.name} is listed twice`).toBe(false);
    names.add(theme.name);
  }
});

test("the repair reaches the ratio by lightness alone: hue and chroma stay, and a colour that passes is left alone", () => {
  expect(repair("#ffffff", "#000000", 7)).toBe("#ffffff");
  const fixed = repair("#839496", "#002b36", 7);
  expect(contrast(fixed, "#002b36")).toBeGreaterThanOrEqual(7);
  const [, a0, b0] = hexToOklab("#839496"), [, a1, b1] = hexToOklab(fixed);
  expect(Math.hypot(a1 - a0, b1 - b0)).toBeLessThan(0.02);
  // Against a light background the colour moves darker.
  expect(hexToOklab(repair("#98c379", "#fafafa", 4.5))[0]).toBeLessThan(hexToOklab("#98c379")[0]);
});
