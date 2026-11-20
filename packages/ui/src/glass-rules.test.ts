/**
 * The glass rules start from an active look's tint (D365 with D322 and D338, #448): a card the look paints at Tinted 75% stays at
 * 75% wherever 4.5:1 is already met there, and the opacity rises above it only where it must. These tests stub the root element,
 * so they run without a browser; the real card is held by `apps/tracer/test/glass-levels-cards.spec.ts`.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { glassFloor, glassFor, lookTint, nominalOpacity } from "./glass-rules.on-demand";
import { THEMES, levelOpacity } from "./themes";

/** Puts a stub document on the global with a look of `tint` (a string as `applyLook` writes it), or no look when `undefined`. */
function withLook(tint: string | undefined): void {
  (globalThis as { document?: unknown }).document = { documentElement: { hasAttribute: (name: string) => name === "data-look" && tint !== undefined, style: { getPropertyValue: () => tint ?? "" } } };
}
afterEach(() => { delete (globalThis as { document?: unknown }).document; });

describe("the look's tint is where the solver starts", () => {
  test("no look: the level's own opacity", () => {
    withLook(undefined);
    expect(lookTint()).toBeUndefined();
    expect(nominalOpacity(THEMES.ink!, 2)).toBe(levelOpacity(THEMES.ink!, 2));
  });
  test("a look: its tint, whatever the level says", () => {
    withLook("0.75");
    expect(lookTint()).toBe(0.75);
    expect(nominalOpacity(THEMES.paper!, 2)).toBe(0.75);
  });
  test("a tint that is not a fraction is ignored", () => {
    withLook("75");
    expect(lookTint()).toBeUndefined();
  });
});

describe("D365 raises the look's fill only where 4.5:1 needs it", () => {
  for (const [id, theme] of Object.entries(THEMES)) {
    for (const tint of [0.5, 0.75, 1]) {
      test(`${id} at a ${tint * 100}% look: never below the look's fill, and the floor never exceeds the ceiling`, () => {
        withLook(String(tint));
        const themed = glassFor(theme, 2), floor = glassFloor(theme, 2);
        expect(themed.alpha).toBeGreaterThanOrEqual(tint);
        expect(floor.alpha).toBeGreaterThanOrEqual(tint);
        expect(floor.alpha).toBeGreaterThanOrEqual(themed.alpha - 1e-9);
      });
    }
    test(`${id}: where the themed set holds at the look's own fill it keeps it exactly`, () => {
      withLook("0.75");
      const themed = glassFor(theme, 2);
      // Solved from the look's tint, a solution that is not raised is the tint itself: nothing of D365's own opacity leaks in.
      if (!themed.raised) expect(themed.alpha).toBe(0.75);
    });
  }
});
