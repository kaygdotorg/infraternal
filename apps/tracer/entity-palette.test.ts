/** The entity palette guarantees text contrast: every fill of both schemes clears 4.5:1 against its scheme's chip text. */
import { expect, test } from "bun:test";
import { contrastRatio } from "../../packages/ui/src/color";
import { ENTITY_COLORS, entityColorIndex, entityPalette, entityTextFor } from "../../packages/ui/src/entity-palette";

test("every fill of both schemes clears 4.5:1 against the chip text, so any gradient of them does too", () => {
  for (const dark of [true, false]) {
    const { fills, text } = entityPalette(dark);
    expect(fills).toHaveLength(ENTITY_COLORS);
    for (const f of fills) expect(contrastRatio(f, text)).toBeGreaterThanOrEqual(4.5);
  }
});

test("a name always gets the same colour, and a chosen colour gets the better text", () => {
  expect(entityColorIndex("ci")).toBe(entityColorIndex("ci"));
  expect(entityTextFor("#ffffff")).toBe("#17171a");
  expect(entityTextFor("#101010")).toBe("#ffffff");
});
