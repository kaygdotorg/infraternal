/** The morph's two ends are the shared icons: editing an icon without its morph fails here. */
import { expect, test } from "bun:test";
import { geometryAt, SPLIT_MORPH, type MorphSpec } from "./icon-morph";
import { ICONS } from "./icons";

const nums = (text: string): number[] => (text.match(/-?\d+(?:\.\d+)?/g) ?? []).map(Number);

/** The frame's x, y, width, height and radius from the icon's <rect>. */
const rectOf = (icon: string): number[] => {
  const tag = icon.match(/<rect[^>]*>/)![0];
  const attr = (name: string): number => Number(tag.match(new RegExp(`${name}="([\\d.]+)"`))![1]);
  return [attr("x"), attr("y"), attr("width"), attr("height"), attr("rx")];
};

/** Every straight bar of the icon's path ("M12 4v16", "M17 9.5v5M14.5 12h5") as x1, y1, x2, y2. */
const barsOf = (icon: string): number[][] => {
  const d = icon.match(/<path d="([^"]+)"/)![1]!;
  return d.split("M").filter(Boolean).map((part) => {
    const [x, y] = nums(part);
    const run = nums(part.slice(part.search(/[hv]/) + 1))[0]!;
    return part.includes("v") ? [x!, y!, x!, y! + run] : [x!, y!, x! + run, y!];
  });
};

const close = (got: number[], want: number[]): void => { got.forEach((v, i) => expect(v).toBeCloseTo(want[i]!, 6)); expect(got.length).toBe(want.length); };

const pairs: Array<[keyof typeof SPLIT_MORPH, keyof typeof ICONS, keyof typeof ICONS]> = [["right", "splitRight", "newRight"], ["down", "splitDown", "newBelow"]];

for (const [name, split, made] of pairs) {
  const spec: MorphSpec = SPLIT_MORPH[name];
  test(`split ${name}: p = 0 is the split icon, p = 1 the new-window icon`, () => {
    close(geometryAt(spec, 0).frame, rectOf(ICONS[split]));
    close(geometryAt(spec, 0).a, barsOf(ICONS[split])[0]!);
    expect(geometryAt(spec, 0).bOpacity).toBe(0);
    close(geometryAt(spec, 1).frame, rectOf(ICONS[made]));
    const [upright, crossbar] = barsOf(ICONS[made]);
    // The plus is drawn upright first on the right, crossbar first... whichever bar the divider turns into is `a`.
    const bars = [geometryAt(spec, 1).a, geometryAt(spec, 1).b];
    for (const bar of [upright!, crossbar!]) expect(bars.some((got) => got.every((v, i) => Math.abs(v - bar[i]!) < 1e-6))).toBe(true);
    expect(geometryAt(spec, 1).bOpacity).toBe(1);
  });
  test(`split ${name}: the frame moves smoothly between the ends`, () => {
    const mid = geometryAt(spec, 0.5).frame;
    const from = geometryAt(spec, 0).frame, to = geometryAt(spec, 1).frame;
    mid.forEach((v, i) => expect(v).toBeCloseTo((from[i]! + to[i]!) / 2, 6));
  });
}
