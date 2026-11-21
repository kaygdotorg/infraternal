/** The machine's pointer shape: what the page accepts from the status reply and the CSS it makes from it (#146). */
import { expect, test } from "bun:test";
import { applyPointer, parsePointerShape, pointerCss, DEFAULT_POINTER } from "./pointer";

const good = { id: "0123456789abcdef", png: "iVBORw0KGgo=", hot_x: 4, hot_y: 3.5, scale: 2, width: 48, height: 48 };

test("a complete shape is read as it was sent", () => {
  expect(parsePointerShape(good)).toEqual({ id: "0123456789abcdef", png: "iVBORw0KGgo=", hotX: 4, hotY: 3.5, scale: 2, width: 48, height: 48 });
});

test("anything incomplete, out of range or oversized is refused, so it never reaches a style", () => {
  for (const bad of [undefined, null, 5, "x", {}, { ...good, id: "XYZ" }, { ...good, id: "0123456789ABCDEF" }, { ...good, png: "" }, { ...good, png: "a b" },
    { ...good, png: "A".repeat(24_001) }, { ...good, png: 'x")' }, { ...good, width: 129 }, { ...good, height: 0 }, { ...good, width: 1.5 }, { ...good, scale: 0.5 }, { ...good, scale: 5 },
    { ...good, hot_x: -1 }, { ...good, hot_x: 25 }, { ...good, hot_y: Number.NaN }, { ...good, hot_y: "1" }]) {
    expect(parsePointerShape(bad)).toBeUndefined();
  }
});

test("the CSS carries the image at its density, the hotspot in whole pixels, and the ordinary pointer as fallback", () => {
  const css = pointerCss(parsePointerShape(good));
  expect(css).toBe('image-set(url("data:image/png;base64,iVBORw0KGgo=") 2x) 4 4, default');
  expect(pointerCss(undefined)).toBe(DEFAULT_POINTER);
});

test("a browser that refuses the standard spelling gets the prefixed one, and never keeps the previous shape", () => {
  const shape = parsePointerShape(good);
  // A style that, like an older browser, accepts only the prefixed image-set and drops what it cannot parse.
  const style = { _v: "", get cursor() { return this._v; }, set cursor(v: string) { if (v === "" || v === "default" || v.startsWith("-webkit-image-set(")) this._v = v; } };
  applyPointer(style as unknown as CSSStyleDeclaration, shape);
  expect(style.cursor).toBe(pointerCss(shape, true));
  applyPointer(style as unknown as CSSStyleDeclaration, undefined);
  expect(style.cursor).toBe("default");
  // A browser that rejects both spellings ends with the stylesheet's pointer, not with the last shape.
  const strict = { _v: "x", get cursor() { return this._v; }, set cursor(v: string) { if (v === "") this._v = v; } };
  applyPointer(strict as unknown as CSSStyleDeclaration, shape);
  expect(strict.cursor).toBe("");
});
