/** Shared sRGB helpers for curated theme contrast checks and mesh color tuning. */

/** A colour in OKLab: perceptual lightness (0 to 1) and the two colour-opponent axes. */
type Oklab = [lightness: number, a: number, b: number];

/** sRGB channel (0 to 1) to linear light. */
const toLinear = (value: number): number => value <= 0.04045
  ? value / 12.92
  : ((value + 0.055) / 1.055) ** 2.4;

/** Linear light to an sRGB channel (0 to 1, not yet clipped). */
const toSrgb = (value: number): number => value <= 0.0031308
  ? 12.92 * value
  : 1.055 * value ** (1 / 2.4) - 0.055;

/** Converts a curated six-digit hex color to OKLab without changing its hue. */
export function hexToOklab(hex: string): Oklab {
  const [r, g, b] = [1, 3, 5].map((index) => toLinear(parseInt(hex.slice(index, index + 2), 16) / 255)) as [number, number, number];
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}

/** Converts OKLab back to clipped six-digit sRGB hex for CSS and WebGL. */
export function oklabToHex([lightness, a, b]: Oklab): string {
  const l = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (lightness - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const rgb = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
  return `#${rgb.map((value) => Math.round(Math.min(1, Math.max(0, toSrgb(value))) * 255).toString(16).padStart(2, "0")).join("")}`;
}

/** WCAG 2.2 relative-luminance contrast ratio for curated six-digit hex colors. */
export function contrastRatio(left: string, right: string): number {
  const luminance = (hex: string): number => {
    const channels = [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16) / 255)
      .map(toLinear);
    return 0.2126 * channels[0]! + 0.7152 * channels[1]! + 0.0722 * channels[2]!;
  };
  const [lighter, darker] = [luminance(left), luminance(right)].sort((a, b) => b - a);
  return (lighter! + 0.05) / (darker! + 0.05);
}
