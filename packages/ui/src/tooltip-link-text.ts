/** Formats terminal link destinations for the shared point-anchored tooltip. */

/** The most characters (graphemes) shown before the middle is replaced by an ellipsis. */
const LINK_TOOLTIP_MAX = 56;
/** Matches the scheme and host of a link (or `mailto:` address, or `file://`), which must never be shortened. */
const LINK_ORIGIN = /^(?:https?:\/\/[^/?#]+|mailto:[^?#]*|file:\/\/)/iu;
/** A canvas context made on first use to measure text; `null` when canvas is unavailable, then widths are estimated. */
let textMeasure: CanvasRenderingContext2D | null | undefined;

/** Keeps the complete scheme and host, shortening the path only at grapheme boundaries. */
export function formatLinkTooltipText(target: string, contentWidth = 258, font = "500 12px ui-monospace"): string {
  const prefix = LINK_ORIGIN.exec(target)?.[0] ?? "";
  const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
  const prefixLength = Array.from(segmenter.segment(prefix)).length;
  const parts = Array.from(segmenter.segment(target), (part) => part.segment);
  if (prefixLength >= LINK_TOOLTIP_MAX) return prefix;
  const tail = parts.slice(prefixLength);
  const measure = (value: string): number => {
    textMeasure ??= document.createElement("canvas").getContext("2d");
    if (!textMeasure) return value.length * 7.2;
    textMeasure.font = font;
    return textMeasure.measureText(value).width;
  };
  const maxLineWidth = contentWidth * 2;
  if (parts.length <= LINK_TOOLTIP_MAX && measure(target) <= maxLineWidth) return target;
  const allowance = LINK_TOOLTIP_MAX - prefixLength;
  const retained = Math.min(allowance - 1, tail.length);
  // Keep a short tail intact (often the final query parameter), and spend the remaining
  // room on the start of the path after the full scheme and host.
  let trailing = Math.min(20, retained);
  let leading = retained - trailing;
  for (;;) {
    const candidate = `${prefix}${tail.slice(0, leading).join("")}…${trailing ? tail.slice(-trailing).join("") : ""}`;
    if (measure(candidate) <= maxLineWidth || (leading === 0 && trailing === 0)) return candidate;
    if (leading > 0) leading -= 1;
    else trailing -= 1;
  }
}

/** Estimates wrapped lines with the same font and content width as the shared surface. */
export function linkTooltipLineCount(text: string, contentWidth: number, font: string): number {
  textMeasure ??= document.createElement("canvas").getContext("2d");
  if (!textMeasure) return Math.max(1, Math.min(2, Math.ceil(text.length * 7.2 / contentWidth)));
  textMeasure.font = font;
  return Math.max(1, Math.min(2, Math.ceil(textMeasure.measureText(text).width / contentWidth)));
}
