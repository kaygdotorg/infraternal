/** Supplies shared, on-demand styling and concise labels for point-anchored link tooltips. */

const LINK_TOOLTIP_MAX = 56;
const LINK_ORIGIN = /^(?:https?:\/\/[^/?#]+|mailto:[^?#]*|file:\/\/)/iu;
let stylesInstalled = false;
let textMeasure: CanvasRenderingContext2D | null | undefined;

/** Extends the one warm tooltip surface for destination previews after the link feature loads. */
export function installLinkTooltipStyles(): void {
  if (stylesInstalled) return;
  stylesInstalled = true;
  const style = document.createElement("style");
  style.dataset.uiLinkTooltip = "";
  style.textContent = `
.tip-pos, .tip-measure { --tip-content-max: min(258px, calc(100vw - 38px)); }
.tip-pos .tip { max-width: calc(var(--tip-content-max) + 22px); }
html body .tip-label { white-space: normal; overflow-wrap: anywhere; }
html body .tip-label.is-leaving { right: 10px; }
html body .tip-measure { box-sizing: border-box; max-width: var(--tip-content-max); letter-spacing: 0; white-space: normal; overflow-wrap: anywhere; }
`;
  document.head.append(style);
}

/** Keeps the shared arrow at the edge of a link label after its two-line height is known. */
export function alignLinkTooltipArrow(): void {
  const position = document.querySelector<HTMLElement>(".tip-pos[data-side='top']");
  const arrow = position?.querySelector<HTMLElement>(".tip-arrow");
  if (position && arrow) arrow.style.top = `${position.offsetHeight - 4}px`;
}

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
