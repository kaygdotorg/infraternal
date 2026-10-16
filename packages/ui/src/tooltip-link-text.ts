/** Formats destinations for the shared tooltip, preserving the origin and shortening only at grapheme boundaries. */

const LINK_TOOLTIP_MAX = 56;
const LINK_ORIGIN = /^(?:https?:\/\/[^/?#]+|mailto:[^?#]*|file:\/\/)/iu;

/** Keeps the complete scheme and host, then gives the path and query a middle ellipsis. */
export function formatLinkTooltipText(target: string): string {
  if (target.length <= LINK_TOOLTIP_MAX) return target;
  const prefix = LINK_ORIGIN.exec(target)?.[0] ?? "";
  const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
  const prefixLength = Array.from(segmenter.segment(prefix)).length;
  if (prefixLength >= LINK_TOOLTIP_MAX) return prefix;
  const tail = Array.from(segmenter.segment(target.slice(prefix.length)), (part) => part.segment);
  const allowance = LINK_TOOLTIP_MAX - prefixLength;
  if (tail.length <= allowance) return target;
  const retained = allowance - 1;
  // Keep a short tail intact (often the final query parameter), and spend the remaining
  // room on the start of the path after the full scheme and host.
  const trailing = Math.min(20, retained);
  const leading = retained - trailing;
  return `${prefix}${tail.slice(0, leading).join("")}…${trailing ? tail.slice(-trailing).join("") : ""}`;
}
