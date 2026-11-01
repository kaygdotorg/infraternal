/**
 * The icon/text centre audit (#282, TASTE "Icon and text share one centre line"): for every icon that sits beside text in
 * the same row, how far is the icon's vertical centre from the text's? Runs inside the page (`page.evaluate(auditIconText)`),
 * so it needs no knowledge of which component drew the row: a new component that nudges its icon with a margin is caught
 * the same way as the shared ones.
 *
 * Two centres are reported for the text, both in CSS px:
 * - `box`: the middle of the text's first line box (what flex centring aligns), and
 * - `cap`: the middle of its capital letters (what the eye reads), from the real baseline and the font's cap height (for a
 *   label that is a flex or grid container, where no baseline can be probed, the line box again).
 * An icon is an `<svg>`, an element holding only one, or a status line's icon cell. A group of several text elements (a
 * name over a detail) is not text of one line and is skipped; a sentence that wraps is measured on its first line.
 */
export interface IconTextPair {
  /** Icon centre minus text-box centre. */
  box: number;
  /** Icon centre minus capital-letter centre. */
  cap: number;
  sample: string;
  icon: string;
  text: string;
}

export function auditIconText(): IconTextPair[] {
  const out: IconTextPair[] = [];
  const visible = (r: DOMRect): boolean => r.width > 0 && r.height > 0 && r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth;
  // A drawing laid over a list (the sidebar's branch lines) is positioned out of the flow: it is not an icon beside text.
  const isIcon = (el: Element): boolean => (el instanceof SVGSVGElement && getComputedStyle(el).position !== "absolute") ||(el.children.length === 1 && el.firstElementChild instanceof SVGSVGElement && !el.textContent?.trim()) || el.matches(".ui-status-icons");
  // A text element of its own: not a whole control beside the icon (an icon button next to a version pill is two controls).
  const hasText = (el: Element): boolean => !isIcon(el) && !(el instanceof HTMLButtonElement || el instanceof HTMLAnchorElement) && !el.querySelector("svg") && el.children.length <= 1 && Boolean(el.textContent?.trim());
  const firstLine = (el: Element): DOMRect | undefined => {
    const range = document.createRange();
    range.selectNodeContents(el);
    return [...range.getClientRects()].find((r) => r.width > 0.5 && r.height > 0.5);
  };
  const baselineOf = (el: Element): number => {
    const probe = document.createElement("span");
    probe.style.cssText = "display:inline-block;width:0;height:0;vertical-align:baseline";
    el.prepend(probe);
    const y = probe.getBoundingClientRect().bottom;
    probe.remove();
    return y;
  };
  const capHeight = (el: Element): number => {
    const cs = getComputedStyle(el);
    const ctx = document.createElement("canvas").getContext("2d")!;
    ctx.font = `${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
    return ctx.measureText("H").actualBoundingBoxAscent;
  };
  const name = (el: Element): string => {
    const parts: string[] = [];
    for (let e: Element | null = el; e && parts.length < 3 && e !== document.body; e = e.parentElement) {
      parts.unshift(e.tagName.toLowerCase() + (typeof e.className === "string" && e.className.trim() ? "." + e.className.trim().split(/\s+/).slice(0, 2).join(".") : ""));
    }
    return parts.join(" > ");
  };
  for (const parent of document.querySelectorAll<HTMLElement>("body *")) {
    if (parent.closest("svg")) continue;
    const kids = [...parent.children];
    if (kids.length < 2) continue;
    const cs = getComputedStyle(parent);
    if (cs.display === "none" || cs.visibility === "hidden" || cs.opacity === "0") continue;
    kids.forEach((icon, i) => {
      if (!isIcon(icon)) return;
      const ir = icon.getBoundingClientRect();
      if (!visible(ir)) return;
      for (const j of [i + 1, i - 1]) {
        const text = kids[j];
        if (!text || !hasText(text) || getComputedStyle(text).opacity === "0") continue;
        const tr = firstLine(text);
        if (!tr || !visible(tr)) continue;
        const iconCy = ir.top + ir.height / 2;
        const boxCy = tr.top + tr.height / 2;
        if (Math.abs(iconCy - boxCy) > 14) continue; // not on the same row
        // The capital-letter centre needs the text's baseline, which a probe finds only in a block or inline text container: in a
        // flex or grid label the probe becomes an item of its own and reports its own bottom. There the line box is the measure.
        const flow = /^(block|inline|inline-block|list-item|flow-root|table-cell)$/.test(getComputedStyle(text).display);
        const capCy = flow ? baselineOf(text) - capHeight(text) / 2 : boxCy;
        out.push({ box: +(iconCy - boxCy).toFixed(2), cap: +(iconCy - capCy).toFixed(2), sample: (text.textContent ?? "").trim().slice(0, 28), icon: name(icon), text: name(text) });
        return;
      }
    });
  }
  return out;
}
