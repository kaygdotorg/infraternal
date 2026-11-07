// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The glass bed: a blurred layer under a small floating card, so that nothing behind the card can be read through it.
 *
 * Why it exists. A card's `backdrop-filter` blurs only what is inside the card's own box, and near the box edge the
 * blur fades out, letting the unblurred page show through. On a card about as tall as the blur is wide (a confirmation
 * is ~118 px tall) that edge zone covers most of the card, and raising the blur makes it worse: measured in a real
 * browser over a dense `ls -la`, `blur(32px)` on the card left the text *more* legible than `blur(8px)`. Tuning the
 * card's blur or tint cannot fix this; the blur has to start well outside the card.
 *
 * What it does. `attachGlassBed(card)` puts one `fixed` element under the card. It is as large as the card plus a margin
 * on every side (twice the blur), carries the strong blur, and is clipped to the card's own rounded shape, so the blur
 * sees the page far beyond the card's edge and nothing fades inside it. The card keeps its own translucent material on
 * top, so the glass still shows colour and shape. The bed is not a tint and draws no border or shadow.
 *
 * Usage. The card must be `position: fixed` with its `left` and `top` written inline in pixels. Call `sync()` after each
 * placement, `setOpen(true)` when the card's open state starts (the bed fades and scales with the card), and `dispose()`
 * when the card is removed. It does nothing when the card has no backdrop blur (the Solid level, reduced transparency).
 */

/** The blur of the bed in CSS pixels: about 1.5 terminal lines, so dense text reads as colour and shape, never as text (TASTE). */
export const GLASS_BED_BLUR = 32;

/** Handle for one bed; see the module note. */
export interface GlassBed {
  /** Follow the card's current box, radius and transform origin. Call after every placement. */
  sync(): void;
  /** Start or end the bed's open state, in step with the card's own `data-open`. */
  setOpen(open: boolean): void;
  /** Remove the bed. */
  dispose(): void;
}

/** Put a glass bed under `card` (see the module note). The bed is a sibling placed just before the card. */
export function attachGlassBed(card: HTMLElement): GlassBed {
  const bed = document.createElement("div");
  bed.className = "ui-glass-bed";
  bed.setAttribute("aria-hidden", "true");
  bed.dataset.open = "false";
  bed.hidden = true;
  card.before(bed);
  return {
    sync(): void {
      const style = getComputedStyle(card);
      // No backdrop blur on the card (Solid level, reduced transparency): it is opaque or flat, so there is nothing to hide.
      if (style.backdropFilter === "none" || style.backdropFilter === "") { bed.hidden = true; return; }
      const reach = GLASS_BED_BLUR * 2;
      const left = parseFloat(card.style.left), top = parseFloat(card.style.top);
      if (!Number.isFinite(left) || !Number.isFinite(top)) return;
      const [originX = 0, originY = 0] = style.transformOrigin.split(" ").map(parseFloat);
      bed.hidden = false;
      bed.style.setProperty("--ui-glass-bed-blur", `${GLASS_BED_BLUR}px`);
      bed.style.setProperty("--ui-glass-bed-reach", `${reach}px`);
      bed.style.setProperty("--ui-glass-bed-radius", style.borderTopLeftRadius);
      bed.style.left = `${left - reach}px`;
      bed.style.top = `${top - reach}px`;
      bed.style.width = `${card.offsetWidth + reach * 2}px`;
      bed.style.height = `${card.offsetHeight + reach * 2}px`;
      bed.style.transformOrigin = `${originX + reach}px ${originY + reach}px`;
    },
    setOpen(open: boolean): void { bed.dataset.open = open ? "true" : "false"; },
    dispose(): void { bed.remove(); },
  };
}
