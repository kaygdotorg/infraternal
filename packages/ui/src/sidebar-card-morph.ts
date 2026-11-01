/**
 * A sidebar card that grows out of its pill and shrinks back into it (D160, #224, #216): the same shared element in both
 * directions, for the person's card and the version panel. It wraps a card made by `createSidebarCard` and changes nothing in
 * it, so the card shell the first screen carries stays as small as it was (D188: this module loads with the mockup, and with the
 * product only once the owner approves the motion).
 *
 * The card is laid out once at its final place. On a pointer open it starts as the pill's box (a translate and a scale from its
 * top-left corner, its content hidden) and one CSS transition takes it to rest; closing runs the same transition backwards from
 * wherever the card is, so a press mid-flight retargets from the current frame (a transition, not keyframes). Only transform and
 * opacity move (about 200 ms, a strong ease-out, see `.ui-sidebar-card[data-morph]` in styles.css), the inline style is cleared
 * at rest so the text is crisp, and the pill's own tooltip and state are untouched. A keyboard open or close has no motion at all;
 * reduced motion keeps only the card's own fade.
 */
import type { SidebarCard } from "./sidebar-card";

/** What opened or closed the card: the keyboard never animates. */
export type CardSource = "pointer" | "keyboard";

export interface MorphingCard extends SidebarCard {
  show(source?: CardSource): void;
  hide(source?: CardSource): void;
}

/** The morph's length (styles.css), and the margin before the inline style is cleared. */
const MORPH_MS = 200;

export function morphSidebarCard(card: SidebarCard, from: HTMLElement): MorphingCard {
  const { root } = card;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let timer = 0;

  /** The card's resting box, read through whatever transform is in flight (the origin is its top-left corner). */
  const restBox = (): { left: number; top: number; width: number; height: number } => {
    const r = root.getBoundingClientRect();
    const m = new DOMMatrixReadOnly(getComputedStyle(root).transform);
    return { left: r.left - m.e, top: r.top - m.f, width: root.offsetWidth, height: root.offsetHeight };
  };
  /** The transform that makes the card's resting box the pill's box. */
  const pillTransform = (): string => {
    const box = restBox();
    const pill = from.getBoundingClientRect();
    return `translate(${pill.left - box.left}px, ${pill.top - box.top}px) scale(${pill.width / box.width}, ${pill.height / box.height})`;
  };
  const clear = (): void => {
    root.style.transition = "";
    root.style.transform = "";
    root.style.opacity = "";
    delete root.dataset.morph;
  };

  return {
    ...card,
    show(source = "pointer") {
      window.clearTimeout(timer);
      if (source === "keyboard" || reduced.matches) {
        clear();
        // No motion: the card's own fade is switched off for the frames it takes to appear.
        if (source === "keyboard") { root.dataset.morph = "none"; timer = window.setTimeout(clear, 260); }
        card.show();
        return;
      }
      const fresh = root.hidden;
      card.show();
      // At rest from the first frame: the shell's own 6 px rise would otherwise be in the box we measure.
      root.dataset.open = "true";
      if (fresh) {
        // From nothing: start as the pill's box, then let the transition take the card to rest.
        root.dataset.morph = "from";
        root.style.transition = "none";
        root.style.transform = "";
        root.style.transform = pillTransform();
        root.style.opacity = "0";
        void root.offsetWidth;
        root.style.transition = "";
      }
      // Already on its way out (or just placed): retarget from wherever it is.
      root.dataset.morph = "in";
      root.style.transform = "";
      root.style.opacity = "";
      timer = window.setTimeout(clear, MORPH_MS + 40);
    },
    hide(source = "pointer") {
      window.clearTimeout(timer);
      if (source === "keyboard" || reduced.matches || root.hidden) {
        if (source === "keyboard") {
          root.dataset.morph = "none";
          timer = window.setTimeout(clear, 260);
          card.hide();
          // Gone at once, not after the shell's leave time (the shell's timer still reports the card hidden).
          root.hidden = true;
          return;
        }
        card.hide();
        return;
      }
      root.dataset.morph = "out";
      root.style.transform = pillTransform();
      root.style.opacity = "0";
      card.hide();
      // The shell removes the card from the layout after its own leave time; the inline style goes after that.
      timer = window.setTimeout(clear, MORPH_MS + 60);
    },
  };
}
