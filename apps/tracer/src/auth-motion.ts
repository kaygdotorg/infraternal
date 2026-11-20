/**
 * The motion between two auth cards (sign-in to recovery and back).
 *
 * The outgoing card leaves as a frozen copy in its own layer while the new card slides in from the
 * side of travel, and the new card's height eases from the old card's height. Everything starts
 * from the *current* visual state, not from a rest state: the ghost copies the old card's computed
 * opacity, transform and height, and the new card replaces the CSS entrance animation. So a click
 * while the page's own entrance (or an earlier swap) is still running composes with it, and a
 * second swap mid-way retargets instead of restarting or being skipped.
 *
 * Reduced motion, and a first mount with no card to leave, render with no swap.
 */
import { EASE_OUT } from "../../../packages/ui/src/motion";

/** How far (px) a card travels sideways as it enters or leaves. */
const SLIDE = 28;

/** Runs `render` (which must replace the host's content) and animates from the card it replaced. */
export function swapCard(host: HTMLElement, direction: 1 | -1 | 0, render: () => void): void {
  const old = host.querySelector<HTMLElement>(":scope > .auth-screen:not(.auth-leaving) > .auth-card");
  if (!old || direction === 0 || matchMedia("(prefers-reduced-motion: reduce)").matches) { render(); return; }

  const now = getComputedStyle(old);
  const from = { opacity: now.opacity, transform: now.transform === "none" ? "translateX(0)" : now.transform, height: old.getBoundingClientRect().height };
  const ghost = old.cloneNode(true) as HTMLElement;
  ghost.removeAttribute("id");
  ghost.querySelectorAll("[id]").forEach((element) => element.removeAttribute("id"));
  ghost.inert = true;
  ghost.setAttribute("aria-hidden", "true");
  Object.assign(ghost.style, { animation: "none", opacity: from.opacity, transform: from.transform, height: `${from.height}px`, overflow: "hidden" });
  const layer = document.createElement("section");
  layer.className = "auth-screen auth-leaving";
  layer.style.pointerEvents = "none";
  layer.append(ghost);

  render();
  host.append(layer);
  const next = host.querySelector<HTMLElement>(":scope > .auth-screen:not(.auth-leaving) > .auth-card");
  if (!next) { layer.remove(); return; }
  next.style.animation = "none";
  next.animate([{ opacity: 0, transform: `translateX(${direction * SLIDE}px)` }, { opacity: 1, transform: "translateX(0)" }], { duration: 260, easing: EASE_OUT });
  const height = next.getBoundingClientRect().height;
  if (Math.abs(height - from.height) > 1) {
    next.animate([{ height: `${from.height}px`, overflow: "hidden" }, { height: `${height}px`, overflow: "hidden" }], { duration: 260, easing: EASE_OUT });
  }
  const out = ghost.animate([{ opacity: from.opacity, transform: from.transform }, { opacity: 0, transform: `translateX(${-direction * SLIDE}px)` }], { duration: 200, easing: "ease-out", fill: "forwards" });
  out.onfinish = () => layer.remove();
}
