/**
 * Scroll fade (D160): a body that scrolls inside a card must never end at a hard edge in the middle of a row. This marks the
 * scrolling element with `data-fade` (`top`, `bottom` or `top bottom`) while there is more to see in that direction, and the
 * `.ui-scroll-fade` styles (styles.css) fade that edge out with a mask: the last row is cut softly, never mid-glyph, and at the
 * end of the content nothing is faded. One attribute write per change of state; the listeners are passive and the work is a
 * read of three numbers, done in an animation frame at most once per frame.
 */
export function watchScrollFade(node: HTMLElement): () => void {
  node.classList.add("ui-scroll-fade");
  let frame = 0;
  const update = (): void => {
    frame = 0;
    const top = node.scrollTop > 1;
    const bottom = node.scrollTop + node.clientHeight < node.scrollHeight - 1;
    const next = [top ? "top" : "", bottom ? "bottom" : ""].filter(Boolean).join(" ");
    if (next) { if (node.dataset.fade !== next) node.dataset.fade = next; } else if (node.dataset.fade !== undefined) delete node.dataset.fade;
  };
  const schedule = (): void => { if (!frame) frame = requestAnimationFrame(update); };
  node.addEventListener("scroll", schedule, { passive: true });
  // The box can change size, and so can what is in it (a pane opening under a row).
  const observer = new ResizeObserver(schedule);
  observer.observe(node);
  for (const child of node.children) observer.observe(child);
  const mutations = new MutationObserver(() => { for (const child of node.children) observer.observe(child); schedule(); });
  mutations.observe(node, { childList: true });
  schedule();
  return () => {
    node.removeEventListener("scroll", schedule);
    observer.disconnect();
    mutations.disconnect();
    if (frame) cancelAnimationFrame(frame);
    node.classList.remove("ui-scroll-fade");
    delete node.dataset.fade;
  };
}
