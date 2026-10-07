/** Shared accessible tab selection with one interruptible, stretching capsule (D120). */
import { Spring } from "./spring";

export interface StretchingCapsule {
  select(id: string, instant?: boolean): void;
  dispose(): void;
}

type PendingMeasure = { animate: boolean; instant: boolean };
const FAST = { visualDuration: 0.16, bounce: 0.12 } as const;
const SOFT = { visualDuration: 0.25, bounce: 0.12 } as const;

/** Installs keyboard semantics and direction-aware two-edge motion on an existing tablist. */
export function installStretchingCapsule(
  tablist: HTMLElement,
  initialId: string,
  onSelect: (id: string, instant: boolean) => void,
): StretchingCapsule {
  const indicator = tablist.querySelector<HTMLElement>(".segmented-capsule");
  if (!indicator) throw new Error("Segmented tablist is missing its shared capsule");
  tablist.classList.add("ui-overlay-surface", "ui-pill");
  let selectedId = initialId;
  let leftSpring: Spring | undefined;
  let rightSpring: Spring | undefined;
  let visualLeft = 0;
  let visualRight = 0;
  let frame = 0;
  let disposed = false;
  let pending: PendingMeasure = { animate: false, instant: true };

  const tabs = (): HTMLButtonElement[] => [...tablist.querySelectorAll<HTMLButtonElement>("[role='tab']")];
  const selectedTab = (): HTMLButtonElement | undefined => tabs().find((tab) => tab.dataset.tab === selectedId && !tab.disabled);
  const draw = (): void => {
    indicator.style.transform = `translate3d(${visualLeft}px, 0, 0)`;
    indicator.style.width = `${Math.max(0, visualRight - visualLeft)}px`;
  };
  const setRovingTab = (): void => {
    for (const tab of tabs()) {
      const selected = tab.dataset.tab === selectedId && !tab.disabled;
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
    }
  };

  function measure(animate: boolean, instant: boolean): void {
    frame = 0;
    if (disposed) return;
    const active = selectedTab();
    if (!active) return;
    const rootRect = tablist.getBoundingClientRect();
    const target = active.getBoundingClientRect();
    const nextLeft = target.left - rootRect.left + tablist.scrollLeft;
    const nextRight = target.right - rootRect.left + tablist.scrollLeft;
    if (!leftSpring || !rightSpring) {
      visualLeft = nextLeft;
      visualRight = nextRight;
      leftSpring = new Spring(visualLeft, (value) => { visualLeft = value; draw(); }, SOFT);
      rightSpring = new Spring(visualRight, (value) => { visualRight = value; draw(); }, SOFT);
      draw();
      return;
    }
    if (!animate || instant) {
      leftSpring.configure(SOFT);
      rightSpring.configure(SOFT);
      leftSpring.set(nextLeft, true);
      rightSpring.set(nextRight, true);
      return;
    }
    const previousCenter = (visualLeft + visualRight) / 2;
    const nextCenter = (nextLeft + nextRight) / 2;
    const movingRight = nextCenter >= previousCenter;
    const leading = movingRight ? rightSpring : leftSpring;
    const trailing = movingRight ? leftSpring : rightSpring;
    leading.configure(FAST);
    trailing.configure(SOFT);
    leading.set(movingRight ? nextRight : nextLeft);
    trailing.set(movingRight ? nextLeft : nextRight);
  }

  function scheduleMeasure(animate: boolean, instant: boolean): void {
    pending = { animate, instant };
    if (frame) return;
    frame = requestAnimationFrame(() => measure(pending.animate, pending.instant));
  }

  function select(id: string, instant = false, notify = true): void {
    const next = tabs().find((tab) => tab.dataset.tab === id && !tab.disabled);
    if (!next) return;
    const changed = selectedId !== id;
    selectedId = id;
    setRovingTab();
    scheduleMeasure(changed, instant);
    if (changed && notify) onSelect(id, instant);
  }

  const click = (event: MouseEvent): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const tab = target.closest<HTMLButtonElement>("[role='tab']");
    if (tab && tablist.contains(tab) && !tab.disabled && tab.dataset.tab) select(tab.dataset.tab, event.detail === 0);
  };
  const keydown = (event: KeyboardEvent): void => {
    const current = (event.target as HTMLElement | null)?.closest<HTMLButtonElement>("[role='tab']");
    if (!current || !tablist.contains(current)) return;
    const enabled = tabs().filter((tab) => !tab.disabled);
    if (!enabled.length) return;
    const index = enabled.indexOf(current);
    const rtl = getComputedStyle(tablist).direction === "rtl";
    let next: HTMLButtonElement | undefined;
    if (event.key === "Home") next = enabled[0];
    else if (event.key === "End") next = enabled.at(-1);
    else if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      const direction = (event.key === "ArrowRight") !== rtl ? 1 : -1;
      next = enabled[(index + direction + enabled.length) % enabled.length];
    }
    if (!next?.dataset.tab) return;
    event.preventDefault();
    select(next.dataset.tab, true);
    next.focus({ preventScroll: true });
  };
  const observer = new ResizeObserver(() => scheduleMeasure(false, true));
  observer.observe(tablist);
  for (const tab of tabs()) observer.observe(tab);
  const contentObserver = new MutationObserver(() => {
    setRovingTab();
    observer.disconnect();
    observer.observe(tablist);
    for (const tab of tabs()) observer.observe(tab);
    scheduleMeasure(false, true);
  });
  contentObserver.observe(tablist, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["disabled"] });
  const fonts = document.fonts;
  void fonts?.ready.then(() => scheduleMeasure(false, true));
  fonts?.addEventListener("loadingdone", scheduleMeasureAfterFont);

  function scheduleMeasureAfterFont(): void { scheduleMeasure(false, true); }

  tablist.addEventListener("click", click);
  tablist.addEventListener("keydown", keydown);
  setRovingTab();
  measure(false, true);

  return {
    select(id, instant = false) { select(id, instant); },
    dispose() {
      disposed = true;
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      observer.disconnect();
      contentObserver.disconnect();
      fonts?.removeEventListener("loadingdone", scheduleMeasureAfterFont);
      tablist.removeEventListener("click", click);
      tablist.removeEventListener("keydown", keydown);
      leftSpring?.set(visualLeft, true);
      rightSpring?.set(visualRight, true);
    },
  };
}
