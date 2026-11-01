/**
 * The dev-only data toggle of the mockups (the break-ui regression fixture): "Demo data / Worst case / Empty / One", fixed at the
 * bottom centre of the screen, small and plain, outside the design under test. Each mockup (the person's card, the version panel)
 * owns a data set per position and swaps it at its own test double, never in its markup; the toggle only says which one.
 *
 *   demo    the friendly data every design is drawn with
 *   worst   realistic worst cases: the longest values the schemas allow, unbreakable strings, huge counts, many items
 *   empty   nothing set: no name, no hosts, no items, nothing to show
 *   one     exactly one of everything, and every count at one
 *
 * The position is in the address (`?data=worst`), so a reload keeps it. Switching is instant: the content does not animate.
 * Mockup only: the production bundle leaves this file out with the rest of `canvas/mock`.
 */
import { createCapsuleTabs, type CapsuleTabs } from "../../../../../packages/ui/src/capsule-tabs";
import { el } from "../dom";

import { DATA_IDS, type DataId } from "./data-ids";
export { DATA_IDS, type DataId };
const LABELS: Record<DataId, string> = { demo: "Demo data", worst: "Worst case", empty: "Empty", one: "One" };

export interface DataMode {
  id(): DataId;
  set(id: DataId): void;
  /** Runs when the position changes (and once now, so a mockup starts in the position the address names). */
  subscribe(run: (id: DataId) => void): () => void;
}

export function createDataMode(initial: DataId): DataMode {
  let current = initial;
  const listeners = new Set<(id: DataId) => void>();
  return {
    id: () => current,
    set(id) {
      if (id === current) return;
      current = id;
      try {
        const url = new URL(location.href);
        if (id === "demo") url.searchParams.delete("data"); else url.searchParams.set("data", id);
        history.replaceState(history.state, "", url);
      } catch { /* the address is only a convenience */ }
      for (const run of listeners) run(id);
    },
    subscribe(run) { listeners.add(run); run(current); return () => { listeners.delete(run); }; },
  };
}

/** Puts the toggle on the screen; returns what removes it. */
export function mountDataToggle(stage: HTMLElement, mode: DataMode): () => void {
  const root = el("div", "cl-data-toggle");
  root.setAttribute("data-mockup-chrome", "");
  const tabs: CapsuleTabs = createCapsuleTabs(DATA_IDS.map((id) => ({ id, label: LABELS[id] })), mode.id(), (id) => mode.set(id as DataId), "Mockup data");
  root.append(tabs.root);
  stage.append(root);
  const stop = mode.subscribe((id) => { if (tabs.selected !== id) tabs.select(id, true); });
  return () => { stop(); tabs.dispose(); root.remove(); };
}
