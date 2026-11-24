/**
 * The test double's Updates controls (#211, S5; `?mock=1&proto=clusters&updates=1`): the Settings › Machines › Updates window,
 * the Inbox item and the toasts, on a source that holds one scripted state (double.ts). The palette has a "Mockup: updates – …"
 * row for each state, so every message can be reached and photographed. Nothing here is real and nothing is saved. The page
 * does not reload after an install; it counts the reloads it would have done in `window.__updatesReloads` for the specs.
 */
import type { CoreScreen, PaletteEntry } from "../../../core-screen";
import { mountUpdateNotices } from "../../updates/notices";
import { setUpdatesSource } from "../../updates/source";
import { createUpdatesDouble, UPDATE_SCENARIOS, type UpdatesDouble } from "./double";

export interface UpdatesMock {
  readonly double: UpdatesDouble;
  entries(): PaletteEntry[];
  /** Puts the double in a scenario and opens the Updates window on it. */
  run(id: string): void;
  dispose(): void;
}

export function createUpdatesMock(core: CoreScreen): UpdatesMock {
  const double = createUpdatesDouble();
  const w = window as unknown as { __updatesReloads?: number; __updatesDouble?: UpdatesDouble };
  w.__updatesReloads = 0;
  w.__updatesDouble = double;
  setUpdatesSource(double);
  const notices = (announceReady: boolean): (() => void) => mountUpdateNotices(core, double, { announceReady, idle: () => true, reload: () => { w.__updatesReloads = (w.__updatesReloads ?? 0) + 1; } });
  let stopNotices = notices(false);
  return {
    double,
    entries: () => [
      { group: "Mockup", glyph: "◇", label: "Mockup: updates window", hint: "Settings · Machines · Updates", action: "canvas:settings:machines.updates" },
      ...UPDATE_SCENARIOS.map((s): PaletteEntry => ({ group: "Mockup", glyph: "◇", label: `Mockup: updates – ${s.label}`, hint: s.hint, action: `proto:upd:${s.id}` })),
    ],
    run(id) {
      // The notices start again on the new state, so a scenario shows its own toast and Inbox item and not a change from the last one.
      stopNotices();
      double.setScenario(id);
      stopNotices = notices(true);
      window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:machines.updates", source: "keyboard" } }));
    },
    dispose() { stopNotices(); setUpdatesSource(undefined); delete w.__updatesDouble; },
  };
}
