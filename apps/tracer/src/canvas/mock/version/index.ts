/**
 * The test double's version area (#216, `?mock=1&proto=clusters&version=1`): the product's pill and panel, mounted on a
 * source that holds one scripted state (double.ts). The palette has a "Mockup: version – …" row for each state, so every
 * message can be reached and photographed; nothing here is real and nothing is saved.
 */
import type { CoreScreen, PaletteEntry } from "../../../core-screen";
import { onDemand } from "../../../on-demand";
import { createVersionDouble, SCENARIOS, type VersionDouble } from "./double";
import type { VersionArea } from "../../version/mount.on-demand";

export interface VersionMock {
  readonly double: VersionDouble;
  entries(): PaletteEntry[];
  run(action: string): void;
  dispose(): void;
}

export function createVersionMock(core: CoreScreen): VersionMock {
  const double = createVersionDouble();
  let area: VersionArea | undefined;
  let gone = false;
  const mounted = onDemand(() => import("../../version/mount.on-demand")).then(async (m) => {
    const made = await m.mountVersionArea(core, double);
    if (gone) made?.dispose(); else area = made;
  });
  return {
    double,
    entries: () => SCENARIOS.map((s): PaletteEntry => ({ group: "Mockup", glyph: "◇", label: `Mockup: version – ${s.label}`, hint: s.hint, action: `proto:ver:${s.id}` })),
    run(id) {
      double.setScenario(id);
      void mounted.then(() => area?.panel.open(true, "keyboard"));
    },
    dispose() { gone = true; area?.dispose(); },
  };
}
