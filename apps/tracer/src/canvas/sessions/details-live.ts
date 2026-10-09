/** Keeps live connection delay subscribed while loading the existing details reader only when its popover opens [188]. */
import type { DetailsSource } from "../windows/details-source";
import { onDemand } from "../../on-demand";
import type { LiveDetailsOptions } from "./details-live.on-demand";

export function createLiveDetails(options: LiveDetailsOptions): { source: DetailsSource; dispose(): void } {
  let delay: number | undefined;
  let source: DetailsSource | undefined;
  let preparing: Promise<void> | undefined;
  const off = options.connection.onRoundTrip((ms) => { delay = ms; });
  return {
    source: {
      prepare: () => preparing ??= onDemand(() => import("./details-live.on-demand")).then((module) => { source = module.createLiveDetailsSource(options, () => delay); }),
      facts: (rec) => source?.facts(rec),
    },
    dispose: off,
  };
}
