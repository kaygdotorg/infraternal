/**
 * The details popover's handle: what the rest of the canvas holds. The module behind it (`details.on-demand.ts`) loads
 * the first time a window's pill is pressed, so it costs no transfer until then (D188). A canvas whose instance cannot
 * answer (no `DetailsSource`) simply has no handle, and the pill opens nothing.
 */
import { onDemand } from "../../on-demand";
import type { Ctx } from "../context";
import type { DetailsModule } from "./details.on-demand";
import type { DetailsSourceLoader } from "./details-source";

/** Keep details actions lazy; a model refresh never loads or opens a closed panel. */
export function createDetailsHandle(cx: Ctx, loadSource: DetailsSourceLoader): DetailsModule {
  let real: DetailsModule | undefined;
  let loading: Promise<DetailsModule> | undefined;
  // Both roots are action-only; start them together so the first open does not pay two download waits.
  const load = (): Promise<DetailsModule> => loading ??= Promise.all([
    onDemand(() => import("./details.on-demand")), loadSource(),
  ]).then(([m, source]) => (real = m.createDetails(cx, source)));
  return {
    toggle: (rec, how) => { void load().then((d) => d.toggle(rec, how)); },
    close: (instant) => real?.close(instant),
    refresh: (windowId) => real?.refresh(windowId),
    isOpen: () => real?.isOpen() ?? false,
    dispose: () => real?.dispose(),
  };
}
