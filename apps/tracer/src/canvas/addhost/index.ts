// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The add-host flow as the canvas mounts it (#87, D183).
 *
 * `createAddHost` returns the `open` function the canvas passes as `Adapters.addHost`, and registers the
 * palette row "Add hosts". Everything else is injected: the `ProvisioningService` (real or test double), the
 * `AddHostSink` that learns about hosts as they finish enrolling, and optionally a `FlowHost` that decides
 * where the card is drawn (default: an overlay over the canvas stage).
 *
 * The wizard itself is on-demand code (`add-host.on-demand.ts`): this file, the service seam and the palette row
 * are all that loads with the canvas. One wizard at a time: opening while it is open focuses it. A host that finished stays enrolled when the
 * wizard closes; closing mid-install cancels what is still running (the server rolls it back).
 */
import type { CoreScreen } from "../../core-screen";
import { createOverlayFlowHost, type FlowHost } from "./flow-host";
import type { AddHostSink, ProvisioningService } from "./service";
import { onDemand } from "../../on-demand";
import type { Wizard } from "./wizard";

/** What `createAddHost` needs; `host` is optional and defaults to an overlay over the stage. */
export interface AddHostOptions {
  /** The provisioning service, or a loader for it: the real one loads with the wizard, not with the canvas (D188). */
  service: ProvisioningService | (() => Promise<ProvisioningService>);
  sink: AddHostSink;
  host?: FlowHost;
}

/** The mounted add-host flow. */
export interface AddHost {
  /** Opens the wizard (or focuses the open one). Pass this as `Adapters.addHost`. */
  open(): void;
  /** Removes the palette row and the action listener, and closes the wizard if one is open. */
  dispose(): void;
}

/**
 * Mounts the add-host flow: the palette row "Add hosts" and the `canvas:addhost` action both call `open`. The wizard's code
 * loads the first time it is needed; if that fails the person gets a toast and the next tap tries again. While a load is
 * running further taps are ignored. Call `dispose` when the canvas goes away.
 */
export function createAddHost(core: CoreScreen, options: AddHostOptions): AddHost {
  const host = options.host ?? createOverlayFlowHost(core.stage);
  let wizard: Wizard | undefined;
  let loading = false;
  const open = (): void => {
    // A wizard that is playing its exit counts as gone: reopening starts a fresh one at once.
    if (wizard && !wizard.isClosing) { wizard.focus(); return; }
    if (loading) return;
    loading = true;
    // The wizard's code loads the first time it is opened; a failed load says so and a second tap tries again.
    const service = typeof options.service === "function" ? options.service() : Promise.resolve(options.service);
    void Promise.all([onDemand(() => import("./add-host.on-demand")), service]).then(([{ Wizard: Open }, service]) => {
      const fresh: Wizard = new Open({ service, sink: options.sink, host, toast: core.toast, onClosed: () => { if (wizard === fresh) wizard = undefined; } });
      wizard = fresh;
      fresh.focus();
    }, () => core.toast.show({ message: "The add-host flow couldn't load. Check your connection and try again." }))
      .finally(() => { loading = false; });
  };
  const removeProvider = core.addPaletteProvider(() => [{ group: "Actions", glyph: "+", label: "Add hosts", hint: "ssh · install · server", action: "canvas:addhost" }]);
  const onAction = (event: Event): void => {
    const detail = (event as CustomEvent<{ action?: string }>).detail;
    if (detail?.action === "canvas:addhost") open();
  };
  window.addEventListener("tracer:canvas-action", onAction);
  return {
    open,
    dispose() {
      window.removeEventListener("tracer:canvas-action", onAction);
      removeProvider();
      wizard?.dispose();
      wizard = undefined;
    },
  };
}
