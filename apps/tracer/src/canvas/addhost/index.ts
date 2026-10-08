// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The add-host flow as the canvas mounts it (#87, D183).
 *
 * `createAddHost` returns the `open` function the canvas passes as `Adapters.addHost`, and registers the
 * palette row "Add hosts". Everything else is injected: the `ProvisioningService` (real or test double), the
 * `AddHostSink` that learns about hosts as they finish enrolling, and optionally a `FlowHost` that decides
 * where the card is drawn (default: an overlay over the canvas stage).
 *
 * One wizard at a time: opening while it is open focuses it. A host that finished stays enrolled when the
 * wizard closes; closing mid-install cancels what is still running (the server rolls it back).
 */
import type { CoreScreen } from "../../core-screen";
import { createOverlayFlowHost, type FlowHost } from "./flow-host";
import type { AddHostSink, ProvisioningService } from "./service";
import { Wizard } from "./wizard";

export interface AddHostOptions {
  service: ProvisioningService;
  sink: AddHostSink;
  host?: FlowHost;
}

export interface AddHost {
  /** Opens the wizard (or focuses the open one). Pass this as `Adapters.addHost`. */
  open(): void;
  dispose(): void;
}

export function createAddHost(core: CoreScreen, options: AddHostOptions): AddHost {
  const host = options.host ?? createOverlayFlowHost(core.stage);
  let wizard: Wizard | undefined;
  const open = (): void => {
    // A wizard that is playing its exit counts as gone: reopening starts a fresh one at once.
    if (wizard && !wizard.isClosing) { wizard.focus(); return; }
    const fresh: Wizard = new Wizard({ service: options.service, sink: options.sink, host, toast: core.toast, onClosed: () => { if (wizard === fresh) wizard = undefined; } });
    wizard = fresh;
    fresh.focus();
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
