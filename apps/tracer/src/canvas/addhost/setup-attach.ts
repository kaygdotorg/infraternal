// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Puts a host's remaining setup into its new window's machine pill (D255, #189). The one place that connects the
 * canvas to the pill: the product and the mock canvas both call it when the wizard hands over a host.
 *
 * The pill's code and the stream's client load here, on first use, so a person who never adds a host never pays for
 * them (D188 deferred budget). The window can close before they arrive; then nothing is bound.
 */
import { onDemand } from "../../on-demand";
import type { WinRec } from "../context";
import type { SetupSource } from "./setup-pill.on-demand";

export interface AttachSetup {
  /** What the person calls the host. */
  host: string;
  hostId: string;
  /** The wizard's status glyph: where the pill's flight starts. Read before the wizard closes. */
  status?: Element | undefined;
  /** Where events come from. Absent: the host's own setup stream (`/v1/bootstrap/setup/ws`). */
  source?: SetupSource;
  tickHold?: number;
}

/**
 * Loads the pill's code ahead of the handover. The flight starts from the wizard's glyph, which is gone soon after the
 * host is handed over, so the code must already be there when that happens; opening the wizard is the person's cue.
 */
export function warmSetup(): void {
  void onDemand(() => import("./setup-pill.on-demand")).catch(() => { /* attachSetup tries again when it is needed */ });
}

export function attachSetup(rec: WinRec, options: AttachSetup): Promise<void> {
  let closed = false;
  const before = rec.cleanup;
  rec.cleanup = () => { closed = true; rec.setup?.dispose(); delete rec.setup; before?.(); };
  return onDemand(() => import("./setup-pill.on-demand")).then((module) => {
    if (closed) return;
    rec.setup = module.bindSetupPill({
      card: rec.card,
      host: options.host,
      hostId: options.hostId,
      source: options.source ?? module.createSetupFeed({ windowId: rec.model.id }),
      ...(options.status ? { from: options.status } : {}),
      ...(options.tickHold === undefined ? {} : { tickHold: options.tickHold }),
    });
  }).catch(() => { /* the pill is news, not a dependency: the terminal works without it */ });
}
