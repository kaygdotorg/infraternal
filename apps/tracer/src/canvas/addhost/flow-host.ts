// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where the add-host wizard draws itself.
 *
 * TASTE asks for a flow to float as its own card over the window it belongs to. The product canvas has no
 * window kind for a flow yet (a window in the document is a terminal, containers, logs, node or settings,
 * D180), so the default host here is an overlay that covers the canvas stage with a dimmed scrim. A canvas
 * that gains a flow window passes its own `FlowHost` and the wizard needs no change: it only ever uses
 * `surface.body`, a positioned box it fills.
 */
export interface FlowSurface {
  /** A positioned element the wizard fills; the wizard centres its card inside it. */
  readonly body: HTMLElement;
  /** Takes the surface away. The wizard has already played its own exit. Safe to call twice. */
  remove(): void;
  /** Tells the wizard the surface went away on its own (the person closed its window). */
  onGone?(callback: () => void): void;
  /** Brings the surface back into view (opening a host window moves the camera away from it). */
  reveal?(): void;
}

/** Decides where the wizard's card is drawn. `open` makes a fresh surface titled `title` (the title is its accessible name). */
export interface FlowHost {
  open(options: { title: string }): FlowSurface;
}

/** An overlay over the whole canvas stage; the scrim blocks the canvas behind the card. */
export function createOverlayFlowHost(stage: HTMLElement): FlowHost {
  return {
    open({ title }) {
      const body = document.createElement("div");
      body.className = "ah-overlay";
      body.setAttribute("aria-label", title);
      stage.append(body);
      return { body, remove: () => body.remove() };
    },
  };
}
