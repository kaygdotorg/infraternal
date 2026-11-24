// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Brings the owner's Updates controls to the product (#211, S5): once the connection is welcomed it asks the server for its update state; if
 * the server answers (this person is the owner), the live source is registered, so Settings › Machines › Updates and the sidebar's version
 * pill show real facts, and the Inbox item "Update ready · <version>" and the reload after an install start. If the server refuses (anyone
 * but the owner) nothing is registered and the window keeps its "Not available yet" line. Loaded when the browser is idle (D188).
 */
import type { CoreScreen } from "../../core-screen";
import { connectUpdates, type UpdatesLink } from "./live";
import { mountUpdateNotices } from "./notices";
import { setUpdatesSource } from "./source";

/** How long the person must have left the keyboard and the screen alone before the page reloads onto a new version. */
const QUIET_MS = 10_000;

/** What the product gives: the connection's action, topic and passkey ways, and a way to wait for the first welcome. */
export interface UpdatesMountInput { link: UpdatesLink; onWelcome(run: () => void): () => void }

/** Mounts the live Updates controls. Returns the remover. */
export function mountProductUpdates(core: CoreScreen, input: UpdatesMountInput): () => void {
  let gone = false;
  let teardown: (() => void) | undefined;
  let asking = false;
  let last = performance.now();
  const touch = (): void => { last = performance.now(); };
  const events = ["keydown", "pointerdown", "paste"] as const;
  for (const name of events) document.addEventListener(name, touch, { capture: true, passive: true });
  const offWelcome = input.onWelcome(() => {
    if (teardown || gone || asking) return;
    asking = true;
    void connectUpdates(input.link).then((source) => {
      asking = false;
      if (gone || teardown) { source.dispose(); return; }
      setUpdatesSource(source);
      const stopNotices = mountUpdateNotices(core, source, { idle: () => performance.now() - last > QUIET_MS, reload: () => window.location.reload() });
      teardown = () => { stopNotices(); source.dispose(); };
    }, () => { asking = false; /* not the owner, or the server has no updater: the window says "Not available yet" */ });
  });
  return () => {
    gone = true;
    offWelcome();
    teardown?.();
    for (const name of events) document.removeEventListener(name, touch, { capture: true });
  };
}
