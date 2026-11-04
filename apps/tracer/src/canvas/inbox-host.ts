// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The sidebar inbox (D234) for the canvas: one card per screen, shared by every source of pending items.
 *
 * The card, its registry and its motion load with the canvas, not with the first screen (D188): which item waits is
 * learned after the first paint anyway. The core screen only provides where it attaches and the toggle's dot
 * (`core.inboxMount`). A source publishes with `inboxFor(core).set(sourceId, items)`; the authority lock
 * (addhost/authority-unlock.ts) is the first, and later sources need no UI of their own.
 */
import type { CoreScreen } from "../core-screen";
import { createInbox, type InboxController } from "../../../../packages/ui/src/inbox";

/** The inbox made for each screen, so a screen has exactly one. */
const made = new WeakMap<CoreScreen, InboxController>();

/** The screen's inbox, made on first use. */
export function inboxFor(core: CoreScreen): InboxController {
  let inbox = made.get(core);
  if (!inbox) { inbox = createInbox(core.inboxMount); made.set(core, inbox); }
  return inbox;
}

/** The screen's inbox if a source ever published, so withdrawing never builds a card for nothing. */
export const existingInbox = (core: CoreScreen): InboxController | undefined => made.get(core);
