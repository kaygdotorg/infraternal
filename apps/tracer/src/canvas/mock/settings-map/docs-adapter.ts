// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Which docs heading explains which window, for the mockup (`?settings=sections`, issue #304). Settings windows read their link
 * from the one table (`catalog.ts`); the other windows are examples of where the same "?" would go: a terminal (the
 * multiplexer page), the add-host dialog (the host join token) and a "No access" card (keys at a glance). Moving a link or
 * giving another window one is a line here or in the table; the canvas does not change.
 */
import type { DocsSource } from "../../docs/docs-source";
import type { DocsAdapter, DocsLink } from "../../docs/docs-adapter";
import { excerptOf } from "../../docs/docs-excerpt";
import { SETTINGS_MAP } from "./catalog";
import { STAND_IN } from "./docs-standin";
import { spotByWindow } from "./model";

const TERMINAL: DocsLink = { page: "terminal/multiplexer", heading: "what-it-does-for-you" };
const NO_ACCESS: DocsLink = { page: "reference/keys", heading: "all-keys-at-a-glance" };
/** The add-host dialog is a window titled "Add hosts". */
const ADD_HOST: DocsLink = { page: "reference/keys", heading: "host-join-token" };

/** `source` is read when a button is pressed: the docs source is made after the canvas, which needs this adapter first. */
export function createMockDocs(source: () => DocsSource | undefined): DocsAdapter {
  return {
    for(m) {
      // A Settings window always has the button; one whose page is not written yet says so when pressed.
      if (m.kind === "settings") { const link = spotByWindow(SETTINGS_MAP, m.id)?.group.docs; return link ? { link } : {}; }
      if (m.kind === "terminal") return { link: m.noAccess ? NO_ACCESS : TERMINAL };
      if (m.kind === "flow" && m.host === "Add hosts") return { link: ADD_HOST };
      return undefined;
    },
    open: (link) => source()?.open(link.page, link.heading) ?? Promise.resolve(false),
    // The excerpt is the index's own quick facts; where the index has none yet, the stand-in in that same shape.
    async preview(link) {
      const found = await source()?.lookup(link.page, link.heading);
      if (!found) return undefined;
      const standIn = link.heading ? STAND_IN[`${link.page}#${link.heading}`] : undefined;
      const heading = found.heading && !found.heading.facts && standIn ? { ...found.heading, ...standIn } : found.heading;
      return excerptOf(found.page, heading);
    },
    warm: () => source()?.warm(),
  };
}
