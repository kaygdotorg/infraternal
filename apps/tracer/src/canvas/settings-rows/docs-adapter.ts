// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Which docs heading explains which window (issue #304). Settings windows read their link from the one table (`catalog.ts`); a terminal
 * (the multiplexer page), the add-host dialog (the host join token) and a "No access" card (keys at a glance) point at the pages that
 * explain them. Every link names a page and heading that exist in `docs/user/` (a unit test reads the docs to check it). Moving a link or
 * giving another window one is a line here or in the table; the canvas does not change.
 */
import type { DocsSource } from "../docs/docs-source";
import type { DocsAdapter, DocsLink } from "../docs/docs-adapter";
import { onDemand } from "../../on-demand";
import { SETTINGS_MAP } from "./catalog";
import { spotByWindow } from "./model";

export const TERMINAL: DocsLink = { page: "terminal/multiplexer", heading: "what-it-does-for-you" };
export const NO_ACCESS: DocsLink = { page: "reference/keys", heading: "all-keys-at-a-glance" };
/** The add-host dialog is a window titled "Add hosts". */
export const ADD_HOST: DocsLink = { page: "reference/keys", heading: "host-join-token" };

/** `source` is read when a button is pressed: the docs source is made after the canvas, which needs this adapter first. */
export function createRowsDocs(source: () => DocsSource | undefined): DocsAdapter {
  return {
    for(m) {
      // A Settings window has the button only when the docs have a page for it: a "?" that opens nothing is not offered.
      if (m.kind === "settings") { const link = spotByWindow(SETTINGS_MAP, m.id)?.group.docs; return link ? { link } : undefined; }
      if (m.kind === "terminal") return { link: m.noAccess ? NO_ACCESS : TERMINAL };
      if (m.kind === "flow" && m.host === "Add hosts") return { link: ADD_HOST };
      return undefined;
    },
    open: (link) => source()?.open(link.page, link.heading) ?? Promise.resolve(false),
    // The excerpt is the index's own quick facts; the code that cuts it loads when the first "?" is pressed.
    async preview(link) {
      const found = await source()?.lookup(link.page, link.heading);
      if (!found) return undefined;
      return (await onDemand(() => import("../docs/docs-excerpt"))).excerptOf(found.page, found.heading);
    },
    warm: () => source()?.warm(),
  };
}
