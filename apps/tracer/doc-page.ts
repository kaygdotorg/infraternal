// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The script of a standalone docs page (`/docs/doc.js`, built by docs-build.ts and loaded deferred). It starts what a page does
 * once it is on screen (src/canvas/docs/doc-enhance.ts: the section being read, copying a code block) and the shared focus
 * ring, so a ring appears for real Tab navigation only. It is a file of its own: it never counts in the app's JavaScript budget.
 */
import { installFocusRing } from "../../packages/ui/src/focus-ring";
import { enhanceDoc } from "./src/canvas/docs/doc-enhance";

installFocusRing();
/** The page's main content, or `null` on a page without one. */
const page = document.querySelector<HTMLElement>("main");
if (page) enhanceDoc(page, null);
