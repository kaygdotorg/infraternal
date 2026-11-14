// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The script of a standalone docs page (`/docs/doc.js`, built by docs-build.ts and loaded deferred). It starts what a page does
 * once it is on screen (src/canvas/docs/doc-enhance.ts: the section being read, copying a code block) and the shared focus
 * ring, so a ring appears for real Tab navigation only. It also wires ⌘K and the search button to the docs search, whose code (site-search.ts) and index load only when it is first opened. It is a file of its own: it never counts in the app's JavaScript budget.
 */
import { installFocusRing } from "../../packages/ui/src/focus-ring";
import { enhanceDoc } from "./src/canvas/docs/doc-enhance";

installFocusRing();
/** The search button of the top bar, on every standalone page that has one. */
const searchButton = document.querySelector<HTMLButtonElement>("[data-search]");
if (searchButton) {
  const keycap = searchButton.querySelector("kbd");
  if (keycap && !/Mac|iPhone|iPad/.test(navigator.platform)) keycap.textContent = "Ctrl K";
  /** The search (`doc-search.js`, built from site-search.ts), loaded the first time it is wanted: reading a page never pays for it. The address is a variable so the bundler leaves the import alone. */
  let search: Promise<ReturnType<typeof import("./site-search").installSiteSearch>> | undefined;
  const searchScript = "/docs/doc-search.js";
  const load = () => (search ??= (import(searchScript) as Promise<typeof import("./site-search")>).then((module) => module.installSiteSearch(searchButton)));
  searchButton.addEventListener("click", () => { void load().then((loaded) => loaded.open()); });
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === "k") {
      event.preventDefault();
      void load().then((loaded) => loaded.toggle());
    }
  });
}
/** The page's main content, or `null` on a page without one. */
const page = document.querySelector<HTMLElement>("main");
if (page) enhanceDoc(page, null);
