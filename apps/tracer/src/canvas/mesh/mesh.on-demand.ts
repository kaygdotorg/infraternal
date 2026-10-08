/**
 * The Mesh view's code that loads on demand (D188): the node cards, grant arrows and their editing, the automatic
 * layout and the levels of detail. `mesh/index.ts` loads it with `onDemand(() => import("./mesh.on-demand"))` the first
 * time the Mesh view is on screen. The build gate reads this file name: what only this module reaches is "on demand".
 */
export { createGraphView } from "./graph-view";
export type { GraphViewModule } from "./graph-view";
