// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The entry of the add-host wizard's on-demand code (D188): the wizard, its pages and its pure rules load only when
 * the person opens the flow, from `index.ts` through `onDemand`. The transfer gate counts this file's chunk apart
 * from the first screen and from the canvas.
 */
export { Wizard } from "./wizard";
