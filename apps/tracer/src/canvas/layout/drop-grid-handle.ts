/**
 * The grid's on-demand module (D188): where a dropped or a closed window of a group lands (layout/drop-grid.on-demand.ts).
 * It is loaded when a view first holds a group (the warm call), so a grouped close finds it there. A close that arrives
 * before it loaded applies the change when it has.
 */
import { onDemand } from "../../on-demand";

export type DropGrid = typeof import("./drop-grid.on-demand");
let loaded: DropGrid | undefined;

export const loadDropGrid = (): Promise<DropGrid> => loaded ? Promise.resolve(loaded) : onDemand(() => import("./drop-grid.on-demand")).then((m) => (loaded = m));
/** The module if it has loaded, else undefined (the caller then waits for `loadDropGrid`). */
export const droppedGrid = (): DropGrid | undefined => loaded;
/** Starts the load without waiting for it (a view that now holds a group). */
export const warmDropGrid = (): void => { void loadDropGrid().catch(() => undefined); };
