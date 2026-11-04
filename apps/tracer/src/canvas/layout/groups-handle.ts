/**
 * The handle on the grouped layout's on-demand module (layout/groups.on-demand.ts, D188). A plain view never calls it.
 *
 * - `loadGroups()` loads the module (the first time, a fetch; afterwards the same instance).
 * - `groupsLoaded()` is the module once it has run, or undefined. A group can only exist once it has, so a caller that found
 *   a group DOM element can use it without waiting.
 * - The canvas starts `loadGroups()` at mount (product.ts), so the first grouped action does not wait for the fetch.
 *
 * The module registers itself here when it evaluates, so a path that imports it statically (the sharing layout, which is
 * already on demand) and a path that loads it through `loadGroups()` see the same functions.
 */
import { onDemand } from "../../on-demand";
import type { groups } from "./groups.on-demand";

/** The functions of the grouped-layout module. */
export type Groups = typeof groups;
/** The module once it has evaluated; `undefined` until then. */
let loaded: Groups | undefined;

/** Called by the module when it evaluates. */
export const registerGroups = (g: Groups): void => { loaded = g; };
/** The grouped-layout module if it has loaded, else `undefined`. Never waits. */
export const groupsLoaded = (): Groups | undefined => loaded;
/** Loads the grouped-layout module (once) and resolves with it. */
export const loadGroups = (): Promise<Groups> => loaded ? Promise.resolve(loaded) : onDemand(() => import("./groups.on-demand")).then(() => loaded!);

/** A column is plain when no group wraps it: its windows stack, and the flat path (what the product always did) is exact. */
export const inGroup = (colEl: HTMLElement): boolean => !!colEl.parentElement?.classList.contains("cl-group");
