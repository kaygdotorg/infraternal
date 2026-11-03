/**
 * The hook of the view list (the list itself is viewlist.on-demand.ts, D188): the top pill, the toolbar and the shortcuts call
 * `toggle`, `close` and `isOpen` from the first screen, and the module that draws the list loads at idle, or on the first
 * tap if that comes first (the list then opens as soon as the module has arrived).
 */
import type { Ctx } from "../context";
import { onDemand, whenIdle } from "../../on-demand";

export interface ViewList {
  toggle(): void;
  close(instant?: boolean): void;
  isOpen(): boolean;
}

/** The shortcut that flies to the view at `index` (Command or Ctrl with a digit). */
export const viewKeys = (index: number) => ({ mac: `⌘${index + 1}`, other: `Ctrl+${index + 1}` });

export function createViewList(cx: Ctx): ViewList {
  let list: ViewList | undefined;
  const load = (): Promise<ViewList> => (loading ??= onDemand(() => import("./viewlist.on-demand")).then((m) => (list = m.createViewListPanel(cx))));
  let loading: Promise<ViewList> | undefined;
  whenIdle(() => { if (!cx.signal.aborted) void load(); });
  return {
    toggle: () => { if (list) list.toggle(); else void load().then((l) => { if (!cx.signal.aborted) l.toggle(); }); },
    close: (instant) => list?.close(instant),
    isOpen: () => list?.isOpen() ?? false,
  };
}
