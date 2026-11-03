/**
 * The window lists a view's hover card and the palette share: the rows of one view's windows (the palette opened from the card's
 * "All N windows", #121) and the five used most recently (see recency.ts).
 *
 * A module of its own, imported only by on-demand code (`view-pointer.on-demand.ts`, `palette-rows.on-demand.ts`): had either of
 * those imported the other, the bundler would turn the dynamic import that fetches it into a static link and move nothing (D188, #322).
 */
import type { PaletteEntry } from "../../core-screen";
import type { Ctx, ViewRec, WinRec } from "../context";
import { recentRows } from "../recency";
import { windowLabel } from "../windows/label";
import { ICON, viewIcon } from "../views/icons";

/** The rows of one view's windows, for the palette opened from the view's hover card ("All N windows", #121). */
export function viewWindowEntries(cx: Ctx, c: ViewRec): PaletteEntry[] {
  return [...c.wins.values()].map((rec) => {
    const m = rec.model;
    const [name, detail] = windowLabel(m, cx.adapters.inventory);
    return { group: c.view.name, glyph: "›_", icon: m.kind === "terminal" ? ICON.terminal : viewIcon(c.view.id), label: name, hint: detail, action: `canvas:win:${m.id}` };
  });
}

/** The windows a view's hover card lists: the five used most recently, filled in window order (see recency.ts). */
export function viewRecentWindows(cx: Ctx, c: ViewRec, n: number): WinRec[] {
  return recentRows(cx.state.recent.get(c.view.id), c.wins, n);
}
