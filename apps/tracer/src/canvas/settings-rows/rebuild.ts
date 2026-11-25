// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Keeps the Settings view in step with what its source can show (#568, D197 M3). The view is built once from the table
 * when the canvas starts. A window whose content arrives later (the Mesh Networks window appears once the server lists
 * subnet routes to its owner) would otherwise never be drawn. When the set of windows changes, the view is rebuilt in
 * place, from the same table and at the same place on the canvas, and the views beside it make room. Nothing happens
 * while the set stays the same, so calling this often is cheap.
 */
import type { Ctx } from "../context";
import type { ComponentDef } from "./catalog";
import { buildSettingsMapView, windowIds } from "./model";

/** Rebuilds the Settings view when `map` draws a different set of windows than the view has now. */
export function rebuildSettingsView(cx: Ctx, map: readonly ComponentDef[]): void {
  const rec = cx.views.get("settings");
  if (!rec) return;
  const have = rec.view.cols.flatMap((c) => c.wins.map((w) => w.id)).sort().join(" ");
  const want = windowIds(map).split(" ").sort().join(" ");
  if (have === want) return;
  rec.view.cols = buildSettingsMapView(map, cx.state.metrics, rec.view).cols;
  cx.view.replace("settings");
  cx.view.settle("settings");
  cx.toolbar.update();
}
