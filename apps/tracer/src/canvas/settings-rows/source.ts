// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The Settings rows as a `SettingsSource` (issue #304): the outline the sidebar, the breadcrumb and ⌘K read, and the render of one
 * window. The product and the mockup's test double both build it; they differ only in what they back (`backing`) and fill in (`data`).
 *
 * The window bodies (`body.on-demand.ts`, with the setting rows and the panels) load the first time a Settings window is drawn, never on the
 * first screen (D188); the outline is small and static because the sidebar needs it at once.
 */
import type { SettingsSource } from "../views/settings-body.on-demand";
import { onDemand } from "../../on-demand";
import { defaultValue, type SettingValue } from "../../../../../packages/ui/src/setting-value";
import type { SettingDef } from "./catalog";
import { entriesOf, locate, rowsOf, spotBySection, visibleMap } from "./model";

export interface RowsOptions {
  /** Whether the viewer sees the administrator rows (Machines, Mesh, Sharing). */
  admin(): boolean;
  backing?: SettingsSource["backing"];
  data?: SettingsSource["data"];
  /** The value ⌘K shows beside a setting; its default when absent. */
  value?(setting: SettingDef): SettingValue;
}

export function createRowsSource(options: RowsOptions): Pick<SettingsSource, "outline" | "render"> & Pick<SettingsSource, "backing" | "data"> {
  const map = () => visibleMap(options.admin());
  const backed = (id: string): boolean => options.backing?.(id) !== undefined;
  return {
    ...(options.backing ? { backing: options.backing } : {}),
    ...(options.data ? { data: options.data } : {}),
    outline: { rows: () => rowsOf(map()), entries: () => entriesOf(map(), options.value ?? ((s) => defaultValue(s.spec)), backed), locate: (target) => locate(map(), target), reveal: (windowId, settingId) => { void onDemand(() => import("./body.on-demand")).then((mod) => { mod.revealSetting(windowId, settingId); }); } },
    render(section, pane, cx) {
      const spot = spotBySection(map(), section);
      if (!spot) return undefined;
      let gone = false, stop: (() => void) | undefined;
      void onDemand(() => import("./body.on-demand")).then((mod) => { if (!gone) stop = mod.renderGroup(cx, pane, `s-${section}`, spot); });
      return () => { gone = true; stop?.(); };
    },
  };
}
