/**
 * On demand (the `.on-demand.ts` name is what the transfer gate reads): loaded the first time a Settings window is
 * drawn, through `onDemand` in body.ts, never on the first screen.
 *
 * The bodies of the Settings view's windows (D179): one panel per section, rendered into its window.
 *
 * The sections that belong to the app itself (appearance, toolbar, shortcuts, about) are rendered here from the
 * shared panels in packages/ui and the core screen. Sections that need account or instance data (devices,
 * account, users, grants, discovery) come from a `SettingsSource`: the product supplies the ones whose server
 * API exists, a mockup supplies test-double panels. A section no source provides is not listed at all.
 */
import { FONTS } from "../../../../../packages/ui/src/fonts";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { renderAppearance, renderHosts, renderWindowSizes, type AppearanceApi, type HostsApi, type WindowSizesApi } from "../../../../../packages/ui/src/settings-panels";
import { SIZE_EVENT, readSizes, writeSize, type DesktopSize, type PhoneSize } from "../window-sizes";
import type { Ctx } from "../context";
import { el } from "../dom";
import { EXTENDED_INFO_EVENT, readExtendedInfo, writeExtendedInfo } from "../windows/extended-info";

/** Account- and instance-level panels. Each returns what to run when its window goes away. */
export interface SettingsSource {
  /** Section ids this source renders (besides the four built-in ones). */
  sections: readonly string[];
  render(section: string, pane: HTMLElement, cx: Ctx): (() => void) | void;
}

export function renderSettingsBody(cx: Ctx, section: string, body: HTMLElement): () => void {
  const { core } = cx;
  const appearance: AppearanceApi = {
    themes: Object.entries(THEMES).map(([id, t]) => ({ id, name: t.name, dark: t.dark, bg: t.bg, accent: t.accent })),
    fonts: FONTS.map((f) => ({ id: f.id, label: f.label, hint: f.hint })),
    state: () => core.appearance(),
    act: (action) => core.act(action),
    onChange(listener) { window.addEventListener("tracer:appearance", listener); return () => window.removeEventListener("tracer:appearance", listener); },
  };
  // Plain names; the technical detail (the percentage) is in each option's subtitle (the plain-names rule).
  const windowSizes: WindowSizesApi = {
    groups: [
      { id: "phone", title: "Phones", options: [
        { id: "full", label: "Full width", hint: "between the margins" },
        { id: "edge", label: "Edge to edge", hint: "99% of the screen" },
        { id: "comfortable", label: "Comfortable", hint: "with margins" },
      ] },
      { id: "desktop", title: "Desktop", options: [
        { id: "comfortable", label: "Comfortable", hint: "one third of the canvas" },
        { id: "wide", label: "Wide", hint: "half of the canvas" },
        { id: "full", label: "Full width", hint: "99% of the canvas" },
      ] },
    ],
    get: (group) => readSizes()[group === "phone" ? "phone" : "desktop"],
    set: (group, option) => { if (group === "phone") writeSize("phone", option as PhoneSize); else writeSize("desktop", option as DesktopSize); },
    onChange(listener) { window.addEventListener(SIZE_EVENT, listener); return () => window.removeEventListener(SIZE_EVENT, listener); },
  };
  const hosts: HostsApi = {
    switches: [{
      id: "extended-info", title: "Details", label: "Extended info", hint: "System, resources and access facts in each window's details",
      get: readExtendedInfo, set: writeExtendedInfo,
      onChange(listener) { window.addEventListener(EXTENDED_INFO_EVENT, listener); return () => window.removeEventListener(EXTENDED_INFO_EVENT, listener); },
    }],
  };
  const pane = el("div", "ui-settings-pane");
  pane.setAttribute("role", "region");
  pane.setAttribute("aria-label", section);
  body.append(pane);
  const done = ((): (() => void) | void => {
    switch (section) {
      case "appearance": return renderAppearance(pane, appearance);
      case "windows": return renderWindowSizes(pane, windowSizes);
      case "hosts": return renderHosts(pane, hosts);
      case "toolbar": return core.settingsPanels.toolbar.render(pane);
      case "shortcuts": return core.settingsPanels.shortcuts.render(pane);
      case "about": return core.settingsPanels.about.render(pane);
      default: return cx.adapters.settings.render(section, pane, cx);
    }
  })();
  return () => { done?.(); pane.remove(); };
}
