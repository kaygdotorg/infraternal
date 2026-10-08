/**
 * The bodies of the Settings view's windows (D179): one panel per section, rendered into its window.
 *
 * The sections that belong to the app itself (appearance, toolbar, shortcuts, about) are rendered here from the
 * shared panels in packages/ui and the core screen. Sections that need account or instance data (devices,
 * account, users, grants, discovery) come from a `SettingsSource`: the product supplies the ones whose server
 * API exists, a mockup supplies test-double panels. A section no source provides is not listed at all.
 */
import { FONTS } from "../../../../../packages/ui/src/fonts";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { renderAppearance, type AppearanceApi } from "../../../../../packages/ui/src/settings-panels";
import type { Ctx } from "../context";
import { el } from "../dom";

/** Account- and instance-level panels. Each returns what to run when its window goes away. */
export interface SettingsSource {
  /** Section ids this source renders (besides the four built-in ones). */
  sections: readonly string[];
  render(section: string, pane: HTMLElement, cx: Ctx): (() => void) | void;
}

/** Sections the app renders itself. */
export const BUILTIN_SECTIONS = ["appearance", "toolbar", "shortcuts", "about"] as const;

export function renderSettingsBody(cx: Ctx, section: string, body: HTMLElement): () => void {
  const { core } = cx;
  const appearance: AppearanceApi = {
    themes: Object.entries(THEMES).map(([id, t]) => ({ id, name: t.name, dark: t.dark, bg: t.bg, accent: t.accent })),
    fonts: FONTS.map((f) => ({ id: f.id, label: f.label, hint: f.hint })),
    state: () => core.appearance(),
    act: (action) => core.act(action),
    onChange(listener) { window.addEventListener("tracer:appearance", listener); return () => window.removeEventListener("tracer:appearance", listener); },
  };
  const pane = el("div", "ui-settings-pane");
  pane.setAttribute("role", "region");
  pane.setAttribute("aria-label", section);
  body.append(pane);
  const done = ((): (() => void) | void => {
    switch (section) {
      case "appearance": return renderAppearance(pane, appearance);
      case "toolbar": return core.settingsPanels.toolbar.render(pane);
      case "shortcuts": return core.settingsPanels.shortcuts.render(pane);
      case "about": return core.settingsPanels.about.render(pane);
      default: return cx.adapters.settings.render(section, pane, cx);
    }
  })();
  return () => { done?.(); pane.remove(); };
}
