/** Builds the legacy Settings overlay and its panels only after a person opens Settings or one of those panels. */
import { aboutSection, createSettingsOverlay, type AboutInfo, type SettingsOverlay, type SettingsSection } from "../../../packages/ui/src/settings-overlay";
import { shortcutsSection } from "../../../packages/ui/src/shortcuts-settings";
import { toolbarSection, type ToolbarSettingsModel } from "../../../packages/ui/src/toolbar-settings";

/** The three shared Settings panels exposed by the core screen. */
export type SettingsPanelId = "toolbar" | "shortcuts" | "about";

/** The live values needed to build a panel or the legacy overlay after its lazy chunk is loaded. */
export interface SettingsUiOptions {
  stage: HTMLElement;
  about: AboutInfo;
  toolbar: ToolbarSettingsModel;
}

/** Creates the requested panel from the current screen state; callers keep the returned section's disposer. */
export function createSettingsPanel(id: SettingsPanelId, options: SettingsUiOptions): SettingsSection {
  switch (id) {
    case "toolbar": return toolbarSection(options.toolbar);
    case "shortcuts": return shortcutsSection(options.stage);
    case "about": return aboutSection(options.about);
    default: {
      const unreachable: never = id;
      return unreachable;
    }
  }
}

/** Creates the sections for the legacy overlay in its original order and includes Toolbar only when the canvas row exists. */
export function createSettingsSections(options: SettingsUiOptions, includeShortcuts: boolean, includeToolbar: boolean): SettingsSection[] {
  const sections = [createSettingsPanel("about", options)];
  if (includeShortcuts) sections.unshift(createSettingsPanel("shortcuts", options));
  if (includeToolbar) sections.unshift(createSettingsPanel("toolbar", options));
  return sections;
}

/** Creates the shared overlay shell around sections prepared by this module. */
export function mountSettingsOverlay(stage: HTMLElement, sections: SettingsSection[]): SettingsOverlay {
  return createSettingsOverlay({ stage, sections });
}
