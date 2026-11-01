/**
 * On demand (the `.on-demand.ts` name is what the transfer gate reads): loaded the first time a Settings window is
 * drawn, through `onDemand` in body.ts, never on the first screen.
 *
 * The bodies of the Settings view's windows (D179): one panel per section, rendered into its window.
 *
 * The sections that belong to the app itself (appearance, toolbar, shortcuts, account, about) are rendered here from the
 * shared panels in packages/ui and the core screen. Sections that need account or instance data (devices,
 * users, grants, discovery) come from a `SettingsSource`: the product supplies the ones whose server
 * API exists, a mockup supplies test-double panels. A section no source provides is not listed at all.
 */
import { FONTS } from "../../../../../packages/ui/src/fonts";
import { THEMES } from "../../../../../packages/ui/src/themes";
import { renderAccount, renderAppearance, renderHosts, renderWindowSizes, type AppearanceApi, type HostsApi, type StatusActionPref, type WindowSizesApi } from "../../../../../packages/ui/src/settings-panels";
import { askSignOut } from "../../sign-out";
import type { AuthorityControl } from "../addhost/authority-unlock";
import { SIZE_EVENT, readSizes, writeSize, type DesktopSize, type PhoneSize } from "../window-sizes";
import type { Ctx } from "../context";
import { el } from "../dom";
import { EXTENDED_INFO_EVENT, readExtendedInfo, writeExtendedInfo } from "../windows/extended-info";

/** Account- and instance-level panels. Each returns what to run when its window goes away. */
export interface SettingsSource {
  /** Section ids this source renders (besides the four built-in ones). */
  sections: readonly string[];
  render(section: string, pane: HTMLElement, cx: Ctx): (() => void) | void;
  /** What the account section lists above its sign-out row (a mockup's passkeys); the product has no facts to show yet. */
  accountFacts?(): Array<{ title: string; rows: Array<{ key: string; value: string }> }>;
}

/** The host-connection lock as a Settings group: plain words for the state, and the button only for an administrator while it is locked. */
function authorityPref(control: AuthorityControl): StatusActionPref {
  return {
    id: "host-connections", title: "Host connections",
    text: () => control.state() === "unknown" ? undefined
      : control.state() === "unlocked" ? "Unlocked"
      : "Locked until an administrator confirms with a passkey",
    action: () => control.state() === "locked" && control.canUnlock() ? "Unlock" : undefined,
    act: () => { void control.unlock(); },
    refresh: () => { void control.refresh(); },
    onChange: (listener) => control.onChange(listener),
  };
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
        { id: "full", label: "Full width", hint: "the whole screen, no neighbours showing" },
        { id: "edge", label: "Edge to edge", hint: "neighbours peek in at the sides" },
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
  const hostsApi = (): HostsApi => ({
    switches: [{
      id: "extended-info", title: "Details", label: "Extended info", hint: "Init, virtualization, shell and locale in each window's details",
      get: readExtendedInfo, set: writeExtendedInfo,
      onChange(listener) { window.addEventListener(EXTENDED_INFO_EVENT, listener); return () => window.removeEventListener(EXTENDED_INFO_EVENT, listener); },
    },
    // Offered only when the server says it can stream (D208): a server without the feature never shows a switch that does nothing.
    ...(cx.appWindows?.serverCan ? [{
      id: "app-windows", title: "App windows", label: "Stream app windows", hint: "Open an app window or a whole screen from a Mac on the canvas",
      get: () => cx.appWindows?.pref ?? false, set: (on: boolean) => cx.appWindows?.setWanted(on),
      onChange: (listener: () => void) => cx.appWindows?.onChange(listener) ?? (() => undefined),
    }] : []),
    ...(cx.adapters.startupHints?.switches() ?? [])],
    ...(cx.adapters.authority ? { statuses: [authorityPref(cx.adapters.authority)] } : {}),
  });
  const pane = el("div", "ui-settings-pane");
  pane.setAttribute("role", "region");
  pane.setAttribute("aria-label", section);
  body.append(pane);
  const done = ((): (() => void) | void => {
    switch (section) {
      case "appearance": return renderAppearance(pane, appearance);
      case "windows": return renderWindowSizes(pane, windowSizes);
      case "hosts": {
        // The Settings windows are drawn at load, before the server has said what it can do: the panel draws again when that
        // changes, so the app-windows switch appears (and only then) without a reload.
        let can = cx.appWindows?.serverCan, stop = renderHosts(pane, hostsApi());
        const off = cx.appWindows?.onChange(() => { if (cx.appWindows?.serverCan === can) return; can = cx.appWindows?.serverCan; stop(); stop = renderHosts(pane, hostsApi()); });
        return () => { off?.(); stop(); };
      }
      case "toolbar": return core.settingsPanels.toolbar.render(pane);
      case "shortcuts": return core.settingsPanels.shortcuts.render(pane);
      case "about": return core.settingsPanels.about.render(pane);
      case "account": return renderAccount(pane, { groups: cx.adapters.settings.accountFacts?.() ?? [], signOut: (anchor) => { askSignOut(anchor, cx.toast); } });
      default: return cx.adapters.settings.render(section, pane, cx);
    }
  })();
  return () => { done?.(); pane.remove(); };
}
