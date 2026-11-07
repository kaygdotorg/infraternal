/**
 * On demand (the `.on-demand.ts` name is what the transfer gate reads): loaded the first time a Settings window is
 * drawn, through `onDemand` in body.ts, never on the first screen.
 *
 * The bodies of the Settings view's windows (D179): one panel per section, rendered into its window.
 *
 * The sections that belong to the app itself (window sizes, hosts, toolbar, shortcuts, account, about) are rendered here from the
 * shared panels in packages/ui and the core screen. Sections that need account or instance data (devices,
 * users, grants, discovery) come from a `SettingsSource`: the product supplies the ones whose server
 * API exists, a mockup supplies test-double panels. A section no source provides is not listed at all.
 */
import { renderAccount, renderHosts, renderWindowSizes, type HostsApi, type StatusActionPref, type WindowSizesApi } from "../../../../../packages/ui/src/settings-panels";
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
  /** Optional account security controls and static facts, above the sign-out row. */
  accountStatuses?(): StatusActionPref[];
  accountRefresh?(): void;
  accountFacts?(): Array<{ title: string; rows: Array<{ key: string; value: string }> }>;
  /** Settings as rows of windows (issue #304): the sidebar, the top breadcrumb and ⌘K show Settings › Component › Group from it. */
  outline?: import("./settings-outline").SettingsOutline;
  /** Where the value of one setting of the table lives (by its id); absent: nobody stores it, so it shows no control. */
  backing?(settingId: string): import("./settings-outline").SettingBacking | undefined;
  /** Lists of facts and keys for a group of the table (component id, group id); absent: the group has none. */
  data?(component: string, group: string): import("../settings-rows/catalog").GroupData | undefined;
}

/** The host-connection lock as a Settings group: plain words for the state, and the button only for an administrator while it is locked. */
function authorityPref(control: AuthorityControl): StatusActionPref {
  return {
    id: "host-connections", title: "Host connections",
    text: () => {
      const state = control.state();
      const warnings = control.expiryWarnings();
      if (state === "unknown" && warnings.length === 0) return undefined;
      const lock = state === "locked" ? "Locked until an administrator confirms with a passkey"
        : state === "unlocked" ? "Unlocked" : "Host connection lock state unknown";
      return [lock, ...warnings].join(" · ");
    },
    action: () => control.state() === "locked" && control.canUnlock() ? "Unlock"
      : control.expiryWarnings().length ? "Review" : undefined,
    act: () => {
      if (control.state() === "locked" && control.canUnlock()) void control.unlock();
      else control.review();
    },
    refresh: () => { void control.refresh(); },
    onChange: (listener) => control.onChange(listener),
  };
}

/** Renders one settings section inside a canvas window and returns its cleanup callback. */
export function renderSettingsBody(cx: Ctx, section: string, body: HTMLElement): () => void {
  const { core } = cx;
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
    ...(cx.adapters.appWindows?.serverCan() ? [{
      id: "app-windows", title: "App windows", label: "Stream app windows", hint: "Open an app window or a whole screen from a Mac on the canvas",
      get: () => cx.adapters.appWindows?.pref ?? false, set: (on: boolean) => cx.adapters.appWindows?.setWanted(on),
      onChange: (listener: () => void) => cx.adapters.appWindows?.onChange(listener) ?? (() => undefined),
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
      case "windows": return renderWindowSizes(pane, windowSizes);
      case "hosts": {
        // The Settings windows are drawn at load, before the server has said what it can do: the panel draws again when that
        // changes, so the app-windows switch appears (and only then) without a reload.
        let can = cx.adapters.appWindows?.serverCan(), stop = renderHosts(pane, hostsApi());
        const off = cx.adapters.appWindows?.onChange(() => { if (cx.adapters.appWindows?.serverCan() === can) return; can = cx.adapters.appWindows?.serverCan(); stop(); stop = renderHosts(pane, hostsApi()); });
        return () => { off?.(); stop(); };
      }
      case "toolbar": return core.settingsPanels.toolbar.render(pane);
      case "shortcuts": return core.settingsPanels.shortcuts.render(pane);
      case "about": return core.settingsPanels.about.render(pane);
      case "account": {
        const stop = renderAccount(pane, { groups: cx.adapters.settings.accountFacts?.() ?? [], statuses: cx.adapters.settings.accountStatuses?.() ?? [], signOut: (anchor) => { askSignOut(anchor, cx.toast); } });
        // Settings windows are prepared off screen. Fetch only when this one comes into view.
        const visible = new IntersectionObserver((entries) => {
          if (cx.state.currentView === "settings" && entries.some((entry) => entry.isIntersecting)) cx.adapters.settings.accountRefresh?.();
        });
        visible.observe(pane);
        return () => { visible.disconnect(); stop(); };
      }
      default: return cx.adapters.settings.render(section, pane, cx);
    }
  })();
  return () => { done?.(); pane.remove(); };
}
