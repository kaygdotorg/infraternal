// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The inside of one Settings window (issue #304): the settings of one group as rows (default, allowed range, Reset, one line of
 * help, a refusal when a value is out of range), then its fact lists and key list, or an existing Settings panel reused as it
 * is (Shortcuts, About, the signed-in devices, a block or two of Appearance, …). The window's own pill names the group and
 * the breadcrumb names the component, so the body repeats neither (TASTE: never repeat the heading in the rows below it). The
 * "?" that opens the group's docs is the first button of the window's action group (`docs/docs-adapter.ts`), not part of the body.
 *
 * A setting is drawn only when its source has a store for it (`SettingsSource.backing`), so nothing here is a control that
 * saves nowhere. A window with nothing to show is not drawn at all: the model leaves it out (`visibleMap`, #568).
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import { createSettingRow, type SettingRow } from "../../../../../packages/ui/src/setting-row";
import { renderFacts } from "../../../../../packages/ui/src/settings-panels";
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { onDemand } from "../../on-demand";
import type { Ctx } from "../context";
import { el } from "../dom";
import type { GroupDef, KeyDef, PanelId } from "./catalog";
import { SETTING_DEFS, type SettingDef } from "./definitions.on-demand";
import type { Spot } from "./model";
import { updatesSource } from "../updates/source";
import { routesSource } from "../mesh/networks";

/** Live rows by window and setting, so ⌘K can show one. A window registers on render and leaves on cleanup. */
const live = new Map<string, Map<string, SettingRow>>();
/** Keys the person revoked in this session (the list is a source's data). */
const revoked = new Set<string>();

export function revealSetting(windowId: string, settingId: string): void {
  const row = live.get(windowId)?.get(settingId);
  if (!row) return;
  const pane = row.root.closest<HTMLElement>(".ui-settings-pane");
  // Only the window's own pane scrolls: scrollIntoView would also move the column and the camera's snapped band.
  if (pane && pane.scrollHeight > pane.clientHeight) pane.scrollTo({ top: Math.max(0, row.root.offsetTop - pane.clientHeight / 3), behavior: "instant" });
  row.found();
}

const KIND_NAME = { cli: "Command line", mcp: "AI tool" } as const;
const KEY_ICON = '<circle cx="8.5" cy="12" r="3.5"/><path d="M12 12h9M18 12v3M15 12v2"/>';

/** The command-line and AI-tool keys: name, kind, last used, when it runs out, and Revoke (with the compact confirmation). */
function renderKeys(pane: HTMLElement, keys: readonly KeyDef[]): () => void {
  const list = el("ul", "ui-sp-devices cl-keys");
  const paint = (): void => {
    list.replaceChildren();
    for (const key of keys.filter((k) => !revoked.has(k.id))) {
      const li = el("li", "ui-sp-device");
      li.dataset.id = key.id;
      li.innerHTML = `<span class="ui-sp-kind" aria-hidden="true"><svg viewBox="0 0 24 24">${KEY_ICON}</svg></span><span class="ui-sp-names"><span class="ui-sp-name-row"><span class="ui-sp-name"></span></span><span class="ui-sp-sub"></span></span><span class="ui-sp-actions"></span>`;
      li.querySelector<HTMLElement>(".ui-sp-name")!.textContent = key.name;
      // One short fact to a line: a window a fifth of the screen wide has no room for them side by side.
      li.querySelector<HTMLElement>(".ui-sp-sub")!.textContent = `${KIND_NAME[key.kind]}\nLast used ${key.lastUsed}\nExpires ${key.expires}`;
      const revoke = el("button", "ui-window-action");
      revoke.type = "button";
      revoke.setAttribute("aria-label", `Revoke ${key.name}`);
      revoke.dataset.tip = "Revoke";
      revoke.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.close}</svg>`;
      revoke.addEventListener("click", () => mountConfirmTip(revoke, {
        title: `Revoke ${key.name}?`, effect: "Anything using this key stops working. You can make a new one.",
        named: true, confirmLabel: "Revoke key", cancelLabel: "Keep key", onConfirm: () => { revoked.add(key.id); paint(); },
      }));
      li.querySelector(".ui-sp-actions")!.append(revoke);
      list.append(li);
    }
    if (!list.children.length) list.append(el("li", "cl-settings-later", "No keys. Make one from the command line."));
  };
  paint();
  pane.append(list);
  return () => list.remove();
}

/** The panels a window shows, from the table's `panel` (one or several). */
const panelsOf = (group: GroupDef): readonly PanelId[] => group.panel === undefined ? [] : typeof group.panel === "string" ? [group.panel] : group.panel;

/** Mounts one settings group and returns cleanup for its rows and subscriptions. */
export function renderGroup(cx: Ctx, pane: HTMLElement, windowId: string, { comp, group }: Spot): () => void {
  const disposers: Array<() => void> = [];
  const mine = new Map<string, SettingRow>();
  live.set(windowId, mine);
  const source = cx.adapters.settings;
  const note = (text: string): HTMLElement => { const n = el("p", "cl-settings-later"); n.textContent = text; pane.append(n); return n; };

  // Settings with a store get a row; the rest get nothing (no control that saves nowhere).
  const backed = (group.settings ?? []).filter((id) => source.backing?.(id)).map((id) => SETTING_DEFS[id]!);
  if (backed.length) {
    const list = el("div", "ui-setting-list");
    // Draws one setting. A failed read (a dropped connection, a store that is down) leaves a note with a Try again button in
    // the row's place; the button draws the row again, so a retry that works gives the person the control back.
    const mount = (def: SettingDef): void => {
      const backing = source.backing!(def.id)!;
      const row = createSettingRow({ id: def.id, title: def.title, explain: def.explain, spec: def.spec, onSave: (v) => backing.write(v) });
      mine.set(def.id, row);
      list.append(row.root);
      disposers.push(() => row.dispose());
      // The row is drawn at once with the default; the stored value arrives when the store has answered.
      let gone = false;
      disposers.push(() => { gone = true; });
      void backing.read().then((v) => {
        if (gone) return;
        if (v === undefined) { row.dispose(); mine.delete(def.id); if (!list.children.length) list.remove(); note("Only the owner can change this."); }
        else row.set(v);
      }, () => {
        if (gone) return;
        row.dispose();
        mine.delete(def.id);
        const line = note("This could not be read just now.");
        const retry = el("button", "ui-button");
        retry.type = "button";
        retry.dataset.button = "primary";
        retry.textContent = "Try again";
        pane.append(retry);
        retry.addEventListener("click", () => {
          line.remove();
          retry.remove();
          // The list leaves the pane when every row was owner-only; a retry that brings a row back puts it back.
          if (!pane.isConnected) return;
          if (!list.isConnected) pane.append(list);
          mount(def);
        }, { once: true });
      });
    };
    for (const def of backed) mount(def);
    pane.append(list);
  }
  // The Machines Updates window: the owner's controls, when a source exists. The example facts the double also holds for this window give way to it.
  const updates = group.updates ? updatesSource() : undefined;
  if (updates) {
    let gone = false, stop: (() => void) | undefined;
    void onDemand(() => import("../updates/panel.on-demand")).then((mod) => { if (!gone) stop = mod.renderUpdates(cx, pane, updates); });
    disposers.push(() => { gone = true; stop?.(); });
  }
  // The Mesh Networks window: advertised, approved and declined networks, when the server lists them to this person (its owner).
  const routes = group.networks ? routesSource() : undefined;
  if (routes) {
    let gone = false, stop: (() => void) | undefined;
    void onDemand(() => import("../mesh/networks-panel.on-demand")).then((mod) => { if (!gone) stop = mod.renderNetworks(cx, pane, routes); });
    disposers.push(() => { gone = true; stop?.(); });
  }
  const data = updates || routes ? undefined : source.data?.(comp.id, group.id);
  if (data?.facts?.length) { disposers.push(renderFacts(pane, group.title, data.facts.map((g) => ({ title: g.title, rows: g.rows })))); }
  if (data?.keys) { disposers.push(renderKeys(pane, data.keys)); }

  // The Appearance Themes window: the strip of theme cards, then the controls that edit the selected one. Loaded when the window draws (D188).
  if (group.themes) {
    let gone = false, stop: (() => void) | undefined;
    void onDemand(() => import("../themes/editor.on-demand")).then((mod) => { if (!gone) stop = mod.renderThemeEditor(pane); });
    disposers.push(() => { gone = true; stop?.(); });
  }

  // Existing panels, unchanged. A panel the source does not offer (devices, in the product today) is not shown.
  const panels = panelsOf(group).filter((id) => id !== "devices" || source.sections.includes("devices"));
  for (const id of panels) {
    const holder = el("div", "cl-settings-nest");
    pane.append(holder);
    let gone = false, stop: (() => void) | undefined;
    void onDemand(() => import("../views/settings-body.on-demand")).then((mod) => {
      if (gone) return;
      stop = mod.renderSettingsBody(cx, id, holder);
      // One panel fills several windows (Appearance is Theme, Font and Size): the blocks that belong to another window go.
      if (group.only) for (const block of holder.querySelectorAll<HTMLElement>(".ui-sp > section")) {
        if (!group.only.includes(block.querySelector(".ui-ts-title")?.textContent ?? "")) block.remove();
      }
    });
    disposers.push(() => { gone = true; stop?.(); holder.remove(); });
  }
  return () => { if (live.get(windowId) === mine) live.delete(windowId); for (const d of disposers) d(); };
}
