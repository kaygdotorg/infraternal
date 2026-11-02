// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The inside of one Settings window (issue #304): the settings of one group as rows (default, allowed range, Reset, one line of
 * help, a refusal when a value is out of range), then its fact lists and key list, or an existing Settings panel reused as it
 * is (Shortcuts, About, the signed-in devices, a block or two of Appearance, …). The window's own pill names the group and
 * the breadcrumb names the component, so the body repeats neither (TASTE: never repeat the heading in the rows below it). The
 * "?" that opens the group's docs is the first button of the window's action group (`docs/docs-adapter.ts`), not part of the body.
 *
 * Nothing is saved anywhere but in memory for the session (`saveValue`): this is a mockup of the layout and the rules.
 */
import { ICONS } from "../../../../../../packages/ui/src/icons";
import { createSettingRow, type SettingRow } from "../../../../../../packages/ui/src/setting-row";
import { renderFacts } from "../../../../../../packages/ui/src/settings-panels";
import { mountConfirmTip } from "../../../../../../packages/ui/src/tooltip";
import { onDemand } from "../../../on-demand";
import type { Ctx } from "../../context";
import { el } from "../../dom";
import type { GroupDef } from "./catalog";
import type { Spot } from "./model";
import { saveValue, valueOf } from "./model";

/** Live rows by window and setting, so ⌘K can show one. A window registers on render and leaves on cleanup. */
const live = new Map<string, Map<string, SettingRow>>();
/** Keys the person revoked in this session (the list is test data). */
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
function renderKeys(pane: HTMLElement, keys: NonNullable<GroupDef["keys"]>): () => void {
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
        label: `Revoke ${key.name}`, title: `Revoke ${key.name}?`, effect: "Anything using this key stops working. You can make a new one.",
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

export function renderGroup(cx: Ctx, pane: HTMLElement, windowId: string, { group }: Spot): () => void {
  const disposers: Array<() => void> = [];
  const mine = new Map<string, SettingRow>();
  live.set(windowId, mine);
  if (group.settings?.length) {
    const list = el("div", "ui-setting-list");
    for (const def of group.settings) {
      const row = createSettingRow({ id: def.id, title: def.title, explain: def.explain, spec: def.spec, value: valueOf(def), onSave: (v) => saveValue(def, v) });
      mine.set(def.id, row);
      list.append(row.root);
      disposers.push(() => row.dispose());
    }
    pane.append(list);
  }
  if (group.facts?.length) disposers.push(renderFacts(pane, group.title, group.facts.map((g) => ({ title: g.title, rows: g.rows }))));
  if (group.keys) disposers.push(renderKeys(pane, group.keys));
  if (group.later) {
    const note = el("p", "cl-settings-later");
    note.textContent = group.later;
    pane.append(note);
  }
  if (group.panel) {
    // An existing panel, unchanged. It makes a pane of its own, which would pad and scroll twice inside this one.
    const holder = el("div", "cl-settings-nest");
    pane.append(holder);
    let gone = false, stop: (() => void) | undefined;
    void onDemand(() => import("../../views/settings-body.on-demand")).then((mod) => {
      if (gone) return;
      stop = mod.renderSettingsBody(cx, group.panel!, holder);
      // One panel fills several windows (Appearance is Theme, Font and Size): the blocks that belong to another window go.
      if (group.only) for (const block of holder.querySelectorAll<HTMLElement>(".ui-sp > section")) {
        if (!group.only.includes(block.querySelector(".ui-ts-title")?.textContent ?? "")) block.remove();
      }
    });
    disposers.push(() => { gone = true; stop?.(); holder.remove(); });
  }
  return () => { if (live.get(windowId) === mine) live.delete(windowId); for (const d of disposers) d(); };
}
