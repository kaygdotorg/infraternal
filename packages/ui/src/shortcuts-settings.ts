/**
 * Settings, Shortcuts (D160): every registered shortcut, grouped by area, from the one registry that
 * also drives `?`, the palette hints and the toolbar tooltips. A row with a binding can be changed:
 * click it, press the new combination, and it saves. A conflict with another action, or with a key the
 * terminal needs, is explained inline; another action's key can be swapped, a terminal key cannot be
 * taken. Built-in keys that have no binding (Esc, the 1 to 9 view jump) are listed, marked fixed.
 *
 * Changed rows and resetting (owner, 2026-11-03, #306): every row keeps its key caps on the one right edge the other
 * Settings rows share, so a changed row adds nothing beside its caps. It is marked by a small dot on the caps' top-left
 * corner (out of the layout flow, so the caps never move) whose tooltip names the default ("Changed from Ctrl+K").
 * Reset lives in the row's menu (the shared row menu, row-menu.ts: right-click, long press, Shift+F10) and on the
 * keyboard (Delete or Backspace on the focused row). "Reset all" is the list's last row and appears only while something
 * is changed; it asks in its own row (row-confirm.ts, TASTE "A destructive row action asks in its own row").
 */
import { allShortcuts, bindingOf, comboLabel, comboOf, isOverridden, keyCaps, onBindingsChange, resetBindings, sameCombo, setBinding, terminalNeeds, type Combo } from "./shortcuts";
import { attachRowMenu, type RowAction } from "./row-menu";
import { mountRowAsk, type RowAsk } from "./row-confirm";
import type { SettingsSection } from "./settings-overlay";

const AREA_TITLE: Record<string, string> = { canvas: "Canvas", terminal: "Terminal", global: "Everywhere" };
/** The reset glyph (inner SVG on the 24 px grid), shared by the row menu. */
const RESET_ICON = '<path d="M5 12a7 7 0 1 0 2.3-5.2M5 5v4h4"/>';

/** `stage` is the element menus float over (the screen); the row menu needs it for its popover. */
export function shortcutsSection(stage: HTMLElement): SettingsSection {
  return {
    id: "shortcuts",
    title: "Shortcuts",
    icon: '<rect x="3" y="6" width="18" height="12" rx="3"/><path d="M7 10h.01M11 10h.01M15 10h.01M8 14h8"/>',
    render(container) {
      const root = document.createElement("div");
      root.className = "ui-shortcuts-settings";
      container.append(root);
      let capturing: string | undefined;
      let pending: { id: string; combo: Combo; message: string; swapWith?: string } | undefined;
      /** The row that had the focus when it was reset: its rebuilt twin takes the focus back (the list repaints from scratch). */
      let refocus: string | undefined;
      let asking: RowAsk | undefined;

      const resetOne = (id: string): void => { pending = undefined; refocus = id; setBinding(id, undefined); };
      const defaultLabel = (id: string): string => {
        const combo = allShortcuts().find((e) => e.shortcut.id === id)?.shortcut.combo;
        return combo ? comboLabel(combo) : "";
      };
      /** Only a changed row has something to do; a fixed or default row has no menu, so its right-click stays the browser's. */
      const rowAt = (target: Element): HTMLElement | undefined => {
        const row = target.closest<HTMLElement>(".ui-ss-row[data-changed]");
        return row && root.contains(row) ? row : undefined;
      };
      const rowMenu = attachRowMenu(root, {
        stage, rowAt,
        anchorOf: (row) => row.querySelector<HTMLElement>(".ui-ss-main") ?? row,
        actions(row): RowAction[] {
          const id = row.dataset.id;
          if (!id || !isOverridden(id)) return [];
          return [{ id: "reset", label: `Reset to ${defaultLabel(id)}`, icon: RESET_ICON, run: () => resetOne(id) }];
        },
      });
      root.addEventListener("keydown", (event) => {
        if ((event.key !== "Delete" && event.key !== "Backspace") || event.repeat || capturing || !(event.target instanceof Element)) return;
        const row = event.target.closest<HTMLElement>(".ui-ss-main") && rowAt(event.target);
        if (!row?.dataset.id) return;
        event.preventDefault();
        resetOne(row.dataset.id);
      });

      const paint = (): void => {
        asking?.close(false);
        asking = undefined;
        root.replaceChildren();
        const all = allShortcuts();
        const byArea = new Map<string, typeof all>();
        for (const entry of all) byArea.set(entry.section.area, [...(byArea.get(entry.section.area) ?? []), entry]);
        for (const [area, entries] of byArea) {
          const block = document.createElement("section");
          block.innerHTML = `<h3 class="ui-ts-title"></h3><ul class="ui-ss-list"></ul>`;
          (block.querySelector(".ui-ts-title") as HTMLElement).textContent = AREA_TITLE[area] ?? area;
          const list = block.querySelector<HTMLElement>(".ui-ss-list")!;
          for (const { shortcut } of entries) {
            const li = document.createElement("li");
            li.className = "ui-ss-row";
            li.dataset.id = shortcut.id;
            const combo = bindingOf(shortcut);
            const fixed = !shortcut.combo;
            li.innerHTML = `<button class="ui-ss-main" type="button"><span class="ui-ss-label"></span><span class="ui-ss-keys"></span></button>`;
            const main = li.querySelector<HTMLButtonElement>(".ui-ss-main")!;
            (li.querySelector(".ui-ss-label") as HTMLElement).textContent = shortcut.label;
            const keys = li.querySelector(".ui-ss-keys") as HTMLElement;
            if (capturing === shortcut.id) { keys.textContent = "Press the new keys"; keys.dataset.capturing = ""; }
            else for (const cap of keyCaps(combo ? comboLabel(combo) : shortcut.keys)) { const k = document.createElement("kbd"); k.textContent = cap; keys.append(k); }
            if (fixed) { main.disabled = true; li.dataset.fixed = ""; main.setAttribute("aria-label", `${shortcut.label}, built in`); }
            else main.addEventListener("click", () => { capturing = shortcut.id; pending = undefined; paint(); main.focus(); });
            if (!fixed && isOverridden(shortcut.id)) {
              li.dataset.changed = "";
              // The mark sits on the caps' corner and takes no room, so the caps keep the shared right edge. The tooltip is on
              // the whole caps group (a 6 px dot is no target). `aria-description`, not `aria-label`: the shared tooltip also
              // reads a button's aria-label, and the row's own name must not surface as a tooltip over its label.
              const was = `Changed from ${defaultLabel(shortcut.id)}`;
              if (capturing !== shortcut.id) {
                const dot = document.createElement("span");
                dot.className = "ui-ss-dot";
                dot.setAttribute("aria-hidden", "true");
                keys.prepend(dot);
                // Touch: a long press on the caps would open the row menu (480 ms) and the tooltip (500 ms) together. The menu
                // already names the default ("Reset to Ctrl+K"), so touch gets no tooltip and the pointer keeps it.
                if (matchMedia("(hover: hover) and (pointer: fine)").matches) keys.dataset.tip = was;
              }
              main.setAttribute("aria-description", `${was}. Press Delete to reset it.`);
            }
            if (pending?.id === shortcut.id) {
              const warn = document.createElement("div");
              warn.className = "ui-ss-warn";
              warn.setAttribute("role", "alert");
              warn.innerHTML = `<span></span><span class="ui-ss-actions"></span>`;
              (warn.firstElementChild as HTMLElement).textContent = pending.message;
              const actions = warn.querySelector(".ui-ss-actions") as HTMLElement;
              const choice = (text: string, run: () => void): void => { const b = document.createElement("button"); b.type = "button"; b.textContent = text; b.addEventListener("click", run); actions.append(b); };
              const p = pending;
              if (p.swapWith) choice("Swap", () => { const other = all.find((e) => e.shortcut.id === p.swapWith)!; const mine = bindingOf(shortcut); pending = undefined; if (mine) setBinding(other.shortcut.id, mine); setBinding(p.id, p.combo); });
              choice("Cancel", () => { pending = undefined; paint(); });
              li.append(warn);
            }
            list.append(li);
          }
          root.append(block);
        }
        // "Reset all": a row of its own at the end, only while there is something to reset (no control looks dead, TASTE).
        if (all.some((e) => e.shortcut.combo && isOverridden(e.shortcut.id))) {
          const block = document.createElement("section");
          block.innerHTML = `<ul class="ui-ss-list"><li class="ui-ss-row" data-reset-all><button class="ui-ss-main" type="button"><span class="ui-ss-label">Reset all</span></button></li></ul>`;
          const row = block.querySelector<HTMLElement>(".ui-ss-row")!;
          const main = row.querySelector<HTMLButtonElement>(".ui-ss-main")!;
          main.addEventListener("click", (event) => {
            asking?.close(false);
            asking = mountRowAsk(row, main, {
              label: "Reset all shortcuts?", question: "Reset all shortcuts?", shortQuestion: "Reset all?",
              effect: "Every shortcut goes back to its default key.",
              alignTo: row.querySelector(".ui-ss-label"), confirmLabel: "Reset", cancelLabel: "Cancel",
              keyboard: event.detail === 0,
              onConfirm: () => { asking = undefined; capturing = undefined; pending = undefined; refocus = "*"; resetBindings(); },
              onCancel: () => { asking = undefined; },
            });
          });
          root.append(block);
        }
        if (refocus) {
          const target = refocus === "*" ? root.querySelector<HTMLElement>(".ui-ss-main:not(:disabled)") : [...root.querySelectorAll<HTMLElement>(".ui-ss-row")].find((r) => r.dataset.id === refocus)?.querySelector<HTMLElement>(".ui-ss-main");
          refocus = undefined;
          target?.focus({ preventScroll: true });
        }
      };

      const onKey = (event: KeyboardEvent): void => {
        if (!capturing) return;
        if (["Control", "Shift", "Alt", "Meta"].includes(event.key)) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        if (event.key === "Escape") { capturing = undefined; paint(); return; }
        const id = capturing;
        const combo = comboOf(event);
        capturing = undefined;
        const why = terminalNeeds(combo);
        const clash = allShortcuts().find((e) => e.shortcut.id !== id && (() => { const c = bindingOf(e.shortcut); return c ? sameCombo(c, combo) : false; })());
        if (why) pending = { id, combo, message: `${comboLabel(combo)} cannot be used. ${why}` };
        else if (clash) pending = { id, combo, message: `${comboLabel(combo)} is already used for ${clash.shortcut.label}.`, swapWith: clash.shortcut.id };
        else { setBinding(id, combo); return; }
        paint();
      };
      document.addEventListener("keydown", onKey, true);
      const off = onBindingsChange(paint);
      paint();
      return () => { document.removeEventListener("keydown", onKey, true); off(); asking?.close(false); rowMenu.dispose(); root.remove(); };
    },
  };
}
