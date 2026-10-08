/**
 * Settings, Shortcuts (D160): every registered shortcut, grouped by area, from the one registry that
 * also drives `?`, the palette hints and the toolbar tooltips. A row with a binding can be changed:
 * click it, press the new combination, and it saves. A conflict with another action, or with a key the
 * terminal needs, is explained inline; another action's key can be swapped, a terminal key cannot be
 * taken. Each changed row has its own reset, and "Reset all" restores every default. Built-in keys that
 * have no binding (Esc, the 1 to 9 view jump) are listed, marked fixed.
 */
import { allShortcuts, bindingOf, comboLabel, comboOf, isOverridden, keyCaps, onBindingsChange, resetBindings, sameCombo, setBinding, terminalNeeds, type Combo } from "./shortcuts";
import type { SettingsSection } from "./settings-overlay";

const AREA_TITLE: Record<string, string> = { canvas: "Canvas", terminal: "Terminal", global: "Everywhere" };

export function shortcutsSection(): SettingsSection {
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

      const paint = (): void => {
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
              const reset = document.createElement("button");
              reset.type = "button"; reset.className = "ui-ss-reset"; reset.setAttribute("aria-label", `Reset ${shortcut.label}`); reset.dataset.tip = "Reset";
              reset.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12a7 7 0 1 0 2.3-5.2M5 5v4h4"/></svg>';
              reset.addEventListener("click", () => setBinding(shortcut.id, undefined));
              li.append(reset);
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
        const resetAll = document.createElement("button");
        resetAll.type = "button"; resetAll.className = "ui-ts-reset"; resetAll.textContent = "Reset all";
        resetAll.addEventListener("click", () => { capturing = undefined; pending = undefined; resetBindings(); });
        root.append(resetAll);
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
      return () => { document.removeEventListener("keydown", onKey, true); off(); root.remove(); };
    },
  };
}
