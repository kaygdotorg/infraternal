/**
 * Settings, Toolbar (D160): the one place the mobile toolbar is customised. Both rows are listed
 * (the canvas row above, the key row below); each control has a handle to drag it to a new place and
 * a switch that shows or hides it, and "Reset to default" puts everything back. The section only
 * edits a preference; whoever owns the toolbar applies it live (core-screen.ts), with motion.
 *
 * Reordering is a pointer drag on the handle: the row follows the pointer, the others glide aside on
 * springs, and the order commits on release. Keyboard: with a handle focused, Alt+Up/Down moves it.
 */
import { Spring } from "./spring";
import { enhanceSwitch } from "./switch";
import type { SettingsSection } from "./settings-overlay";

export interface ToolbarSettingsControl { id: string; label: string; icon: string }
export interface ToolbarSettingsRow {
  id: string;
  title: string;
  /** Controls in their current order. */
  controls: ToolbarSettingsControl[];
  hidden: Set<string>;
}
export interface ToolbarSettingsModel {
  rows(): ToolbarSettingsRow[];
  /** Where the layout in force comes from: the account (every device) or an override on this device. */
  source(): "account" | "device";
  customise(): void;
  useAccount(): void;
  /** Persist and apply a row's new order and hidden set. */
  change(rowId: string, order: string[], hidden: string[]): void;
  reset(): void;
}

const GRIP = '<path d="M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01" stroke-width="2.4"/>';

export function toolbarSection(model: ToolbarSettingsModel): SettingsSection {
  return {
    id: "toolbar",
    title: "Toolbar",
    icon: '<rect x="3" y="14" width="18" height="6" rx="3"/><path d="M7 17h.01M12 17h.01M17 17h.01"/><path d="M8 9h8M10 5h4"/>',
    render(container) {
      const reduced = matchMedia("(prefers-reduced-motion: reduce)");
      const root = document.createElement("div");
      root.className = "ui-toolbar-settings";
      container.append(root);
      let live = 0;

      const paint = (): void => {
        root.replaceChildren();
        const head = document.createElement("div");
        head.className = "ui-ts-source";
        const onDevice = model.source() === "device";
        head.innerHTML = `<span class="ui-ts-tag"></span><button type="button" class="ui-ts-reset"></button>`;
        (head.querySelector(".ui-ts-tag") as HTMLElement).textContent = onDevice ? "This device" : "Account layout";
        (head.querySelector(".ui-ts-tag") as HTMLElement).dataset.device = String(onDevice);
        const toggle = head.querySelector<HTMLButtonElement>("button")!;
        toggle.textContent = onDevice ? "Use account layout" : "Customise for this device";
        toggle.addEventListener("click", () => { if (onDevice) model.useAccount(); else model.customise(); paint(); });
        root.append(head);
        for (const row of model.rows()) {
          const section = document.createElement("section");
          section.className = "ui-ts-row";
          section.innerHTML = `<h3 class="ui-ts-title"></h3><ul class="ui-ts-list"></ul>`;
          (section.querySelector(".ui-ts-title") as HTMLElement).textContent = row.title;
          const list = section.querySelector<HTMLElement>(".ui-ts-list")!;
          const commit = (): void => {
            const order = [...list.children].map((li) => (li as HTMLElement).dataset.id!);
            const hidden = [...list.children].filter((li) => !(li.querySelector("input") as HTMLInputElement).checked).map((li) => (li as HTMLElement).dataset.id!);
            model.change(row.id, order, hidden);
          };
          for (const control of row.controls) {
            const li = document.createElement("li");
            li.className = "ui-ts-item";
            li.dataset.id = control.id;
            li.innerHTML = `<button class="ui-ts-grip" type="button" aria-label="Move" data-tip="Drag to reorder"><svg viewBox="0 0 24 24" aria-hidden="true">${GRIP}</svg></button>
              <span class="ui-ts-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${control.icon}</svg></span><span class="ui-ts-label"></span>
              <input class="ui-ts-switch" type="checkbox">`;
            (li.querySelector(".ui-ts-label") as HTMLElement).textContent = control.label;
            const input = li.querySelector<HTMLInputElement>("input")!;
            input.checked = !row.hidden.has(control.id);
            input.setAttribute("aria-label", `Show ${control.label}`);
            enhanceSwitch(input);
            input.addEventListener("change", commit);
            list.append(li);
          }
          wireDrag(list, commit);
          root.append(section);
        }
        const reset = document.createElement("button");
        reset.type = "button";
        reset.className = "ui-ts-reset";
        reset.textContent = "Reset to default";
        reset.addEventListener("click", () => { model.reset(); live++; paint(); });
        root.append(reset);
      };

      /** Moves `item` to `index` of `list`, gliding the others on springs. */
      const moveTo = (list: HTMLElement, item: HTMLElement, index: number): void => {
        const before = new Map([...list.children].map((c) => [c as HTMLElement, (c as HTMLElement).getBoundingClientRect().top]));
        const ref = [...list.children].filter((c) => c !== item)[index] ?? null;
        list.insertBefore(item, ref);
        if (reduced.matches) return;
        for (const [el, top] of before) {
          if (el === item) continue;
          const dy = top - el.getBoundingClientRect().top;
          if (Math.abs(dy) < 1) continue;
          const sp = new Spring(1, (p) => { el.style.transform = p === 0 ? "" : `translateY(${dy * p}px)`; }, { visualDuration: 0.3 });
          sp.set(0);
        }
      };
      const wireDrag = (list: HTMLElement, commit: () => void): void => {
        list.addEventListener("pointerdown", (e) => {
          const grip = (e.target as Element).closest<HTMLElement>(".ui-ts-grip");
          const item = grip?.closest<HTMLElement>(".ui-ts-item");
          if (!grip || !item) return;
          e.preventDefault();
          grip.setPointerCapture(e.pointerId);
          const startY = e.clientY;
          item.dataset.dragging = "";
          const startTop = item.offsetTop;
          const move = (ev: PointerEvent): void => {
            const dy = ev.clientY - startY;
            const siblings = [...list.children].filter((c) => c !== item) as HTMLElement[];
            // The slot under the dragged row's centre (its layout box moves with the pointer through its transform).
            const mid = item.getBoundingClientRect().top + item.offsetHeight / 2;
            const index = siblings.filter((c) => c.getBoundingClientRect().top + c.offsetHeight / 2 < mid).length;
            if (index !== [...list.children].indexOf(item)) moveTo(list, item, index);
            item.style.transform = `translateY(${dy - (item.offsetTop - startTop)}px)`;
          };
          const up = (): void => {
            grip.removeEventListener("pointermove", move);
            grip.removeEventListener("pointerup", up);
            grip.removeEventListener("pointercancel", up);
            const from = item.getBoundingClientRect().top;
            item.style.transform = "";
            const dy = from - item.getBoundingClientRect().top;
            delete item.dataset.dragging;
            if (!reduced.matches && Math.abs(dy) > 1) new Spring(1, (p) => { item.style.transform = p === 0 ? "" : `translateY(${dy * p}px)`; }, { visualDuration: 0.3 }).set(0);
            commit();
          };
          grip.addEventListener("pointermove", move);
          grip.addEventListener("pointerup", up);
          grip.addEventListener("pointercancel", up);
        });
        list.addEventListener("keydown", (e) => {
          const item = (e.target as Element).closest<HTMLElement>(".ui-ts-item");
          if (!item || !(e.target as Element).closest(".ui-ts-grip") || !e.altKey || (e.key !== "ArrowUp" && e.key !== "ArrowDown")) return;
          e.preventDefault();
          const at = [...list.children].indexOf(item);
          moveTo(list, item, Math.max(0, Math.min(list.children.length - 1, at + (e.key === "ArrowUp" ? -1 : 1))));
          (item.querySelector(".ui-ts-grip") as HTMLElement).focus();
          commit();
        });
      };

      paint();
      return () => { live++; root.remove(); };
    },
  };
}
