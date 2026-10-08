/**
 * Key/value list: the one way infraternal shows facts (machine details, connection,
 * session). Keys sit left, values right; a long value wraps onto more lines, still
 * right-aligned, and is never cut off with an ellipsis (docs/design/TASTE.md §4).
 *
 * Copying has no buttons. Each key and each value is its own copyable cell:
 * - desktop: one click copies;
 * - touch: a double tap copies (a single tap stays free for scrolling and selection);
 * - keyboard: Enter or Space on a focused cell copies.
 * The cell confirms with the shared tick and a "Copied" tooltip for 900 ms.
 *
 * Meters (memory, disk) are a thin bar under the value; they span the value column.
 */
import { TICK_PATH } from "./tick";
import { flashTip } from "./tooltip";

export interface KeyValueRow {
  key: string;
  value: string;
  meter?: number; // 0..100
  /** Copied instead of `value` when the value is an abbreviation (a short commit id). */
  copy?: string;
}

export interface KeyValueList {
  readonly root: HTMLElement;
  set(rows: KeyValueRow[]): void;
  dispose(): void;
}

const DOUBLE_TAP_MS = 320;
const DOUBLE_TAP_SLOP = 12;
const HOLD_MS = 900;

/** Builds a list; call `set` to (re)fill it. */
export function createKeyValueList(label: string): KeyValueList {
  const root = document.createElement("div");
  root.className = "ui-kv";
  root.setAttribute("role", "list");
  root.setAttribute("aria-label", label);

  const timers = new WeakMap<HTMLElement, number>();
  const copy = async (cell: HTMLElement): Promise<void> => {
    const text = cell.dataset.copy ?? "";
    try {
      if (!navigator.clipboard) return;
      await navigator.clipboard.writeText(text);
    } catch {
      return;
    }
    clearTimeout(timers.get(cell));
    cell.dataset.copied = "";
    flashTip(cell, "Copied", HOLD_MS);
    timers.set(cell, window.setTimeout(() => { delete cell.dataset.copied; }, HOLD_MS));
  };

  let lastTap: { cell: HTMLElement; time: number; x: number; y: number } | undefined;
  const pointerup = (event: PointerEvent): void => {
    if (event.pointerType !== "touch") return;
    const cell = (event.target as Element | null)?.closest<HTMLElement>(".ui-kv-cell");
    if (!cell) return;
    const now = event.timeStamp;
    if (lastTap && lastTap.cell === cell && now - lastTap.time < DOUBLE_TAP_MS
      && Math.hypot(event.clientX - lastTap.x, event.clientY - lastTap.y) < DOUBLE_TAP_SLOP) {
      lastTap = undefined;
      void copy(cell);
    } else {
      lastTap = { cell, time: now, x: event.clientX, y: event.clientY };
    }
  };
  let touchActivation = false;
  const pointerdown = (event: PointerEvent): void => { touchActivation = event.pointerType === "touch"; };
  const click = (event: MouseEvent): void => {
    const cell = (event.target as Element | null)?.closest<HTMLElement>(".ui-kv-cell");
    if (!cell || touchActivation) return;
    void copy(cell);
  };

  root.addEventListener("pointerdown", pointerdown);
  root.addEventListener("pointerup", pointerup);
  root.addEventListener("click", click);

  const tick = `<svg class="ui-kv-tick" viewBox="0 0 24 24" aria-hidden="true"><path d="${TICK_PATH}"/></svg>`;
  const cell = (kind: "key" | "value", text: string, copyText = text): HTMLButtonElement => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `ui-kv-cell ui-kv-${kind}`;
    button.dataset.copy = copyText;
    button.setAttribute("aria-description", "Copies to the clipboard");
    const span = document.createElement("span");
    span.className = "ui-kv-text";
    span.textContent = text;
    button.innerHTML = tick;
    if (kind === "key") button.prepend(span); else button.append(span);
    return button;
  };

  return {
    root,
    set(rows) {
      root.replaceChildren(...rows.map((row) => {
        const item = document.createElement("div");
        item.className = "ui-kv-row";
        item.setAttribute("role", "listitem");
        item.append(cell("key", row.key), cell("value", row.value, row.copy ?? row.value));
        if (row.meter !== undefined) {
          const meter = document.createElement("span");
          meter.className = "ui-kv-meter";
          meter.setAttribute("role", "meter");
          meter.setAttribute("aria-valuemin", "0");
          meter.setAttribute("aria-valuemax", "100");
          meter.setAttribute("aria-valuenow", String(Math.round(row.meter)));
          meter.setAttribute("aria-label", `${row.key} used`);
          meter.style.setProperty("--meter", String(Math.max(0, Math.min(100, row.meter)) / 100));
          item.append(meter);
        }
        return item;
      }));
    },
    dispose() {
      root.removeEventListener("pointerdown", pointerdown);
      root.removeEventListener("pointerup", pointerup);
      root.removeEventListener("click", click);
      root.remove();
    },
  };
}
