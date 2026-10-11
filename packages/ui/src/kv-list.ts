/**
 * Key/value list: the one way infraternal shows facts (machine details, connection,
 * session). Keys sit left, values right; a long value wraps onto more lines, still
 * right-aligned, and is never cut off with an ellipsis (docs/design/TASTE.md §4).
 *
 * Copying has no buttons. Each key and each value is its own copyable cell:
 * - desktop: one click copies;
 * - touch: a double tap copies (a single tap stays free for scrolling and selection);
 * - keyboard: Enter or Space on a focused cell copies.
 * The cell confirms through the shared copy feedback (copy-feedback.ts: the tick that morphs in,
 * plus the "Copied" tooltip), exactly as the sign-in and recovery copy buttons do.
 *
 * Rows may carry a `group`: consecutive rows with the same group sit under one quiet title (the machine tab's
 * System, Resources and Access). A list with no groups is the flat list it always was.
 *
 * Meters (memory, disk) are a thin bar under the value; they span the value column.
 */
import { copyFeedback, inlineTickNode } from "./copy-feedback";

export interface KeyValueRow {
  key: string;
  value: string;
  meter?: number; // 0..100
  /** Copied instead of `value` when the value is an abbreviation (a short commit id). */
  copy?: string;
  /** A technical subtitle under the key, for a plainly named row ("Connection delay": "Round-trip time to the server"). */
  hint?: string;
  /** A short title for the group this row starts or continues. Rows with the same consecutive group share one titled section. */
  group?: string;
}

export interface KeyValueList {
  readonly root: HTMLElement;
  set(rows: KeyValueRow[]): void;
  dispose(): void;
}

const DOUBLE_TAP_MS = 320;
const DOUBLE_TAP_SLOP = 12;

/** Builds a list; call `set` to (re)fill it. */
export function createKeyValueList(label: string): KeyValueList {
  const root = document.createElement("div");
  root.className = "ui-kv";
  root.setAttribute("role", "list");
  root.setAttribute("aria-label", label);

  const copy = async (cell: HTMLElement, instant = false): Promise<void> => {
    await copyFeedback(cell, cell.dataset.copy ?? "", instant, true);
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
      void copy(cell, false);
    } else {
      lastTap = { cell, time: now, x: event.clientX, y: event.clientY };
    }
  };
  let touchActivation = false;
  const pointerdown = (event: PointerEvent): void => { touchActivation = event.pointerType === "touch"; };
  const click = (event: MouseEvent): void => {
    const cell = (event.target as Element | null)?.closest<HTMLElement>(".ui-kv-cell");
    if (!cell || touchActivation) return;
    void copy(cell, event.detail === 0);
  };

  root.addEventListener("pointerdown", pointerdown);
  root.addEventListener("pointerup", pointerup);
  root.addEventListener("click", click);

  const cell = (kind: "key" | "value", text: string, copyText = text, hint?: string): HTMLButtonElement => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `ui-kv-cell ui-kv-${kind}`;
    button.dataset.copy = copyText;
    button.setAttribute("aria-description", "Copies to the clipboard");
    // The highlight belongs to the text run, not to the button: an inline span with cloned box
    // decoration hugs the text with even padding and follows every line of a wrapped value. The
    // tick lives inside the run, so it is inside the highlight when it appears.
    const span = document.createElement("span");
    span.className = "ui-kv-text";
    const label = document.createTextNode(text);
    span.append(kind === "key" ? label : inlineTickNode(), kind === "key" ? inlineTickNode() : label);
    button.append(span);
    if (hint) {
      const sub = document.createElement("span");
      sub.className = "ui-kv-hint";
      sub.textContent = hint;
      button.append(sub);
    }
    return button;
  };

  const rowNode = (row: KeyValueRow): HTMLElement => {
    const item = document.createElement("div");
    item.className = "ui-kv-row";
    item.setAttribute("role", "listitem");
    item.append(cell("key", row.key, row.key, row.hint), cell("value", row.value, row.copy ?? row.value));
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
  };

  let titleSeq = 0;
  return {
    root,
    set(rows) {
      if (!rows.some((row) => row.group)) {
        root.setAttribute("role", "list");
        root.replaceChildren(...rows.map(rowNode));
        return;
      }
      // Titled sections: the root becomes a plain container, each section a labelled group holding its own list.
      root.setAttribute("role", "group");
      const sections: HTMLElement[] = [];
      let current: { group: string | undefined; list: HTMLElement } | undefined;
      for (const row of rows) {
        if (!current || current.group !== row.group) {
          const section = document.createElement("div");
          section.className = "ui-kv-section";
          section.setAttribute("role", "group");
          const list = document.createElement("div");
          list.className = "ui-kv-rows";
          list.setAttribute("role", "list");
          if (row.group) {
            const title = document.createElement("div");
            title.className = "ui-kv-group";
            title.id = `ui-kv-group-${titleSeq++}`;
            title.textContent = row.group;
            section.setAttribute("aria-labelledby", title.id);
            section.append(title);
          }
          section.append(list);
          sections.push(section);
          current = { group: row.group, list };
        }
        current.list.append(rowNode(row));
      }
      root.replaceChildren(...sections);
    },
    dispose() {
      root.removeEventListener("pointerdown", pointerdown);
      root.removeEventListener("pointerup", pointerup);
      root.removeEventListener("click", click);
      root.remove();
    },
  };
}
