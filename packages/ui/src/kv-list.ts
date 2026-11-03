/**
 * Key/value list: the one way infraternal shows facts (machine details, connection,
 * session, version). Keys sit left, values right; a long value wraps onto more lines, still
 * right-aligned, and is never cut off with an ellipsis (docs/design/TASTE.md §4).
 *
 * What a press does (owner, 2026-11-01: "the default action should be contextual; if there's no contextual action, copy it"):
 * - a value with a `press` does that action, and only that: a state you can change from its own row ("Updates")
 *   checks, retries or proceeds. Such a value never copies;
 * - every other value, and every key, copies its own text. There are no copy buttons.
 * How a press is made:
 * - desktop: one click;
 * - touch: a double tap copies (a single tap stays free for scrolling and selection); a value with a `press` answers a
 *   single tap, because it is a button the person was meant to press;
 * - keyboard: Enter or Space on a focused cell.
 * A copy confirms in place (copy-feedback.ts `confirmInPlace`): the text fades out and a clipboard icon with "Copied"
 * replaces it, then the text fades back. There is no tooltip for it.
 *
 * Rows may carry a `group`: consecutive rows with the same group sit under one quiet title (the machine tab's
 * System, Resources and Access). A list with no groups is the flat list it always was.
 *
 * Meters (memory, disk) are a thin bar under the value; they span the value column.
 *
 * `set` again with the same rows (same groups, keys and layout, only new values) patches in place: a list that
 * refreshes every second while its popover is open keeps its hover and its copy confirmation, and a value that changes
 * (text, mark, press) fades out and back in with its new content instead of snapping.
 *
 * A `wide` row has no key: its value spans the row, left-aligned. With `press` it is a link (a quiet chevron at the end,
 * for "What's new"); without it, a plain line of text that belongs under a group's title.
 */
import { copyTextInPlace } from "./copy-feedback";
import { ICONS } from "./icons";

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
  /**
   * A small mark before the value: `ok` is a tick (something that is fine), `warn` an exclamation (something waits for
   * you), `off` a quiet cross (something that could not be known), `busy` a turning arc (something is being done now).
   */
  mark?: "ok" | "off" | "warn" | "busy";
  /**
   * The value is the row's contextual action: pressing it runs this instead of copying. `tip` is its warm tooltip and
   * its spoken description.
   */
  press?: { run(cell: HTMLElement): void; tip: string };
  /** No key: the value spans the whole row. A wide row with `press` is a link and shows a chevron. */
  wide?: boolean;
  /**
   * A pane that belongs to the row and opens under it (the privileged-access consent under "Access level"). The row owns
   * only its place: the pane opens and closes itself and is the same element across `set` calls, so a repaint does not
   * rebuild it, and whatever step it shows survives a change of the row's own value.
   */
  panel?: HTMLElement;
}

export interface KeyValueList {
  readonly root: HTMLElement;
  set(rows: KeyValueRow[]): void;
  dispose(): void;
}

const DOUBLE_TAP_MS = 320;
const DOUBLE_TAP_SLOP = 12;
/** The fade-out of a value that changes (styles.css, `[data-swapping]`); its new content is written once it is gone. */
const SWAP_MS = 110;

interface Entry {
  row: KeyValueRow;
  value: HTMLButtonElement;
  label: Text;
  meter?: HTMLElement;
  /** Pending content change of a value that is fading out. */
  swap: number | undefined;
}

/**
 * The one copy gesture for every `.ui-kv-cell` under `root`: a click on desktop, a double tap on touch (a single tap stays
 * free for scrolling and selection), Enter or Space on a focused cell (a click with no pointer). A cell with an action of
 * its own (`pressOf` returns it) runs that on a click or a single tap instead; it never copies. Returns the remover.
 * Layouts that are not a key/value list but copy text the same way (the version panel's heading) install it too.
 */
export function installCopyCells(root: HTMLElement, pressOf: (cell: HTMLElement) => ((cell: HTMLElement) => void) | undefined): () => void {
  const copy = (cell: HTMLElement, instant: boolean): void => { void copyTextInPlace(cell, cell.dataset.copy ?? "", instant); };
  let lastTap: { cell: HTMLElement; time: number; x: number; y: number } | undefined;
  const pointerup = (event: PointerEvent): void => {
    if (event.pointerType !== "touch") return;
    const cell = (event.target as Element | null)?.closest<HTMLElement>(".ui-kv-cell");
    // A pressable value is answered by the click that follows the tap; only copying needs the double tap.
    if (!cell || pressOf(cell)) return;
    const now = event.timeStamp;
    if (lastTap && lastTap.cell === cell && now - lastTap.time < DOUBLE_TAP_MS
      && Math.hypot(event.clientX - lastTap.x, event.clientY - lastTap.y) < DOUBLE_TAP_SLOP) {
      lastTap = undefined;
      copy(cell, false);
    } else {
      lastTap = { cell, time: now, x: event.clientX, y: event.clientY };
    }
  };
  let touchActivation = false;
  const pointerdown = (event: PointerEvent): void => { touchActivation = event.pointerType === "touch"; };
  const click = (event: MouseEvent): void => {
    const cell = (event.target as Element | null)?.closest<HTMLElement>(".ui-kv-cell");
    if (!cell) return;
    const press = pressOf(cell);
    if (press) { press(cell); return; }
    if (touchActivation) return;
    copy(cell, event.detail === 0);
  };
  root.addEventListener("pointerdown", pointerdown);
  root.addEventListener("pointerup", pointerup);
  root.addEventListener("click", click);
  return () => {
    root.removeEventListener("pointerdown", pointerdown);
    root.removeEventListener("pointerup", pointerup);
    root.removeEventListener("click", click);
  };
}

/** Builds a list; call `set` to (re)fill it. */
export function createKeyValueList(label: string): KeyValueList {
  const root = document.createElement("div");
  root.className = "ui-kv";
  root.setAttribute("role", "list");
  root.setAttribute("aria-label", label);

  /** Cells whose press is their row's own action, not a copy. */
  const presses = new WeakMap<HTMLElement, (cell: HTMLElement) => void>();
  const removeGestures = installCopyCells(root, (cell) => presses.get(cell));

  const cell = (kind: "key" | "value", text: string, copyText = text, hint?: string): { button: HTMLButtonElement; label: Text } => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `ui-kv-cell ui-kv-${kind}`;
    button.dataset.copy = copyText;
    button.setAttribute("aria-description", "Copies to the clipboard");
    // The highlight belongs to the text run, not to the button: an inline span with cloned box decoration hugs the text
    // with even padding and follows every line of a wrapped value. The copy confirmation fades this run out and sits
    // over the cell's edge (copy-feedback.ts), so the cell never changes size.
    const span = document.createElement("span");
    span.className = "ui-kv-text";
    const label = document.createTextNode(text);
    span.append(label);
    button.append(span);
    if (hint) {
      const sub = document.createElement("span");
      sub.className = "ui-kv-hint";
      sub.textContent = hint;
      button.append(sub);
    }
    return { button, label };
  };

  let entries: Entry[] = [];

  /** Writes what a value shows: its mark, its text, what it copies and what a press does. */
  const paint = (entry: Entry): void => {
    const { row, value, label: text } = entry;
    text.data = row.value;
    value.dataset.copy = row.copy ?? row.value;
    const run = value.querySelector(".ui-kv-text")!;
    let mark = run.querySelector<HTMLElement>(":scope > .ui-kv-mark");
    if (row.mark) {
      if (!mark) {
        mark = document.createElement("span");
        mark.className = "ui-mark ui-kv-mark";
        mark.setAttribute("aria-hidden", "true");
        run.prepend(mark);
      }
      mark.dataset.mark = row.mark;
    } else mark?.remove();
    if (row.press) {
      value.classList.add("ui-kv-press");
      value.dataset.tip = row.press.tip;
      value.removeAttribute("aria-description");
      value.setAttribute("aria-label", `${row.value}. ${row.press.tip}`);
      presses.set(value, row.press.run);
    } else {
      value.classList.remove("ui-kv-press");
      delete value.dataset.tip;
      value.removeAttribute("aria-label");
      value.setAttribute("aria-description", "Copies to the clipboard");
      presses.delete(value);
    }
  };

  const rowNode = (row: KeyValueRow): HTMLElement => {
    const item = document.createElement("div");
    item.className = "ui-kv-row";
    item.setAttribute("role", "listitem");
    const key = cell("key", row.key, row.key, row.hint);
    const value = cell("value", row.value, row.copy ?? row.value);
    const entry: Entry = { row, value: value.button, label: value.label, swap: undefined };
    paint(entry);
    if (row.wide) {
      item.classList.add("ui-kv-wide");
      if (row.press) {
        const chevron = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        chevron.setAttribute("viewBox", "0 0 24 24");
        chevron.setAttribute("aria-hidden", "true");
        chevron.setAttribute("class", "ui-kv-chevron");
        chevron.innerHTML = ICONS.next;
        value.button.append(chevron);
      }
      item.append(value.button);
    } else item.append(key.button, value.button);
    if (row.meter !== undefined) {
      const meter = document.createElement("span");
      meter.className = "ui-kv-meter";
      meter.setAttribute("role", "meter");
      meter.setAttribute("aria-valuemin", "0");
      meter.setAttribute("aria-valuemax", "100");
      meter.setAttribute("aria-label", `${row.key} used`);
      item.append(meter);
      entry.meter = meter;
      paintMeter(meter, row.meter);
    }
    if (row.panel) item.append(row.panel);
    entries.push(entry);
    return item;
  };
  const paintMeter = (meter: HTMLElement, percent: number): void => {
    meter.setAttribute("aria-valuenow", String(Math.round(percent)));
    meter.style.setProperty("--meter", String(Math.max(0, Math.min(100, percent)) / 100));
  };

  /** What decides the structure: rows that differ only in value, mark, press and meter level patch in place. */
  const shapeOf = (rows: KeyValueRow[]): string => rows.map((r) => `${r.group ?? ""}\u0001${r.key}\u0001${r.hint ?? ""}\u0001${r.meter === undefined ? "-" : "m"}${r.wide ? "w" : ""}${r.wide && r.press ? "p" : ""}${r.panel ? "n" : ""}`).join("\u0002");
  let shape: string | undefined;
  const sameFace = (a: KeyValueRow, b: KeyValueRow): boolean => a.value === b.value && a.mark === b.mark && a.press?.tip === b.press?.tip && Boolean(a.press) === Boolean(b.press);

  const patch = (rows: KeyValueRow[]): void => {
    rows.forEach((row, i) => {
      const entry = entries[i]!;
      const was = entry.row;
      entry.row = row;
      // The action itself may change without the row looking different (a new closure over fresh state).
      if (row.press) presses.set(entry.value, row.press.run);
      if (entry.meter && row.meter !== undefined) paintMeter(entry.meter, row.meter);
      if (sameFace(was, row)) { entry.value.dataset.copy = row.copy ?? row.value; return; }
      if (!root.isConnected || entry.value.offsetParent === null) { window.clearTimeout(entry.swap); delete entry.value.dataset.swapping; paint(entry); return; }
      // The value fades out, says its new thing while it is gone, and fades back in. A change that arrives while it is
      // fading out is written with the first one's fade: only the latest row is ever painted.
      if (entry.swap === undefined) {
        entry.value.dataset.swapping = "";
        entry.swap = window.setTimeout(() => {
          entry.swap = undefined;
          paint(entry);
          delete entry.value.dataset.swapping;
        }, SWAP_MS);
      }
    });
  };

  let titleSeq = 0;
  return {
    root,
    set(rows) {
      const next = shapeOf(rows);
      if (next === shape && entries.length === rows.length && rows.every((r, i) => r.panel === entries[i]!.row.panel)) { patch(rows); return; }
      for (const entry of entries) window.clearTimeout(entry.swap);
      shape = next;
      entries = [];
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
      for (const entry of entries) window.clearTimeout(entry.swap);
      removeGestures();
      root.remove();
    },
  };
}
