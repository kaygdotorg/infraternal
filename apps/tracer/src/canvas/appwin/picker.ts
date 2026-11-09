/**
 * The "New window" picker (D208 A1): one list of everything that can be opened on a machine, with one field that
 * filters it. A machine's group holds its shell, its whole screen (or each of its displays) and every app window that is
 * open on it right now, each with the app's tile, the app's name and the window's title. Typing a machine's name, an
 * app, or words of a title narrows the list; nothing is a tab or a mode (TASTE: one input, not modes).
 *
 * The list is live: while the picker is open the machines are asked again every couple of seconds and the rows follow,
 * in place. A row that appears fades in, the rows that move glide by a transform, and the highlighted row and the
 * typed text are never disturbed by an update.
 *
 * It reuses the session manager's card (`cl-sx-*` classes, the anchored popover, the overlay material) so the two
 * popovers look and move the same; only the search field and the app tile are new.
 */
import { openAnchoredPopover, type AnchoredPopover, type PopoverSource } from "../../../../../packages/ui/src/anchored-popover";
import { hostIconMarkup } from "../../../../../packages/ui/src/host-icons";
import { entityTile } from "../../../../../packages/ui/src/entity-chip";
import { ICONS } from "../../../../../packages/ui/src/icons";
import { createSpinner } from "../../../../../packages/ui/src/spinner";
import type { Ctx } from "../context";
import { el, reduced } from "../dom";
import type { HostEntry } from "../sessions/adapter";
import { ICON } from "../views/icons";
import { entryTitle, matches, type Entry } from "./inventory";
import { canStream, type Machines } from "./machines";
import { EASE_OUT } from "../../../../../packages/ui/src/motion";

/** The ease-out curve for rows that glide to a new place. */
/** Icon paths (a display) for screen rows. */
const SCREEN_ICON = '<rect x="3" y="4.5" width="18" height="12.5" rx="2.5"/><path d="M8.5 20.5h7M12 17v3.5"/>';
/** The padlock drawn beside a missing-permission note. */
const LOCK_ICON = ICONS.lock;

/** What choosing a row opens. */
export type Choice =
  | { kind: "shell"; machine: HostEntry }
  | { kind: "stream"; machine: HostEntry; entry: Entry };

/** One line of the picker: what choosing it opens, how it looks, and the words the search field matches. */
interface Row {
  id: string;
  choice: Choice;
  mark: "shell" | "screen" | "app";
  name: string;
  sub: string;
  meta: string;
  /** Lower-cased words the field matches: the machine's name is always part of it, so a machine's name lists the machine. */
  words: string;
  appName?: string;
}

/** The rows of one machine, in the order they are shown. */
export function rowsOf(machine: HostEntry, machines: Machines): Row[] {
  const rows: Row[] = [{
    id: `${machine.id}/shell`, choice: { kind: "shell", machine }, mark: "shell", name: "Shell", sub: machine.user ? `${machine.user}@${machine.name}` : machine.name, meta: "",
    words: `${machine.name} shell terminal ssh console`.toLowerCase(),
  }];
  if (!canStream(machine)) return rows;
  const inv = machines.state(machine.id)?.inventory;
  for (const screen of inv?.screens ?? []) {
    rows.push({ id: `${machine.id}/${screen.key}`, choice: { kind: "stream", machine, entry: screen }, mark: "screen", name: screen.name, sub: entryTitle(screen), meta: "", words: `${machine.name} ${screen.name} screen display desktop`.toLowerCase() });
  }
  for (const w of inv?.windows ?? []) {
    rows.push({ id: `${machine.id}/${w.key}`, choice: { kind: "stream", machine, entry: w }, mark: "app", name: w.appName, sub: entryTitle(w), meta: w.onScreen || !w.title ? "" : "minimised", words: `${machine.name} ${w.appName} ${w.title} ${w.bundleId ?? ""}`.toLowerCase(), appName: w.appName });
  }
  return rows;
}

/** True when every word of `query` (any order, any case) appears in the row's search words. An empty query matches all. */
const wordsMatch = (row: Row, query: string): boolean => {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return words.every((w) => row.words.includes(w));
};

/**
 * The "New window" popover. It polls the machines while it is open and repaints rows in place, so the highlighted row and the typed text
 * are not disturbed. Arrow keys move the highlight, Enter chooses the highlighted row (or the first one), and scrolling the canvas
 * closes it. `choose` gets the picked `Choice`; `onClosed` runs once, after the popover has closed and the picker has stopped polling.
 */
export class Picker {
  readonly popover: AnchoredPopover;
  private readonly scroll: HTMLElement;
  private readonly input: HTMLInputElement;
  private readonly life = new AbortController();
  private readonly stopPoll: () => void;
  private readonly rowEls = new Map<string, HTMLElement>();
  private active: string | undefined;
  private query = "";

  constructor(private readonly cx: Ctx, private readonly machines: Machines, anchor: HTMLElement, source: PopoverSource, private readonly choose: (choice: Choice, how: PopoverSource) => void, onClosed: () => void, initialQuery = "") {
    const { stage } = cx;
    this.popover = openAnchoredPopover({ stage, anchor, label: "New window", className: "cl-sx-pop aw-pop", align: "start", maxWidth: 400,
      // On a phone the key tray (and the canvas row it carries) sits at the foot of the screen: the card stops above it.
      bottomLimit: () => { const tray = stage.querySelector<HTMLElement>("#keybar"); return tray && getComputedStyle(tray).display !== "none" ? tray.getBoundingClientRect().top - 8 : undefined; } }, source, () => { this.dispose(); onClosed(); });
    const root = this.popover.root;
    root.innerHTML = `<header class="cl-sx-head aw-head"><span class="cl-sx-logo"><svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.search}</svg></span><input class="aw-search" type="text" role="combobox" aria-expanded="true" aria-autocomplete="list" aria-controls="aw-list" placeholder="Search windows and machines" spellcheck="false" autocomplete="off" aria-label="Search windows and machines"></header><div class="cl-sx-scroll aw-list" id="aw-list" role="listbox" aria-label="Windows you can open"></div>`;
    this.input = root.querySelector<HTMLInputElement>(".aw-search")!;
    this.input.value = initialQuery;
    this.query = initialQuery;
    this.scroll = root.querySelector<HTMLElement>(".aw-list")!;
    this.input.addEventListener("input", () => { this.query = this.input.value; this.active = undefined; this.render(); });
    this.input.addEventListener("keydown", (e) => this.key(e));
    this.scroll.addEventListener("click", (e) => {
      const row = (e.target as Element).closest<HTMLElement>("[data-row]");
      const found = row && this.find(row.dataset.row!);
      if (found) this.choose(found.choice, e.detail === 0 ? "keyboard" : "pointer");
    });
    // The canvas moving under it ends it: the card belongs to the screen position it opened at.
    cx.viewport.addEventListener("wheel", () => this.popover.close("pointer"), { passive: true, signal: this.life.signal });
    const off = machines.onChange(() => this.render());
    this.life.signal.addEventListener("abort", off, { once: true });
    this.stopPoll = machines.poll();
    this.render();
    // The field takes the keys at once on a device with a keyboard; a phone's keyboard waits for a tap in the field.
    if (source === "keyboard" || !matchMedia("(pointer: coarse)").matches) this.input.focus({ preventScroll: true });
  }

  /** Closes the popover; `source` says whether the pointer or the keyboard caused it, so focus returns sensibly. */
  close(source: PopoverSource): void { this.popover.close(source); }
  private dispose(): void { this.life.abort(); this.stopPoll(); }

  private find(id: string): Row | undefined { return this.all().find((r) => r.id === id); }
  private all(): Row[] { return this.cx.adapters.sessions.hosts().flatMap((m) => rowsOf(m, this.machines)); }

  private visibleIds(): string[] { return [...this.scroll.querySelectorAll<HTMLElement>("[data-row]")].map((n) => n.dataset.row!); }

  private key(e: KeyboardEvent): void {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const ids = this.visibleIds();
      if (!ids.length) return;
      const at = this.active ? ids.indexOf(this.active) : -1;
      const next = ids[Math.max(0, Math.min(ids.length - 1, at + (e.key === "ArrowDown" ? 1 : -1)))]!;
      this.setActive(next, true);
    } else if (e.key === "Enter") {
      const row = this.active ? this.find(this.active) : this.find(this.visibleIds()[0] ?? "");
      if (row) { e.preventDefault(); this.choose(row.choice, "keyboard"); }
    }
  }

  private setActive(id: string | undefined, scroll: boolean): void {
    this.active = id;
    for (const [rowId, node] of this.rowEls) {
      const on = rowId === id;
      node.toggleAttribute("data-kbd", on);
      node.setAttribute("aria-selected", String(on));
    }
    const node = id ? this.rowEls.get(id) : undefined;
    if (id) this.input.setAttribute("aria-activedescendant", `aw-${id}`); else this.input.removeAttribute("aria-activedescendant");
    if (scroll) node?.scrollIntoView({ block: "nearest" });
  }

  // ---- drawing ----------------------------------------------------------------------------------------------------

  private markFor(row: Row): HTMLElement {
    const mark = el("span", "aw-rowmark");
    if (row.mark === "app") mark.append(entityTile(row.appName ?? row.name));
    else mark.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${row.mark === "shell" ? ICON.terminal : SCREEN_ICON}</svg>`;
    return mark;
  }

  private rowEl(row: Row): HTMLElement {
    const node = el("button", "cl-sx-main aw-row");
    node.type = "button";
    node.dataset.row = row.id;
    node.id = `aw-${row.id}`;
    node.setAttribute("role", "option");
    node.tabIndex = -1;
    node.setAttribute("aria-label", `${row.name}${row.sub ? `, ${row.sub}` : ""}, on ${row.choice.machine.name}`);
    node.append(this.markFor(row));
    const text = el("span", "cl-sx-text");
    text.append(el("span", "cl-sx-line aw-name", row.name), el("span", "cl-sx-sub-line aw-sub", row.sub || " "));
    const meta = el("span", "cl-sx-meta", row.meta);
    node.append(text, meta);
    node.addEventListener("pointermove", () => { if (this.active !== row.id) this.setActive(row.id, false); });
    return node;
  }

  /** Repaints the list from the machines' current answers, keeping rows that did not change and gliding those that moved. */
  render(): void {
    const machines = this.cx.adapters.sessions.hosts();
    const before = new Map([...this.rowEls].map(([id, node]) => [id, node.getBoundingClientRect().top]));
    const groups: HTMLElement[] = [];
    const keep = new Map<string, HTMLElement>();
    let count = 0;
    for (const machine of machines) {
      const all = rowsOf(machine, this.machines);
      const rows = all.filter((r) => wordsMatch(r, this.query));
      const state = canStream(machine) ? this.machines.state(machine.id) : undefined;
      const notes = this.notes(machine, state);
      if (!rows.length && !(notes.length && !this.query)) continue;
      const group = el("section", "cl-sx-group aw-group");
      group.setAttribute("role", "group");
      group.setAttribute("aria-label", machine.name);
      const head = el("h3", "cl-sx-eyebrow aw-eyebrow");
      head.innerHTML = machine.os ? hostIconMarkup(machine.os, "ui-host-mark") : "";
      head.append(el("span", "", machine.name));
      group.append(head);
      const ul = el("div", "cl-sx-list");
      for (const row of rows) {
        let node = this.rowEls.get(row.id);
        const fresh = !node;
        if (!node) node = this.rowEl(row);
        else this.updateRow(node, row);
        keep.set(row.id, node);
        ul.append(node);
        if (fresh && before.size && !reduced.matches) node.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease-out" });
        count++;
      }
      for (const n of notes) ul.append(n);
      group.append(ul);
      groups.push(group);
    }
    this.rowEls.clear();
    for (const [id, node] of keep) this.rowEls.set(id, node);
    if (!count) groups.push(el("p", "cl-sx-empty", this.query ? "Nothing matches" : "Nothing to open yet"));
    this.scroll.replaceChildren(...groups);
    // Rows that were already there and moved glide by a transform to their new place (no layout animation, no jump).
    if (!reduced.matches) {
      for (const [id, node] of keep) {
        const was = before.get(id);
        if (was === undefined) continue;
        const dy = was - node.getBoundingClientRect().top;
        if (Math.abs(dy) > 1) node.animate([{ transform: `translateY(${dy}px)` }, { transform: "none" }], { duration: 240, easing: EASE_OUT });
      }
    }
    const ids = this.visibleIds();
    if (!this.active || !ids.includes(this.active)) this.active = this.query ? ids[0] : undefined;
    this.setActive(this.active, false);
    this.popover.place();
  }

  private updateRow(node: HTMLElement, row: Row): void {
    const name = node.querySelector<HTMLElement>(".aw-name"), sub = node.querySelector<HTMLElement>(".aw-sub"), meta = node.querySelector<HTMLElement>(".cl-sx-meta");
    if (name && name.textContent !== row.name) name.textContent = row.name;
    if (sub && sub.textContent !== (row.sub || " ")) sub.textContent = row.sub || " ";
    if (meta && meta.textContent !== row.meta) meta.textContent = row.meta;
  }

  /** What a machine says about itself under its rows: still looking, unreachable, or missing a permission and what to do. */
  private notes(machine: HostEntry, state: ReturnType<Machines["state"]>): HTMLElement[] {
    if (!canStream(machine)) return [];
    const out: HTMLElement[] = [];
    if (!state || (state.status === "loading" && !state.inventory)) {
      const loading = el("div", "cl-sx-state aw-note");
      loading.dataset.kind = "loading";
      loading.setAttribute("role", "status");
      loading.append(createSpinner(), el("span", "", `Looking for windows on ${machine.name}`));
      out.push(loading);
    } else if (state.status === "error" && !state.inventory) {
      out.push(el("p", "cl-sx-empty aw-note", `${machine.name} did not answer. It may be asleep.`));
    }
    const p = state?.inventory?.permissions;
    if (p?.screenRecording === false) {
      const note = el("p", "cl-sx-empty aw-note aw-perm");
      note.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${LOCK_ICON}</svg>`;
      note.append(`Allow Screen Recording for infraternal on ${machine.name}: System Settings, Privacy & Security.`);
      out.push(note);
    } else if (p?.accessibility === false) {
      const note = el("p", "cl-sx-empty aw-note aw-perm");
      note.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${LOCK_ICON}</svg>`;
      note.append(`To control ${machine.name} too, allow Accessibility for infraternal: System Settings, Privacy & Security.`);
      out.push(note);
    }
    return out;
  }
}

/** The rows the palette lists for the machines' cached answers: "Open <app> on <machine>" and the whole screen. */
export function paletteRows(machines: Machines, query?: string): Array<{ machine: HostEntry; entry: Entry; label: string; hint: string }> {
  const out: Array<{ machine: HostEntry; entry: Entry; label: string; hint: string }> = [];
  for (const machine of machines.streamable()) {
    const inv = machines.state(machine.id)?.inventory;
    if (!inv) continue;
    for (const s of inv.screens) out.push({ machine, entry: s, label: `Open ${s.name.toLowerCase()} on ${machine.name}`, hint: "screen · display · desktop" });
    for (const w of inv.windows) if (!query || matches(w, query)) out.push({ machine, entry: w, label: `Open ${w.appName} on ${machine.name}`, hint: `${w.title || "window"}${w.onScreen ? "" : " · minimised"} · app window` });
  }
  return out;
}
