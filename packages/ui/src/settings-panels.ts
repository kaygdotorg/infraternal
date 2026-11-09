/**
 * The contents of the Settings windows (D160). Settings is a view on the canvas and each section
 * is a window; these functions fill a window's body. Sections that already exist as shared
 * components (Toolbar, Shortcuts, About) are filled by their own `render`; the rest live here:
 * Hosts, Window Sizes, Devices, Account and the admin-only placeholders (Users, Access, Found hosts). The Appearance
 * Themes window is `canvas/themes/editor.on-demand.ts`, built from the option lists and sliders here.
 *
 * Rows are the shared kinds: a tappable row with a tick for the current choice, a key/value
 * list for facts, icon buttons with the warm tooltip, and the compact confirmation for a
 * destructive step.
 */
import { ICONS } from "./icons";
import { createKeyValueList } from "./kv-list";
import { enhanceSwitch } from "./switch";
import { mountConfirmTip } from "./tooltip";

/** One on/off preference: a titled row with a label, a quiet subtitle and a switch. */
export interface SwitchPref {
  id: string;
  title: string;
  label: string;
  hint?: string;
  get(): boolean;
  set(on: boolean): void;
  /** Called after the value changes (here or elsewhere); returns a remover. */
  onChange(listener: () => void): () => void;
}

const CHECK = '<path d="m5.5 12.5 4 4 9-9"/>';

/** A section title of a Settings window (shared with the Themes window). */
export function heading(text: string): HTMLElement {
  const h = document.createElement("h3");
  h.className = "ui-ts-title";
  h.textContent = text;
  return h;
}

export interface ChoiceItem { id: string; label: string; hint?: string; swatch?: { bg: string; accent: string } }

/**
 * Decides once per list, and again only when its width changes (a ResizeObserver on the list itself, the list being the
 * container: never the viewport, never per frame), how descriptions sit with their names. Beside: the name is left and
 * the description right-aligned at the end of the text column (see the CSS), the layout of every row that fits. Under:
 * when any row's name + gap + description is wider than the room the list's text column has, every row of the list puts
 * its description under its name as a subtitle instead. Each row is measured against its own two widths, not against the
 * widest name, because beside the names no longer share a column. Measured in the beside layout, where names and
 * descriptions are `nowrap` and report their natural widths. One decision per list keeps every row in the same mode (a
 * short row never stacks alone or stays beside while its siblings stack), and a stacked list does not jump when the
 * selection changes. A CSS container query cannot compare a container with the width of its own text, hence the observer.
 */
function fitHints(list: HTMLElement): void {
  let width = -1;
  const decide = (): void => {
    if (!list.isConnected) { observer.disconnect(); return; }
    if (list.clientWidth === 0) return;
    list.removeAttribute("data-stacked");
    const hinted = [...list.querySelectorAll<HTMLElement>(".ui-sp-text")].filter((t) => t.querySelector<HTMLElement>(".ui-sp-hint")!.textContent !== "");
    if (hinted.length === 0) return;
    // The used widths, not rects: a rect carries every transform above it (the canvas camera's zoom), and a name measured
    // at 0.8 would be judged to fit at 1. Rounded up so a fraction of a pixel never lets a name touch its description.
    const used = (n: Element): number => Number.parseFloat(getComputedStyle(n).width) || 0;
    const stack = hinted.some((t) => {
      const gap = Number.parseFloat(getComputedStyle(t).columnGap) || 0;
      return Math.ceil(used(t.querySelector(".ui-sp-label")!) + gap + used(t.querySelector(".ui-sp-hint")!)) > used(t);
    });
    if (stack) list.dataset.stacked = "";
  };
  const observer = new ResizeObserver(() => {
    if (list.clientWidth === width) return;
    width = list.clientWidth;
    decide();
  });
  observer.observe(list);
  void document.fonts?.ready.then(decide);
}

/**
 * A titled radio list of rows: a label on the left, an optional quiet description (the technical detail) on the right, and
 * a tick in its own column at the far right on the current one. The name never wraps and is never truncated. A list reads
 * as one: if any row cannot hold its name and description on one line, every row of the list puts its description under
 * its name as a subtitle (`data-stacked` on the list, see `fitHints`), so text never collides at any width (TASTE: "Text
 * never collides"). `reserveSwatch` keeps the swatch's place empty in a list without swatches whose window also has a list
 * with them (Settings → Appearance), so names line up across the window; a window without swatches reserves nothing.
 */
export function choiceBlock(title: string, items: ChoiceItem[], kind: string, current: () => string, pick: (id: string) => void, reserveSwatch = false): HTMLElement {
  const block = document.createElement("section");
  block.append(heading(title));
  const list = document.createElement("div");
  list.className = "ui-sp-list";
  list.setAttribute("role", "radiogroup");
  list.setAttribute("aria-label", title);
  for (const item of items) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "ui-sp-row";
    row.dataset.id = item.id;
    row.setAttribute("role", "radio");
    const lead = item.swatch ? '<span class="ui-sp-swatch" aria-hidden="true"></span>' : reserveSwatch ? '<span class="ui-sp-slot" aria-hidden="true"></span>' : "";
    row.innerHTML = `${lead}<span class="ui-sp-text"><span class="ui-sp-label"></span><span class="ui-sp-hint"></span></span><svg class="ui-sp-tick" viewBox="0 0 24 24" aria-hidden="true">${CHECK}</svg>`;
    (row.querySelector(".ui-sp-label") as HTMLElement).textContent = item.label;
    (row.querySelector(".ui-sp-hint") as HTMLElement).textContent = item.hint ?? "";
    const sw = row.querySelector<HTMLElement>(".ui-sp-swatch");
    if (sw && item.swatch) { sw.style.background = item.swatch.bg; sw.style.setProperty("--dot", item.swatch.accent); }
    row.addEventListener("click", () => pick(item.id));
    list.append(row);
  }
  block.append(list);
  fitHints(list);
  block.dataset.kind = kind;
  block.dataset.current = current();
  return block;
}

/** A titled row with a switch for an on/off preference. */
function switchBlock(pref: SwitchPref): { block: HTMLElement; sync(): void; dispose(): void } {
  const block = document.createElement("section");
  block.dataset.kind = pref.id;
  block.append(heading(pref.title));
  const row = document.createElement("label");
  row.className = "ui-sp-row ui-sp-switch";
  row.innerHTML = '<span class="ui-sp-names"><span class="ui-sp-label"></span><span class="ui-sp-hint"></span></span><input type="checkbox">';
  (row.querySelector(".ui-sp-label") as HTMLElement).textContent = pref.label;
  (row.querySelector(".ui-sp-hint") as HTMLElement).textContent = pref.hint ?? "";
  const input = row.querySelector<HTMLInputElement>("input")!;
  input.setAttribute("aria-label", pref.label);
  const toggle = enhanceSwitch(input);
  input.addEventListener("change", () => pref.set(input.checked));
  block.append(row);
  const off = pref.onChange(() => toggle.set(pref.get()));
  toggle.set(pref.get());
  return { block, sync: () => toggle.set(pref.get()), dispose: () => { off(); toggle.dispose(); } };
}

/**
 * A group of one fact and, when something can be done about it, one action: the host-connection lock. The product
 * owns the state; the panel only draws it and calls `act`.
 */
export interface StatusActionPref {
  id: string;
  title: string;
  /** What is true now, in plain words; undefined hides the whole group (the state is unknown or not the viewer's to see). */
  text(): string | undefined;
  /** The button's label, or undefined when there is nothing to do (unlocked, or the viewer may not). */
  action(): string | undefined;
  act(): void;
  /** Asks the product for a fresh answer; called when the panel opens. */
  refresh(): void;
  onChange(listener: () => void): () => void;
}

export interface HostsApi {
  /** Switches grouped under one title each; `title` is the group's heading. */
  switches: SwitchPref[];
  /** Further groups of a state and its action, after the switches. */
  statuses?: StatusActionPref[];
}

/** One titled group: a row of words and, at its end, a pill button that fades away when there is nothing to do. */
function statusBlock(pref: StatusActionPref): { block: HTMLElement; dispose(): void } {
  const block = document.createElement("section");
  block.dataset.kind = pref.id;
  block.append(heading(pref.title));
  const row = document.createElement("div");
  row.className = "ui-sp-row ui-sp-status";
  row.innerHTML = '<span class="ui-sp-names"><span class="ui-sp-label"></span></span><button type="button" class="ui-ts-reset ui-sp-status-action"></button>';
  const label = row.querySelector<HTMLElement>(".ui-sp-label")!;
  const button = row.querySelector<HTMLButtonElement>("button")!;
  button.addEventListener("click", () => pref.act());
  block.append(row);
  const paint = (): void => {
    const text = pref.text();
    block.hidden = text === undefined;
    if (text !== undefined) label.textContent = text;
    const action = pref.action();
    if (action) button.textContent = action;
    // The button stays in the layout while it fades so the words do not jump; inert keeps it out of reach.
    button.dataset.shown = String(Boolean(action));
    button.toggleAttribute("inert", !action);
  };
  paint();
  const off = pref.onChange(paint);
  pref.refresh();
  return { block, dispose: off };
}

/** Settings, Hosts: what the product shows and does for machines. One titled group per concern: the details popover's facts, then the host-connection lock. */
export function renderHosts(container: HTMLElement, api: HostsApi): () => void {
  const root = document.createElement("div");
  root.className = "ui-sp";
  container.append(root);
  const blocks = api.switches.map(switchBlock);
  const statuses = (api.statuses ?? []).map(statusBlock);
  root.append(...blocks.map((b) => b.block), ...statuses.map((b) => b.block));
  return () => { for (const b of blocks) b.dispose(); for (const b of statuses) b.dispose(); root.remove(); };
}

/** Ticks the row of `current` in a choice block. */
export function paintChoice(block: HTMLElement, current: string): void {
  for (const row of block.querySelectorAll<HTMLElement>(".ui-sp-row")) {
    const on = row.dataset.id === current;
    row.setAttribute("aria-checked", String(on));
    row.toggleAttribute("data-current", on);
  }
}

export interface WindowSizesApi {
  /** One titled group of choices per kind of device. `id` is what `get` and `set` take. */
  groups: Array<{ id: string; title: string; options: Array<{ id: string; label: string; hint: string }> }>;
  get(group: string): string;
  set(group: string, option: string): void;
  /** Called after a size changes (here or elsewhere); returns a remover. */
  onChange(listener: () => void): () => void;
}

/** How wide a terminal window is, per kind of device. Plain option names; the percentage lives in the subtitle. */
export function renderWindowSizes(container: HTMLElement, api: WindowSizesApi): () => void {
  const root = document.createElement("div");
  root.className = "ui-sp";
  root.dataset.ticks = "";
  container.append(root);
  const blocks = api.groups.map((g) => ({ id: g.id, block: choiceBlock(g.title, g.options, `window-size-${g.id}`, () => api.get(g.id), (id) => api.set(g.id, id)) }));
  for (const b of blocks) root.append(b.block);
  const paint = (): void => { for (const b of blocks) paintChoice(b.block, api.get(b.id)); };
  paint();
  const off = api.onChange(paint);
  return () => { off(); root.remove(); };
}

export type DeviceKind = "phone" | "tablet" | "laptop" | "desktop";
export interface DeviceRow { id: string; name: string; kind: DeviceKind; type: string; lastSeen: string; view: string; online: boolean; current?: boolean }
export interface DevicesApi {
  devices: DeviceRow[];
  jump(view: string): void;
  signOut(device: DeviceRow): void;
  /** A device's name was edited. */
  rename(device: DeviceRow, name: string): void;
}

const DEVICE_ICON: Record<DeviceKind, string> = {
  phone: '<rect x="7" y="3" width="10" height="18" rx="2.5"/><path d="M11 18h2"/>',
  tablet: '<rect x="4" y="4" width="16" height="16" rx="2.5"/><path d="M11 17h2"/>',
  laptop: '<rect x="5" y="5" width="14" height="10" rx="2"/><path d="M3 19h18"/>',
  desktop: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M9 20h6M12 16v4"/>',
};
export const deviceIcon = (kind: DeviceKind): string => DEVICE_ICON[kind];

const ICON_JUMP = '<path d="M7 17 17 7M9 7h8v8"/>';

/** The signed-in devices: name, type, last seen, current view, online; jump to its view, sign it out (with the compact confirmation). */
export function renderDevices(container: HTMLElement, api: DevicesApi): () => void {
  const root = document.createElement("div");
  root.className = "ui-sp";
  const list = document.createElement("ul");
  list.className = "ui-sp-devices";
  container.append(root);
  root.append(list);
  const paint = (): void => {
    list.replaceChildren();
    for (const d of api.devices) {
      const li = document.createElement("li");
      li.className = "ui-sp-device";
      li.dataset.id = d.id;
      li.innerHTML = `<span class="ui-sp-kind" aria-hidden="true"><svg viewBox="0 0 24 24">${DEVICE_ICON[d.kind]}</svg><i class="ui-sp-dot" data-online="${d.online}"></i></span>
        <span class="ui-sp-names"><span class="ui-sp-name-row"><input class="ui-sp-name" type="text" spellcheck="false" autocomplete="off" maxlength="40"><span class="ui-sp-here"></span></span><span class="ui-sp-sub"></span></span><span class="ui-sp-actions"></span>`;
      const name = li.querySelector<HTMLInputElement>(".ui-sp-name")!;
      name.value = d.name;
      name.setAttribute("aria-label", `Name of ${d.name}`);
      name.size = Math.max(6, d.name.length);
      name.addEventListener("input", () => { name.size = Math.max(6, name.value.length); });
      const commit = (): void => { const v = name.value.trim(); if (v && v !== d.name) { d.name = v; api.rename(d, v); } else name.value = d.name; };
      name.addEventListener("blur", commit);
      name.addEventListener("keydown", (e) => { if (e.key === "Enter") name.blur(); else if (e.key === "Escape") { name.value = d.name; name.blur(); } });
      (li.querySelector(".ui-sp-here") as HTMLElement).textContent = d.current ? "this device" : "";
      (li.querySelector(".ui-sp-sub") as HTMLElement).textContent = `${d.type} · ${d.online ? "online" : `last seen ${d.lastSeen}`} · in ${d.view}`;
      const actions = li.querySelector<HTMLElement>(".ui-sp-actions")!;
      const button = (label: string, icon: string, run: (b: HTMLButtonElement) => void): void => {
        const b = document.createElement("button");
        b.type = "button"; b.className = "ui-window-action"; b.setAttribute("aria-label", label); b.dataset.tip = label;
        b.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${icon}</svg>`;
        b.addEventListener("click", () => run(b));
        actions.append(b);
      };
      button("Jump to its view", ICON_JUMP, () => api.jump(d.view));
      if (!d.current) button("Sign out this device", ICONS.signOut, (b) => mountConfirmTip(b, {
        label: `Sign out ${d.name}`, title: `Sign out ${d.name}?`, effect: "That device will be signed out and will need your passkey to sign in again.",
        named: true, confirmLabel: "Sign out device", cancelLabel: "Keep signed in", onConfirm: () => { api.signOut(d); paint(); },
      }));
      list.append(li);
    }
  };
  paint();
  return () => root.remove();
}

type FactGroup = { title: string; rows: Array<{ key: string; value: string }> };

/** The titled key/value groups of a facts window, appended to `root`. */
function factSections(root: HTMLElement, label: string, groups: FactGroup[]): Array<{ dispose(): void }> {
  return groups.map((g) => {
    const section = document.createElement("section");
    section.append(heading(g.title));
    const list = createKeyValueList(`${label}: ${g.title}`);
    list.set(g.rows);
    section.append(list.root);
    root.append(section);
    return list;
  });
}

/** A window of facts (placeholders): a key/value list under a heading. */
export function renderFacts(container: HTMLElement, label: string, groups: FactGroup[]): () => void {
  const root = document.createElement("div");
  root.className = "ui-sp";
  container.append(root);
  const lists = factSections(root, label, groups);
  return () => { for (const l of lists) l.dispose(); root.remove(); };
}

export interface AccountApi {
  /** Facts the product knows about the account, shown above the device group. */
  groups?: FactGroup[];
  /** Account security uses the same state/action rows as host settings. */
  statuses?: StatusActionPref[];
  /** Signs this device out. The product asks first (the compact confirmation) at `anchor`, the button that was pressed. */
  signOut(anchor: HTMLElement): void;
}

/** Settings, Account (D230): the person's own details, and the way out of this device. */
export function renderAccount(container: HTMLElement, api: AccountApi): () => void {
  const root = document.createElement("div");
  root.className = "ui-sp";
  container.append(root);
  const lists = factSections(root, "Account", api.groups ?? []);
  const statuses = (api.statuses ?? []).map(statusBlock);
  root.append(...statuses.map((status) => status.block));
  const block = document.createElement("section");
  block.dataset.kind = "this-device";
  block.append(heading("This device"));
  const row = document.createElement("div");
  row.className = "ui-sp-row ui-sp-status";
  row.innerHTML = '<span class="ui-sp-names"><span class="ui-sp-label"></span><span class="ui-sp-hint"></span></span>';
  (row.querySelector(".ui-sp-label") as HTMLElement).textContent = "Sign out of this device";
  (row.querySelector(".ui-sp-hint") as HTMLElement).textContent = "You will need your passkey to sign in again";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "ui-window-action";
  button.dataset.action = "sign-out";
  button.setAttribute("aria-label", "Sign out");
  button.dataset.tip = "Sign out";
  button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.signOut}</svg>`;
  button.addEventListener("click", () => api.signOut(button));
  row.append(button);
  block.append(row);
  root.append(block);
  return () => { for (const l of lists) l.dispose(); for (const status of statuses) status.dispose(); root.remove(); };
}
