/**
 * The contents of the Settings windows (D160). Settings is a view on the canvas and each section
 * is a window; these functions fill a window's body. Sections that already exist as shared
 * components (Toolbar, Shortcuts, About) are filled by their own `render`; the rest live here:
 * Appearance (theme, font, background and card transparency), Devices, Account and the
 * admin-only placeholders (Users, Access, Found hosts).
 *
 * Rows are the shared kinds: a tappable row with a tick for the current choice, a key/value
 * list for facts, icon buttons with the warm tooltip, and the compact confirmation for a
 * destructive step. Everything applies live: choosing a theme or a font repaints the whole screen
 * at once, through the same actions the command palette uses.
 */
import { createCapsuleTabs } from "./capsule-tabs";
import { ICONS } from "./icons";
import { createKeyValueList } from "./kv-list";
import { createSlider } from "./slider";
import { enhanceSwitch } from "./switch";
import { mountConfirmTip } from "./tooltip";
import { LEVEL_NAMES } from "./themes";

export interface AppearanceApi {
  themes: Array<{ id: string; name: string; dark: boolean; bg: string; accent: string }>;
  fonts: Array<{ id: string; label: string; hint: string }>;
  /** The choices in force now. */
  state(): { theme: string; font: string; card: number; windows: number; background: string };
  /** Runs a palette action (`theme:ink`, `font:geist-mono`, `card:2`, `bg:mesh`). */
  act(action: string): void;
  /** Called after any appearance change; returns a remover. */
  onChange(listener: () => void): () => void;
  /** The whole UI's size (#283): a percentage within `min` and `max`, in `step`s, of the standard size. */
  uiSize?: { min: number; max: number; step: number; get(): number; set(percent: number): void; onChange(listener: () => void): () => void };
}

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

function heading(text: string): HTMLElement {
  const h = document.createElement("h3");
  h.className = "ui-ts-title";
  h.textContent = text;
  return h;
}

export interface ChoiceItem { id: string; label: string; hint?: string; swatch?: { bg: string; accent: string } }

/**
 * Decides once per list, and again only when its width changes (a ResizeObserver callback, never per frame), how hints
 * sit with their names. Beside: every name takes the width of the list's widest name (`--ui-sp-label-w`), so all hints
 * start at one x, a column, however long each name is. Under: when the widest name + gap + the longest hint is wider than the
 * room the list has, every row puts its hint under its name instead. Measured in the inline layout, where names and hints
 * are `nowrap` and report their natural widths. One decision per list keeps every row's hint in the same place, and a
 * stacked list does not jump when the selection changes.
 */
function fitHints(list: HTMLElement): void {
  let width = -1;
  const decide = (): void => {
    if (!list.isConnected) { observer.disconnect(); return; }
    if (list.clientWidth === 0) return;
    list.removeAttribute("data-stacked");
    list.style.removeProperty("--ui-sp-label-w");
    const texts = [...list.querySelectorAll<HTMLElement>(".ui-sp-text")];
    const hinted = texts.filter((t) => t.querySelector<HTMLElement>(".ui-sp-hint")!.textContent !== "");
    if (hinted.length === 0) return;
    // Rounded up so a name never loses a fraction of a pixel to its own column and gets an ellipsis. The used width, not a
    // rect: a rect carries every transform above it (the canvas camera's zoom), and a column measured at 0.8 would clip at 1.
    const column = Math.ceil(Math.max(...texts.map((t) => Number.parseFloat(getComputedStyle(t.querySelector<HTMLElement>(".ui-sp-label")!).width) || 0)));
    list.style.setProperty("--ui-sp-label-w", `${column}px`);
    const stack = hinted.some((t) => column + 10 + t.querySelector<HTMLElement>(".ui-sp-hint")!.scrollWidth > t.clientWidth);
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
 * A titled radio list of rows: a label, an optional quiet subtitle (the technical detail) and a tick on the current one.
 * The name never wraps. A list reads as one: if the widest row cannot hold its name and hint on one line, every row of the
 * list puts its hint under its name (`data-stacked` on the list, see `fitHints`), so text never collides at any width
 * (TASTE: "Text never collides").
 */
function choiceBlock(title: string, items: ChoiceItem[], kind: string, current: () => string, pick: (id: string) => void): HTMLElement {
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
    row.innerHTML = `${item.swatch ? '<span class="ui-sp-swatch" aria-hidden="true"></span>' : ""}<span class="ui-sp-text"><span class="ui-sp-label"></span><span class="ui-sp-hint"></span></span><svg class="ui-sp-tick" viewBox="0 0 24 24" aria-hidden="true">${CHECK}</svg>`;
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
function paintChoice(block: HTMLElement, current: string): void {
  for (const row of block.querySelectorAll<HTMLElement>(".ui-sp-row")) {
    const on = row.dataset.id === current;
    row.setAttribute("aria-checked", String(on));
    row.toggleAttribute("data-current", on);
  }
}

/** Theme, font, background, card transparency and the size of the whole UI. */
export function renderAppearance(container: HTMLElement, api: AppearanceApi): () => void {
  const root = document.createElement("div");
  root.className = "ui-sp";
  container.append(root);

  const choices = (title: string, items: ChoiceItem[], kind: string, current: () => string): HTMLElement => choiceBlock(title, items, kind, current, (id) => api.act(`${kind}:${id}`));
  const theme = choices("Theme", api.themes.map((t) => ({ id: t.id, label: t.name, hint: t.dark ? "dark" : "light", swatch: { bg: t.bg, accent: t.accent } })), "theme", () => api.state().theme);
  const font = choices("Font", api.fonts.map((f) => ({ id: f.id, label: f.label, hint: f.hint })), "font", () => api.state().font);
  const background = document.createElement("section");
  background.append(heading("Background"));
  const bgTabs = createCapsuleTabs([{ id: "none", label: "Plain" }, { id: "soft", label: "Soft" }, { id: "mesh", label: "Mesh" }], api.state().background, (id) => api.act(`bg:${id}`), "Background");
  background.append(bgTabs.root);
  const levels = LEVEL_NAMES.map((label, i) => ({ id: String(i + 1), label }));
  const card = document.createElement("section");
  card.append(heading("Card transparency"));
  const cardTabs = createCapsuleTabs(levels, String(api.state().card), (id) => api.act(`card:${id}`), "Card transparency");
  card.append(cardTabs.root);
  const windows = document.createElement("section");
  windows.append(heading("Window transparency"));
  const windowTabs = createCapsuleTabs(levels, String(api.state().windows), (id) => api.act(`windows:${id}`), "Window transparency");
  windows.append(windowTabs.root);
  root.append(theme, font, background, card, windows);
  // The size of the whole UI (#283): live while the thumb moves; the terminal's own font size is a separate setting.
  const size = api.uiSize;
  const sizeSlider = size ? createSlider({ label: "UI size", min: size.min, max: size.max, step: size.step, value: size.get(), format: (v) => `${v} %`, onInput: (v) => size.set(v) }) : undefined;
  if (size && sizeSlider) {
    const section = document.createElement("section");
    section.append(heading("UI size"), sizeSlider.root);
    const hint = document.createElement("p");
    hint.className = "ui-sp-sub";
    hint.textContent = "Scales text, rows, buttons and icons together. The terminal's own font size is separate.";
    section.append(hint);
    root.insertBefore(section, theme);
  }
  const offSize = size?.onChange(() => sizeSlider?.set(size.get()));

  const paint = (): void => {
    const s = api.state();
    for (const [block, current] of [[theme, s.theme], [font, s.font]] as const) paintChoice(block, current);
    bgTabs.select(s.background, true);
    cardTabs.select(String(s.card), true);
    windowTabs.select(String(s.windows), true);
  };
  paint();
  const off = api.onChange(paint);
  return () => { off(); offSize?.(); sizeSlider?.dispose(); bgTabs.dispose(); cardTabs.dispose(); windowTabs.dispose(); root.remove(); };
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
  /** Signs this device out. The product asks first (the compact confirmation) at `anchor`, the button that was pressed. */
  signOut(anchor: HTMLElement): void;
}

/** Settings, Account (D230): the person's own details, and the way out of this device. */
export function renderAccount(container: HTMLElement, api: AccountApi): () => void {
  const root = document.createElement("div");
  root.className = "ui-sp";
  container.append(root);
  const lists = factSections(root, "Account", api.groups ?? []);
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
  return () => { for (const l of lists) l.dispose(); root.remove(); };
}
