/**
 * The inbox (D234): the things that wait on the person, in one generic card at the bottom of the sidebar.
 *
 * A pending action is never only in Settings. Each source (the host-connection lock today; an unknown machine that
 * asked to boot, an update, later) publishes its items with `set(source, items)` and replaces them as its state
 * changes; an empty list withdraws them. The card is titled "Inbox" with a count and shows every item as one compact
 * line (icon, short title). Activating a line expands it in place to its full context and its actions; activating it
 * again, or pressing Escape, collapses it. One line is open at a time. There is exactly one row component for every
 * kind of item: a new kind is data (`icon`, `title`, `body`, `actions`), never a panel of its own. The card
 * disappears entirely when there are no items.
 *
 * The card sits inside the sidebar (the caller passes the element and the footer to sit above), so it follows the
 * sidebar everywhere: open on a desktop, in the drawer on a phone. `onCount` tells the caller how many items wait,
 * for the dot on the sidebar toggle while the card itself is out of view.
 *
 * Motion: the card fades and rises 6 px (opacity and transform only, under 200 ms). A row opens by animating the
 * height of its panel (a grid track from 0fr to 1fr, 180 ms, interruptible because it is a CSS transition) while
 * the panel's content fades; reduced motion keeps only the fade. The collapsed panel is `inert`, so its actions
 * are neither focusable nor read. Rows are reused by id across updates, so a source republishing never collapses
 * or restarts what the person has open.
 */
import { ICONS } from "./icons";
import { createSidebarCard } from "./sidebar-card";

export interface InboxAction {
  label: string;
  run(): void;
  /** The primary action takes the product's primary button style; others are quiet. At most one per item. */
  primary?: boolean;
}

export interface InboxItem {
  id: string;
  /** Glyph for the collapsed line: the inner markup of a 24x24 stroke icon (see `ICONS`). */
  icon: string;
  /** What is waiting, in a few words ("Unlock host connections"). Shown on the collapsed line. */
  title: string;
  /** The full context, shown when the line is expanded: why it waits and what the actions do. */
  body: string;
  actions: readonly InboxAction[];
  /**
   * False when the person cannot act on it: the item is not drawn (a control that cannot act is not shown). The
   * server still enforces who may; this only keeps the card honest.
   */
  canAct?: boolean;
}

export interface InboxController {
  /** Replaces the items of one source; an empty list withdraws them. */
  set(source: string, items: readonly InboxItem[]): void;
  /** How many items are drawn now. */
  count(): number;
  dispose(): void;
}

export interface InboxOptions {
  /** The element the card goes into (the sidebar). */
  parent: HTMLElement;
  /** The card is inserted before this child (the sidebar footer) so the footer stays last. */
  before?: Element | null;
  /** Called whenever the number of items changes. */
  onCount?(count: number): void;
}

interface Row {
  root: HTMLElement;
  toggle: HTMLButtonElement;
  glyph: SVGSVGElement;
  title: HTMLElement;
  panel: HTMLElement;
  body: HTMLElement;
  actions: HTMLElement;
}

const svg = (inner: string, className: string): SVGSVGElement => {
  const el = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  el.setAttribute("viewBox", "0 0 24 24");
  el.setAttribute("aria-hidden", "true");
  el.setAttribute("class", className);
  el.innerHTML = inner;
  return el;
};

let serial = 0;

export function createInbox(options: InboxOptions): InboxController {
  const shell = createSidebarCard({
    parent: options.parent, before: options.before ?? null, label: "Inbox", className: "ui-inbox",
    onHidden: () => { rows.clear(); list.replaceChildren(); expanded = undefined; },
  });
  const card = shell.root;
  const badge = document.createElement("span");
  badge.className = "ui-inbox-count";
  shell.header.append(badge);
  const list = document.createElement("div");
  list.className = "ui-inbox-list";
  card.append(list);

  const sources = new Map<string, readonly InboxItem[]>();
  const rows = new Map<string, Row>();
  let expanded: string | undefined;
  let shown = 0;

  const setExpanded = (id: string | undefined): void => {
    expanded = id;
    for (const [key, row] of rows) {
      const open = key === id;
      row.root.dataset.expanded = String(open);
      row.toggle.setAttribute("aria-expanded", String(open));
      row.panel.inert = !open;
    }
    // While a line is open the card takes Escape for itself, so the sidebar stays and only the line closes.
    card.toggleAttribute("data-owns-escape", id !== undefined);
  };

  const makeRow = (): Row => {
    const n = ++serial;
    const root = document.createElement("div");
    root.className = "ui-inbox-item";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "ui-inbox-row";
    toggle.id = `ui-inbox-row-${n}`;
    toggle.setAttribute("aria-controls", `ui-inbox-panel-${n}`);
    const title = document.createElement("span");
    title.className = "ui-inbox-title";
    toggle.append(title);
    const panel = document.createElement("div");
    panel.className = "ui-inbox-panel";
    panel.id = `ui-inbox-panel-${n}`;
    panel.setAttribute("role", "group");
    panel.setAttribute("aria-labelledby", toggle.id);
    const inner = document.createElement("div");
    inner.className = "ui-inbox-panel-inner";
    const body = document.createElement("p");
    body.className = "ui-inbox-body";
    const actions = document.createElement("div");
    actions.className = "ui-inbox-actions";
    inner.append(body, actions);
    panel.append(inner);
    root.append(toggle, panel);
    const glyph = svg("", "ui-inbox-glyph");
    toggle.prepend(glyph);
    toggle.append(svg(ICONS.next, "ui-inbox-chevron"));
    return { root, toggle, glyph, title, panel, body, actions };
  };

  const fill = (row: Row, item: InboxItem, id: string): void => {
    row.glyph.innerHTML = item.icon;
    row.title.textContent = item.title;
    row.body.textContent = item.body;
    row.toggle.onclick = () => setExpanded(expanded === id ? undefined : id);
    row.actions.replaceChildren(...item.actions.map((action) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ui-inbox-action ui-button";
      button.dataset.button = action.primary ? "primary" : "secondary";
      button.textContent = action.label;
      button.addEventListener("click", () => action.run());
      return button;
    }));
  };

  // Escape collapses the open line and keeps focus on it; with nothing open it is left to whoever else listens
  // (the sidebar), so a closed card never swallows the key.
  card.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || expanded === undefined) return;
    const row = rows.get(expanded);
    event.stopPropagation();
    event.preventDefault();
    setExpanded(undefined);
    if (row && row.panel.contains(document.activeElement)) row.toggle.focus();
  });

  const render = (): void => {
    const items = [...sources.values()].flat().filter((item) => item.canAct !== false);
    const was = shown;
    shown = items.length;
    if (items.length) {
      const ids = new Set(items.map((item) => item.id));
      for (const [id, row] of rows) if (!ids.has(id)) { row.root.remove(); rows.delete(id); }
      if (expanded !== undefined && !ids.has(expanded)) expanded = undefined;
      items.forEach((item, index) => {
        let row = rows.get(item.id);
        if (!row) { row = makeRow(); rows.set(item.id, row); }
        fill(row, item, item.id);
        if (list.children[index] !== row.root) list.insertBefore(row.root, list.children[index] ?? null);
      });
      setExpanded(expanded);
      badge.textContent = String(items.length);
      shell.show();
    } else {
      // Keep the last content while it fades out.
      shell.hide();
    }
    if (was !== shown) options.onCount?.(shown);
  };

  return {
    set(source, items) { if (items.length) sources.set(source, items); else sources.delete(source); render(); },
    count: () => shown,
    dispose() { shell.dispose(); sources.clear(); rows.clear(); },
  };
}
