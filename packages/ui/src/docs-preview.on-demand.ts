// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The "?" preview (issue #304): a few lines about the window the person is looking at, in a popover anchored to the "?" button (a bottom sheet
 * on a phone). It shows the most helpful immediate information and nothing more: the title, one lead sentence, two to four short bullets and, when
 * the answer is a few figures, a small table. The expand icon at the top right opens the whole page; Escape or a press outside closes it.
 *
 * It is built from `DocsPreviewContent` (the app's excerpt of the docs index), so the same text is written once, in the docs. A window with no page
 * yet gets one plain sentence and no expand icon, rather than a button that does nothing.
 *
 * Keyboard: opened from the keyboard the first control (the expand icon) takes focus and Escape returns it to the "?"; opened by a pointer nothing
 * takes focus and no ring shows (TASTE: rings come only from real Tab navigation). The popover stays inside its window with the same inset on every side
 * (the shared anchored popover); on a phone the sheet keeps clear of the home indicator.
 */
import { openAnchoredPopover, type PopoverSource } from "./anchored-popover";
import { openBottomSheet } from "./bottom-sheet";
import { ICONS } from "./icons";
import { hideTips } from "./tooltip";

/** What a docs preview shows: a title, a lead, bullets, an optional small table, or one line saying there is nothing. */
export interface DocsPreviewContent {
  title: string;
  lead?: string;
  bullets: string[];
  table?: { head: string[]; rows: string[][] };
  empty?: string;
}

/** Where a docs preview opens (a popover on a desktop, a sheet on a phone), what it shows and what its expand icon does. */
export interface DocsPreviewOptions {
  stage: HTMLElement;
  /** The "?" button (or what stands in for it); focus returns here. */
  anchor: HTMLElement;
  label: string;
  /** The excerpt, or a promise of it. A promise that takes more than a moment shows a quiet "Loading" line first. */
  content: DocsPreviewContent | Promise<DocsPreviewContent>;
  /** Opens the whole page. Absent: no expand icon. */
  onExpand?: () => void;
  /** A phone: a bottom sheet instead of a popover. */
  touch: boolean;
  source: PopoverSource;
  onClosed(): void;
}

/** A docs preview that is open; closing it returns the focus to where it came from. */
export interface DocsPreview { close(source: PopoverSource): void }

/** The popover's contents. `expand` is the top-right icon button (absent when there is nothing to expand to). */
export function renderDocsPreview(content: DocsPreviewContent, onExpand: (() => void) | undefined): { root: HTMLElement; expand: HTMLButtonElement | undefined } {
  const root = document.createElement("div");
  root.className = "ui-dp";
  const head = document.createElement("header");
  head.className = "ui-dp-head";
  const title = document.createElement("h3");
  title.className = "ui-dp-title";
  title.textContent = content.title;
  head.append(title);
  let expand: HTMLButtonElement | undefined;
  if (onExpand && !content.empty) {
    expand = document.createElement("button");
    expand.type = "button";
    expand.className = "ui-window-action ui-dp-expand";
    expand.setAttribute("aria-label", "Open the full page");
    expand.dataset.tip = "Open the full page";
    expand.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.expandPage}</svg>`;
    expand.addEventListener("click", onExpand);
    head.append(expand);
  }
  root.append(head);
  const text = (tag: "p" | "li", className: string, value: string): HTMLElement => { const n = document.createElement(tag); n.className = className; n.textContent = value; return n; };
  if (content.empty) root.append(text("p", "ui-dp-empty", content.empty));
  if (content.lead) root.append(text("p", "ui-dp-lead", content.lead));
  if (content.bullets.length) {
    const list = document.createElement("ul");
    list.className = "ui-dp-bullets";
    for (const bullet of content.bullets) list.append(text("li", "ui-dp-bullet", bullet));
    root.append(list);
  }
  if (content.table) {
    const wrap = document.createElement("div");
    wrap.className = "ui-dp-table-wrap";
    const table = document.createElement("table");
    table.className = "ui-dp-table";
    const header = table.createTHead().insertRow();
    for (const cell of content.table.head) { const th = document.createElement("th"); th.scope = "col"; th.textContent = cell; header.append(th); }
    const body = table.createTBody();
    for (const row of content.table.rows) { const tr = body.insertRow(); for (const cell of row) tr.insertCell().textContent = cell; }
    wrap.append(table);
    root.append(wrap);
  }
  return { root, expand };
}

/** Opens the docs preview for a window: a popover anchored to its "?" button, or a bottom sheet on a touch screen. */
export function openDocsPreview(options: DocsPreviewOptions): DocsPreview {
  // The button's own tooltip would sit on top of the preview it just opened (the pointer is still resting on it): none while it is open.
  hideTips();
  options.anchor.setAttribute("data-tip-off", "");
  const closed = options.onClosed;
  options = { ...options, onClosed: () => { options.anchor.removeAttribute("data-tip-off"); closed(); } };
  const holder = document.createElement("div");
  holder.className = "ui-dp-holder";
  const first = options.content instanceof Promise ? undefined : options.content;
  const fill = (content: DocsPreviewContent): void => {
    const view = renderDocsPreview(content, options.onExpand ? () => { handle.close("pointer"); options.onExpand!(); } : undefined);
    holder.replaceChildren(view.root);
    if (options.source === "keyboard") view.expand?.focus({ preventScroll: true });
    pop?.place();
  };
  let pop: { place(): void; close(source: PopoverSource): void } | undefined;
  let sheet: { close(source: PopoverSource): void } | undefined;
  const handle: DocsPreview = { close: (source) => (pop ?? sheet)?.close(source) };
  holder.append(renderDocsPreview({ title: options.label.replace(/^About /, ""), bullets: [], ...(first ? {} : { empty: "Loading" }) }, undefined).root);
  if (options.touch) {
    sheet = openBottomSheet({ stage: options.stage, label: options.label, content: holder, opener: options.anchor, source: options.source, onClosed: options.onClosed });
  } else {
    const popover = openAnchoredPopover({ stage: options.stage, anchor: options.anchor, label: options.label, className: "ui-dp-pop", align: "end", hug: true, maxWidth: 380 }, options.onClosed);
    popover.root.append(holder);
    pop = popover;
  }
  if (first) fill(first); else void (options.content as Promise<DocsPreviewContent>).then(fill);
  return handle;
}
