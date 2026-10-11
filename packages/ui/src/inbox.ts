/**
 * The inbox (D234): the things that wait on the person, in one card at the bottom of the sidebar.
 *
 * A pending action is never only in Settings. Each source (the host-connection lock today; an unknown machine that
 * asked to boot, peers behind on rules, later) publishes its items with `set(source, items)` and replaces them as
 * its state changes; an empty list withdraws them. The card shows every item with its one primary action and
 * disappears entirely when there are none, so nothing is drawn for a person with nothing to do. Sources need no
 * UI of their own: a new kind of item is data.
 *
 * The card sits inside the sidebar (the caller passes the element and the footer to sit above), so it follows the
 * sidebar everywhere: open on a desktop, in the drawer on a phone. `onCount` tells the caller how many items wait,
 * for the dot on the sidebar toggle while the card itself is out of view.
 *
 * Motion: the card fades and rises 6 px (opacity and transform only, under 200 ms, a short fade under reduced motion).
 * A change made with the keyboard or while the sidebar is closed is not animated: nobody watches it.
 */
export interface InboxItem {
  id: string;
  /** What is waiting, as a short sentence ("Host connections are locked"). */
  title: string;
  /** One line that says why or what the action does. */
  detail?: string;
  action: { label: string; run(): void };
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

export function createInbox(options: InboxOptions): InboxController {
  const card = document.createElement("section");
  card.className = "ui-inbox";
  card.hidden = true;
  card.dataset.open = "false";
  card.setAttribute("aria-label", "Waiting for you");
  options.parent.insertBefore(card, options.before ?? null);

  const sources = new Map<string, readonly InboxItem[]>();
  let hideTimer = 0;
  let shown = 0;

  const render = (): void => {
    const items = [...sources.values()].flat().filter((item) => item.canAct !== false);
    const was = shown;
    shown = items.length;
    if (items.length) {
      card.replaceChildren(...items.map((item) => {
        const row = document.createElement("div");
        row.className = "ui-inbox-item";
        row.dataset.id = item.id;
        const text = document.createElement("div");
        text.className = "ui-inbox-text";
        const title = document.createElement("span");
        title.className = "ui-inbox-title";
        title.textContent = item.title;
        text.append(title);
        if (item.detail) {
          const detail = document.createElement("span");
          detail.className = "ui-inbox-detail";
          detail.textContent = item.detail;
          text.append(detail);
        }
        const action = document.createElement("button");
        action.type = "button";
        action.className = "ui-inbox-action ui-button";
        action.dataset.button = "primary";
        action.textContent = item.action.label;
        action.addEventListener("click", () => item.action.run());
        row.append(text, action);
        return row;
      }));
      window.clearTimeout(hideTimer);
      if (card.hidden) {
        card.hidden = false;
        card.dataset.open = "false";
        requestAnimationFrame(() => { if (!card.hidden) card.dataset.open = "true"; });
      } else card.dataset.open = "true";
    } else if (!card.hidden) {
      card.dataset.open = "false";
      // Keep the last content while it fades out.
      hideTimer = window.setTimeout(() => { if (card.dataset.open === "false") { card.hidden = true; card.replaceChildren(); } }, 190);
    }
    if (was !== shown) options.onCount?.(shown);
  };

  return {
    set(source, items) { if (items.length) sources.set(source, items); else sources.delete(source); render(); },
    count: () => shown,
    dispose() { window.clearTimeout(hideTimer); card.remove(); sources.clear(); },
  };
}
