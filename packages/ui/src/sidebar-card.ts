/**
 * The sidebar card (D234, D160): the one shell for a card that lives inside the sidebar, above its footer. The Inbox is
 * the first; the version and licence panel (#216) is the second. A card is a header (a title, and room for one trailing
 * control) and a body the caller fills.
 *
 * It shows and hides the way the Inbox always has: it is in the sidebar's flow (the host tree gives way, the footer stays
 * last), it fades and rises 6 px when it appears (opacity and transform only, under 200 ms, transform cleared at rest),
 * and it keeps its content while it fades out before it leaves the layout. Reduced motion keeps only the fade.
 *
 * The caller owns the content and the way back. While a card holds something that an Escape should close first, the caller
 * marks the card (and whatever else holds focus) with `data-owns-escape`, which the core screen already honours so the
 * sidebar stays open.
 */
export interface SidebarCardOptions {
  /** The element the card goes into (the sidebar). */
  parent: HTMLElement;
  /** The card is inserted before this child (the sidebar footer) so the footer stays last. */
  before?: Element | null;
  /** The accessible name of the card, and by default its title. */
  label: string;
  /** Extra classes on the card (the Inbox adds its tint). */
  className?: string;
  /** Called once the card has left the layout after `hide()`. */
  onHidden?(): void;
}

export interface SidebarCard {
  readonly root: HTMLElement;
  /** The header row: the title on the left; the caller may append one control or count on the right. */
  readonly header: HTMLElement;
  readonly title: HTMLElement;
  isOpen(): boolean;
  show(): void;
  hide(): void;
  dispose(): void;
}

/** Long enough for the fade (160 ms) to finish before the card leaves the layout. */
const LEAVE_MS = 190;

export function createSidebarCard(options: SidebarCardOptions): SidebarCard {
  const root = document.createElement("section");
  root.className = `ui-sidebar-card ${options.className ?? ""}`.trim();
  root.hidden = true;
  root.dataset.open = "false";
  root.setAttribute("aria-label", options.label);
  const header = document.createElement("div");
  header.className = "ui-sidebar-card-header";
  const title = document.createElement("span");
  title.className = "ui-sidebar-card-title";
  title.textContent = options.label;
  header.append(title);
  root.append(header);
  options.parent.insertBefore(root, options.before ?? null);

  let timer = 0;
  /** What the person asked for, true from `show()` on: the card is not yet drawn at full opacity on the same frame. */
  let wanted = false;
  return {
    root, header, title,
    isOpen: () => wanted,
    show() {
      wanted = true;
      window.clearTimeout(timer);
      if (root.hidden) {
        root.hidden = false;
        root.dataset.open = "false";
        requestAnimationFrame(() => { if (wanted && !root.hidden) root.dataset.open = "true"; });
      } else root.dataset.open = "true";
    },
    hide() {
      wanted = false;
      if (root.hidden) return;
      root.dataset.open = "false";
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        if (root.dataset.open !== "false") return;
        root.hidden = true;
        options.onHidden?.();
      }, LEAVE_MS);
    },
    dispose() { window.clearTimeout(timer); root.remove(); },
  };
}
