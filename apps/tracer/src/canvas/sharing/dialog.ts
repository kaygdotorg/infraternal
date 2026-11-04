/**
 * The share dialog (D182): pick the views to send, pick who gets them, send. The panel is built
 * here and shown by the caller with the shared pill morph, in the shared overlay material.
 *
 * - Views are toggle chips (the shared chip look; "All views" selects every one).
 * - Recipients use the shared chip input: users and groups from the test double resolve to chips as you
 *   type; a bare name that is both does not exist here, so a token is unambiguous once it matches.
 * - Operators can also publish to the team: followers keep a linked, read-only copy that updates.
 * - One quiet line says what the recipient gets. Send is an icon button with the warm tooltip.
 */
import { mountChipInput, type Chip, type ChipInputController } from "../../../../../packages/ui/src/chip-input";
import { enhanceSwitch } from "../../../../../packages/ui/src/switch";

/** What the person chose to send: which views, to whom, and whether to publish to the team. */
export interface ShareChoice { views: string[]; to: string[]; publish: boolean }
/** What the dialog needs: the views to offer and the ones preselected, the sender, who can receive, whether publishing is allowed, and the send callback. */
export interface ShareDialogOptions {
  /** Views that can be shared (not Settings). */
  views: Array<{ id: string; name: string }>;
  /** Pre-selected view ids. */
  selected: string[];
  sender: string;
  /** Who can receive a layout: people and groups on this instance (the adapter supplies them). */
  directory: { people: readonly string[]; groups: Readonly<Record<string, readonly string[]>> };
  canPublish: boolean;
  onSend(choice: ShareChoice): void;
}
/** The built dialog: its `panel` (shown by the caller), `focus`, and the `recipients` input. */
export interface ShareDialog { panel: HTMLElement; content: HTMLElement[]; focus(): void; recipients(): ChipInputController; dispose(): void }

/** Icon markup for a person recipient. */
const USER = '<svg viewBox="0 0 24 24" class="is-line" aria-hidden="true"><circle cx="12" cy="8" r="3.5"/><path d="M5 20c1-4 4-5.5 7-5.5s6 1.5 7 5.5"/></svg>';
/** Icon markup for a group recipient. */
const GROUP = '<svg viewBox="0 0 24 24" class="is-line" aria-hidden="true"><circle cx="9" cy="8" r="3"/><path d="M3 19c.8-3.4 3.2-5 6-5s5.2 1.6 6 5M16 5.5a3 3 0 0 1 0 5.5M18 14.5c1.7.6 2.7 2 3 4.5"/></svg>';
/** Icon markup for the send button. */
const SEND = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12 20 4l-4 16-4.5-6.5z"/><path d="m11.5 13.5 8.5-9.5"/></svg>';

/** Builds the dialog panel. It does not show it: the caller morphs it out of the top pill. `onSend` receives the choice when the person sends. */
export function buildShareDialog(options: ShareDialogOptions): ShareDialog {
  const panel = document.createElement("section");
  panel.className = "cl-share ui-overlay-surface";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-label", "Share layout");
  panel.innerHTML = `<header class="cl-share-head"><span class="cl-share-title">Share layout</span></header>
    <div class="cl-share-body">
      <p class="cl-share-label">Views</p><div class="cl-share-views" role="group" aria-label="Views to share"></div>
      <p class="cl-share-label">To</p><div class="cl-share-to"></div>
      <label class="cl-share-publish" hidden><span>Publish to team</span><input type="checkbox" aria-label="Publish to team"></label>
      <p class="cl-share-note">They get their own copy. Windows connect with their access.</p>
    </div>
    <footer class="cl-share-foot"><button type="button" class="ui-pill ui-pill-icon cl-share-send" aria-label="Send" data-tip="Send" disabled>${SEND}</button></footer>`;
  const viewsEl = panel.querySelector<HTMLElement>(".cl-share-views")!;
  const picked = new Set(options.selected);
  const chips = new Map<string, HTMLButtonElement>();
  const all = document.createElement("button");
  const make = (label: string, id: string): HTMLButtonElement => {
    const b = document.createElement("button");
    b.type = "button"; b.className = "ui-chip cl-share-chip"; b.dataset.view = id;
    b.innerHTML = `<span class="ui-chip-label"></span>`;
    (b.querySelector(".ui-chip-label") as HTMLElement).textContent = label;
    return b;
  };
  const allChip = make("All views", "*");
  viewsEl.append(allChip);
  for (const v of options.views) { const b = make(v.name, v.id); chips.set(v.id, b); viewsEl.append(b); }
  void all;
  const send = panel.querySelector<HTMLButtonElement>(".cl-share-send")!;
  const publishRow = panel.querySelector<HTMLElement>(".cl-share-publish")!;
  const publishBox = publishRow.querySelector<HTMLInputElement>("input")!;
  publishRow.hidden = !options.canPublish;
  enhanceSwitch(publishBox);

  let recipients: ChipInputController;
  const paint = (): void => {
    for (const [id, b] of chips) b.setAttribute("aria-pressed", String(picked.has(id)));
    allChip.setAttribute("aria-pressed", String(options.views.length > 0 && options.views.every((v) => picked.has(v.id))));
    send.disabled = picked.size === 0 || recipients.chips().length === 0;
  };
  viewsEl.addEventListener("click", (e) => {
    const b = (e.target as Element).closest<HTMLButtonElement>(".cl-share-chip");
    if (!b) return;
    if (b.dataset.view === "*") {
      const every = options.views.every((v) => picked.has(v.id));
      for (const v of options.views) { if (every) picked.delete(v.id); else picked.add(v.id); }
    } else if (picked.has(b.dataset.view!)) picked.delete(b.dataset.view!); else picked.add(b.dataset.view!);
    paint();
  });

  const resolve = (token: string): Chip | undefined => {
    const t = token.trim().replace(/^@/, "").toLowerCase();
    if (!t) return undefined;
    const user = options.directory.people.find((p) => p === t && p !== options.sender);
    if (user) return { id: `user:${user}`, label: user, icon: USER };
    if (t in options.directory.groups) return { id: `group:${t}`, label: t, icon: GROUP };
    return undefined;
  };
  recipients = mountChipInput(panel.querySelector<HTMLElement>(".cl-share-to")!, {
    label: "Recipients", placeholder: "A user or a group", resolve: (token) => resolve(token),
    onChange: paint, onSubmit: () => { if (!send.disabled) send.click(); },
  });
  send.addEventListener("click", () => {
    if (send.disabled) return;
    options.onSend({ views: options.views.filter((v) => picked.has(v.id)).map((v) => v.id), to: recipients.chips().map((c) => c.id), publish: options.canPublish && publishBox.checked });
  });
  paint();
  return {
    panel, content: [...panel.children] as HTMLElement[],
    focus: () => recipients.input.focus({ preventScroll: true }),
    recipients: () => recipients,
    dispose() { recipients.dispose(); panel.remove(); },
  };
}
