/**
 * The person's card (D283): what the sidebar's person pill opens. It is a card inside the sidebar, above the footer, built on
 * the shared sidebar card the Inbox and the version panel use (it grows out of the pill, the host tree gives way, the pill
 * toggles it, Escape and the close button close it). Its body is the shared key/value list.
 *
 *   ( K )  Kay G  ✎                                                         ×      the heading is the person: picture, name, username
 *         kayg
 *   Email                                                       Not added          a fact is a row, never a heading
 *   Company                                                     Northwind Labs     (EE only: Company and Role)
 *   Logs in as                                                kayg 12  root 2  ›   opens the machines, a card for each tag
 *   SIGN-IN
 *   Passkeys                                                                 2
 *   Recovery key                                                       Set up
 *   Devices                                                                  4
 *   Sign out of this device
 *
 * Where each thing is edited (Q2: one home per thing): the card edits the name (double-click it, or the pencil), the picture
 * (press it: upload, or back to the initials) and the email (press it) in place, when the model can save them. The username is only
 * shown, under the name. The passkeys, the recovery key and the devices show their state only and are links to their home in
 * Settings. A row the model cannot fill yet is not drawn at all.
 *
 * Values state the state plainly and say a concern themselves (words.ts): "Set up", "2", and, when it matters, "Not verified
 * since 3 Mar, verify now" with the amber mark. There is no line of grey text under a key that reports when it was last looked
 * at. Nothing is said twice: no "Account" title, a section's title is never repeated by its rows, and a value never repeats
 * its key.
 *
 * The "Logs in as" pane opens between the two lists, directly under its row. Two lists and not one with a pane inside a row:
 * the list stays the shared one, and the pane is this card's own.
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import { inlineRename } from "../../../../../packages/ui/src/inline-rename";
import { decorateKeyValueRow } from "../../../../../packages/ui/src/kv-decorate";
import { createKeyValueList, type KeyValueList, type KeyValueRow } from "../../../../../packages/ui/src/kv-list";
import { createSidebarCard } from "../../../../../packages/ui/src/sidebar-card";
import { morphSidebarCard, type CardSource, type MorphingCard } from "../../../../../packages/ui/src/sidebar-card-morph";
import { watchScrollFade } from "../../../../../packages/ui/src/scroll-fade";
import type { ToastController } from "../../../../../packages/ui/src/toast";
import { askSignOut } from "../../sign-out";
import { paintAvatar } from "./avatar";
import { el } from "../dom";
import { createLoginsCard, type LoginsCard } from "./logins-card";
import type { AccountModel, Person } from "./model";
import { healthRows, looksLikeEmail, loginChips, loginChipsText, NO_EMAIL, NO_LOGINS, shownName } from "./words";

export interface AccountPanelEnv {
  /** The sidebar, and the footer the card sits directly above. */
  parent: HTMLElement;
  before: Element | null;
  /** The person's pill: it toggles the card, shows `aria-expanded`, and keeps Escape for the card while it is open. */
  anchor: HTMLElement;
  stage: HTMLElement;
  model: AccountModel;
  toast: Pick<ToastController, "show">;
  /** Opens a section of Settings (the rows of sign-in health, and the access rules). */
  openSettings(section: "account" | "grants"): void;
}

export interface AccountPanel {
  readonly root: HTMLElement;
  isOpen(): boolean;
  /** `focus`: move focus into the card (a palette action opened it; a press on the pill keeps focus on the pill). */
  open(focus: boolean, source?: CardSource): void;
  close(focusPill: boolean, source?: CardSource): void;
  /** Starts editing the email in place (when the model can save it). */
  editEmail(): void;
  /** Scrolls to the sign-in rows. */
  showSignIn(): void;
  /** Opens the "Logs in as" pane. */
  showLogins(): void;
  dispose(): void;
}

const PENCIL = '<path d="M5 19.5v-3.2L16.2 5.1a1.8 1.8 0 0 1 2.5 0l.2.2a1.8 1.8 0 0 1 0 2.5L7.7 19H5z"/><path d="m14.5 7 2.5 2.5"/>';
const UPLOAD = '<path d="M12 15.5V5M8 8.5 12 4.5l4 4M5 14.5V18a1.5 1.5 0 0 0 1.5 1.5h11A1.5 1.5 0 0 0 19 18v-3.5"/>';
const INITIALS = '<path d="M6 18 12 6l6 12M8.5 13.5h7"/>';

interface Built { facts: KeyValueList; signIn: KeyValueList; logins: LoginsCard; stop(): void }

export function createAccountPanel(env: AccountPanelEnv): AccountPanel {
  const { model, anchor } = env;
  let built: Built | undefined;
  const card: MorphingCard = morphSidebarCard(createSidebarCard({ parent: env.parent, before: env.before, label: "Account", className: "ac", onHidden: () => { built?.logins.close(); } }), anchor);

  // ---- the heading: the person (picture, name, username) and the close button --------------------------------------------
  const avatar = el("button", "ui-sidebar-avatar ac-avatar");
  avatar.type = "button";
  const nameLine = el("div", "ac-nameline");
  const nameText = el("span", "ac-name");
  const pencil = el("button", "ac-pencil");
  pencil.type = "button";
  pencil.dataset.tip = "Rename";
  pencil.setAttribute("aria-label", "Rename");
  pencil.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${PENCIL}</svg>`;
  nameLine.append(nameText);
  const userText = el("span", "ac-username");
  const names = el("div", "ac-names");
  names.append(nameLine, userText);
  card.title.className = "ui-sidebar-card-title ac-who";
  card.title.replaceChildren(avatar, names);
  const closeButton = el("button", "ui-sidebar-card-close");
  closeButton.type = "button";
  closeButton.dataset.tip = "Close";
  closeButton.setAttribute("aria-label", "Close account");
  closeButton.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.close}</svg>`;
  card.header.append(closeButton);

  /** What the model lets the person change: nothing, until the server can store it. */
  const editable = (): boolean => typeof model.patch === "function";

  const paintHeading = (): void => {
    const person = model.person();
    paintAvatar(avatar, person);
    // A person with no name in the data is shown by their username, once.
    const named = Boolean(person.name.trim());
    nameText.textContent = shownName(person);
    nameText.dataset.tip = shownName(person);
    userText.textContent = person.username;
    userText.dataset.tip = person.username;
    userText.hidden = !named;
    // Controls that would do nothing are not drawn (TASTE: no control looks dead; no invented chrome).
    const can = editable();
    avatar.disabled = !can;
    if (can) { avatar.dataset.tip = "Change picture"; avatar.setAttribute("aria-label", "Change picture"); avatar.setAttribute("aria-haspopup", "menu"); }
    else { delete avatar.dataset.tip; avatar.setAttribute("aria-label", shownName(person)); avatar.removeAttribute("aria-haspopup"); }
    if (can && !pencil.isConnected) nameLine.append(pencil);
    if (!can) pencil.remove();
  };

  // ---- editing in place --------------------------------------------------------------------------------------------------
  const rename = (): void => {
    if (!editable() || !nameText.isConnected || card.root.querySelector(".ac-nameline .ui-inline-rename")) return;
    inlineRename(nameText, {
      value: model.person().name, label: "Name", placeholder: "Your name",
      done(value) {
        const next = value?.trim();
        if (next && next !== model.person().name) model.patch?.({ name: next });
      },
    });
  };
  pencil.addEventListener("click", rename);
  nameText.addEventListener("dblclick", rename);

  const editEmail = (cell?: HTMLElement): void => {
    if (!editable()) return;
    const target = cell ?? built?.facts.root.querySelector<HTMLElement>(".ui-kv-row .ui-kv-value");
    if (!target) return;
    inlineRename(target, {
      value: model.person().email ?? "", label: "Email", placeholder: "name@example.com",
      done(value) {
        if (value === undefined) return;
        const next = value.trim();
        if (next === (model.person().email ?? "")) return;
        if (next && !looksLikeEmail(next)) { env.toast.show({ message: "That doesn't look like an email address.", tone: "error" }); return; }
        model.patch?.({ email: next });
      },
    });
  };

  // The picture: a tiny menu, upload or back to the initials. The file field and the menu are made the first time they are asked for.
  let file: HTMLInputElement | undefined;
  let menu: { close(source: "pointer" | "keyboard"): void } | undefined;
  let opening = false;
  avatar.addEventListener("click", (event) => {
    if (!editable()) return;
    if (menu) { menu.close(event.detail === 0 ? "keyboard" : "pointer"); return; }
    if (opening) return;
    opening = true;
    const source = event.detail === 0 ? "keyboard" : "pointer";
    if (!file) {
      file = el("input");
      file.type = "file";
      file.accept = "image/*";
      file.hidden = true;
      file.addEventListener("change", () => {
        const chosen = file?.files?.[0];
        if (chosen) model.patch?.({ picture: URL.createObjectURL(chosen) });
        if (file) file.value = "";
      });
      card.root.append(file);
    }
    void import("../../../../../packages/ui/src/window-menu.on-demand").then((m) => {
      opening = false;
      const has = Boolean(model.person().picture);
      menu = m.openWindowMenu(env.stage, avatar, [
        { id: "upload", label: has ? "Upload another" : "Upload a picture", icon: UPLOAD, run: () => file?.click() },
        ...(has ? [{ id: "initials", label: "Use initials", icon: INITIALS, run: () => model.patch?.({ picture: undefined }) }] : []),
      ], source, () => { menu = undefined; }, { label: "Picture", side: "below", align: "start", hug: true, maxWidth: 220 });
    }, () => { opening = false; });
  });

  // ---- the rows ----------------------------------------------------------------------------------------------------------
  /** What the last drawn "Logs in as" row needs added after the list has drawn it. */
  let loginsChips: ReturnType<typeof loginChips> | undefined;
  const factRows = (b: Built, person: Person): KeyValueRow[] => {
    const out: KeyValueRow[] = [];
    loginsChips = undefined;
    // Email is optional and never part of sign-in (Q4). A model that cannot hold one has no row; one that can says plainly when there is none.
    if (person.email) out.push({ key: "Email", value: person.email, copy: person.email, ...(editable() ? { press: { tip: "Change email", run: (cell: HTMLElement) => editEmail(cell) } } : {}) });
    else if (person.email !== undefined && editable()) out.push({ key: "Email", value: NO_EMAIL, copy: NO_EMAIL, press: { tip: "Add an email address", run: (cell) => editEmail(cell) } });
    // The organisation and the role are facts: plain rows like every other, never a section title (Q5: shown only with more than one person).
    if (person.org) out.push({ key: "Company", value: person.org.name, copy: person.org.name }, { key: "Role", value: person.org.role, copy: person.org.role });
    if (person.loginAs !== undefined) {
      if (!person.loginAs.length) out.push({ key: "Logs in as", value: NO_LOGINS, copy: NO_LOGINS });
      else {
        const value = loginChipsText(person.loginAs);
        loginsChips = loginChips(person.loginAs);
        out.push({ key: "Logs in as", value, copy: value, press: { tip: "See the machines, by account and tag", run: () => b.logins.toggle() } });
      }
    }
    return out;
  };
  const signInRows = (person: Person): KeyValueRow[] => healthRows(person).map((row) => ({
    group: "Sign-in", key: row.key, value: row.value, mark: row.mark, copy: row.value, press: { tip: row.tip, run: () => env.openSettings("account") },
  }));

  const decorate = (b: Built): void => {
    if (!loginsChips) return;
    decorateKeyValueRow(b.facts.root.querySelector('[data-tip="See the machines, by account and tag"]')?.closest(".ui-kv-row"), { chevron: true, parts: loginsChips });
  };

  const render = (): void => {
    if (!built) return;
    const person = model.person();
    paintHeading();
    built.logins.set(person.loginAs ?? [], person.org?.role !== "Member");
    built.facts.set(factRows(built, person));
    built.signIn.set(signInRows(person));
    decorate(built);
    // A list with nothing in it takes no room (and no gap).
    built.facts.root.hidden = !built.facts.root.querySelector(".ui-kv-row");
    built.signIn.root.hidden = !built.signIn.root.querySelector(".ui-kv-row");
    built.logins.el.hidden = !loginsChips;
    if (!loginsChips) built.logins.close();
  };

  const build = (): Built => {
    const logins = createLoginsCard({
      openRules: () => env.openSettings("grants"),
      focusRow: () => built?.facts.root.querySelector<HTMLElement>('[data-tip="See the machines, by account and tag"]')?.focus({ preventScroll: true }),
    });
    const facts = createKeyValueList("Account");
    const signIn = createKeyValueList("Sign-in");
    const body = el("div", "ac-body");
    const signOut = el("button", "ac-signout");
    signOut.type = "button";
    signOut.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.signOut}</svg><span>Sign out of this device</span>`;
    signOut.addEventListener("click", () => { askSignOut(signOut, env.toast); });
    body.append(facts.root, logins.el, signIn.root);
    const stopFade = watchScrollFade(body);
    // Sign out stays pinned under the scrolling list, so a short screen never hides the way out of this device.
    card.root.append(body, signOut);
    // The rows follow the model, also while the card is closed, so a warm open has nothing to rebuild.
    const stop = model.onChange(() => render());
    return { facts, signIn, logins, stop: () => { stop(); stopFade(); logins.dispose(); facts.dispose(); signIn.dispose(); } };
  };

  const setOpen = (open: boolean): void => {
    anchor.setAttribute("aria-expanded", String(open));
    // While the card is open, Escape on the pill or inside the card closes the card and keeps the sidebar.
    anchor.toggleAttribute("data-owns-escape", open);
    card.root.toggleAttribute("data-owns-escape", open);
  };

  const open = (focus: boolean, source: CardSource = "pointer"): void => {
    if (card.isOpen()) return;
    if (!built) { built = build(); render(); }
    // Next to the pill that opens it, below an Inbox that may be showing.
    if (card.root.nextElementSibling !== env.before) env.parent.insertBefore(card.root, env.before);
    card.show(source);
    setOpen(true);
    if (focus) closeButton.focus({ preventScroll: true });
  };
  const close = (focusPill: boolean, source: CardSource = "pointer"): void => {
    if (!card.isOpen()) return;
    const inside = card.root.contains(document.activeElement);
    card.hide(source);
    setOpen(false);
    if (focusPill || inside) anchor.focus({ preventScroll: true });
  };
  closeButton.addEventListener("click", (event) => close(true, event.detail === 0 ? "keyboard" : "pointer"));
  const onKey = (event: KeyboardEvent): void => {
    if (event.key !== "Escape" || !card.isOpen()) return;
    // A name or an email being edited takes its own Escape.
    if ((event.target as Element | null)?.closest(".ui-inline-rename")) return;
    event.preventDefault();
    event.stopPropagation();
    // The "Logs in as" pane is the innermost thing that is open: Escape closes it first, the card after it.
    if (built?.logins.isOpen()) { built.logins.close(true); return; }
    close(true, "keyboard");
  };
  card.root.addEventListener("keydown", onKey);
  anchor.addEventListener("keydown", onKey);

  return {
    root: card.root,
    isOpen: () => card.isOpen(),
    open,
    close,
    editEmail() { open(false, "keyboard"); window.setTimeout(() => editEmail(), 60); },
    showSignIn() { open(false, "keyboard"); window.setTimeout(() => built?.signIn.root.scrollIntoView({ block: "nearest" }), 60); },
    showLogins() { open(false, "keyboard"); window.setTimeout(() => built?.logins.open(), 60); },
    dispose() { built?.stop(); card.dispose(); setOpen(false); },
  };
}
