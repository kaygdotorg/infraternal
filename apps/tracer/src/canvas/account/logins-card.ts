/**
 * The "Logs in as" pane (D283): opens under its row in the person's card. Read-only. It is the part of the card that holds
 * the most data (an account on a thousand machines, a fleet with a dozen tags), so it is built to be read:
 *
 *   kayg                                                         1,202 hosts      one block for each account the person can log in as
 *   ┌ #prod ─────────────────────────────────────────── 340 ┐                     one card for each tag, in the tag's own colour
 *   │ ( build-01 ) ( db-01 ) ( proxy ) …  +316 more        │                     each machine a chip: a gradient of ITS tags' colours
 *   └───────────────────────────────────────────────────────┘
 *   ┌ No tag ─────────────────────────────────────────── 3 ┐
 *
 * TASTE "Named things are chips" (owner 2026-10-09, reaffirmed 2026-11-01): a tag is a solid colour, a machine a linear
 * gradient of its tags' colours, the same colour everywhere the tag appears. So the colour tells the machines apart: a
 * pane where every machine looks the same says nothing. A machine that carries several tags is listed in each tag's card
 * (as a filter by that tag would list it), and its own chip shows all of its tags.
 *
 * Bounded on purpose: six tag cards for each account and 24 chips in each card, then one quiet "+N more", so a fleet of a
 * thousand machines never draws a thousand chips. The change itself belongs to the access rules, so the pane ends in a link
 * to them (Settings, Access) and has no control of its own.
 *
 * Contrast: the card is an opaque mix of the tag's colour into the sidebar card's own solid colour, never a transparent
 * wash over whatever is behind, so its text can be measured; counts and names use --fg and --fg-2, not --fg-3.
 */
import { entityChip } from "../../../../../packages/ui/src/entity-chip";
import { entityColorIndex } from "../../../../../packages/ui/src/entity-palette";
import { ICONS } from "../../../../../packages/ui/src/icons";
import { el } from "../dom";
import type { Login } from "./model";
import { accountHosts, HOSTS_PER_TAG, num, TAG_CARDS_SHOWN, tagGroups, type TagGroup } from "./words";

export interface LoginsCardEnv {
  /** Opens Settings, Access. */
  openRules(): void;
  /** Puts focus back on the row that opens the pane (Escape closed it). */
  focusRow(): void;
}

export interface LoginsCard {
  /** The pane; the caller places it under the row that opens it. */
  readonly el: HTMLElement;
  /** Fills the pane; the link to the rules is there only when the person can see them. */
  set(logins: Login[], rules: boolean): void;
  toggle(): void;
  open(): void;
  close(focusRow?: boolean): void;
  isOpen(): boolean;
  dispose(): void;
}

function tagCard(group: TagGroup): HTMLElement {
  const card = el("div", "ac-tag");
  const head = el("div", "ac-tag-head");
  if (group.tag === null) {
    card.dataset.untagged = "";
    head.append(el("span", "ac-tag-none", "No tag"));
  } else {
    card.classList.add("ui-entity-card");
    // The card wears the tag's colour through the same token the tag's chip uses, so the two can never disagree.
    card.style.setProperty("--tag", `var(--ui-ent-${entityColorIndex(group.tag)})`);
    head.append(entityChip({ kind: "tag", name: group.tag }));
  }
  head.append(el("span", "ac-tag-count", num(group.hosts.length)));
  const hosts = el("div", "ac-tag-hosts");
  hosts.append(...group.hosts.slice(0, HOSTS_PER_TAG).map((host) => {
    const chip = entityChip({ kind: "host", name: host.name, platform: host.platform, via: host.tags });
    chip.dataset.tip = host.tags.length ? `${host.name}: ${host.tags.join(", ")}` : host.name;
    return chip;
  }));
  if (group.hosts.length > HOSTS_PER_TAG) hosts.append(el("span", "ac-more", `+${num(group.hosts.length - HOSTS_PER_TAG)} more`));
  card.append(head, hosts);
  return card;
}

export function createLoginsCard(env: LoginsCardEnv): LoginsCard {
  const root = el("div", "ac-pane");
  const clip = el("div", "ac-pane-clip");
  const body = el("div", "ac-pane-body");
  clip.append(body);
  root.append(clip);
  let open = false;

  const follow = new ResizeObserver(() => { if (open) body.scrollIntoView({ block: "nearest" }); });
  follow.observe(body);

  const close = (focusRow = false): void => {
    if (!open) return;
    open = false;
    root.removeAttribute("data-open");
    root.inert = true;
    if (focusRow) env.focusRow();
  };
  const show = (): void => {
    if (open) return;
    open = true;
    root.inert = false;
    root.setAttribute("data-open", "");
  };
  // Escape closes the pane first (the pane owns that key), the card after it.
  root.dataset.ownsEscape = "";
  root.addEventListener("keydown", (e) => { if (e.key === "Escape" && open) { e.preventDefault(); e.stopPropagation(); close(true); } });
  root.inert = true;

  return {
    el: root,
    set(logins, rules) {
      const accounts = logins.map((login) => {
        const account = el("section", "ac-account");
        account.setAttribute("aria-label", login.account);
        const head = el("div", "ac-account-head");
        const name = el("span", "ac-account-name", login.account);
        name.dataset.tip = login.account;
        head.append(name, el("span", "ac-account-count", accountHosts(login)));
        account.append(head);
        const groups = tagGroups(login);
        account.append(...groups.slice(0, TAG_CARDS_SHOWN).map(tagCard));
        if (groups.length > TAG_CARDS_SHOWN) account.append(el("span", "ac-more", `+${num(groups.length - TAG_CARDS_SHOWN)} more tags`));
        return account;
      });
      body.replaceChildren(...accounts);
      if (rules) {
        const link = el("button", "ac-rules");
        link.type = "button";
        link.append(el("span", "", "Access rules"));
        link.insertAdjacentHTML("beforeend", `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS.next}</svg>`);
        link.addEventListener("click", env.openRules);
        body.append(link);
      }
    },
    toggle: () => (open ? close(true) : show()),
    open: show,
    close,
    isOpen: () => open,
    dispose() { follow.disconnect(); root.remove(); },
  };
}
