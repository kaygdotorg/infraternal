/**
 * Wires the person's card (D283) into the sidebar footer: a press on the person's pill opens the card inside the sidebar
 * instead of the small menu, and the pill carries one amber mark when something needs attention (Q6, words.ts). The same
 * mount serves the product (its model knows the name and the username) and the mock (a test double that knows everything),
 * so the card is one thing in both.
 *
 * This file is small and is all the first screen's path needs; the card itself (`panel.on-demand.ts`) and its styles
 * (`account.css`) load on idle after the first paint, or at the first press, whichever comes first (D188). The pill's
 * press is claimed in the capture phase straight away, so the old menu can never open in the meantime.
 *
 * The card is in the sidebar, so the sidebar must be showing it: the palette actions open the sidebar first.
 */
import type { CoreScreen } from "../../core-screen";
import { onDemand, whenIdle } from "../../on-demand";
import type { CardSource } from "../../../../../packages/ui/src/sidebar-card-morph";
import type { AccountModel } from "./model";
import { paintAvatar } from "./avatar";
import type { AccountPanel } from "./panel.on-demand";
import { attention, pillLabel, shownName } from "./words";

export interface AccountMount {
  /** Opens the card (the sidebar first), then does `after` once it is built. */
  show(after?: (panel: AccountPanel) => void): void;
  /** The card, once it exists (tests and palette actions). */
  panel(): AccountPanel | undefined;
  dispose(): void;
}

export interface AccountMountEnv {
  core: CoreScreen;
  model: AccountModel;
  /** Opens a section of Settings. */
  openSettings(section: "account" | "grants"): void;
}

let styles: Promise<void> | undefined;
/** The card's styles, added once; resolved when they apply, so the card never draws unstyled. */
function loadStyles(): Promise<void> {
  styles ??= new Promise<void>((done) => {
    const link = Object.assign(document.createElement("link"), { rel: "stylesheet", href: "./account.css" });
    link.addEventListener("load", () => done(), { once: true });
    link.addEventListener("error", () => done(), { once: true });
    document.head.append(link);
  });
  return styles;
}

export function mountAccountCard(env: AccountMountEnv): AccountMount | undefined {
  const { core, model } = env;
  const foot = core.stage.querySelector<HTMLElement>(".ui-sidebar-foot");
  const pill = foot?.querySelector<HTMLButtonElement>(".ui-sidebar-user");
  if (!foot || !pill) return undefined;
  const nameNode = pill.querySelector<HTMLElement>(".ui-sidebar-name");
  const avatar = pill.querySelector<HTMLElement>(".ui-sidebar-avatar");
  // The pill carries the picture and the name only (it identifies; the card holds the rest): the username is in the card.
  pill.querySelector<HTMLElement>(".ui-sidebar-secondary")?.remove();
  const badge = document.createElement("span");
  badge.className = "ac-badge";
  badge.setAttribute("aria-hidden", "true");
  badge.textContent = "!";
  pill.setAttribute("aria-haspopup", "dialog");
  pill.setAttribute("aria-expanded", "false");

  /** The version panel opens in the same place: one card at a time, whichever is pressed last. */
  const closeVersion = (): void => { foot.querySelector<HTMLElement>('.ui-version-pill[aria-expanded="true"]')?.click(); };

  let panel: AccountPanel | undefined;
  let loading: Promise<AccountPanel> | undefined;
  /** The card, built once: its code and its styles arrive together. */
  const load = (): Promise<AccountPanel> => loading ??= Promise.all([onDemand(() => import("./panel.on-demand")), loadStyles()]).then(([m]) => {
    panel = m.createAccountPanel({
      parent: foot.parentElement ?? core.stage, before: foot, anchor: pill, stage: core.stage, model, toast: core.toast, openSettings: env.openSettings,
    });
    return panel;
  });

  // ---- the pill: the person, and one amber mark when something needs attention ----------------------------------------------
  const sync = (): void => {
    const person = model.person();
    const reason = attention(person);
    if (nameNode) nameNode.textContent = shownName(person);
    if (avatar) paintAvatar(avatar, person);
    pill.setAttribute("aria-label", pillLabel(person, reason));
    if (reason) { pill.dataset.tip = reason.tip; pill.dataset.attention = reason.why; if (!badge.isConnected) pill.append(badge); }
    else { delete pill.dataset.tip; delete pill.dataset.attention; badge.remove(); }
  };
  sync();
  const stopSync = model.onChange(sync);

  // ---- opening: the pill replaces its menu; one card at a time --------------------------------------------------------------
  const toggle = (source: CardSource): void => {
    void load().then((p) => {
      if (p.isOpen()) { p.close(false, source); return; }
      closeVersion();
      p.open(false, source);
    });
  };
  // In the capture phase, so the pill's own menu never opens.
  const onFootClick = (event: MouseEvent): void => {
    const target = event.target as Element | null;
    if (target?.closest(".ui-sidebar-user")) { event.stopImmediatePropagation(); event.preventDefault(); toggle(event.detail === 0 ? "keyboard" : "pointer"); }
    else if (target?.closest(".ui-version-pill") && panel?.isOpen()) panel.close(false, "keyboard");
  };
  foot.addEventListener("click", onFootClick, true);

  // The card is wanted soon enough that it is worth having ready: on idle, so the first screen is never slowed.
  whenIdle(() => { void load(); });

  return {
    show(after) {
      if (!core.stage.hasAttribute("data-sidebar-open")) core.stage.querySelector<HTMLElement>("#sidebar-toggle")?.click();
      void load().then((p) => { window.setTimeout(() => { closeVersion(); p.open(true, "keyboard"); after?.(p); }, 80); });
    },
    panel: () => panel,
    dispose() {
      stopSync();
      foot.removeEventListener("click", onFootClick, true);
      badge.remove();
      panel?.dispose();
    },
  };
}

/**
 * What the product knows of the person today: the name and the username of the signed-in account. The server has no store
 * for the rest yet (passkeys, the recovery key's state, devices, the machines each account logs in to, email, picture), so
 * the model leaves them undefined and the card draws no row for them, and offers no control to change what cannot be saved.
 */
export function identityModel(identity: { name: string; username: string }): AccountModel {
  const person = { name: identity.name, username: identity.username };
  return { person: () => person, onChange: () => () => undefined };
}
