/**
 * The privileged-access consent, in place (#215, D286; D139 root needs explicit consent, D141 H13 the consent and "apply to all N hosts
 * that allow sudo", H14 a small confirm, never a popup, never automatic). It is the pane that opens under the "Access level" row
 * of the machine popover's Host tab, and goes through these steps with the shared step transition (the sign-in card's spring):
 *
 *   consent  → password  → progress → done           (the way forward)
 *                 ↑  wrong password: the same step says so, the field is empty again, nothing shakes
 *   offline / no answer: one step that says nothing changed, with retry and close
 *
 * - Consent: the question in everyday words and three icon buttons with warm tooltips: ? (what this changes, the docs), × (not
 *   now), ✓ (continue). Nothing is asked of the machine until ✓.
 * - Password: which secret and why. The machine decides: "Your sudo password for kayg" or "Your doas password for kayg" when the
 *   person can use them, otherwise "The root password for build-01" (and when sudo is installed but this person may not use it,
 *   the step says so in one line instead of failing later). One field, Enter or ✓ sends, and one quiet line: used once, never
 *   stored or logged.
 * - Progress: the shared spinner with a warm tooltip that says what is happening (D139); with several machines one line each.
 * - Several machines (bulk): one consent and one password for every machine that allows sudo; the others are named and left out.
 *
 * Escape closes the pane first (it owns that key), and the popover after it. What the machine reports and what happens on a try come from the instance's `PrivilegeService` (sessions/privilege.ts);
 * this file only asks. Nothing is asked of the machine until the person presses ✓ on the consent.
 */
import { ICON_ALERT, ICON_INFO, icon } from "../../../../../packages/ui/src/icons";
import { PaneStepper } from "../../../../../packages/ui/src/pane-stepper";
import { createSpinner } from "../../../../../packages/ui/src/spinner";
import { mountStepStatus } from "../../../../../packages/ui/src/step-status";
import { installTooltipStyles } from "../../../../../packages/ui/src/tooltip";
import { tick } from "../../../../../packages/ui/src/tick";
import type { KeyValueRow } from "../../../../../packages/ui/src/kv-list";
import { el } from "../dom";
import { SESSION_ICON } from "../views/icons";
import type { Ctx } from "../context";
import type { Method, PrivilegeService, Probe } from "../sessions/privilege";

const QUESTION = '<path d="M9.2 9.4a2.9 2.9 0 1 1 4.3 2.5c-.9.5-1.5 1.1-1.5 2.1M12 17.6v.01"/><circle cx="12" cy="12" r="9"/>';
const CROSS = '<path d="m7 7 10 10M17 7 7 17"/>';
const TICK = '<path d="m5.5 12.5 4 4 9-9"/>';

export interface PrivilegeCardEnv { cx: Ctx; service: PrivilegeService; loginOf(host: string): string; /** Repaints the row (its mark and value) after a change. */ refresh(): void }
export interface PrivilegeCard { readonly el: HTMLElement; toggle(): void; close(): void; isOpen(): boolean; dispose(): void }

const listJoin = (names: string[]): string => names.length < 2 ? (names[0] ?? "") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;

export function createPrivilegeCard(host: string, env: PrivilegeCardEnv): PrivilegeCard {
  installTooltipStyles();
  const { cx, service } = env;
  const root = el("div", "ui-kv-panel cl-pv");
  const clip = el("div", "cl-pv-clip");
  const card = el("div", "cl-pv-card");
  const viewport = el("div", "cl-pv-viewport");
  card.append(viewport);
  clip.append(card);
  root.append(clip);
  let stepper = new PaneStepper(viewport);
  let open = false;
  let busy = false;
  let timer = 0;

  const names = (): string[] => service.selection(host);
  const bulk = (): boolean => names().length > 1;
  const targets = (): string[] => (bulk() ? service.sudoHosts(host) : [host]);
  const left = (): string[] => names().filter((h) => !targets().includes(h));

  // The popover scrolls inside its window: as the pane's height changes (a step, an error line) the whole pane stays in view.
  const follow = new ResizeObserver(() => { if (open) card.scrollIntoView({ block: "nearest" }); });
  follow.observe(card);

  // ---- pieces ---------------------------------------------------------------------------------------------------------
  const text = (cls: string, value: string): HTMLElement => el("p", cls, value);
  const iconButton = (cls: string, label: string, paths: string, run: () => void): HTMLButtonElement => {
    const b = el("button", cls);
    b.type = "button";
    b.dataset.tip = label;
    // The buttons sit under the text and the password field: their tip goes below, so it never covers what is being typed.
    b.dataset.tipSide = "bottom";
    b.setAttribute("aria-label", label);
    b.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
    b.addEventListener("click", run);
    return b;
  };
  const bar = (...buttons: HTMLElement[]): HTMLElement => { const b = el("div", "ui-confirm-bar cl-pv-actions"); b.append(...buttons); return b; };
  const pane = (...children: HTMLElement[]): HTMLElement => { const p = el("div", "cl-pv-pane"); p.append(...children); return p; };
  const go = (next: HTMLElement, direction: 1 | -1 | 0, focus?: () => void): void => {
    stepper.show(next, direction);
    if (focus) requestAnimationFrame(focus);
  };

  // ---- steps ----------------------------------------------------------------------------------------------------------
  const consent = (direction: 1 | -1 | 0 = 0): void => {
    const who = listJoin(targets());
    const many = bulk();
    const title = text("ui-confirm-tip-message", many ? `Allow full access on ${targets().length} computers?` : "Allow full access?");
    const lines = many
      ? `The infraternal agent on ${who} runs without special privileges now. ${targets().length === 2 ? "Both" : "All"} let ${env.loginOf(host)} use sudo, so one password does it for all. ${left().length ? `${listJoin(left())} ${left().length > 1 ? "don't" : "doesn't"} allow sudo and ${left().length > 1 ? "are" : "is"} left out.` : ""}`
      : `Right now the infraternal agent on ${host} runs without special privileges. With them it can manage a lot more. Do you consent to privileged access?`;
    const body = text("ui-confirm-tip-detail", lines.trim());
    const docs = iconButton("cl-pv-docs", "What changes? Read the docs", QUESTION, () => { if (cx.views.has("docs")) { close(); cx.nav.flyView("docs"); } else cx.toast.show({ message: "The documentation is not available on this instance.", icon: ICON_INFO }); });
    const no = iconButton("ui-confirm-no", "Not now", CROSS, () => close());
    const yes = iconButton("ui-confirm-yes", many ? `Apply to all ${targets().length} hosts that allow sudo` : "Continue", TICK, () => { passwordStep(1); });
    go(pane(title, body, bar(docs, no, yes)), direction, () => no.focus({ preventScroll: true }));
  };

  /** Which secret the machine wants, from what it reports. */
  const wording = (method: Method, denied: boolean): { title: string; field: string; note?: string } => {
    const login = env.loginOf(host);
    if (method === "sudo" || method === "doas") return { title: `Your ${method} password for ${login}`, field: `${method} password` };
    return { title: `The root password for ${host}`, field: "root password", ...(denied ? { note: `${login} isn't allowed to use sudo on ${host}, so this needs the root password.` } : {}) };
  };

  const passwordStep = (direction: 1 | -1 | 0, error?: string): void => {
    // The machine says how this person gets privileges (a round trip), so the step is drawn once it has answered.
    void service.probe(host).then((probe) => {
      if (!open) return;
      if (!probe.reachable) { unreachable("offline", direction); return; }
      drawPassword(probe, direction, error);
    });
  };
  const drawPassword = (probe: Probe, direction: 1 | -1 | 0, error?: string): void => {
    const w = wording(probe.method, probe.denied);
    const title = text("ui-confirm-tip-message", w.title);
    const detail = text("ui-confirm-tip-detail", [w.note, "Used once, then forgotten. Never stored or logged."].filter(Boolean).join(" "));
    const field = el("input", "ui-field cl-pv-field");
    field.type = "password";
    field.autocomplete = "off";
    field.spellcheck = false;
    field.placeholder = "Password";
    field.setAttribute("aria-label", w.title);
    field.setAttribute("autocapitalize", "off");
    const problem = el("div", "cl-pv-error");
    const problemText = el("span");
    problem.append(problemText);
    problem.setAttribute("role", "alert");
    const say = (message: string): void => { if (message) problemText.textContent = message; field.setAttribute("aria-invalid", String(Boolean(message))); problem.toggleAttribute("data-on", Boolean(message)); };
    if (error) say(error);
    const back = iconButton("ui-confirm-no", "Cancel", CROSS, () => close());
    const send = (): void => {
      const secret = field.value;
      if (!secret) { say("Type the password first."); field.focus({ preventScroll: true }); return; }
      field.value = ""; // the secret leaves the page as soon as it is sent
      void run(probe.method, secret);
    };
    const yes = iconButton("ui-confirm-yes", bulk() ? `Give full access on ${targets().length} computers` : "Give full access", TICK, send);
    field.addEventListener("input", () => { if (problem.hasAttribute("data-on")) say(""); });
    field.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); send(); } });
    go(pane(title, detail, field, problem, bar(back, yes)), direction, () => field.focus({ preventScroll: true }));
  };

  const run = async (method: Method, secret: string): Promise<void> => {
    if (busy) return;
    busy = true;
    const hosts = targets();
    // Progress: one line per machine, each its own spinner and warm tooltip until it is done.
    const rows = hosts.map((h) => {
      const row = el("div", "cl-pv-run");
      const mark = el("span", "cl-pv-run-mark");
      const status = mountStepStatus(mark, "running");
      mark.dataset.tip = `Giving the infraternal agent on ${h} full access`;
      row.append(mark, el("span", "cl-pv-run-name", hosts.length > 1 ? h : `Giving ${h} full access…`));
      return { h, row, status };
    });
    const list = el("div", "cl-pv-runs");
    list.setAttribute("role", "status");
    list.append(...rows.map((r) => r.row));
    go(pane(list), 1);
    let failure: "wrong" | "timeout" | "offline" | undefined;
    await Promise.all(rows.map(async (r, i) => {
      if (i) await new Promise((resolve) => window.setTimeout(resolve, 450 * i));
      const out = await service.attempt(r.h, method, secret);
      if (out.ok) r.status.set("done"); else { r.status.set("failed"); failure ??= out.reason; }
    }));
    busy = false;
    if (!open) return;
    if (failure === "wrong") { passwordStep(-1, `That ${method === "root" ? "root " : ""}password didn't work. Try again.`); return; }
    if (failure) { unreachable(failure, 1); return; }
    window.setTimeout(() => { if (open) done(hosts); }, 700);
    env.refresh();
  };

  const done = (ran: string[]): void => {
    const mark = el("span", "cl-pv-done-tick");
    const t = tick(mark, false);
    const message = text("ui-confirm-tip-message", ran.length > 1 ? `${listJoin(ran)} now have full access.` : `${host} now has full access.`);
    const p = pane(el("div", "cl-pv-run"));
    p.firstElementChild!.append(mark, message);
    go(p, 1);
    requestAnimationFrame(() => t.set(true));
    timer = window.setTimeout(() => close(), 1500);
  };

  const unreachable = (why: "offline" | "timeout", direction: 1 | -1 | 0): void => {
    const head = el("div", "cl-pv-run");
    const sign = el("span", "cl-pv-alert");
    sign.innerHTML = icon(ICON_ALERT);
    head.append(sign, text("ui-confirm-tip-message", why === "offline" ? `${host} can't be reached right now` : `${host} didn't answer in time`));
    const detail = text("ui-confirm-tip-detail", why === "offline"
      ? "Its infraternal agent isn't connected, so nothing was changed. Try again when it is back."
      : "Nothing was changed. The computer may be busy or the connection slow. Try again.");
    const no = iconButton("ui-confirm-no", "Close", CROSS, () => close());
    const again = iconButton("ui-confirm-yes", "Try again", SESSION_ICON.retry, () => passwordStep(1));
    go(pane(head, detail, bar(no, again)), direction, () => again.focus({ preventScroll: true }));
  };

  // ---- opening and closing ----------------------------------------------------------------------------------------------
  const onKey = (e: KeyboardEvent): void => { if (e.key === "Escape" && open) { e.preventDefault(); e.stopPropagation(); close(true); } };
  root.dataset.ownsEscape = "";
  root.addEventListener("keydown", onKey);
  const close = (focusRow = false): void => {
    window.clearTimeout(timer);
    if (!open) return;
    open = false;
    root.removeAttribute("data-open");
    root.inert = true;
    if (focusRow) root.closest(".ui-kv-row")?.querySelector<HTMLElement>(".ui-kv-press")?.focus({ preventScroll: true });
  };
  const show = (): void => {
    if (open) return;
    open = true;
    root.inert = false;
    viewport.replaceChildren();
    stepper = new PaneStepper(viewport);
    consent(0);
    // The popover can only scroll as far as its content is tall, and the pane grows into its clip over the next 240 ms: keep it in
    // view, frame by frame, until it has.
    const from = performance.now();
    const track = (): void => { if (!open) return; card.scrollIntoView({ block: "nearest" }); if (performance.now() - from < 300) requestAnimationFrame(track); };
    requestAnimationFrame(track);
    // An offline machine is said at once, before the person types a password it could not take.
    void service.probe(host).then((probe) => { if (open && !busy && !probe.reachable) unreachable("offline", 0); });
    root.setAttribute("data-open", "");
  };
  root.inert = true;
  return { el: root, toggle: () => (open ? close(true) : show()), close, isOpen: () => open, dispose() { window.clearTimeout(timer); follow.disconnect(); root.remove(); } };
}

/**
 * The "Access level" row of a machine's Host tab and the pane under it. A machine whose infraternal agent has full access
 * shows a tick and "Full access"; any other shows a quiet cross and "Limited", and pressing it opens the consent under the
 * row. One card per machine is kept while the details are open, so a repaint of the row never rebuilds a pane that is
 * showing a step.
 */
export interface AccessLevel {
  /** The row for `host`; `refresh` repaints the open details after a change. */
  row(host: string, login: string, refresh: () => void): KeyValueRow;
  dispose(): void;
}

export function createAccessLevel(cx: Ctx, service: PrivilegeService): AccessLevel {
  const cards = new Map<string, { card: PrivilegeCard; box: { refresh: () => void; login: string } }>();
  const cardFor = (host: string): { card: PrivilegeCard; box: { refresh: () => void; login: string } } => {
    let held = cards.get(host);
    if (!held) {
      const box = { refresh: (): void => {}, login: "your user" };
      held = { card: createPrivilegeCard(host, { cx, service, loginOf: () => box.login, refresh: () => box.refresh() }), box };
      cards.set(host, held);
    }
    return held;
  };
  // A machine that went back to limited (a new service state) closes a consent that was showing its success.
  const stop = service.onChange(() => { for (const [host, { card }] of cards) if (card.isOpen() && !service.isFull(host)) card.close(); });
  return {
    row(host, login, refresh) {
      const held = cardFor(host);
      held.box.refresh = refresh;
      held.box.login = login;
      const full = service.isFull(host);
      return {
        key: "Access level",
        value: full ? "Full access" : "Limited", mark: full ? "ok" : "off", copy: full ? "Full access" : "Limited",
        ...(full ? {} : { press: { tip: "Allow full access", run: () => held.card.toggle() } }),
        panel: held.card.el,
      };
    },
    dispose() { stop(); for (const { card } of cards.values()) card.dispose(); cards.clear(); },
  };
}
