/**
 * The add-host flow (mock only, `?mock=1&proto=addhost`): one window on the canvas.
 *
 * Shape (DECISIONS 138–141, 144, 171):
 * - One field. Typing filters the hosts the server already discovered; text that
 *   matches no discovered host becomes a quiet "Add <text> manually" row, so there
 *   is never a mode switch.
 * - Discovered hosts are one plain list. Selection shows only in the checkbox.
 * - Credentials appear only when a host needs them; root always asks first.
 * - Installs run per host, failures explain what happened and what to do, and a
 *   finished host opens its terminal window while the canvas stays put (H16).
 *
 * Every step change animates as one page leaving and the next entering from the
 * direction of travel (Back reverses it). Pages are swapped with the Web
 * Animations API so a new step interrupts a running transition from its current
 * frame instead of restarting from zero.
 */
import {
  createSpinner,
  hostSourceIconMarkup,
  installFocusRing,
  mountConfirmTip,
  mountStepStatus,
  mountToast,
  showTip,
  Spring,
  springCheckbox,
  type ConfirmTipController,
  type HostSource,
  type StepStatusController,
  type ToastController,
} from "../../../packages/ui/src/index";
import type { AddHostFixture } from "./add-host-contract";
import type { CoreScreen } from "./core-screen";

const FIXTURES_URL = "/__mock/proto/addhost";
const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
const SOURCE_LABELS: Record<HostSource, string> = {
  netbird: "NetBird",
  tailscale: "Tailscale",
  "known-hosts": "Known hosts",
  "ssh-config": "SSH config",
  "already-added": "Added",
};
const BOOTSTRAP_STEPS = [
  { id: "check", label: "Read-only system check" },
  { id: "install", label: "Install infraternal agent" },
  { id: "facts", label: "Gather host facts" },
  { id: "connect", label: "Connect to server" },
] as const;

type Step = "empty" | "discovery" | "credentials" | "root" | "progress" | "failure" | "success";
type FailureKind = "unreachable" | "authentication" | "mesh-policy";
type Failure = { kind: FailureKind; host: AddHostFixture };
type Direction = 1 | -1 | 0;

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]!));

const reducedMotion = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

function failureFor(host: AddHostFixture): Failure | undefined {
  if (host.reachability === "unreachable") return { kind: "unreachable", host };
  if (host.reachability === "mesh-policy") return { kind: "mesh-policy", host };
  if (host.authentication === "refused") return { kind: "authentication", host };
  return undefined;
}

/** Parses `user@host[:port]`; returns undefined for text that cannot name a host. */
function parseTarget(raw: string): { user: string | undefined; host: string; port: number | undefined } | undefined {
  const text = raw.trim();
  const match = /^(?:([a-z_][a-z0-9_.-]*)@)?([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])(?::(\d{1,5}))?$/i.exec(text);
  if (!match) return undefined;
  const port = match[3] ? Number(match[3]) : undefined;
  if (port !== undefined && (port < 1 || port > 65535)) return undefined;
  return { user: match[1], host: match[2]!, port };
}

function statusOf(host: AddHostFixture): { label: string; tone: "ok" | "warn" | "off" | "none" } {
  if (host.alreadyAdded) return { label: "Added", tone: "none" };
  if (host.reachability === "ready") return { label: "SSH ready", tone: "ok" };
  if (host.reachability === "mesh-policy") return { label: "Blocked by mesh policy", tone: "warn" };
  return { label: "No SSH response", tone: "off" };
}

const CLOSE_ICON = `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8M12 4l-8 8"/></svg>`;
const CARET_ICON = `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m6 4 4 4-4 4"/></svg>`;
const PLUS_ICON = `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 3v10M3 8h10"/></svg>`;

/** Loads the test-double inventory and binds the window to the app's entry points. */
export async function mountAddHostPrototype(core: CoreScreen): Promise<{ dispose(): void }> {
  installFocusRing();
  const response = await fetch(FIXTURES_URL, { cache: "no-store" });
  if (!response.ok) throw new Error("The add-host test-double inventory is unavailable");
  const payload = await response.json() as { hosts?: unknown };
  if (!Array.isArray(payload.hosts)) throw new Error("The add-host test double returned no hosts");
  const hosts = payload.hosts as AddHostFixture[];

  const stage = core.stage;
  const foundPanes = stage.querySelector<HTMLElement>(".panes");
  const originalCard = core.terminalHost.closest<HTMLElement>(".pane-card");
  if (!foundPanes || !originalCard) throw new Error("The canvas is missing");
  const panes: HTMLElement = foundPanes;
  stage.classList.add("has-windows-prototype", "has-addhost-prototype");
  panes.dataset.windowCanvas = "true";
  originalCard.setAttribute("aria-hidden", "true");

  const group = document.createElement("section");
  group.className = "ah-group";
  const card = document.createElement("section");
  card.className = "pane-card ah";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-label", "Add hosts");
  card.innerHTML = `
    <button class="ah-close" type="button" data-ah="close" aria-label="Close">${CLOSE_ICON}</button>
    <div class="ah-scroll"><div class="ah-pages"></div></div>
    <footer class="ah-foot"></footer>`;
  group.append(card);
  panes.append(group);
  const scroller = card.querySelector<HTMLElement>(".ah-scroll")!;
  const pages = card.querySelector<HTMLElement>(".ah-pages")!;
  const foot = card.querySelector<HTMLElement>(".ah-foot")!;
  const toast: ToastController = mountToast(stage);

  const query = new URLSearchParams(location.search);
  let step: Step = query.get("empty") === "1" ? "empty" : "discovery";
  let current: HTMLElement | undefined;
  let text = "";
  let selected: AddHostFixture[] = [];
  /** Hosts typed by hand and ticked; they live in the list like discovered ones. */
  let manualHosts: AddHostFixture[] = [];
  const allHosts = (): AddHostFixture[] => [...manualHosts, ...hosts];
  /** Autofocus only with a fine pointer: on touch it would raise the keyboard over the list. */
  const focusField = (page: ParentNode | undefined): void => {
    if (matchMedia("(pointer: fine)").matches) page?.querySelector<HTMLInputElement>(".ah-input")?.focus({ preventScroll: true });
  };
  let installing: AddHostFixture[] = [];
  let skipped: Failure[] = [];
  let failure: Failure | undefined;
  let rootConsent = false;
  let asRoot = false;
  let timers: number[] = [];
  let resultWindows: Array<{ group: HTMLElement; card: HTMLElement; host: AddHostFixture }> = [];
  let confirmTip: ConfirmTipController | undefined;
  let disposed = false;

  const clearTimers = (): void => { for (const id of timers) window.clearTimeout(id); timers = []; };
  const later = (ms: number, fn: () => void): void => { timers.push(window.setTimeout(fn, ms)); };

  // ── Page transitions ────────────────────────────────────────────────────────
  /** Swaps in a new page, sliding along the direction of travel, interruptibly. */
  function show(page: HTMLElement, dir: Direction): void {
    const reduce = reducedMotion();
    const before = scroller.offsetHeight;
    for (const leaving of pages.querySelectorAll<HTMLElement>(".ah-page[data-leaving]")) leaving.remove();
    const old = current;
    if (old) {
      // Freeze the leaving page at its current frame so an interrupted entry
      // leaves from where it is, not from where it was going.
      for (const animation of old.getAnimations()) { animation.commitStyles(); animation.cancel(); }
      old.dataset.leaving = "true";
      old.inert = true;
      old.style.position = "absolute";
      old.style.inset = "0 0 auto 0";
    }
    page.classList.add("ah-page");
    pages.append(page);
    current = page;
    scroller.scrollTop = 0;
    card.classList.remove("is-scrolled");
    const after = scroller.offsetHeight;
    if (!old) return;
    const distance = reduce || dir === 0 ? 0 : 14 * dir;
    const exit = old.animate(
      [{ opacity: getComputedStyle(old).opacity, transform: getComputedStyle(old).transform === "none" ? "none" : getComputedStyle(old).transform },
        { opacity: 0, transform: `translateX(${-distance}px)` }],
      { duration: 150, easing: EASE, fill: "forwards" },
    );
    exit.onfinish = () => old.remove();
    page.animate(
      [{ opacity: 0, transform: `translateX(${distance}px)` }, { opacity: 1, transform: "translateX(0)" }],
      { duration: 220, easing: EASE },
    );
    if (!reduce && before !== after) {
      scroller.animate([{ height: `${before}px` }, { height: `${after}px` }], { duration: 220, easing: EASE });
    }
  }

  /** Replaces the footer actions with a quick crossfade (they belong to the page). */
  function setFoot(markup: string): void {
    foot.innerHTML = markup;
    foot.hidden = markup === "";
    if (!reducedMotion() && markup) foot.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: EASE });
  }

  function go(next: Step, dir: Direction = 1): void {
    clearTimers();
    step = next;
    card.dataset.step = next;
    const page = document.createElement("div");
    page.dataset.page = next;
    if (next === "empty") renderEmpty(page);
    else if (next === "discovery") renderDiscovery(page);
    else if (next === "credentials") renderCredentials(page);
    else if (next === "root") renderRoot(page);
    else if (next === "progress") renderProgress(page);
    else if (next === "failure") renderFailure(page);
    else renderSuccess(page);
    show(page, dir);
    if (next === "progress") startProgress();
    if (next === "discovery") focusField(page);
  }

  // ── Empty state ─────────────────────────────────────────────────────────────
  function renderEmpty(page: HTMLElement): void {
    page.innerHTML = `<h1 class="ah-title">No hosts yet</h1>
      <p class="ah-lede">Add a host to open its terminal here.</p>`;
    setFoot(`<button class="ah-primary" type="button" data-ah="begin">Add a host</button>`);
  }

  // ── Discovery: one field, one list ──────────────────────────────────────────
  function hostRow(host: AddHostFixture): string {
    const typed = manualHosts.includes(host);
    const status = typed ? { label: "Checked on continue", tone: "none" as const } : statusOf(host);
    const sources = host.sources.map((source) =>
      `<span class="ah-src">${hostSourceIconMarkup(source)}${SOURCE_LABELS[source]}</span>`).join("");
    const checked = selected.some((item) => item.id === host.id);
    return `<label class="ah-row${host.alreadyAdded ? " is-added" : ""}" data-host="${escapeHtml(host.id)}">
      <span class="ah-check check"><input type="checkbox" value="${escapeHtml(host.id)}" ${host.alreadyAdded ? "disabled" : ""} ${checked ? "checked" : ""}
        aria-label="${escapeHtml(host.id)}, ${escapeHtml(status.label)}" /></span>
      <span class="ah-main">
        <span class="ah-name">${escapeHtml(host.id)}</span>
        <span class="ah-meta">${typed ? `<span class="ah-os">Typed by hand · ${escapeHtml(host.user)}@${escapeHtml(host.address)}</span>` : `<span class="ah-os">${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}</span>${sources}`}</span>
      </span>
      <span class="ah-side">
        <span class="ah-status" data-tone="${status.tone}">${status.label}</span>
        ${typed ? "" : `<button class="ah-ip" type="button" data-ah="ip" data-id="${escapeHtml(host.id)}">Show IP</button>`}
      </span>
    </label>`;
  }

  function renderDiscovery(page: HTMLElement): void {
    page.innerHTML = `<h1 class="ah-title">Add hosts</h1>
      <p class="ah-lede">Hosts this server can reach. Nothing logs in until you continue.</p>
      <input class="ah-input" type="text" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false"
        placeholder="Find a host or type user@host" aria-label="Find a host or type user@host" value="${escapeHtml(text)}" />
      <div class="ah-label" aria-hidden="true">Reachable from this server</div>
      <div class="ah-list" role="group" aria-label="Hosts"></div>`;
    renderList(page);
    setFoot(`<span class="ah-count" aria-live="polite"></span><button class="ah-primary" type="button" data-ah="continue">Continue</button>`);
    updateCount();
  }

  /** Builds the list: a manual candidate row first, then typed and discovered hosts. */
  function renderList(page: HTMLElement): void {
    const list = page.querySelector<HTMLElement>(".ah-list")!;
    list.innerHTML = `<label class="ah-row ah-candidate" hidden>
        <span class="ah-check check"><input type="checkbox" data-candidate aria-label="Add the typed host" /></span>
        <span class="ah-main"><span class="ah-name">Add <span class="ah-manual-target"></span></span>
          <span class="ah-meta"><span class="ah-os">Not discovered · checked when you continue</span></span></span>
      </label>
      ${allHosts().map(hostRow).join("")}
      <p class="ah-none" hidden>No discovered host matches.</p>`;
    for (const input of list.querySelectorAll<HTMLInputElement>(".ah-row input")) springCheckbox(input);
    applyFilter(page, false);
  }

  /**
   * Shows rows that match the field. Selected rows always stay visible, so nothing
   * selected is ever hidden; text that names no other host offers the candidate row.
   */
  function applyFilter(page: HTMLElement = current!, animate = true): void {
    const needle = text.trim().toLocaleLowerCase();
    let visible = 0;
    let exact = false;
    for (const row of page.querySelectorAll<HTMLElement>(".ah-row[data-host]")) {
      const host = allHosts().find((item) => item.id === row.dataset.host)!;
      const isSelected = selected.some((item) => item.id === host.id);
      const haystack = `${host.user}@${host.id} ${host.address} ${host.operatingSystem} ${host.architecture}`.toLocaleLowerCase();
      const target = parseTarget(needle);
      const match = !needle || haystack.includes(needle) || (!!target && (host.id === target.host || host.address === target.host));
      if (target && (host.id === target.host.toLowerCase() || host.address === target.host)) exact = true;
      const wasHidden = row.hidden;
      row.hidden = !match && !isSelected;
      if (match && !isSelected) visible++;
      if (animate && wasHidden && !row.hidden && !reducedMotion()) row.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 140, easing: EASE });
    }
    const manual = page.querySelector<HTMLElement>(".ah-candidate")!;
    const target = parseTarget(text);
    const offerManual = !!target && !exact && visible === 0;
    if (offerManual && manual.hidden && animate && !reducedMotion()) manual.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 140, easing: EASE });
    manual.hidden = !offerManual;
    if (target) page.querySelector<HTMLElement>(".ah-manual-target")!.textContent = text.trim();
    const shown = page.querySelectorAll(".ah-row[data-host]:not([hidden])").length;
    page.querySelector<HTMLElement>(".ah-none")!.hidden = shown > 0 || offerManual || !needle;
    const label = page.querySelector<HTMLElement>(".ah-label");
    if (label) label.hidden = shown === 0 && !offerManual;
  }

  function updateCount(): void {
    if (step !== "discovery") return;
    const count = foot.querySelector<HTMLElement>(".ah-count");
    const primary = foot.querySelector<HTMLButtonElement>("[data-ah='continue']");
    if (count) count.textContent = selected.length === 0 ? "" : `${selected.length} selected`;
    if (primary) primary.disabled = selected.length === 0;
  }

  /** A typed host that discovery does not know: reachable but asks for an identity (mock). */
  function manualHost(): AddHostFixture | undefined {
    const target = parseTarget(text);
    if (!target) return undefined;
    const known = allHosts().find((host) => host.id === target.host.toLowerCase() || host.address === target.host);
    if (known) return { ...known, user: target.user ?? known.user };
    return {
      id: target.host,
      user: target.user ?? "root",
      address: target.host,
      operatingSystem: "Linux",
      architecture: "unknown",
      sources: [],
      reachability: target.host.startsWith("10.99.") ? "unreachable" : "ready",
      evidence: `connect ${target.host}:${target.port ?? 22}: no response after 3 attempts (5 s each); no login was attempted`,
      alreadyAdded: false,
      rootAvailable: true,
      credentialRequired: true,
      authentication: "accepted",
    };
  }

  /** Ticks the typed host: it joins the list as a selected row and the field clears. */
  function addManual(): void {
    const host = manualHost();
    if (!host || !current) return;
    const existing = allHosts().find((item) => item.id === host.id);
    if (existing) {
      if (!selected.some((item) => item.id === existing.id)) selected = [...selected, existing];
    } else {
      manualHosts = [host, ...manualHosts];
      selected = [...selected, host];
    }
    text = "";
    const input = current.querySelector<HTMLInputElement>(".ah-input");
    if (input) input.value = "";
    renderList(current);
    const row = current.querySelector<HTMLElement>(`.ah-row[data-host="${CSS.escape(host.id)}"]`);
    if (row && !reducedMotion()) row.animate([{ opacity: 0, transform: "translateY(-4px)" }, { opacity: 1, transform: "none" }], { duration: 180, easing: EASE });
    updateCount();
  }

  // ── After selection ─────────────────────────────────────────────────────────
  function proceed(): void {
    const chosen = selected.filter((host) => !host.alreadyAdded);
    const blocked = chosen.filter((host) => failureFor(host) && host.authentication !== "refused");
    const ready = chosen.filter((host) => !blocked.includes(host));
    skipped = blocked.map((host) => failureFor(host)!);
    if (ready.length === 0) { failure = skipped[0]; if (failure) go("failure"); return; }
    selected = ready;
    if (ready.some((host) => host.credentialRequired)) go("credentials");
    else afterCredentials();
  }

  function afterCredentials(): void {
    const refused = selected.filter((host) => host.authentication === "refused");
    skipped = [...skipped, ...refused.map((host) => failureFor(host)!)];
    selected = selected.filter((host) => host.authentication !== "refused");
    if (selected.length === 0) { failure = skipped[skipped.length - 1]; if (failure) go("failure"); return; }
    rootConsent = false;
    if (selected.some((host) => host.rootAvailable)) go("root");
    else startInstall(false);
  }

  function renderCredentials(page: HTMLElement): void {
    const needing = selected.filter((host) => host.credentialRequired);
    const names = needing.map((host) => `${host.user}@${host.id}`);
    page.innerHTML = `<h1 class="ah-title">SSH identity</h1>
      <p class="ah-lede">${escapeHtml(names.join(", "))} ${needing.length > 1 ? "need" : "needs"} a way to log in.</p>
      <div class="ah-options" role="radiogroup" aria-label="SSH identity">
        <label class="ah-option"><input type="radio" name="ah-identity" value="server" checked /><span class="ah-radio" aria-hidden="true"></span>
          <span class="ah-option-text"><span>Use this server's SSH key</span><span class="ah-option-hint">Used in place, never copied.</span></span></label>
        <label class="ah-option"><input type="radio" name="ah-identity" value="paste" /><span class="ah-radio" aria-hidden="true"></span>
          <span class="ah-option-text"><span>Paste a key or password</span><span class="ah-option-hint">Encrypted with your passkey.</span></span></label>
      </div>
      <textarea class="ah-secret" rows="3" spellcheck="false" autocomplete="off" aria-label="SSH key or password" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" hidden></textarea>
      ${needing.length > 1 ? `<label class="ah-consent check"><input type="checkbox" checked /><span>Use for all ${needing.length} hosts</span></label>` : ""}`;
    for (const input of page.querySelectorAll<HTMLInputElement>(".ah-consent input")) springCheckbox(input);
    setFoot(`<button class="ah-secondary" type="button" data-ah="back">Back</button><button class="ah-primary" type="button" data-ah="credentials">Continue</button>`);
  }

  function renderRoot(page: HTMLElement): void {
    const roots = selected.filter((host) => host.rootAvailable);
    const names = roots.map((host) => host.id);
    const subject = roots.length === 1 ? names[0]! : `${roots.length} hosts`;
    page.innerHTML = `<h1 class="ah-title">Install as root on ${escapeHtml(subject)}?</h1>
      <p class="ah-lede">${escapeHtml(names.join(", "))} ${roots.length > 1 ? "allow" : "allows"} passwordless sudo. That alone is not permission.</p>
      <p class="ah-body">A root infraternal agent can manage packages, services and containers, and can read every file on the host. You can also install as a user now and switch to root later.</p>
      <p class="ah-quote">Trust is one thing we can't get back once lost.</p>
      <label class="ah-consent check"><input type="checkbox" data-consent /><span>I trust infraternal with root on ${escapeHtml(subject)}</span></label>`;
    for (const input of page.querySelectorAll<HTMLInputElement>(".ah-consent input")) springCheckbox(input);
    setFoot(`<button class="ah-secondary" type="button" data-ah="as-user">Install as user</button><button class="ah-primary" type="button" data-ah="as-root" disabled>Install as root</button>`);
  }

  // ── Progress ────────────────────────────────────────────────────────────────
  let marks = new Map<string, StepStatusController[]>();

  function startInstall(root: boolean): void {
    asRoot = root;
    installing = [...selected];
    go("progress");
  }

  function renderProgress(page: HTMLElement): void {
    const one = installing.length === 1;
    page.innerHTML = `<h1 class="ah-title">${one ? `Adding ${escapeHtml(installing[0]!.id)}` : `Adding ${installing.length} hosts`}</h1>
      <p class="ah-lede">${one ? "This takes a few seconds." : "Each host installs on its own; one failure never blocks another."}</p>
      ${installing.map((host) => `<section class="ah-host" data-progress="${escapeHtml(host.id)}">
        <div class="ah-host-head"><span class="ah-name">${escapeHtml(host.id)}</span><span class="ah-os">${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}${asRoot ? " · root" : ""}</span></div>
        <ol class="ah-steps">${BOOTSTRAP_STEPS.map((item) => `<li data-state="pending"><span class="ah-mark"></span><span>${item.label}</span></li>`).join("")}</ol>
      </section>`).join("")}
      ${skipped.map((item) => `<p class="ah-note">${escapeHtml(item.host.id)} was skipped: ${escapeHtml(failureCopy(item).short)}</p>`).join("")}`;
    marks = new Map();
    for (const host of installing) {
      const section = page.querySelector<HTMLElement>(`[data-progress="${CSS.escape(host.id)}"]`)!;
      marks.set(host.id, [...section.querySelectorAll<HTMLElement>(".ah-mark")].map((mark) => mountStepStatus(mark)));
    }
    setFoot("");
  }

  function startProgress(): void {
    const advance = (done: number): void => {
      if (disposed || step !== "progress") return;
      for (const host of installing) {
        const items = [...current!.querySelectorAll<HTMLElement>(`[data-progress="${CSS.escape(host.id)}"] li`)];
        items.forEach((item, index) => {
          const state = index < done ? "done" : index === done ? "running" : "pending";
          item.dataset.state = state;
          marks.get(host.id)?.[index]?.set(state);
        });
      }
      if (done >= BOOTSTRAP_STEPS.length) later(380, () => go("success"));
      else later(560, () => advance(done + 1));
    };
    later(120, () => advance(0));
  }

  // ── Success and failure ─────────────────────────────────────────────────────
  function renderSuccess(page: HTMLElement): void {
    const first = installing[0]!;
    const many = installing.length > 1;
    page.innerHTML = `<div class="ah-done"><span class="ah-done-mark"></span></div>
      <h1 class="ah-title">${many ? `${installing.length} hosts are ready` : `${escapeHtml(first.id)} is ready`}</h1>
      <p class="ah-lede">${many ? "Their terminal windows are open on the canvas." : "Its terminal window is open on the canvas."}</p>
      ${skipped.map((item) => `<p class="ah-note">${escapeHtml(item.host.id)} was not added: ${escapeHtml(failureCopy(item).short)}</p>`).join("")}`;
    mountStepStatus(page.querySelector<HTMLElement>(".ah-done-mark")!, "done");
    setFoot(`<button class="ah-secondary" type="button" data-ah="again">Add another host</button><button class="ah-primary" type="button" data-ah="done">Done</button>`);
    openResultWindows();
  }

  function failureCopy(item: Failure): { title: string; happened: string; next: string; short: string } {
    const name = item.host.id;
    if (item.kind === "unreachable") return {
      title: `${name} didn't answer`,
      happened: `Nothing answered on SSH port 22 at ${name}.`,
      next: "Check that the host is on and SSH is running, then retry.",
      short: "no SSH response",
    };
    if (item.kind === "authentication") return {
      title: `${name} refused the key`,
      happened: `${name} answered, but refused the SSH identity.`,
      next: "Choose another identity, or add this server's key to the host, then retry.",
      short: "SSH key refused",
    };
    return {
      title: "Blocked by the mesh policy",
      happened: `The mesh access policy blocks SSH (TCP 22) from this server to ${name}.`,
      next: "Ask a mesh admin to allow TCP 22 from this server, then retry.",
      short: "blocked by the mesh policy",
    };
  }

  function renderFailure(page: HTMLElement): void {
    const copy = failureCopy(failure!);
    page.innerHTML = `<h1 class="ah-title">${escapeHtml(copy.title)}</h1>
      <p class="ah-lede">${escapeHtml(copy.happened)}</p>
      <p class="ah-body">${escapeHtml(copy.next)}</p>
      <details class="ah-details"><summary>${CARET_ICON}<span>Details</span></summary><pre>${escapeHtml(failure!.host.evidence)}</pre></details>`;
    setFoot(`<button class="ah-secondary" type="button" data-ah="back">Back</button><button class="ah-primary" type="button" data-ah="retry">Retry</button>`);
  }

  // ── Result windows (finished hosts open their terminal; the canvas stays) ──
  function openResultWindows(): void {
    closeResultWindows();
    for (const host of installing) {
      const resultGroup = document.createElement("section");
      resultGroup.className = "window-group ah-result-group";
      const resultCard = document.createElement("section");
      resultCard.className = "pane-card window-card ah-result";
      resultCard.tabIndex = -1;
      resultCard.setAttribute("aria-label", `Terminal on ${host.id}`);
      resultCard.innerHTML = `<header class="ah-result-head">
          <span class="ah-result-host">${escapeHtml(host.user)}@${escapeHtml(host.id)}</span>
          <span class="ah-os">${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}</span>
          ${!asRoot && host.rootAvailable ? `<button class="ah-root-pill" type="button">Root available</button>` : ""}
          <span class="dot live" aria-label="Connected"></span>
        </header>
        <pre class="ah-result-term">${escapeHtml(`${host.operatingSystem} · ${host.architecture}\n\n${host.user}@${host.id}:~$ `)}</pre>`;
      resultGroup.append(resultCard);
      panes.append(resultGroup);
      resultWindows.push({ group: resultGroup, card: resultCard, host });
      const pill = resultCard.querySelector<HTMLButtonElement>(".ah-root-pill");
      if (pill) pill.addEventListener("click", () => {
        confirmTip?.close(false);
        confirmTip = mountConfirmTip(pill, {
          label: "Install as root",
          message: `Install the infraternal agent as root on ${host.id}?`,
          confirmLabel: "Yes",
          cancelLabel: "No",
          onConfirm: () => {
            const spinner = createSpinner();
            pill.prepend(spinner);
            later(1100, () => { spinner.remove(); pill.textContent = "Root active"; pill.disabled = true; showTip(pill, "Root agent ready"); });
          },
        });
      });
    }
    const first = resultWindows[0];
    if (!first) return;
    toast.show({
      message: `${first.host.id} is ready`,
      action: { label: "Go to window", onSelect: () => first.card.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", inline: "start", block: "nearest" }) },
    });
  }

  function closeResultWindows(): void {
    for (const view of resultWindows) view.group.remove();
    resultWindows = [];
  }

  // ── Window open and close ───────────────────────────────────────────────────
  const windowSpring = new Spring(0, (value) => {
    card.style.opacity = String(Math.min(1, value));
    card.style.transform = `translateY(${(1 - value) * 8}px) scale(${0.98 + value * 0.02})`;
  }, { visualDuration: 0.26, bounce: 0.12 });

  function openWindow(animate: boolean): void {
    group.hidden = false;
    if (animate && !reducedMotion()) { windowSpring.set(0, true); requestAnimationFrame(() => windowSpring.set(1)); }
    else windowSpring.set(1, true);
    if (step === "success" || step === "failure") { selected = []; manualHosts = []; text = ""; go("discovery", 0); }
    else focusField(current);
  }

  function closeWindow(): void {
    if (reducedMotion()) { group.hidden = true; return; }
    const exit = card.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(4px) scale(0.99)" }], { duration: 140, easing: EASE });
    exit.onfinish = () => { group.hidden = true; };
  }

  // ── Events ──────────────────────────────────────────────────────────────────
  function onClick(event: MouseEvent): void {
    const target = event.target instanceof Element ? event.target.closest<HTMLElement>("[data-ah]") : null;
    if (!target) return;
    const action = target.dataset.ah;
    if (action === "close" || action === "done") { toast.dismiss(); closeWindow(); }
    else if (action === "begin") go("discovery");
    else if (action === "continue") proceed();
    else if (action === "credentials") afterCredentials();
    else if (action === "as-root") startInstall(true);
    else if (action === "as-user") startInstall(false);
    else if (action === "retry") {
      const host = failure?.host;
      if (host) { selected = [{ ...host, reachability: "ready", authentication: "accepted" }]; skipped = []; proceed(); }
    } else if (action === "back") go("discovery", -1);
    else if (action === "again") { selected = []; manualHosts = []; text = ""; skipped = []; toast.dismiss(); go("discovery", -1); }
    else if (action === "ip") {
      event.preventDefault();
      const host = hosts.find((item) => item.id === target.dataset.id);
      if (host && target.textContent !== host.address) target.textContent = host.address;
    }
  }

  function onChange(event: Event): void {
    const input = event.target;
    if (!(input instanceof HTMLInputElement)) return;
    if (input.matches("[data-candidate]")) { if (input.checked) addManual(); return; }
    if (input.closest(".ah-row")) {
      const host = allHosts().find((item) => item.id === input.value);
      if (!host) return;
      selected = input.checked ? [...selected.filter((item) => item.id !== host.id), host] : selected.filter((item) => item.id !== host.id);
      updateCount();
    } else if (input.matches("[data-consent]")) {
      rootConsent = input.checked;
      const primary = foot.querySelector<HTMLButtonElement>("[data-ah='as-root']");
      if (primary) primary.disabled = !rootConsent;
    } else if (input.name === "ah-identity") {
      const secret = current?.querySelector<HTMLTextAreaElement>(".ah-secret");
      if (secret) secret.hidden = input.value !== "paste";
    }
  }

  function onInput(event: Event): void {
    if (!(event.target instanceof HTMLInputElement) || !event.target.matches(".ah-input")) return;
    text = event.target.value;
    applyFilter();
  }

  function onKeyDown(event: KeyboardEvent): void {
    if (event.key === "Escape" && !group.hidden) { closeWindow(); return; }
    if (event.key !== "Enter" || !(event.target instanceof HTMLInputElement) || !event.target.matches(".ah-input")) return;
    event.preventDefault();
    const manual = current?.querySelector<HTMLElement>(".ah-candidate");
    if (manual && !manual.hidden) { addManual(); return; }
    const rows = [...(current?.querySelectorAll<HTMLElement>(".ah-row:not([hidden]):not(.is-added)") ?? [])];
    if (rows.length === 1 && selected.length === 0) rows[0]!.querySelector<HTMLInputElement>("input")!.click();
    else if (selected.length) proceed();
  }

  function onProtoAction(event: Event): void {
    const detail = (event as CustomEvent<{ action?: unknown; source?: unknown }>).detail;
    if (detail?.action === "proto:addhost") openWindow(detail.source !== "keyboard");
  }

  const sidebar = stage.querySelector<HTMLElement>("#sidebar");
  const sidebarButton = document.createElement("button");
  sidebarButton.type = "button";
  sidebarButton.className = "ah-sidebar-add";
  sidebarButton.innerHTML = `${PLUS_ICON}<span>Add hosts</span>`;
  const openFromSidebar = (): void => openWindow(true);
  sidebarButton.addEventListener("click", openFromSidebar);
  sidebar?.append(sidebarButton);

  const onScroll = (): void => { card.classList.toggle("is-scrolled", scroller.scrollTop > 4); };
  scroller.addEventListener("scroll", onScroll, { passive: true });
  card.addEventListener("click", onClick);
  card.addEventListener("change", onChange);
  card.addEventListener("input", onInput);
  card.addEventListener("keydown", onKeyDown);
  window.addEventListener("tracer:proto-action", onProtoAction);
  go(step, 0);
  if (reducedMotion()) windowSpring.set(1, true);
  else requestAnimationFrame(() => windowSpring.set(1));

  return {
    dispose() {
      disposed = true;
      clearTimers();
      confirmTip?.close(false);
      toast.dispose();
      scroller.removeEventListener("scroll", onScroll);
      card.removeEventListener("click", onClick);
      card.removeEventListener("change", onChange);
      card.removeEventListener("input", onInput);
      card.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("tracer:proto-action", onProtoAction);
      sidebarButton.removeEventListener("click", openFromSidebar);
      sidebarButton.remove();
      closeResultWindows();
      group.remove();
      originalCard.removeAttribute("aria-hidden");
      panes.removeAttribute("data-window-canvas");
      stage.classList.remove("has-addhost-prototype", "has-windows-prototype");
    },
  };
}
