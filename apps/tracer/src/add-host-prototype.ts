/**
 * The add-host flow (mock only, `?mock=1&proto=addhost`).
 *
 * The wizard lives inside an ordinary window card on the canvas, the same card
 * and header a terminal uses, with its content centred in the window. When a
 * host is ready, that window becomes the host's terminal in place (a morph:
 * the wizard leaves, the header becomes `user@host`, the terminal appears), so
 * no second window opens beside it. "Add another host" starts a fresh wizard
 * window.
 *
 * Flow shape (DECISIONS 138–141, 144, 171): one field that filters discovered
 * hosts and turns unknown text into a selectable typed-host row; one plain list
 * where selection shows only in the checkbox; credentials only when needed;
 * explicit root consent; per-host progress; failures that say what happened and
 * what to do.
 *
 * Text crispness: every transform is cleared once its animation ends (springs
 * write `transform: none` at rest, page transitions use unfilled Web
 * Animations), so settled text never sits on a fractional transform.
 */
import {
  createSpinner,
  hostIconMarkup,
  installFocusRing,
  mountConfirmTip,
  mountStepStatus,
  mountToast,
  showTip,
  Spring,
  springCheckbox,
  type ConfirmTipController,
  type HostPlatform,
  type HostSource,
  type StepStatusController,
  type ToastController,
  hostSourceIconMarkup,
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

/** Line icons: 24 px grid, drawn with currentColor at the instance's stroke width. */
const ICON = {
  plus: `<path d="M12 5v14M5 12h14"/>`,
  close: `<path d="m7 7 10 10M17 7 7 17"/>`,
  servers: `<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>`,
  key: `<circle cx="8" cy="15" r="4"/><path d="m10.9 12.1 8.6-8.6M16.5 6l2.5 2.5M14 8.5l1.5 1.5"/>`,
  shield: `<path d="M12 3.2 5 6v5.2c0 4.4 2.9 8.1 7 9.6 4.1-1.5 7-5.2 7-9.6V6z"/>`,
  shieldCheck: `<path d="M12 3.2 5 6v5.2c0 4.4 2.9 8.1 7 9.6 4.1-1.5 7-5.2 7-9.6V6z"/><path d="m9 12 2.2 2.2L15.2 10"/>`,
  warning: `<path d="M10.3 4.6 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17h.01"/>`,
  ready: `<circle cx="12" cy="12" r="8.5"/><path d="m8.5 12.2 2.4 2.4 4.6-4.8"/>`,
  blocked: `<path d="M12 3.2 5 6v5.2c0 4.4 2.9 8.1 7 9.6 4.1-1.5 7-5.2 7-9.6V6z"/><path d="M9.6 10.2l4.8 4.8M14.4 10.2l-4.8 4.8"/>`,
  silent: `<circle cx="12" cy="12" r="8.5"/><path d="M6 18 18 6"/>`,
  added: `<path d="m5.5 12.5 4 4 9-9"/>`,
  pending: `<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>`,
  typed: `<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 10h.01M11 10h.01M15 10h.01M8 14h8"/>`,
  caret: `<path d="m9 6 6 6-6 6"/>`,
  rocket: `<path d="M12 15.5 8.5 12c1-4 3.5-7.2 8.5-8.5-1.3 5-4.5 7.5-5 12z"/><path d="M8.5 12 5.5 11.5 8 8.5h3M12 15.5l.5 3 3-2.5v-3M6.5 17.5c-1 .5-1.5 1.5-1.5 2.5 1 0 2-.5 2.5-1.5"/>`,
} as const;
const svg = (paths: string, className = "ah-icon"): string => `<svg class="${className}" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;

type Step = "empty" | "discovery" | "credentials" | "root" | "progress" | "failure";
type FailureKind = "unreachable" | "authentication" | "mesh-policy";
type Failure = { kind: FailureKind; host: AddHostFixture };
type Direction = 1 | -1 | 0;

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]!));
const reducedMotion = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

function platformOf(host: AddHostFixture): HostPlatform {
  const os = host.operatingSystem.toLowerCase();
  if (os.includes("ubuntu")) return "ubuntu";
  if (os.includes("debian")) return "debian";
  if (os.includes("proxmox")) return "proxmox";
  if (os.includes("rhel") || os.includes("red hat")) return "redhat";
  if (os.includes("nixos")) return "nixos";
  if (os.includes("macos")) return "apple";
  return "unknown";
}

function failureFor(host: AddHostFixture): Failure | undefined {
  if (host.reachability === "unreachable") return { kind: "unreachable", host };
  if (host.reachability === "mesh-policy") return { kind: "mesh-policy", host };
  if (host.authentication === "refused") return { kind: "authentication", host };
  return undefined;
}

/** Parses `user@host[:port]`; returns undefined for text that cannot name a host. */
function parseTarget(raw: string): { user: string | undefined; host: string; port: number | undefined } | undefined {
  const match = /^(?:([a-z_][a-z0-9_.-]*)@)?([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])(?::(\d{1,5}))?$/i.exec(raw.trim());
  if (!match) return undefined;
  const port = match[3] ? Number(match[3]) : undefined;
  if (port !== undefined && (port < 1 || port > 65535)) return undefined;
  return { user: match[1], host: match[2]!, port };
}

function statusOf(host: AddHostFixture): { label: string; tone: "ok" | "warn" | "off" | "none"; icon: string } {
  if (host.alreadyAdded) return { label: "Added", tone: "none", icon: ICON.added };
  if (host.reachability === "ready") return { label: "SSH ready", tone: "ok", icon: ICON.ready };
  if (host.reachability === "mesh-policy") return { label: "Blocked by mesh policy", tone: "warn", icon: ICON.blocked };
  return { label: "No SSH response", tone: "off", icon: ICON.silent };
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

/** Loads the test-double inventory and binds wizard windows to the app's entry points. */
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

  const toast: ToastController = mountToast(stage);
  const added: AddHostFixture[] = [];
  const windows: HTMLElement[] = [];
  let wizard: Wizard | undefined;
  let confirmTip: ConfirmTipController | undefined;
  let disposed = false;

  /** One wizard window. Its card outlives the wizard: it becomes the host's terminal. */
  class Wizard {
    readonly group = document.createElement("section");
    readonly card = document.createElement("section");
    private readonly pages: HTMLElement;
    private readonly foot: HTMLElement;
    private readonly body: HTMLElement;
    private readonly pill: HTMLElement;
    private step: Step;
    private current: HTMLElement | undefined;
    private text = "";
    private selected: AddHostFixture[] = [];
    private typed: AddHostFixture[] = [];
    private installing: AddHostFixture[] = [];
    private skipped: Failure[] = [];
    private failure: Failure | undefined;
    private asRoot = false;
    private timers: number[] = [];
    private marks = new Map<string, StepStatusController[]>();
    private alive = true;
    private readonly spring: Spring;
    private readonly resize: ResizeObserver;

    constructor(startEmpty: boolean, animate: boolean) {
      this.step = startEmpty ? "empty" : "discovery";
      this.group.className = "window-group ah-group";
      this.card.className = "pane-card window-card ah";
      this.card.setAttribute("role", "group");
      this.card.setAttribute("aria-label", "Add hosts window");
      this.card.innerHTML = `
        <header class="window-header">
          <div class="window-host-pill ui-pill ui-overlay-surface ah-pill">${svg(ICON.plus, "ah-pill-icon")}<span class="window-pill-host">New host</span></div>
          <div class="window-header-actions ah-actions">
            <button class="window-header-action ui-icon-button" type="button" data-ah="close" aria-label="Close">${svg(ICON.close, "")}</button>
          </div>
        </header>
        <div class="ah-body"><div class="ah-panel"><div class="ah-pages"></div><footer class="ah-foot"></footer></div></div>`;
      this.group.append(this.card);
      panes.append(this.group);
      this.pages = this.card.querySelector(".ah-pages")!;
      this.foot = this.card.querySelector(".ah-foot")!;
      this.body = this.card.querySelector(".ah-body")!;
      this.pill = this.card.querySelector(".ah-pill")!;
      const overflow = (): void => { this.body.classList.toggle("is-overflowing", this.body.scrollHeight > this.body.clientHeight + 1); };
      this.resize = new ResizeObserver(overflow);
      this.resize.observe(this.body);
      this.resize.observe(this.pages);
      this.card.addEventListener("click", this.onClick);
      this.card.addEventListener("change", this.onChange);
      this.card.addEventListener("input", this.onInput);
      this.card.addEventListener("keydown", this.onKeyDown);
      // At rest the card carries no transform at all, so its text stays on the pixel grid.
      this.spring = new Spring(animate && !reducedMotion() ? 0 : 1, (value) => {
        if (value === 1) { this.card.style.transform = ""; this.card.style.opacity = ""; return; }
        this.card.style.opacity = String(Math.min(1, Math.max(0, value)));
        this.card.style.transform = `translateY(${(1 - value) * 10}px) scale(${0.98 + value * 0.02})`;
      }, { visualDuration: 0.28, bounce: 0.12 });
      this.go(this.step, 0);
      if (animate) requestAnimationFrame(() => this.spring.set(1));
    }

    private later(ms: number, fn: () => void): void { this.timers.push(window.setTimeout(fn, ms)); }
    private clearTimers(): void { for (const id of this.timers) window.clearTimeout(id); this.timers = []; }
    private all(): AddHostFixture[] { return [...this.typed, ...hosts.filter((host) => !added.some((item) => item.id === host.id)), ...hosts.filter((host) => added.some((item) => item.id === host.id)).map((host) => ({ ...host, alreadyAdded: true }))]; }
    private focusField(): void {
      if (matchMedia("(pointer: fine)").matches) this.current?.querySelector<HTMLInputElement>(".ah-input")?.focus({ preventScroll: true });
    }

    // ── Page transitions ──────────────────────────────────────────────────────
    private show(page: HTMLElement, dir: Direction): void {
      const reduce = reducedMotion();
      const before = this.pages.offsetHeight;
      for (const leaving of this.pages.querySelectorAll<HTMLElement>(".ah-page[data-leaving]")) leaving.remove();
      const old = this.current;
      if (old) {
        for (const animation of old.getAnimations()) { animation.commitStyles(); animation.cancel(); }
        old.dataset.leaving = "true";
        old.inert = true;
      }
      page.classList.add("ah-page");
      this.pages.append(page);
      this.current = page;
      const after = page.offsetHeight;
      if (!old) return;
      const distance = reduce || dir === 0 ? 0 : 14 * dir;
      const exit = old.animate([{ opacity: getComputedStyle(old).opacity }, { opacity: 0, transform: `translateX(${-distance}px)` }], { duration: 140, easing: EASE, fill: "forwards" });
      exit.onfinish = () => old.remove();
      page.animate([{ opacity: 0, transform: `translateX(${distance}px)` }, { opacity: 1, transform: "none" }], { duration: 220, easing: EASE });
      if (!reduce && before !== after) this.pages.animate([{ height: `${before}px` }, { height: `${after}px` }], { duration: 220, easing: EASE });
    }

    private setFoot(markup: string): void {
      this.foot.innerHTML = markup;
      this.foot.hidden = markup === "";
      if (!reducedMotion() && markup) this.foot.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: EASE });
    }

    private hero(icon: string, tone = ""): string {
      return `<div class="ah-hero"${tone ? ` data-tone="${tone}"` : ""}>${svg(icon)}</div>`;
    }

    go(next: Step, dir: Direction = 1): void {
      this.clearTimers();
      this.step = next;
      this.card.dataset.step = next;
      const page = document.createElement("div");
      page.dataset.page = next;
      if (next === "empty") this.renderEmpty(page);
      else if (next === "discovery") this.renderDiscovery(page);
      else if (next === "credentials") this.renderCredentials(page);
      else if (next === "root") this.renderRoot(page);
      else if (next === "progress") this.renderProgress(page);
      else this.renderFailure(page);
      this.show(page, dir);
      if (next === "progress") this.startProgress();
      if (next === "discovery") this.focusField();
    }

    // ── Steps ─────────────────────────────────────────────────────────────────
    private renderEmpty(page: HTMLElement): void {
      page.innerHTML = `${this.hero(ICON.servers)}<h1 class="ah-title">No hosts yet</h1>
        <p class="ah-lede">Add a host to open its terminal here.</p>`;
      this.setFoot(`<button class="ah-primary" type="button" data-ah="begin">${svg(ICON.plus)}<span>Add a host</span></button>`);
    }

    private hostRow(host: AddHostFixture): string {
      const typed = this.typed.includes(host);
      const status = typed ? { label: "Checked on continue", tone: "none" as const, icon: ICON.pending } : statusOf(host);
      const sources = host.sources.map((source) => `<span class="ah-src">${hostSourceIconMarkup(source)}${SOURCE_LABELS[source]}</span>`).join("");
      const checked = this.selected.some((item) => item.id === host.id);
      const mark = typed ? svg(ICON.typed, "ah-os-mark is-line") : hostIconMarkup(platformOf(host), "ah-os-mark");
      return `<label class="ah-row${host.alreadyAdded ? " is-added" : ""}" data-host="${escapeHtml(host.id)}">
        <span class="ah-check check"><input type="checkbox" value="${escapeHtml(host.id)}" ${host.alreadyAdded ? "disabled" : ""} ${checked ? "checked" : ""}
          aria-label="${escapeHtml(host.id)}, ${escapeHtml(status.label)}" /></span>
        ${mark}
        <span class="ah-main">
          <span class="ah-name">${escapeHtml(host.id)}</span>
          <span class="ah-meta">${typed ? `<span>${escapeHtml(host.user)}@${escapeHtml(host.address)}</span>` : `<span>${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}</span>${sources}`}</span>
        </span>
        <span class="ah-side">
          <span class="ah-status" data-tone="${status.tone}">${svg(status.icon, "ah-status-icon")}${status.label}</span>
          ${typed || host.alreadyAdded ? "" : `<button class="ah-ip" type="button" data-ah="ip" data-id="${escapeHtml(host.id)}">Show IP</button>`}
        </span>
      </label>`;
    }

    private renderDiscovery(page: HTMLElement): void {
      page.innerHTML = `<h1 class="ah-title">Add hosts</h1>
        <p class="ah-lede">Hosts this server can reach. Nothing logs in until you continue.</p>
        <div class="ah-field">${svg(ICON.servers, "ah-field-icon")}
          <input class="ah-input" type="text" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false"
            placeholder="Find or type user@host" aria-label="Find a host or type user@host" value="${escapeHtml(this.text)}" /></div>
        <div class="ah-list" role="group" aria-label="Hosts"></div>`;
      this.renderList(page);
      this.setFoot(`<span class="ah-count" aria-live="polite"></span><button class="ah-primary" type="button" data-ah="continue"><span>Continue</span></button>`);
      this.updateCount();
    }

    private renderList(page: HTMLElement): void {
      const list = page.querySelector<HTMLElement>(".ah-list")!;
      list.innerHTML = `<label class="ah-row ah-candidate" hidden>
          <span class="ah-check check"><input type="checkbox" data-candidate aria-label="Add the typed host" /></span>
          ${svg(ICON.plus, "ah-os-mark is-line")}
          <span class="ah-main"><span class="ah-name">Add <span class="ah-manual-target"></span></span>
            <span class="ah-meta"><span>Not discovered · checked when you continue</span></span></span>
        </label>
        ${this.all().map((host) => this.hostRow(host)).join("")}
        <p class="ah-none" hidden>No discovered host matches.</p>`;
      for (const input of list.querySelectorAll<HTMLInputElement>(".ah-row input")) springCheckbox(input);
      this.applyFilter(page, false);
    }

    /** Shows matching rows; selected rows always stay; unmatched text offers the typed-host row. */
    private applyFilter(page: HTMLElement = this.current!, animate = true): void {
      const needle = this.text.trim().toLocaleLowerCase();
      const target = parseTarget(this.text);
      let visible = 0;
      let exact = false;
      for (const row of page.querySelectorAll<HTMLElement>(".ah-row[data-host]")) {
        const host = this.all().find((item) => item.id === row.dataset.host)!;
        const isSelected = this.selected.some((item) => item.id === host.id);
        const haystack = `${host.user}@${host.id} ${host.address} ${host.operatingSystem} ${host.architecture}`.toLocaleLowerCase();
        const named = !!target && (host.id === target.host.toLowerCase() || host.address === target.host);
        const match = !needle || haystack.includes(needle) || named;
        if (named) exact = true;
        const wasHidden = row.hidden;
        row.hidden = !match && !isSelected;
        if (match && !isSelected) visible++;
        if (animate && wasHidden && !row.hidden && !reducedMotion()) row.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 140, easing: EASE });
      }
      const candidate = page.querySelector<HTMLElement>(".ah-candidate")!;
      const offer = !!target && !exact && visible === 0;
      if (offer && candidate.hidden && animate && !reducedMotion()) candidate.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 140, easing: EASE });
      candidate.hidden = !offer;
      if (target) page.querySelector<HTMLElement>(".ah-manual-target")!.textContent = this.text.trim();
      const shown = page.querySelectorAll(".ah-row[data-host]:not([hidden])").length;
      page.querySelector<HTMLElement>(".ah-none")!.hidden = shown > 0 || offer || !needle;
    }

    private updateCount(): void {
      if (this.step !== "discovery") return;
      const count = this.foot.querySelector<HTMLElement>(".ah-count");
      const primary = this.foot.querySelector<HTMLButtonElement>("[data-ah='continue']");
      if (count) count.textContent = this.selected.length === 0 ? "" : `${this.selected.length} selected`;
      if (primary) primary.disabled = this.selected.length === 0;
    }

    private typedHost(): AddHostFixture | undefined {
      const target = parseTarget(this.text);
      if (!target) return undefined;
      const known = this.all().find((host) => host.id === target.host.toLowerCase() || host.address === target.host);
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
    private addTyped(): void {
      const host = this.typedHost();
      if (!host || !this.current) return;
      const existing = this.all().find((item) => item.id === host.id);
      if (existing) {
        if (!this.selected.some((item) => item.id === existing.id)) this.selected = [...this.selected, existing];
      } else {
        this.typed = [host, ...this.typed];
        this.selected = [...this.selected, host];
      }
      this.text = "";
      const input = this.current.querySelector<HTMLInputElement>(".ah-input");
      if (input) input.value = "";
      this.renderList(this.current);
      const row = this.current.querySelector<HTMLElement>(`.ah-row[data-host="${CSS.escape(host.id)}"]`);
      if (row && !reducedMotion()) row.animate([{ opacity: 0, transform: "translateY(-4px)" }, { opacity: 1, transform: "none" }], { duration: 180, easing: EASE });
      this.updateCount();
    }

    private proceed(): void {
      const chosen = this.selected.filter((host) => !host.alreadyAdded);
      const blocked = chosen.filter((host) => failureFor(host) && host.authentication !== "refused");
      const ready = chosen.filter((host) => !blocked.includes(host));
      this.skipped = blocked.map((host) => failureFor(host)!);
      if (ready.length === 0) { this.failure = this.skipped[0]; if (this.failure) this.go("failure"); return; }
      this.selected = ready;
      if (ready.some((host) => host.credentialRequired)) this.go("credentials");
      else this.afterCredentials();
    }

    private afterCredentials(): void {
      const refused = this.selected.filter((host) => host.authentication === "refused");
      this.skipped = [...this.skipped, ...refused.map((host) => failureFor(host)!)];
      this.selected = this.selected.filter((host) => host.authentication !== "refused");
      if (this.selected.length === 0) { this.failure = this.skipped[this.skipped.length - 1]; if (this.failure) this.go("failure"); return; }
      if (this.selected.some((host) => host.rootAvailable)) this.go("root");
      else this.startInstall(false);
    }

    private renderCredentials(page: HTMLElement): void {
      const needing = this.selected.filter((host) => host.credentialRequired);
      const names = needing.map((host) => `${host.user}@${host.id}`);
      page.innerHTML = `${this.hero(ICON.key)}<h1 class="ah-title">SSH identity</h1>
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
      this.setFoot(`<button class="ah-secondary" type="button" data-ah="back">Back</button><button class="ah-primary" type="button" data-ah="credentials"><span>Continue</span></button>`);
    }

    private renderRoot(page: HTMLElement): void {
      const roots = this.selected.filter((host) => host.rootAvailable);
      const names = roots.map((host) => host.id);
      const subject = roots.length === 1 ? names[0]! : `${roots.length} hosts`;
      page.innerHTML = `${this.hero(ICON.shield)}<h1 class="ah-title">Install as root on ${escapeHtml(subject)}?</h1>
        <p class="ah-lede">${escapeHtml(names.join(", "))} ${roots.length > 1 ? "allow" : "allows"} passwordless sudo. That alone is not permission.</p>
        <p class="ah-text">A root infraternal agent can manage packages, services and containers, and can read every file on the host. You can also install as a user now and switch to root later.</p>
        <p class="ah-quote">Trust is one thing we can't get back once lost.</p>
        <label class="ah-consent check"><input type="checkbox" data-consent /><span>I trust infraternal with root on ${escapeHtml(subject)}</span></label>`;
      for (const input of page.querySelectorAll<HTMLInputElement>(".ah-consent input")) springCheckbox(input);
      this.setFoot(`<button class="ah-secondary" type="button" data-ah="as-user">Install as user</button><button class="ah-primary" type="button" data-ah="as-root" disabled>${svg(ICON.shieldCheck)}<span>Install as root</span></button>`);
    }

    private startInstall(root: boolean): void {
      this.asRoot = root;
      this.installing = [...this.selected];
      this.go("progress");
    }

    private renderProgress(page: HTMLElement): void {
      const one = this.installing.length === 1;
      page.innerHTML = `${this.hero(ICON.rocket)}<h1 class="ah-title">${one ? `Adding ${escapeHtml(this.installing[0]!.id)}` : `Adding ${this.installing.length} hosts`}</h1>
        <p class="ah-lede">${one ? "This takes a few seconds." : "Each host installs on its own; one failure never blocks another."}</p>
        ${this.installing.map((host) => `<section class="ah-host" data-progress="${escapeHtml(host.id)}">
          <div class="ah-host-head">${hostIconMarkup(platformOf(host), "ah-os-mark")}<span class="ah-name">${escapeHtml(host.id)}</span><span class="ah-host-os">${escapeHtml(host.operatingSystem)} · ${escapeHtml(host.architecture)}${this.asRoot ? " · root" : ""}</span></div>
          <ol class="ah-steps">${BOOTSTRAP_STEPS.map((item) => `<li data-state="pending"><span class="ah-mark"></span><span>${item.label}</span></li>`).join("")}</ol>
        </section>`).join("")}
        ${this.skipped.map((item) => `<p class="ah-note">${svg(ICON.warning)}<span>${escapeHtml(item.host.id)} was skipped: ${escapeHtml(failureCopy(item).short)}</span></p>`).join("")}`;
      this.marks = new Map();
      for (const host of this.installing) {
        const section = page.querySelector<HTMLElement>(`[data-progress="${CSS.escape(host.id)}"]`)!;
        this.marks.set(host.id, [...section.querySelectorAll<HTMLElement>(".ah-mark")].map((mark) => mountStepStatus(mark)));
      }
      this.setFoot("");
    }

    private startProgress(): void {
      const advance = (done: number): void => {
        if (!this.alive || this.step !== "progress") return;
        for (const host of this.installing) {
          const items = [...this.current!.querySelectorAll<HTMLElement>(`[data-progress="${CSS.escape(host.id)}"] li`)];
          items.forEach((item, index) => {
            const state = index < done ? "done" : index === done ? "running" : "pending";
            item.dataset.state = state;
            this.marks.get(host.id)?.[index]?.set(state);
          });
        }
        if (done >= BOOTSTRAP_STEPS.length) this.later(420, () => this.finish());
        else this.later(560, () => advance(done + 1));
      };
      this.later(120, () => advance(0));
    }

    private renderFailure(page: HTMLElement): void {
      const copy = failureCopy(this.failure!);
      page.innerHTML = `${this.hero(ICON.warning, "danger")}<h1 class="ah-title">${escapeHtml(copy.title)}</h1>
        <p class="ah-lede">${escapeHtml(copy.happened)}</p>
        <p class="ah-text">${escapeHtml(copy.next)}</p>
        <details class="ah-details"><summary>${svg(ICON.caret)}<span>Details</span></summary><pre>${escapeHtml(this.failure!.host.evidence)}</pre></details>`;
      this.setFoot(`<button class="ah-secondary" type="button" data-ah="back">Back</button><button class="ah-primary" type="button" data-ah="retry"><span>Retry</span></button>`);
    }

    // ── The morph: this window becomes the first host's terminal ─────────────
    private finish(): void {
      const [first, ...rest] = this.installing;
      if (!first) return;
      added.push(...this.installing);
      this.retire();
      const reduce = reducedMotion();
      const panel = this.card.querySelector<HTMLElement>(".ah-panel")!;
      const terminal = terminalMarkup(first);
      const swap = (): void => {
        this.body.replaceWith(terminal);
        this.card.classList.remove("ah");
        this.card.dataset.hostId = first.id;
        this.card.setAttribute("aria-label", `${first.user}@${first.id} terminal window`);
        this.pill.innerHTML = `${hostIconMarkup(platformOf(first), "os-mark window-os-mark")}<span class="window-pill-host">${escapeHtml(first.user)}@${escapeHtml(first.id)}</span><span class="dot live" aria-hidden="true"></span>`;
        this.decorateHeader(first);
        if (!reduce) {
          terminal.animate([{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }], { duration: 240, easing: EASE });
          for (const child of this.pill.children) child.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, easing: EASE });
        }
      };
      if (reduce) swap();
      else {
        const out = panel.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(-8px)" }], { duration: 180, easing: EASE, fill: "forwards" });
        for (const child of this.pill.children) child.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 160, easing: EASE, fill: "forwards" });
        out.onfinish = swap;
      }
      for (const host of rest) openTerminalWindow(host, this.group, !this.asRoot);
      const message = rest.length ? `${this.installing.length} hosts are ready` : `${first.id} is ready`;
      toast.show({ message, action: { label: "Add another", onSelect: () => openWizard(true, true) } });
      if (wizard === this) wizard = undefined;
    }

    private decorateHeader(host: AddHostFixture): void {
      const actions = this.card.querySelector<HTMLElement>(".ah-actions")!;
      actions.replaceChildren();
      actions.classList.remove("ah-actions");
      if (!this.asRoot && host.rootAvailable) actions.append(rootPill(host));
    }

    /** Stops listening as a wizard; the card stays as a terminal window. */
    private retire(): void {
      this.alive = false;
      this.resize.disconnect();
      this.clearTimers();
      this.card.removeEventListener("click", this.onClick);
      this.card.removeEventListener("change", this.onChange);
      this.card.removeEventListener("input", this.onInput);
      this.card.removeEventListener("keydown", this.onKeyDown);
      windows.push(this.group);
    }

    close(): void {
      this.alive = false;
      this.clearTimers();
      const remove = (): void => { this.group.remove(); };
      if (reducedMotion()) { remove(); return; }
      this.card.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(6px) scale(0.985)" }], { duration: 150, easing: EASE, fill: "forwards" }).onfinish = remove;
    }

    focus(): void {
      this.group.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", inline: "center", block: "nearest" });
      this.focusField();
    }

    // ── Events ────────────────────────────────────────────────────────────────
    private readonly onClick = (event: MouseEvent): void => {
      const target = event.target instanceof Element ? event.target.closest<HTMLElement>("[data-ah]") : null;
      if (!target) return;
      const action = target.dataset.ah;
      if (action === "close") { this.close(); if (wizard === this) wizard = undefined; }
      else if (action === "begin") this.go("discovery");
      else if (action === "continue") this.proceed();
      else if (action === "credentials") this.afterCredentials();
      else if (action === "as-root") this.startInstall(true);
      else if (action === "as-user") this.startInstall(false);
      else if (action === "retry") {
        const host = this.failure?.host;
        if (host) { this.selected = [{ ...host, reachability: "ready", authentication: "accepted" }]; this.skipped = []; this.proceed(); }
      } else if (action === "back") this.go("discovery", -1);
      else if (action === "ip") {
        event.preventDefault();
        const host = this.all().find((item) => item.id === target.dataset.id);
        if (host && target.textContent !== host.address) target.textContent = host.address;
      }
    };

    private readonly onChange = (event: Event): void => {
      const input = event.target;
      if (!(input instanceof HTMLInputElement)) return;
      if (input.matches("[data-candidate]")) { if (input.checked) this.addTyped(); return; }
      if (input.closest(".ah-row")) {
        const host = this.all().find((item) => item.id === input.value);
        if (!host) return;
        this.selected = input.checked ? [...this.selected.filter((item) => item.id !== host.id), host] : this.selected.filter((item) => item.id !== host.id);
        this.updateCount();
      } else if (input.matches("[data-consent]")) {
        const primary = this.foot.querySelector<HTMLButtonElement>("[data-ah='as-root']");
        if (primary) primary.disabled = !input.checked;
      } else if (input.name === "ah-identity") {
        const secret = this.current?.querySelector<HTMLTextAreaElement>(".ah-secret");
        if (secret) secret.hidden = input.value !== "paste";
      }
    };

    private readonly onInput = (event: Event): void => {
      if (!(event.target instanceof HTMLInputElement) || !event.target.matches(".ah-input")) return;
      this.text = event.target.value;
      this.applyFilter();
    };

    private readonly onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") { this.close(); if (wizard === this) wizard = undefined; return; }
      if (event.key !== "Enter" || !(event.target instanceof HTMLInputElement) || !event.target.matches(".ah-input")) return;
      event.preventDefault();
      const candidate = this.current?.querySelector<HTMLElement>(".ah-candidate");
      if (candidate && !candidate.hidden) { this.addTyped(); return; }
      const rows = [...(this.current?.querySelectorAll<HTMLElement>(".ah-row[data-host]:not([hidden]):not(.is-added)") ?? [])];
      if (rows.length === 1 && this.selected.length === 0) rows[0]!.querySelector<HTMLInputElement>("input")!.click();
      else if (this.selected.length) this.proceed();
    };

    dispose(): void {
      this.alive = false;
      this.clearTimers();
      this.group.remove();
    }
  }

  // ── Terminal windows ────────────────────────────────────────────────────────
  function terminalMarkup(host: AddHostFixture): HTMLElement {
    const terminal = document.createElement("div");
    terminal.className = "window-fake-terminal ah-terminal";
    terminal.setAttribute("role", "application");
    terminal.setAttribute("aria-label", `Terminal on ${host.id}`);
    const output = document.createElement("pre");
    output.className = "window-fake-output";
    output.textContent = `${host.operatingSystem} · ${host.architecture}\n\n${host.user}@${host.id}:~$ `;
    terminal.append(output);
    return terminal;
  }

  function rootPill(host: AddHostFixture): HTMLButtonElement {
    const pill = document.createElement("button");
    pill.type = "button";
    pill.className = "ah-root-pill";
    pill.innerHTML = `${svg(ICON.shield, "ah-root-icon")}<span>Root available</span>`;
    pill.addEventListener("click", () => {
      confirmTip?.close(false);
      confirmTip = mountConfirmTip(pill, {
        label: "Install as root",
        message: `Install the infraternal agent as root on ${host.id}?`,
        confirmLabel: "Yes",
        cancelLabel: "No",
        onConfirm: () => {
          const spinner = createSpinner();
          pill.querySelector(".ah-root-icon")?.replaceWith(spinner);
          window.setTimeout(() => {
            pill.innerHTML = `${svg(ICON.shieldCheck, "ah-root-icon")}<span>Root active</span>`;
            pill.disabled = true;
            showTip(pill, "Root agent ready");
          }, 1100);
        },
      });
    });
    return pill;
  }

  /** Extra hosts from a multi-host add open their own windows after the morphed one. */
  function openTerminalWindow(host: AddHostFixture, after: HTMLElement, offerRoot: boolean): void {
    const group = document.createElement("section");
    group.className = "window-group";
    const card = document.createElement("section");
    card.className = "pane-card window-card";
    card.dataset.hostId = host.id;
    card.setAttribute("aria-label", `${host.user}@${host.id} terminal window`);
    card.innerHTML = `<header class="window-header">
        <div class="window-host-pill ui-pill ui-overlay-surface">${hostIconMarkup(platformOf(host), "os-mark window-os-mark")}<span class="window-pill-host">${escapeHtml(host.user)}@${escapeHtml(host.id)}</span><span class="dot live" aria-hidden="true"></span></div>
        <div class="window-header-actions"></div>
      </header>`;
    if (offerRoot && host.rootAvailable) card.querySelector(".window-header-actions")!.append(rootPill(host));
    card.append(terminalMarkup(host));
    group.append(card);
    after.after(group);
    windows.push(group);
    if (!reducedMotion()) card.animate([{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "none" }], { duration: 240, easing: EASE });
  }

  function openWizard(animate: boolean, fresh = false): void {
    if (wizard && !fresh) { wizard.focus(); return; }
    wizard = new Wizard(false, animate);
    wizard.focus();
  }

  // ── Sidebar: shift only what it would cover ─────────────────────────────────
  const sidebar = stage.querySelector<HTMLElement>("#sidebar");
  const roomForSidebar = (): void => {
    const desktop = matchMedia("(pointer: fine) and (min-width: 900px)").matches;
    if (!sidebar || sidebar.hidden || !desktop) { panes.style.removeProperty("--ah-shift"); return; }
    // Layout box, not the animated one: the sidebar scales in, so its rect is short while opening.
    const parent = (sidebar.offsetParent as HTMLElement | null)?.getBoundingClientRect().left ?? 0;
    const reach = Math.round(parent + sidebar.offsetLeft + sidebar.offsetWidth + 12);
    const shift = Number.parseFloat(panes.style.getPropertyValue("--ah-shift") || "0");
    let first = Infinity;
    for (const group of panes.querySelectorAll<HTMLElement>(".window-group:not([hidden])")) {
      const left = group.getBoundingClientRect().left - shift;
      if (group.getBoundingClientRect().right > 0) first = Math.min(first, left);
    }
    const needed = Number.isFinite(first) ? Math.max(0, Math.ceil(reach - first)) : 0;
    if (needed) panes.style.setProperty("--ah-shift", `${needed}px`);
    else panes.style.removeProperty("--ah-shift");
  };
  const sidebarObserver = new MutationObserver(roomForSidebar);
  if (sidebar) sidebarObserver.observe(sidebar, { attributes: true, attributeFilter: ["hidden"] });

  const sidebarButton = document.createElement("button");
  sidebarButton.type = "button";
  sidebarButton.className = "ah-sidebar-add";
  sidebarButton.innerHTML = `${svg(ICON.plus)}<span>Add hosts</span>`;
  const openFromSidebar = (): void => openWizard(true);
  sidebarButton.addEventListener("click", openFromSidebar);
  sidebar?.append(sidebarButton);

  const onProtoAction = (event: Event): void => {
    const detail = (event as CustomEvent<{ action?: unknown; source?: unknown }>).detail;
    if (detail?.action === "proto:addhost") openWizard(detail.source !== "keyboard");
  };
  window.addEventListener("tracer:proto-action", onProtoAction);

  wizard = new Wizard(new URLSearchParams(location.search).get("empty") === "1", true);

  return {
    dispose() {
      disposed = true;
      void disposed;
      wizard?.dispose();
      for (const group of windows) group.remove();
      confirmTip?.close(false);
      toast.dispose();
      sidebarObserver.disconnect();
      window.removeEventListener("tracer:proto-action", onProtoAction);
      sidebarButton.removeEventListener("click", openFromSidebar);
      sidebarButton.remove();
      panes.style.removeProperty("--ah-shift");
      originalCard.removeAttribute("aria-hidden");
      panes.removeAttribute("data-window-canvas");
      stage.classList.remove("has-addhost-prototype", "has-windows-prototype");
    },
  };
}
