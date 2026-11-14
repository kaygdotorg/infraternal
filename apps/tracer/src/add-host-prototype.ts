/**
 * The add-host flow (mock only, on the canvas at `?mock=1&proto=windows`; the alias
 * `proto=addhost` opens the same preview with the wizard already open).
 *
 * Shape (DECISIONS 138–141, 144, 160, 171; docs/design/TASTE.md):
 * - A flow opens from "+", the sidebar's "Add hosts" or the palette. The canvas hands
 *   it a window (the one window card, packages/ui window-card) and the wizard mounts
 *   inside that window's body as its own floating card over a dimmed scrim. On
 *   success the card lifts away and the same window becomes the first host's terminal
 *   window, with the canvas's header, popover and activation; other hosts from the
 *   batch get windows on the canvas right after it. The canvas places and pans.
 * - One field with chips (packages/ui chip-input): a discovered host name or a
 *   `user@host[:port]` becomes a pill as soon as it is unambiguous or ended by
 *   space, comma or Enter. Chips and list checkboxes are the same selection.
 * - Steps move with the shared pane stepper (packages/ui pane-stepper):
 *   overlapping panes on springs, a spring-driven height, Back reverses.
 * - Batches install concurrently; every host has a row with its current step,
 *   a status glyph and a thin progress bar; failures stay listed with Retry.
 *
 * Text crispness: every transform is cleared at rest (springs write
 * `transform: none` when settled), so settled text never sits on a fractional
 * transform.
 */
import {
  createSpinner,
  hostIconMarkup,
  hostPlatformFromOs,
  hostSourceIconMarkup,
  installFocusRing,
  mountChipInput,
  mountConfirmTip,
  mountStepStatus,
  PaneStepper,
  flashTip,
  Spring,
  springCheckbox,
  type Chip,
  type ChipInputController,
  type ConfirmTipController,
  type HostPlatform,
  type HostSource,
  type StepStatusController,
  type Tick,
  type ToastController,
} from "../../../packages/ui/src/index";
import type { AddHostFixture } from "./add-host-contract";
import { guideFor } from "./canvas/addhost/model";
import type { CanvasController, CanvasFlowWindow, CanvasHost, CanvasWindowHandle } from "./canvas/mock/windows-proto/canvas";
import type { CoreScreen } from "./core-screen";
import {
  foldEvent,
  pendingTarget,
  PHASES,
  ProvisioningRun,
  targetIdFor,
  type BootstrapEvent,
  type FailureKind,
  type StartTarget,
  type TargetView,
} from "./provisioning-client";
import { EASE_OUT } from "../../../packages/ui/src/motion";

/** Where the mock server serves the discovery data. */
const FIXTURES_URL = "/__mock/proto/addhost";
/** The strong ease-out curve used for the wizard's motion. */
/** The name shown for each discovery source. */
const SOURCE_LABELS: Record<HostSource, string> = {
  netbird: "NetBird",
  tailscale: "Tailscale",
  "known-hosts": "Known hosts",
  "ssh-config": "SSH config",
  "already-added": "Added",
};

/** Line icons on a 24 px grid, drawn with currentColor at a 1.5 stroke. */
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
  retry: `<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3"/><path d="M19.5 4.5v4h-4"/>`,
  rocket: `<path d="M12 15.5 8.5 12c1-4 3.5-7.2 8.5-8.5-1.3 5-4.5 7.5-5 12z"/><path d="M8.5 12 5.5 11.5 8 8.5h3M12 15.5l.5 3 3-2.5v-3M6.5 17.5c-1 .5-1.5 1.5-1.5 2.5 1 0 2-.5 2.5-1.5"/>`,
} as const;
/** An icon element from inner SVG markup on the 24 grid. */
const svg = (paths: string, className = "ah-icon"): string => `<svg class="${className}" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;

/** The wizard's screens, in the order a flow normally visits them. */
type Step = "empty" | "discovery" | "credentials" | "root" | "progress" | "failure";
/** A failed host as the server reported it: kind, its human text and its log tail. */
type Failure = { kind: FailureKind; host: AddHostFixture; message: string; evidence: string; phase: number };
/** Which way a step moves: forward, back, or replace in place. */
type Direction = 1 | -1 | 0;
/** One host of the batch. Everything about its progress is `view`, folded from server events. */
type Job = { host: AddHostFixture; target: string; view: TargetView; run: ProvisioningRun | undefined };
/** A finished batch whose failed hosts can still be retried on its open run. */
type Review = { failures: Failure[]; run: ProvisioningRun };

/** Escapes text for use in HTML. */
const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]!));
/** Whether the user asks for reduced motion. */
const reducedMotion = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

/** The platform of a discovered host, from its operating system. */
function platformOf(host: AddHostFixture): HostPlatform {
  return hostPlatformFromOs(host.operatingSystem);
}


/** Parses `user@host[:port]`; returns undefined for text that cannot name a host. */
function parseTarget(raw: string): { user: string | undefined; host: string; port: number | undefined } | undefined {
  const match = /^(?:([a-z_][a-z0-9_.-]*)@)?([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])(?::(\d{1,5}))?$/i.exec(raw.trim());
  if (!match) return undefined;
  const port = match[3] ? Number(match[3]) : undefined;
  if (port !== undefined && (port < 1 || port > 65535)) return undefined;
  return { user: match[1], host: match[2]!.toLowerCase(), port };
}

/** The label, tone and icon that describe how reachable a discovered host is. */
function statusOf(host: AddHostFixture): { label: string; tone: "ok" | "warn" | "off" | "none"; icon: string } {
  if (host.alreadyAdded) return { label: "Added", tone: "none", icon: ICON.added };
  if (host.reachability === "ready") return { label: "Reached the host", tone: "ok", icon: ICON.ready };
  if (host.reachability === "mesh-policy") return { label: "Your network rules block this host", tone: "warn", icon: ICON.blocked };
  return { label: "This host isn't answering", tone: "off", icon: ICON.silent };
}

/** The wording is the product wizard's (canvas/addhost/model.ts), so the two cannot drift apart. */
function failureCopy(item: Failure): { title: string; happened: string; next: string } {
  const { title, happened, next } = guideFor(item.host.id, { kind: item.kind, message: item.message, log_tail: [] });
  return { title, happened, next };
}

/** Maps a discovered host to the machine facts the canvas popover shows (only what the flow knows). */
function canvasHostOf(host: AddHostFixture, root: boolean): CanvasHost {
  const split = /^(.*?)\s+(\d[\d.]*)$/.exec(host.operatingSystem);
  const mesh = host.sources.find((source) => source === "netbird" || source === "tailscale");
  return {
    id: host.id, user: host.user, name: host.id, os: platformOf(host), osName: split?.[1] ?? host.operatingSystem, version: split?.[2] ?? "",
    architecture: host.architecture === "unknown" ? "" : host.architecture, model: "", cpu: "", cores: 0, memory: 0, disk: 0, uptime: "",
    load: "", kernel: "", init: "", virtualization: "", shell: "", locale: "", ips: [host.address], engines: [],
    mode: root ? "root" : "rootless", status: "live",
    connection: {
      route: "relay · Frankfurt → host", transport: "SSH bootstrap → WebSocket · TLS 1.3",
      mesh: mesh ? `${SOURCE_LABELS[mesh]} · connected` : "", certificate: "", roundTrip: "", bytes: "", reconnects: 0,
    },
    sessions: [],
  };
}

/** Loads the test-double inventory and binds flow windows to the app's entry points. */
export async function mountAddHostPrototype(core: CoreScreen, canvas: CanvasController, startEmpty: boolean, openAtStart: boolean): Promise<{ dispose(): void }> {
  installFocusRing();
  const response = await fetch(FIXTURES_URL, { cache: "no-store" });
  if (!response.ok) throw new Error("The add-host test-double inventory is unavailable");
  const payload = await response.json() as { hosts?: unknown };
  if (!Array.isArray(payload.hosts)) throw new Error("The add-host test double returned no hosts");
  const hosts = payload.hosts as AddHostFixture[];

  const stage = core.stage;

  // The canvas owns the one shared toast (its connection messages use it too).
  const toast: ToastController = canvas.toast;
  const added: AddHostFixture[] = [];
  let wizard: Wizard | undefined;
  let confirmTip: ConfirmTipController | undefined;
  /** The connection of the last batch that ended with failures, until Review takes it over. */
  let reviewRun: ProvisioningRun | undefined;

  /** One wizard: a floating card over a new window that becomes the first host's terminal. */
  class Wizard {
    /** The canvas window this flow lives in; its card is the one shared window card. */
    private readonly win: CanvasFlowWindow;
    readonly card: HTMLElement;
    private readonly pages: HTMLElement;
    private readonly foot: HTMLElement;
    private readonly scroller: HTMLElement;
    private readonly stageEl: HTMLElement;
    private readonly float: HTMLElement;
    private readonly stepper: PaneStepper;
    private readonly spring: Spring;
    private readonly resize: ResizeObserver;
    private step: Step = "discovery";
    private current: HTMLElement | undefined;
    private chips: ChipInputController | undefined;
    private ticks = new Map<string, Tick>();
    private token = "";
    private selected: AddHostFixture[] = [];
    private typed: AddHostFixture[] = [];
    private jobs: Job[] = [];
    private marks = new Map<string, StepStatusController>();
    private failure: Failure | undefined;
    private asRoot = false;
    private timers: number[] = [];
    /** The batch's connection: one per start, kept open while failed hosts can be retried. */
    private run: ProvisioningRun | undefined;
    /** Ports typed after `user@host:`; the fixture has no field for them. */
    private readonly ports = new Map<string, number>();
    private alive = true;
    private finished = false;

    /**
     * Builds the card and its first step. `startEmpty` opens on the empty state, `animate` plays the card's
     * entrance (ease-out, under 300 ms; off under reduced motion), and `review` replays a recorded run.
     */
    constructor(startEmpty: boolean, animate: boolean, review?: Review) {
      this.win = canvas.openFlowWindow({ title: "Add hosts", icon: svg(ICON.plus, "is-line") });
      this.card = this.win.card.root;
      this.card.classList.add("ah");
      this.win.card.body.innerHTML = `
        <div class="ah-stage">
          <div class="ah-scrim"></div>
          <section class="ah-float ui-overlay-surface" data-overlay-size="large" role="dialog" aria-label="Add hosts">
            <button class="ah-close" type="button" data-ah="close" aria-label="Close" data-tip="Close">${svg(ICON.close, "")}</button>
            <div class="ah-scroll" data-canvas-scroll><div class="ah-pages"></div></div>
            <footer class="ah-foot"></footer>
          </section>
        </div>`;
      this.pages = this.card.querySelector(".ah-pages")!;
      this.foot = this.card.querySelector(".ah-foot")!;
      this.scroller = this.card.querySelector(".ah-scroll")!;
      this.stageEl = this.card.querySelector(".ah-stage")!;
      this.float = this.card.querySelector(".ah-float")!;
      this.stepper = new PaneStepper(this.pages);
      const overflow = (): void => { this.float.classList.toggle("is-overflowing", this.scroller.scrollHeight > this.scroller.clientHeight + 1); };
      this.resize = new ResizeObserver(overflow);
      this.resize.observe(this.scroller);
      this.resize.observe(this.pages);
      this.card.addEventListener("click", this.onClick);
      this.card.addEventListener("change", this.onChange);
      this.card.addEventListener("keydown", this.onKeyDown);
      // The card rises onto its dimmed stage; at rest it carries no transform at all.
      const scrim = this.stageEl.querySelector<HTMLElement>(".ah-scrim")!;
      this.spring = new Spring(animate && !reducedMotion() ? 0 : 1, (value) => {
        if (value === 1) { this.float.style.transform = ""; this.float.style.opacity = ""; scrim.style.opacity = ""; return; }
        const clamped = Math.min(1, Math.max(0, value));
        this.float.style.opacity = String(clamped);
        this.float.style.transform = `translateY(${(1 - value) * 12}px) scale(${0.97 + value * 0.03})`;
        scrim.style.opacity = String(clamped);
      }, { visualDuration: 0.26 });
      if (review?.failures.length) {
        this.run = review.run;
        this.jobs = review.failures.map((failure) => ({
          host: failure.host, target: targetIdFor(failure.host.id), run: review.run,
          view: { state: "failed", attempt: 1, phase: failure.phase, message: failure.message, failure: { kind: failure.kind, message: failure.message, log_tail: [failure.evidence] }, leftovers: undefined, elapsedMs: 0, authentication: undefined },
        }));
        this.go("progress", 0);
      } else this.go(startEmpty ? "empty" : "discovery", 0);
      if (animate) requestAnimationFrame(() => this.spring.set(1));
    }

    private later(ms: number, fn: () => void): void { this.timers.push(window.setTimeout(fn, ms)); }
    private clearTimers(): void { for (const id of this.timers) window.clearTimeout(id); this.timers = []; }
    private all(): AddHostFixture[] {
      const isAdded = (host: AddHostFixture): boolean => added.some((item) => item.id === host.id);
      return [...this.typed, ...hosts.filter((host) => !isAdded(host)), ...hosts.filter(isAdded).map((host) => ({ ...host, alreadyAdded: true }))];
    }
    private focusField(): void {
      if (matchMedia("(pointer: fine)").matches) this.chips?.input.focus({ preventScroll: true });
    }

    // ── Steps ─────────────────────────────────────────────────────────────────
    /** Shared step transition: overlapping panes on springs, spring height, Back reverses. */
    private go(next: Step, dir: Direction = 1): void {
      this.clearTimers();
      this.step = next;
      this.card.dataset.step = next;
      const page = document.createElement("div");
      page.className = "ah-page";
      page.dataset.page = next;
      if (next !== "discovery") this.chips = undefined;
      if (next === "empty") this.renderEmpty(page);
      else if (next === "discovery") this.renderDiscovery(page);
      else if (next === "credentials") this.renderCredentials(page);
      else if (next === "root") this.renderRoot(page);
      else if (next === "progress") this.renderProgress(page);
      else this.renderFailure(page);
      this.stepper.show(page, dir);
      this.current = page;
      this.scroller.scrollTop = 0;
      if (next === "discovery") this.focusField();
    }

    /** Replaces the footer's buttons with `markup` and gives the new buttons the production button geometry. */
    private setFoot(markup: string): void {
      this.foot.innerHTML = markup;
      // Fixture buttons use the same primitive and instance geometry as production.
      for (const button of this.foot.querySelectorAll<HTMLButtonElement>(".ah-primary, .ah-secondary")) {
        button.classList.add("ui-button");
        button.dataset.button = button.classList.contains("ah-primary") ? "primary" : "secondary";
      }
      this.foot.hidden = markup === "";
      if (!reducedMotion() && markup) this.foot.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 220, easing: EASE_OUT });
    }

    private hero(icon: string, tone = ""): string {
      return `<div class="ah-hero"${tone ? ` data-tone="${tone}"` : ""}>${svg(icon)}</div>`;
    }

    private renderEmpty(page: HTMLElement): void {
      page.innerHTML = `${this.hero(ICON.servers)}<h1 class="ah-title">No hosts yet</h1>
        <p class="ah-lede">Add a host to open its terminal here.</p>`;
      this.setFoot(`<button class="ah-primary" type="button" data-ah="begin">${svg(ICON.plus)}<span>Add a host</span></button>`);
    }

    // ── Discovery: chips + one list ───────────────────────────────────────────
    private chipFor(host: AddHostFixture): Chip {
      const typed = this.typed.includes(host);
      return {
        id: host.id,
        label: typed ? `${host.user}@${host.id}` : host.id,
        icon: typed ? svg(ICON.typed, "is-line") : hostIconMarkup(platformOf(host), ""),
      };
    }

    private hostRow(host: AddHostFixture): string {
      const typed = this.typed.includes(host);
      const status = typed ? { label: "We'll check it when you continue", tone: "none" as const, icon: ICON.pending } : statusOf(host);
      const sources = host.sources.map((source) => `<span class="ah-src" title="${SOURCE_LABELS[source]}" aria-label="${SOURCE_LABELS[source]}">${hostSourceIconMarkup(source)}</span>`).join("");
      const checked = this.selected.some((item) => item.id === host.id);
      const mark = typed ? svg(ICON.typed, "ah-os-mark is-line") : hostIconMarkup(platformOf(host), "ah-os-mark");
      return `<label class="ah-row${host.alreadyAdded ? " is-added" : ""}" data-host="${escapeHtml(host.id)}">
        <span class="ah-check check"><input type="checkbox" value="${escapeHtml(host.id)}" ${host.alreadyAdded ? "disabled" : ""} ${checked ? "checked" : ""}
          aria-label="${escapeHtml(host.id)}, ${escapeHtml(status.label)}" /></span>
        ${mark}
        <span class="ah-main">
          <span class="ah-name">${escapeHtml(host.id)}</span>
          <span class="ah-meta">${typed ? `<span>${escapeHtml(host.user)}@${escapeHtml(host.address)}</span>` : `<span>${escapeHtml(host.operatingSystem)}</span><span>· ${escapeHtml(host.architecture)}</span>`}${sources ? `<span class="ah-srcs">${sources}</span>` : ""}</span>
        </span>
        <span class="ah-status" data-tone="${status.tone}">${svg(status.icon, "ah-status-icon")}<span>${status.label}</span></span>
      </label>`;
    }

    private renderDiscovery(page: HTMLElement): void {
      page.innerHTML = `<h1 class="ah-title">Add hosts</h1>
        <p class="ah-lede">Hosts this server can reach. Nothing logs in until you continue.</p>
        <div class="ah-field">${svg(ICON.servers, "ah-field-icon")}</div>
        <div class="ah-list" role="group" aria-label="Hosts"></div>`;
      this.chips = mountChipInput(page.querySelector<HTMLElement>(".ah-field")!, {
        label: "Hosts to add",
        placeholder: "Find or type user@host",
        resolve: (token, delimited) => this.resolve(token, delimited),
        onChange: (chips) => this.syncSelection(chips),
        onToken: (token) => { this.token = token; this.applyFilter(); },
        onSubmit: () => { if (this.selected.length) this.proceed(); },
      });
      for (const host of this.selected) this.chips.add(this.chipFor(host));
      this.renderList(page);
      this.setFoot(`<span class="ah-count" aria-live="polite"></span><button class="ah-primary" type="button" data-ah="continue"><span>Continue</span></button>`);
      this.updateCount();
    }

    /** A token becomes a chip when it names exactly one host, or is ended and parses as user@host. */
    private resolve(token: string, delimited: boolean): Chip | undefined {
      const target = parseTarget(token);
      if (!target) return undefined;
      const all = this.all().filter((host) => !host.alreadyAdded);
      const known = all.find((host) => host.id === target.host || host.address === target.host);
      if (known) {
        const longer = all.some((host) => host !== known && host.id.startsWith(target.host));
        if (!delimited && longer) return undefined;
        const host = target.user && target.user !== known.user ? { ...known, user: target.user } : known;
        if (host !== known) this.typed = [host, ...this.typed.filter((item) => item.id !== host.id)];
        return this.chipFor(host);
      }
      if (!delimited) return undefined;
      const host: AddHostFixture = {
        id: target.host,
        user: target.user ?? "root",
        address: target.host,
        operatingSystem: "Linux",
        architecture: "unknown",
        sources: [],
        reachability: "ready",
        evidence: "",
        alreadyAdded: false,
        rootAvailable: true,
        credentialRequired: false,
        authentication: "accepted",
      };
      this.typed = [host, ...this.typed];
      if (target.port) this.ports.set(host.id, target.port);
      if (this.current) this.renderList(this.current);
      return this.chipFor(host);
    }

    /** Chips are the selection; checkboxes follow them. */
    private syncSelection(chips: Chip[]): void {
      const all = this.all();
      this.selected = chips.map((chip) => all.find((host) => host.id === chip.id)).filter((host): host is AddHostFixture => !!host);
      // While a discovery page is being built, `current` is still the previous page; it renders from `selected`.
      if (this.current?.dataset.page === "discovery") {
        if (chips.some((chip) => !this.current!.querySelector(`.ah-row[data-host="${CSS.escape(chip.id)}"]`))) this.renderList(this.current);
        for (const [id, tick] of this.ticks) {
          const want = this.selected.some((host) => host.id === id);
          const input = this.current.querySelector<HTMLInputElement>(`.ah-row[data-host="${CSS.escape(id)}"] input`);
          if (input && input.checked !== want) { input.checked = want; tick.set(want); }
        }
        this.applyFilter();
      }
      this.updateCount();
    }

    private renderList(page: HTMLElement): void {
      const list = page.querySelector<HTMLElement>(".ah-list")!;
      list.innerHTML = `<label class="ah-row ah-candidate" hidden>
          <span class="ah-check check"><input type="checkbox" data-candidate aria-label="Add the typed host" /></span>
          ${svg(ICON.plus, "ah-os-mark is-line")}
          <span class="ah-main"><span class="ah-name">Add <span class="ah-manual-target"></span></span>
            <span class="ah-meta"><span>Not in the list. We'll check it when you continue.</span></span></span>
        </label>
        ${this.all().map((host) => this.hostRow(host)).join("")}
        <p class="ah-none" hidden>No discovered host matches.</p>`;
      this.ticks = new Map();
      for (const input of list.querySelectorAll<HTMLInputElement>(".ah-row[data-host] input")) this.ticks.set(input.value, springCheckbox(input));
      for (const input of list.querySelectorAll<HTMLInputElement>(".ah-candidate input")) springCheckbox(input);
      this.applyFilter(page);
    }

    /** Shows rows matching the unfinished token; selected rows always stay listed. */
    private applyFilter(page: HTMLElement | undefined = this.current): void {
      if (!page || page.dataset.page !== "discovery") return;
      const needle = this.token.toLowerCase();
      const target = parseTarget(this.token);
      let visible = 0;
      let exact = false;
      for (const row of page.querySelectorAll<HTMLElement>(".ah-row[data-host]")) {
        const host = this.all().find((item) => item.id === row.dataset.host);
        if (!host) continue;
        const isSelected = this.selected.some((item) => item.id === host.id);
        const named = !!target && (host.id === target.host || host.address === target.host);
        const match = !needle || `${host.user}@${host.id} ${host.address} ${host.operatingSystem} ${host.architecture}`.toLowerCase().includes(needle) || named;
        if (named) exact = true;
        const wasHidden = row.hidden;
        row.hidden = !match && !isSelected;
        if (match && !isSelected) visible++;
        if (wasHidden && !row.hidden && !reducedMotion()) row.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: EASE_OUT });
      }
      const candidate = page.querySelector<HTMLElement>(".ah-candidate")!;
      const offer = !!target && !exact && visible === 0;
      candidate.hidden = !offer;
      if (offer) page.querySelector<HTMLElement>(".ah-manual-target")!.textContent = this.token;
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

    private proceed(): void {
      if (!this.selected.length) return;
      if (this.selected.some((host) => host.credentialRequired)) this.go("credentials");
      else this.afterCredentials();
    }

    private afterCredentials(): void {
      if (this.selected.some((host) => host.rootAvailable && host.reachability === "ready")) this.go("root");
      else this.startInstall(false);
    }

    /** Draws the credentials page: one secret field for the hosts that need a key or password. */
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
        <div class="ah-reveal" data-open="false"><div class="ah-reveal-in">
          <textarea class="ah-secret" rows="3" spellcheck="false" autocomplete="off" autocapitalize="none" autocorrect="off" aria-label="SSH key or password" placeholder="Paste a private key or password" tabindex="-1"></textarea>
        </div></div>`;
      this.setFoot(`<button class="ah-secondary" type="button" data-ah="back">Back</button><button class="ah-primary" type="button" data-ah="credentials"><span>Continue</span></button>`);
    }

    private renderRoot(page: HTMLElement): void {
      const roots = this.selected.filter((host) => host.rootAvailable && host.reachability === "ready");
      const subject = roots.length === 1 ? roots[0]!.id : `${roots.length} hosts`;
      const names = roots.length <= 3 ? roots.map((host) => host.id).join(", ") : `${roots.slice(0, 2).map((host) => host.id).join(", ")} and ${roots.length - 2} more`;
      page.innerHTML = `${this.hero(ICON.shield)}<h1 class="ah-title">Install as root on ${escapeHtml(subject)}?</h1>
        <p class="ah-lede">${escapeHtml(names)} ${roots.length > 1 ? "allow" : "allows"} passwordless sudo. That alone is not permission.</p>
        <p class="ah-text">A root infraternal agent can manage packages, services and containers, and can read every file on the host. You can also install as a user now and switch to root later.</p>
        <p class="ah-quote">Trust is one thing we can't get back once lost.</p>
        <label class="ah-consent check"><input type="checkbox" data-consent /><span>I trust infraternal with root on ${escapeHtml(subject)}</span></label>`;
      for (const input of page.querySelectorAll<HTMLInputElement>(".ah-consent input")) springCheckbox(input);
      this.setFoot(`<button class="ah-secondary" type="button" data-ah="as-user">Install as user</button><button class="ah-primary" type="button" data-ah="as-root" disabled>${svg(ICON.shieldCheck)}<span>Install as root</span></button>`);
    }

    // ── Progress: every host, concurrently ────────────────────────────────────
    private startInstall(root: boolean): void {
      this.asRoot = root;
      this.closeRun();
      const targets = this.selected.map((host): StartTarget => {
        const target: StartTarget = { id: targetIdFor(host.id), address: this.addressOf(host) };
        // Root needs explicit consent; the consent page asked for it, and only for hosts that offer sudo.
        if (root && host.rootAvailable) { target.mode = "root"; target.root_consent = true; }
        return target;
      });
      this.jobs = this.selected.map((host, index) => ({ host, target: targets[index]!.id, view: pendingTarget(), run: undefined }));
      this.go("progress");
      const run = new ProvisioningRun({
        onEvent: (event) => this.onEvent(run, event),
        onClose: () => { if (this.run === run) this.run = undefined; },
      });
      this.run = run;
      for (const job of this.jobs) job.run = run;
      run.start(targets);
    }

    /** A discovered host goes by inventory id; anything typed, or with another login name, goes as text. */
    private addressOf(host: AddHostFixture): StartTarget["address"] {
      const listed = hosts.find((item) => item.id === host.id);
      if (listed && !this.typed.includes(host)) return { kind: "discovered", value: host.id };
      const port = this.ports.get(host.id);
      return { kind: "manual", value: `${host.user}@${host.address}${port ? `:${port}` : ""}` };
    }

    private closeRun(): void {
      this.run?.close();
      this.run = undefined;
    }

    /** The one way progress changes: a server event, folded into that host's view. */
    private onEvent(run: ProvisioningRun, event: BootstrapEvent): void {
      if (!this.alive) return;
      const job = this.jobs.find((item) => item.run === run && item.target === event.target);
      if (!job) return;
      job.view = foldEvent(job.view, event);
      this.paint(job);
      this.summarise();
      if (job.view.state === "done" || job.view.state === "failed") this.settle();
    }

    /** Retries on the batch's own connection; the server owns the attempt and its address. */
    private retryJob(job: Job): void {
      if (!job.run?.open) return;
      this.finished = false;
      job.view = { ...pendingTarget(), attempt: job.view.attempt };
      this.paint(job);
      this.summarise();
      this.setFoot("");
      job.run.retry(job.target);
    }

    private renderProgress(page: HTMLElement): void {
      const one = this.jobs.length === 1;
      page.innerHTML = `${this.hero(ICON.rocket)}<h1 class="ah-title">${one ? `Adding ${escapeHtml(this.jobs[0]!.host.id)}` : `Adding ${this.jobs.length} hosts`}</h1>
        <p class="ah-lede ah-summary" aria-live="polite"></p>
        <ol class="ah-jobs">${this.jobs.map((job) => `<li class="ah-job" data-job="${escapeHtml(job.host.id)}">
          ${hostIconMarkup(platformOf(job.host), "ah-os-mark")}
          <span class="ah-main"><span class="ah-name">${escapeHtml(job.host.id)}</span><span class="ah-meta ah-job-step"></span></span>
          <button class="ah-icon-button ah-job-retry" type="button" data-ah="retry-job" data-id="${escapeHtml(job.host.id)}" aria-label="Retry ${escapeHtml(job.host.id)}" data-tip="Retry" hidden>${svg(ICON.retry)}</button>
          <span class="ah-mark"></span>
          <span class="ah-bar" aria-hidden="true"><span></span></span>
        </li>`).join("")}</ol>`;
      this.marks = new Map();
      for (const job of this.jobs) {
        const row = page.querySelector<HTMLElement>(`[data-job="${CSS.escape(job.host.id)}"]`)!;
        this.marks.set(job.host.id, mountStepStatus(row.querySelector<HTMLElement>(".ah-mark")!, job.view.state));
      }
      this.setFoot("");
      for (const job of this.jobs) this.paint(job, page);
      this.summarise(page);
    }

    private paint(job: Job, page: HTMLElement | undefined = this.current): void {
      const row = page?.querySelector<HTMLElement>(`[data-job="${CSS.escape(job.host.id)}"]`);
      if (!row) return;
      const { state, phase, message } = job.view;
      row.dataset.state = state;
      // The server's own text for the latest event; a host with no event yet is queued.
      row.querySelector<HTMLElement>(".ah-job-step")!.textContent = state === "pending" ? "Waiting" : message;
      const fraction = state === "done" ? 1 : state === "pending" ? 0 : (phase + (state === "running" ? 0.5 : 0)) / PHASES.length;
      row.querySelector<HTMLElement>(".ah-bar > span")!.style.transform = `scaleX(${fraction})`;
      row.querySelector<HTMLElement>(".ah-job-retry")!.hidden = state !== "failed";
      this.marks.get(job.host.id)?.set(state);
    }

    private summarise(page: HTMLElement | undefined = this.current): void {
      const summary = page?.querySelector<HTMLElement>(".ah-summary");
      if (!summary) return;
      const done = this.jobs.filter((job) => job.view.state === "done").length;
      const failed = this.jobs.filter((job) => job.view.state === "failed").length;
      const running = this.jobs.length - done - failed;
      summary.textContent = this.jobs.length === 1
        ? (running ? "This takes a few seconds." : done ? "Ready." : "This host needs attention.")
        : `${done} of ${this.jobs.length} ready${failed ? ` · ${failed} need attention` : ""}${running ? "" : "."}`;
    }

    /** When nothing is running: open what succeeded; a lone failure gets its own page. */
    private settle(): void {
      if (this.jobs.some((job) => job.view.state === "pending" || job.view.state === "running") || this.finished) return;
      const done = this.jobs.filter((job) => job.view.state === "done").map((job) => job.host);
      const failed = this.jobs.filter((job) => job.view.state === "failed").map((job) => this.failureOf(job));
      if (done.length === 0) {
        if (this.jobs.length === 1) { this.failure = failed[0]; this.later(500, () => this.go("failure")); }
        else this.setFoot(`<button class="ah-secondary" type="button" data-ah="back">Back</button>`);
        return;
      }
      this.finished = true;
      this.later(600, () => this.finish(done, failed));
    }

    private failureOf(job: Job): Failure {
      const detail = job.view.failure;
      return {
        kind: detail?.kind ?? "install", host: job.host, phase: job.view.phase,
        message: detail?.message ?? job.view.message,
        evidence: (detail?.log_tail.length ? detail.log_tail : [detail?.message ?? job.view.message]).join("\n"),
      };
    }

    private renderFailure(page: HTMLElement): void {
      const copy = failureCopy(this.failure!);
      page.innerHTML = `${this.hero(ICON.warning, "danger")}<h1 class="ah-title">${escapeHtml(copy.title)}</h1>
        <p class="ah-lede">${escapeHtml(copy.happened)}</p>
        <p class="ah-text">${escapeHtml(copy.next)}</p>
        <details class="ah-details"><summary>${svg(ICON.caret)}<span>Details</span></summary><pre>${escapeHtml(this.failure!.evidence)}</pre></details>`;
      this.setFoot(`<button class="ah-secondary" type="button" data-ah="back">Back</button><button class="ah-primary" type="button" data-ah="retry">${svg(ICON.retry)}<span>Retry</span></button>`);
    }

    // ── The result: this window becomes the first host's terminal window ─────
    /** Ends the run: this window becomes the first added host's terminal window, and `failed` lists the hosts that did not make it. */
    private finish(done: AddHostFixture[], failed: Failure[]): void {
      const [first, ...rest] = done;
      if (!first) return;
      added.push(...done);
      this.retire();
      const reduce = reducedMotion();
      const card = this.win.card;
      let fades: Animation[] = [];
      const swapHeader = (): void => {
        // The fade-out holds its end state; drop it so the new title is not stuck invisible.
        for (const fade of fades) fade.cancel();
        this.win.becomeHost(canvasHostOf(first, this.asRoot));
        card.root.classList.remove("ah");
        if (!this.asRoot && first.rootAvailable) addRootPill(card, first);
        if (!reduce) for (const child of card.pill.children) child.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, easing: EASE_OUT });
        // The rest of the batch gets windows right after this one, in order, in the same tick as
        // this window's header change, so the sidebar tree gets all its new rows in one rebuild.
        // The canvas lays them out and pans to the first with its own pan animation.
        let after: CanvasWindowHandle = this.win;
        for (const host of rest) {
          after = canvas.openHostWindow(canvasHostOf(host, this.asRoot), after.id);
          if (!this.asRoot && host.rootAvailable) addRootPill(after.card, host);
        }
        if (rest.length) canvas.reveal(this.win.id, "start");
      };
      const done2 = (): void => { this.stageEl.remove(); };
      if (reduce) { swapHeader(); done2(); }
      else {
        const scrim = this.stageEl.querySelector<HTMLElement>(".ah-scrim")!;
        this.float.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(-6px) scale(0.98)" }], { duration: 200, easing: EASE_OUT, fill: "forwards" });
        scrim.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 280, easing: EASE_OUT, fill: "forwards" }).onfinish = done2;
        fades = [...card.pill.children].map((child) => child.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 140, easing: EASE_OUT, fill: "forwards" }));
        void (fades[0]?.finished ?? Promise.resolve()).then(swapHeader);
      }
      // A batch with failures keeps its connection: Review retries on it, and closing it
      // would cancel the work. Anything else is finished, so the connection ends here.
      if (reviewRun !== this.run) reviewRun?.close();
      reviewRun = undefined;
      if (failed.length && this.run) reviewRun = this.run; else this.run?.close();
      this.run = undefined;
      const message = failed.length
        ? `${done.length} ${done.length === 1 ? "host" : "hosts"} ready · ${failed.length} need attention`
        : done.length > 1 ? `${done.length} hosts are ready` : `${first.id} is ready`;
      toast.show({
        message,
        action: failed.length
          ? { label: "Review", onSelect: () => {
            const run = reviewRun;
            reviewRun = undefined;
            openWizard(true, true, run ? { failures: failed, run } : undefined);
          } }
          : { label: "Add another", onSelect: () => openWizard(true, true) },
      });
      if (wizard === this) wizard = undefined;
    }

    private retire(): void {
      this.alive = false;
      this.resize.disconnect();
      this.clearTimers();
      this.card.removeEventListener("click", this.onClick);
      this.card.removeEventListener("change", this.onChange);
      this.card.removeEventListener("keydown", this.onKeyDown);
    }

    /** Closes the wizard: marks it no longer alive, then clears its timers and closes its run. */
    close(): void {
      this.alive = false;
      this.clearTimers();
      this.closeRun();
      this.card.removeEventListener("click", this.onClick);
      this.card.removeEventListener("change", this.onChange);
      this.card.removeEventListener("keydown", this.onKeyDown);
      this.resize.disconnect();
      const remove = (): void => { this.win.remove(); };
      if (reducedMotion()) { remove(); return; }
      this.float.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(6px) scale(0.98)" }], { duration: 160, easing: EASE_OUT, fill: "forwards" });
      this.card.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 200, delay: 60, easing: EASE_OUT, fill: "forwards" }).onfinish = remove;
    }

    focus(): void {
      canvas.activate(this.win.id);
      canvas.reveal(this.win.id, "start");
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
      else if (action === "back") this.go("discovery", -1);
      else if (action === "retry") {
        const job = this.jobs.find((item) => item.host.id === this.failure?.host.id);
        if (!job) return;
        this.jobs = [job];
        this.go("progress");
        this.retryJob(job);
      } else if (action === "retry-job") {
        const job = this.jobs.find((item) => item.host.id === target.dataset.id);
        if (job) this.retryJob(job);
      }
    };

    private readonly onChange = (event: Event): void => {
      const input = event.target;
      if (!(input instanceof HTMLInputElement)) return;
      if (input.matches("[data-candidate]")) {
        if (input.checked) { input.checked = false; this.chips?.commit(); }
        return;
      }
      if (input.closest(".ah-row[data-host]")) {
        const host = this.all().find((item) => item.id === input.value);
        if (!host || !this.chips) return;
        if (input.checked) this.chips.add(this.chipFor(host));
        else this.chips.remove(host.id);
      } else if (input.matches("[data-consent]")) {
        const primary = this.foot.querySelector<HTMLButtonElement>("[data-ah='as-root']");
        if (primary) primary.disabled = !input.checked;
      } else if (input.name === "ah-identity") {
        const reveal = this.current?.querySelector<HTMLElement>(".ah-reveal");
        if (!reveal) return;
        const open = input.value === "paste";
        reveal.dataset.open = String(open);
        reveal.querySelector<HTMLTextAreaElement>("textarea")!.tabIndex = open ? 0 : -1;
      }
    };

    private readonly onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") { this.close(); if (wizard === this) wizard = undefined; }
    };

    dispose(): void {
      this.alive = false;
      this.clearTimers();
      this.closeRun();
      this.resize.disconnect();
    }
  }

  // ── Root offer in a host window's header ────────────────────────────────────
  /** The "Root available" pill sits in the window card's own action area, next to the title pill. */
  function addRootPill(card: CanvasWindowHandle["card"], host: AddHostFixture): void {
    const pill = document.createElement("button");
    pill.type = "button";
    pill.className = "ui-window-pill ah-root-pill";
    pill.innerHTML = `${svg(ICON.shield, "ah-root-icon")}<span>Root available</span>`;
    // On a phone the label would crowd the host name out of the header; the icon stays, named.
    pill.setAttribute("aria-label", "Root available");
    pill.addEventListener("click", () => {
      confirmTip?.close(false);
      confirmTip = mountConfirmTip(pill, {
        label: "Install as root",
        boundary: pill.closest(".ui-window"),
        title: `Install as root on ${host.id}?`,
        effect: "The infraternal agent on this host will run as root, so it can change anything there.",
        confirmLabel: "Install as root",
        cancelLabel: "Cancel",
        onConfirm: () => {
          const spinner = createSpinner();
          pill.querySelector(".ah-root-icon")?.replaceWith(spinner);
          window.setTimeout(() => {
            pill.innerHTML = `${svg(ICON.shieldCheck, "ah-root-icon")}<span>Root active</span>`;
            pill.setAttribute("aria-label", "Root active");
            pill.disabled = true;
            flashTip(pill, "Root agent ready");
          }, 1100);
        },
      });
    });
    card.header.querySelector<HTMLElement>(".ui-window-actions")!.append(pill);
  }

  function openWizard(animate: boolean, fresh = false, review?: Review): void {
    if (wizard && !fresh) { wizard.focus(); return; }
    wizard = new Wizard(false, animate, review);
    wizard.focus();
  }

  // ── Entry points: "+" in the top bar, the sidebar's "Add hosts", the palette ───
  const sidebar = stage.querySelector<HTMLElement>("#sidebar");
  const sidebarToggle = stage.querySelector<HTMLButtonElement>("#sidebar-toggle");
  const closeSidebarOnTouch = (): void => {
    // On a phone the sidebar covers the canvas; the flow is what the person asked for.
    if (matchMedia("(pointer: coarse)").matches && sidebar && !sidebar.hidden) sidebarToggle?.click();
  };

  const sidebarButton = document.createElement("button");
  sidebarButton.type = "button";
  sidebarButton.className = "ah-sidebar-add";
  sidebarButton.innerHTML = `${svg(ICON.plus)}<span>Add hosts</span>`;
  const openFromSidebar = (): void => { closeSidebarOnTouch(); openWizard(true); };
  sidebarButton.addEventListener("click", openFromSidebar);
  // Above the sidebar footer, which stays pinned at the bottom.
  sidebar?.insertBefore(sidebarButton, sidebar.querySelector(".ui-sidebar-foot"));

  // The top bar's "+" is a disabled session button in the product; here it opens the flow.
  const plus = stage.querySelector<HTMLButtonElement>(".tab-add");
  const plusLabel = plus?.getAttribute("aria-label") ?? null;
  const openFromPlus = (): void => openWizard(true);
  if (plus) {
    plus.disabled = false;
    plus.setAttribute("aria-label", "Add hosts");
    plus.dataset.tip = "Add hosts";
    plus.addEventListener("click", openFromPlus);
  }

  const onProtoAction = (event: Event): void => {
    const detail = (event as CustomEvent<{ action?: unknown; source?: unknown }>).detail;
    if (detail?.action === "proto:addhost") openWizard(detail.source !== "keyboard");
  };
  window.addEventListener("tracer:canvas-action", onProtoAction);

  if (openAtStart) wizard = new Wizard(startEmpty, true);

  return {
    dispose() {
      wizard?.dispose();
      reviewRun?.close();
      confirmTip?.close(false);
      window.removeEventListener("tracer:canvas-action", onProtoAction);
      sidebarButton.removeEventListener("click", openFromSidebar);
      sidebarButton.remove();
      if (plus) {
        plus.removeEventListener("click", openFromPlus);
        plus.disabled = true;
        delete plus.dataset.tip;
        if (plusLabel) plus.setAttribute("aria-label", plusLabel);
      }
    },
  };
}
