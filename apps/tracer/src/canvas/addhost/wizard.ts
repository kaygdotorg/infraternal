// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The add-host wizard (D138-D141, D160, D183; #87).
 *
 * The person starts with the host: picked from discovery, typed as `user@host[:port]`, or pasted from an
 * ssh config. The server then detects how to sign in and the wizard shows only what happened, never a menu
 * of methods up front: network access, the server's own key, a saved key, a password typed once (that
 * order is the server's, contracts/ssh-bootstrap.md). The person is asked to choose only when every
 * automatic method failed (`failure.choose_method`). A host key this server does not know is shown with its
 * fingerprint and never trusted without a click.
 *
 * Pages (one `PaneStepper` moves between them):
 *   discovery -> [root] -> progress -> choose | hostkey | failure | install -> progress
 *
 * Invariants:
 * - Every status on screen is folded from a provisioning event (`foldEvent`). There are no timers that
 *   invent progress. A host with no event yet is "Waiting".
 * - One provisioning run (socket) per batch. A run is closed when no host uses it any more or the wizard
 *   closes; closing is a real cancel with rollback on the server.
 * - Secrets live in a field until the person submits. `submitCredential` sends them once to the service,
 *   clears every field first, and keeps only the opaque reference the service returns.
 * - Hosts are handed to the canvas (`sink.enrolled`) the moment the server reports them done, because
 *   `done` already means a terminal opened through the session router.
 *
 * Text crispness: springs write no transform at rest, so settled text never sits on a fractional transform.
 */
import { createSpinner, hostIconMarkup, hostSourceIconMarkup, installFocusRing, mountChipInput, mountStepStatus, PaneStepper, Spring, springCheckbox, createKeyValueList } from "../../../../../packages/ui/src/index";
import type { Chip, ChipInputController, HostPlatform, HostSource, StepStatusController, Tick, ToastController } from "../../../../../packages/ui/src/index";
import { awaitingFresh, awaitingKey, foldEvent, pendingTarget, ProvisioningRun, targetIdFor } from "../../provisioning-client";
import type { BootstrapEvent, FailureDetail, StartTarget, TargetView } from "../../provisioning-client";
import type { FlowHost, FlowSurface } from "./flow-host";
import { hostKeyPresentation } from "./host-key";
import { ICON, escapeHtml, svg } from "./icons";
import { failureDiagnostics, failureLine, guideFor, looksLikeSshConfig, parseSshConfig, parseTarget, RUNNING_TEXT, stagesOf, STAGES } from "./model";
import type { Guide, ParsedTarget } from "./model";
import { matchListed } from "./model";
import { ServiceError } from "./service";
import { runUnlock } from "./authority-run.on-demand";
import type { AddHostSink, DiscoveredHost, EnrolledHost, InstallCommand, ProvisioningService, SavedKey, ServerKey } from "./service";

/** Trusted bootstrap boundaries use plain labels in the existing details disclosure. */
const FAILED_STEP_LABELS: Record<NonNullable<FailureDetail["failed_step"]>, string> = {
  connect: "Connect to the host",
  // Plain names first; the processor architecture stays as quiet secondary text, where it helps to pick the right file.
  "get-arm64-binary": "Download infraternal (arm64)", "get-x86-64-binary": "Download infraternal (x86_64)",
  upload: "Copy infraternal to the host", install: "Install infraternal on the host",
  join: "Connect the host to this server", start: "Start infraternal on the host", readiness: "Check that the terminal opens",
};
const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
const SOURCE_LABELS: Record<HostSource, string> = { netbird: "NetBird", tailscale: "Tailscale", "known-hosts": "Known hosts", "ssh-config": "SSH config", "already-added": "Added" };
const reducedMotion = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

type Page = "authority" | "discovery" | "root" | "progress" | "choose" | "hostkey" | "failure" | "takeover" | "install";
type Direction = 1 | -1 | 0;

/** One host the person picked or typed. */
interface Entry {
  id: string;
  label: string;
  user: string | undefined;
  address: string;
  port: number | undefined;
  os: HostPlatform;
  discovered: DiscoveredHost | undefined;
}

/** One host of the batch; everything about its progress is `view`, folded from server events. */
interface Job { entry: Entry; target: string; view: TargetView; run: ProvisioningRun | undefined; root: boolean }

/** What the person sees for a host: an attempt paused on leftovers reads as needing attention, like a failure. */
const shownState = (job: Job): TargetView["state"] => awaitingFresh(job.view) ? "failed" : awaitingKey(job.view) ? "running" : job.view.state;
/** Still working without the person: not done, not failed, not paused on a new host key (a question, not a fault). */
const working = (job: Job): boolean => { const state = shownState(job); return (state === "pending" || state === "running") && !awaitingKey(job.view); };

export function platformOf(name: string | undefined): HostPlatform {
  const os = (name ?? "").toLowerCase();
  if (os.includes("ubuntu")) return "ubuntu";
  if (os.includes("debian")) return "debian";
  if (os.includes("proxmox")) return "proxmox";
  if (os.includes("rhel") || os.includes("red hat")) return "redhat";
  if (os.includes("nixos")) return "nixos";
  if (os.includes("macos")) return "apple";
  return "unknown";
}

function statusOf(host: DiscoveredHost): { label: string; tone: "ok" | "warn" | "off" | "none"; icon: string } {
  if (host.alreadyAdded) return { label: "Added", tone: "none", icon: ICON.added };
  if (host.reach === "ready") return { label: "Reached the host", tone: "ok", icon: ICON.ready };
  if (host.reach === "mesh-policy") return { label: "Your network rules block this host", tone: "warn", icon: ICON.blocked };
  if (host.reach === "unreachable") return { label: "This host isn't answering", tone: "off", icon: ICON.silent };
  return { label: "", tone: "none", icon: ICON.pending };
}

export interface WizardDeps {
  service: ProvisioningService;
  sink: AddHostSink;
  host: FlowHost;
  toast: ToastController;
  /** Called once, after the wizard has gone. */
  onClosed(): void;
}

/** The add-host wizard: discovery, CA unlock when needed, then enrollment. */
export class Wizard {
  private readonly surface: FlowSurface;
  private readonly root: HTMLElement;
  private readonly pages: HTMLElement;
  private readonly foot: HTMLElement;
  private readonly scroller: HTMLElement;
  private readonly float: HTMLElement;
  private readonly scrim: HTMLElement;
  private readonly stepper: PaneStepper;
  private readonly spring: Spring;
  private readonly resize: ResizeObserver;
  private readonly opener: Element | null = document.activeElement;
  private page: Page = "discovery";
  private current: HTMLElement | undefined;
  private chips: ChipInputController | undefined;
  private ticks = new Map<string, Tick>();
  private token = "";
  /** The invalid-entry hint appears only after the person ended a token (delimiter, Enter, Tab, Continue), never mid-typing. */
  private hintArmed = false;
  /** What discovery returned; `loading` until it answers. */
  private discovered: DiscoveredHost[] = [];
  private discovery: { state: "loading" | "ready" | "failed"; message: string } = { state: "loading", message: "" };
  private selected: Entry[] = [];
  /** Typed entries (not in discovery, or with another login), newest first. */
  private typed: Entry[] = [];
  private jobs: Job[] = [];
  private marks = new Map<string, StepStatusController>();
  private stageMarks = new Map<string, StepStatusController>();
  /** The host the choose / hostkey / failure / install pages are about. */
  private fixing: Job | undefined;
  private serverKey: ServerKey | undefined;
  private savedKey: SavedKey | undefined;
  private install: { state: "loading" | "ready" | "unavailable" | "failed"; command?: InstallCommand; message?: string } = { state: "loading" };
  /** The page the install command was opened from, so Back returns to it. */
  private installFrom: "choose" | "failure" = "failure";
  private busy = false;
  private authorityReady = false;
  private authorityInitialized = false;
  private authorityRoot = false;
  private timers: number[] = [];
  /** Stage siblings made inert while the card is open. */
  private readonly inerted: Element[] = [];
  private alive = true;
  private closing = false;

  constructor(private readonly deps: WizardDeps) {
    installFocusRing();
    this.surface = deps.host.open({ title: "Add hosts" });
    this.root = this.surface.body;
    this.root.classList.add("ah", "ah-surface");
    // A window closed from its own frame ends the wizard and cancels what is running.
    this.surface.onGone?.(() => { if (this.alive) { this.dispose(); this.deps.onClosed(); } });
    this.root.innerHTML = `
      <div class="ah-stage">
        <div class="ah-scrim"></div>
        <section class="ah-float ui-overlay-surface" data-overlay-size="large" role="dialog" aria-modal="${this.root.classList.contains("ah-overlay")}" aria-label="Add hosts">
          <button class="ah-close" type="button" data-ah="close" aria-label="Close" data-tip="Close">${svg(ICON.close, "")}</button>
          <div class="ah-scroll" data-canvas-scroll><div class="ah-pages"></div></div>
          <footer class="ah-foot"></footer>
        </section>
      </div>`;
    this.pages = this.root.querySelector(".ah-pages")!;
    this.foot = this.root.querySelector(".ah-foot")!;
    this.scroller = this.root.querySelector(".ah-scroll")!;
    this.float = this.root.querySelector(".ah-float")!;
    this.scrim = this.root.querySelector(".ah-scrim")!;
    this.stepper = new PaneStepper(this.pages);
    const overflow = (): void => { this.float.classList.toggle("is-overflowing", this.scroller.scrollHeight > this.scroller.clientHeight + 1); };
    this.resize = new ResizeObserver(overflow);
    this.resize.observe(this.scroller);
    this.resize.observe(this.pages);
    // The card is modal: the rest of the stage is unreachable by keyboard and assistive technology until it closes.
    // (Only an overlay covers the stage; a flow window is one window among others and stays part of the canvas.)
    for (const sibling of this.root.classList.contains("ah-overlay") ? this.root.parentElement?.children ?? [] : []) {
      if (sibling !== this.root && !sibling.hasAttribute("inert")) { sibling.setAttribute("inert", ""); this.inerted.push(sibling); }
    }
    this.root.addEventListener("click", this.onClick);
    this.root.addEventListener("change", this.onChange);
    // Keys go through the document: after a step change the focused button is gone, and focus is on the body.
    document.addEventListener("keydown", this.onKeyDown, true);
    this.root.addEventListener("paste", this.onPaste, true);
    // The card rises onto its dimmed stage; at rest it carries no transform at all.
    this.spring = new Spring(reducedMotion() ? 1 : 0, (value) => {
      if (value === 1) { this.float.style.transform = ""; this.float.style.opacity = ""; this.scrim.style.opacity = ""; return; }
      const clamped = Math.min(1, Math.max(0, value));
      this.float.style.opacity = String(clamped);
      this.float.style.transform = `translateY(${(1 - value) * 12}px) scale(${0.97 + value * 0.03})`;
      this.scrim.style.opacity = String(clamped);
    }, { visualDuration: 0.32 });
    this.go("discovery", 0);
    requestAnimationFrame(() => this.spring.set(1));
    void this.loadDiscovery();
    void deps.service.serverKey().then((key) => { this.serverKey = key; }, () => { /* the key is a convenience; absence is shown where it matters */ });
    void deps.service.savedKey().then((key) => { this.savedKey = key; }, () => { /* no saved key */ });
  }

  // ── Discovery data ─────────────────────────────────────────────────────────
  private async loadDiscovery(): Promise<void> {
    this.discovery = { state: "loading", message: "" };
    this.refreshDiscoveryList();
    try {
      this.discovered = await this.deps.service.discover();
      this.discovery = { state: "ready", message: "" };
      // A token typed while the list was loading names a host only now: it chips at once, as it would have.
      this.chips?.recheck();
    } catch (error: unknown) {
      this.discovery = { state: "failed", message: error instanceof ServiceError ? error.message : "Hosts couldn't be listed." };
    }
    if (!this.alive) return;
    this.refreshDiscoveryList();
  }

  private refreshDiscoveryList(): void {
    if (this.current?.dataset.page === "discovery") this.renderList(this.current);
  }

  private entryOf(host: DiscoveredHost): Entry {
    return { id: host.id, label: host.id, user: host.user, address: host.address, port: undefined, os: host.os ?? platformOf(host.operatingSystem), discovered: host };
  }

  /** Discovered hosts as list rows: those not added first, then the added ones (listed, not selectable). */
  private listed(): Array<{ entry: Entry; added: boolean }> {
    const rows = this.discovered.map((host) => ({ entry: this.entryOf(host), added: host.alreadyAdded === true }));
    return [...rows.filter((row) => !row.added), ...rows.filter((row) => row.added)];
  }

  /** Any host the field can hold. Typed hosts are chips only; they never get a list row. */
  private find(id: string): Entry | undefined {
    return this.typed.find((entry) => entry.id === id) ?? this.listed().find((row) => row.entry.id === id)?.entry;
  }

  private later(ms: number, fn: () => void): void { this.timers.push(window.setTimeout(fn, ms)); }
  private clearTimers(): void { for (const id of this.timers) window.clearTimeout(id); this.timers = []; }
  private focusField(): void { if (matchMedia("(pointer: fine)").matches) this.chips?.input.focus({ preventScroll: true }); }
  /** The discovery page on screen, when it is the one showing. */
  private discoveryPage(): HTMLElement | undefined { return this.current?.dataset.page === "discovery" ? this.current : undefined; }

  // ── Steps ──────────────────────────────────────────────────────────────────
  /** Shared step transition: overlapping panes on springs, spring height, Back reverses. */
  private go(next: Page, dir: Direction = 1): void {
    this.clearTimers();
    this.page = next;
    this.root.dataset.step = next;
    const page = document.createElement("div");
    page.className = "ah-page";
    page.dataset.page = next;
    if (next !== "discovery") this.chips = undefined;
    if (next === "discovery") this.renderDiscovery(page);
    else if (next === "root") this.renderRoot(page);
    else if (next === "authority") this.renderAuthority(page);
    else if (next === "progress") this.renderProgress(page);
    else if (next === "choose") this.renderChoose(page);
    else if (next === "hostkey") this.renderHostKey(page);
    else if (next === "takeover") this.renderTakeOver(page);
    else if (next === "install") this.renderInstall(page);
    else this.renderFailure(page);
    this.stepper.show(page, dir);
    this.current = page;
    this.scroller.scrollTop = 0;
    if (next === "discovery") this.focusField();
    // Focus stays inside the modal card when the control that had it has gone with the old page.
    else if (!this.float.contains(document.activeElement)) { page.tabIndex = -1; page.focus({ preventScroll: true }); }
  }

  private setFoot(markup: string): void {
    this.foot.innerHTML = markup;
    this.foot.hidden = markup === "";
    if (!reducedMotion() && markup) this.foot.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 220, easing: EASE });
  }

  private hero(icon: string, tone = ""): string { return `<div class="ah-hero"${tone ? ` data-tone="${tone}"` : ""}>${svg(icon)}</div>`; }

  /** A failure sits directly above the primary action (TASTE), announced politely. */
  private showError(message: string): void {
    let line = this.current?.querySelector<HTMLElement>(".ah-error");
    if (!line) {
      line = document.createElement("p");
      line.className = "ah-error";
      line.setAttribute("role", "alert");
      this.current?.append(line);
    }
    line.textContent = message;
  }

  // ── Discovery: chips + one list ────────────────────────────────────────────
  private chipFor(entry: Entry): Chip {
    const typed = !entry.discovered || this.typed.includes(entry);
    // A typed chip reads as it was typed, port included, so Backspace puts back exactly that text.
    const label = typed ? `${entry.user ? `${entry.user}@` : ""}${entry.label}${entry.port ? `:${entry.port}` : ""}` : entry.label;
    return { id: entry.id, label, icon: typed && !entry.discovered ? svg(ICON.typed, "is-line") : hostIconMarkup(entry.os, "") };
  }

  private rowOf(entry: Entry, added: boolean): string {
    const host = entry.discovered!;
    const status = statusOf(host);
    const sources = host.sources.map((source) => `<span class="ah-src" title="${SOURCE_LABELS[source]}" aria-label="${SOURCE_LABELS[source]}">${hostSourceIconMarkup(source)}</span>`).join("");
    const checked = this.selected.some((item) => item.id === entry.id);
    const facts = [host.operatingSystem, host.architecture].filter(Boolean).map((item, index) => `<span>${index ? "· " : ""}${escapeHtml(item!)}</span>`).join("") || `<span>${escapeHtml(entry.address)}</span>`;
    return `<label class="ah-row${added ? " is-added" : ""}" data-host="${escapeHtml(entry.id)}">
      <span class="ah-check check"><input type="checkbox" value="${escapeHtml(entry.id)}" ${added ? "disabled" : ""} ${checked ? "checked" : ""}
        aria-label="${escapeHtml(entry.label)}${status.label ? `, ${escapeHtml(status.label)}` : ""}" /></span>
      ${hostIconMarkup(entry.os, "ah-os-mark")}
      <span class="ah-main">
        <span class="ah-name">${escapeHtml(entry.label)}</span>
        <span class="ah-meta">${facts}${sources ? `<span class="ah-srcs">${sources}</span>` : ""}</span>
      </span>
      <span class="ah-status" data-tone="${status.tone}">${svg(status.icon, "ah-status-icon")}<span>${escapeHtml(status.label)}</span></span>
    </label>`;
  }

  private renderDiscovery(page: HTMLElement): void {
    page.innerHTML = `<h1 class="ah-title">Add hosts</h1>
      <p class="ah-lede">Pick a host, type <span class="ah-code">user@host</span>, or paste your SSH config. We won't sign in to anything until you continue.</p>
      <div class="ah-field">${svg(ICON.servers, "ah-field-icon")}</div>
      <p class="ah-hint" id="ah-host-hint">Type user@host, or user@host:2222 for another port</p>
      <div class="ah-list" role="group" aria-label="Hosts"></div>`;
    this.token = "";
    this.chips = mountChipInput(page.querySelector<HTMLElement>(".ah-field")!, {
      label: "Hosts to add",
      placeholder: "Find or type user@host",
      resolve: (token, delimited) => this.resolve(token, delimited),
      onChange: (chips) => this.syncSelection(chips),
      onToken: (token) => { this.token = token; if (!token.trim() || parseTarget(token)) this.hintArmed = false; this.refreshDiscovery(); },
      onSubmit: () => { if (this.selected.length) this.proceed(); },
    });
    // The hint is the field's description for assistive technology at all times; it is only drawn once a token fails.
    this.chips.input.setAttribute("aria-describedby", "ah-host-hint");
    for (const entry of this.selected) this.chips.add(this.chipFor(entry));
    this.renderList(page);
    this.setFoot(`<span class="ah-count" aria-live="polite"></span><button class="ui-button ah-primary" data-button="primary" type="button" data-ah="continue"><span>Continue</span></button>`);
    this.refreshDiscovery(page);
  }

  /** How a target relates to the listed hosts that are not added yet. */
  private matchOf(target: ParsedTarget): { host: Entry | undefined; prefixed: boolean } {
    const matched = matchListed(target, this.listed().filter((row) => !row.added).map((row) => row.entry));
    return { host: matched.named, prefixed: matched.prefixed };
  }

  /**
   * Turns a token into a chip, or returns undefined while it must still be typed. A token that names a listed host
   * chips at once, unless it is also the start of other hosts' names: then it waits for a delimiter. An ended token
   * (delimiter, Tab, Enter, Continue) is final: a valid target that names no listed host becomes a typed host.
   */
  private resolve(token: string, delimited: boolean): Chip | undefined {
    const target = parseTarget(token);
    if (!target) {
      if (delimited && token.trim()) { this.hintArmed = true; const page = this.discoveryPage(); if (page) this.updateHint(page); }
      return undefined;
    }
    const { host, prefixed } = this.matchOf(target);
    if (host) {
      if (prefixed && !delimited) return undefined;
      // An explicit port is part of the typed destination even when its host is listed.
      if ((target.user && target.user !== host.user) || target.port !== undefined) return this.typedChip(target, host);
      return this.chipFor(host);
    }
    return delimited ? this.typedChip(target) : undefined;
  }

  /** True when the unfinished token is a valid target that Continue would commit (the same rule as Enter). */
  private pendingReady(): boolean {
    return parseTarget(this.token) !== undefined;
  }

  private typedChip(target: ParsedTarget, base?: Entry): Chip {
    const user = target.user ?? base?.user;
    const id = `${user ?? ""}@${target.host}${target.port ? `:${target.port}` : ""}`;
    let entry = this.typed.find((item) => item.id === id);
    if (!entry) {
      // An inventory name identifies the saved destination; an explicit port
      // changes that destination's port without turning its name into DNS.
      entry = { id, label: target.host, user, address: base?.address ?? target.host, port: target.port, os: base?.os ?? "unknown", discovered: base?.discovered };
      this.typed = [entry, ...this.typed];
    }
    return this.chipFor(entry);
  }

  /** Chips are the selection; checkboxes follow them. */
  private syncSelection(chips: Chip[]): void {
    this.selected = chips.map((chip) => this.find(chip.id)).filter((entry): entry is Entry => !!entry);
    // While a discovery page is being built, `current` is still the previous page; it renders from `selected`.
    const page = this.discoveryPage();
    if (page) {
      for (const [id, tick] of this.ticks) {
        const want = this.selected.some((entry) => entry.id === id);
        const input = page.querySelector<HTMLInputElement>(`.ah-row[data-host="${CSS.escape(id)}"] input`);
        if (input && input.checked !== want) { input.checked = want; tick.set(want); }
      }
    }
    this.refreshDiscovery(page);
  }

  private renderList(page: HTMLElement): void {
    const list = page.querySelector<HTMLElement>(".ah-list")!;
    const rows = this.listed();
    let note = "";
    if (this.discovery.state === "loading") note = `<p class="ah-note ah-loading" role="status"><span class="ah-spin"></span><span>Looking for hosts…</span></p>`;
    else if (this.discovery.state === "failed") note = `<p class="ah-note ah-load-error" role="alert">${svg(ICON.warning)}<span>${escapeHtml(this.discovery.message)}</span><button class="ah-link" type="button" data-ah="reload">Try again</button></p>`;
    else if (!rows.length) note = `<p class="ah-note ah-empty">${svg(ICON.servers)}<span>No hosts found yet. Type one above, or paste your SSH config.</span></p>`;
    list.innerHTML = `${rows.map(({ entry, added }) => this.rowOf(entry, added)).join("")}
      ${note}
      <p class="ah-none" hidden>No host matches.</p>`;
    const spin = list.querySelector<HTMLElement>(".ah-spin");
    if (spin) spin.replaceWith(createSpinner());
    this.ticks = new Map();
    for (const input of list.querySelectorAll<HTMLInputElement>(".ah-row[data-host] input")) this.ticks.set(input.value, springCheckbox(input));
    this.applyFilter(page);
  }

  /** Everything the unfinished token and the chips drive: the list filter, the hint, the count and Continue. */
  private refreshDiscovery(page: HTMLElement | undefined = this.discoveryPage()): void {
    if (page) { this.applyFilter(page); this.updateHint(page); }
    this.updateCount();
  }

  /** Shows rows matching the unfinished token; selected rows always stay listed. */
  private applyFilter(page: HTMLElement): void {
    const needle = this.token.toLowerCase();
    const target = parseTarget(this.token);
    const hosts = new Map(this.listed().map((row) => [row.entry.id, row.entry]));
    for (const row of page.querySelectorAll<HTMLElement>(".ah-row[data-host]")) {
      const found = hosts.get(row.dataset.host ?? "");
      if (!found) continue;
      const isSelected = this.selected.some((item) => item.id === found.id);
      const named = !!target && (found.label === target.host || found.address === target.host);
      const match = !needle || `${found.user ?? ""}@${found.label} ${found.address} ${found.discovered?.operatingSystem ?? ""} ${found.discovered?.architecture ?? ""}`.toLowerCase().includes(needle) || named;
      const wasHidden = row.hidden;
      row.hidden = !match && !isSelected;
      if (wasHidden && !row.hidden && !reducedMotion()) row.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: EASE });
    }
    // "No host matches" would contradict a token that is about to become a chip.
    const shown = page.querySelectorAll(".ah-row[data-host]:not([hidden])").length;
    page.querySelector<HTMLElement>(".ah-none")!.hidden = shown > 0 || !needle || hosts.size === 0 || this.pendingReady();
  }

  /** The quiet hint shows once an ended token is not a host name (never while typing); it reserves its line so nothing below jumps. */
  private updateHint(page: HTMLElement): void {
    const hint = page.querySelector<HTMLElement>(".ah-hint")!;
    const invalid = this.hintArmed && this.token !== "" && !parseTarget(this.token);
    hint.dataset.show = String(invalid);
  }

  /** The count and Continue reflect the chips and the unfinished token, which Continue will commit. */
  private updateCount(): void {
    if (this.page !== "discovery") return;
    const count = this.foot.querySelector<HTMLElement>(".ah-count");
    const primary = this.foot.querySelector<HTMLButtonElement>("[data-ah='continue']");
    const total = this.selected.length + (this.pendingReady() ? 1 : 0);
    if (count) count.textContent = total === 0 ? "" : `${total} ${total === 1 ? "host" : "hosts"}`;
    if (primary) primary.disabled = total === 0;
  }

  /** Pasted ssh_config becomes chips; anything else pastes as text for the chip field to split. */
  private readonly onPaste = (event: ClipboardEvent): void => {
    if (!this.chips || event.target !== this.chips.input) return;
    const text = event.clipboardData?.getData("text") ?? "";
    // A pasted `ssh …` command or `ssh://` address is one target; the chip field would split it at the spaces.
    if (/^\s*ssh(:\/\/|\s)/i.test(text) && !looksLikeSshConfig(text) && parseTarget(text)) {
      event.preventDefault();
      const chip = this.resolve(text.trim(), true);
      if (chip) this.chips.add(chip);
      return;
    }
    if (!looksLikeSshConfig(text)) return;
    const found = parseSshConfig(text);
    event.preventDefault();
    if (!found.length) { this.deps.toast.show({ message: "Couldn't find any hosts in that SSH config." }); return; }
    for (const spec of found) {
      const chip = this.resolve(spec, true);
      if (chip) this.chips.add(chip);
    }
  };

  // ── Root consent (D139) ────────────────────────────────────────────────────
  private rootCandidates(): Entry[] {
    return this.selected.filter((entry) => entry.user === "root" || (entry.discovered?.rootAvailable && entry.discovered.reach !== "unreachable"));
  }

  private proceed(): void {
    // Continue ends the unfinished token first, exactly as Enter would; a token that is not a target stays as text.
    this.chips?.commit();
    const pending = this.token ?? "";
    if (pending.trim() && !parseTarget(pending)) { this.hintArmed = true; this.refreshDiscovery(); }
    if (!this.selected.length) return;
    if (this.rootCandidates().length) this.go("root");
    else this.startBatch(false);
  }

  private renderRoot(page: HTMLElement): void {
    const roots = this.rootCandidates();
    const directRoot = roots.some((entry) => entry.user === "root");
    const subject = roots.length === 1 ? roots[0]!.label : `${roots.length} hosts`;
    const names = roots.length <= 3 ? roots.map((entry) => entry.label).join(", ") : `${roots.slice(0, 2).map((entry) => entry.label).join(", ")} and ${roots.length - 2} more`;
    page.innerHTML = `${this.hero(ICON.shield)}<h1 class="ah-title">Install as root on ${escapeHtml(subject)}?</h1>
      <p class="ah-lede">${directRoot ? `${roots.length === 1 ? "This host uses" : "These hosts use"} a root SSH login. Installing as root needs your explicit consent.` : `${escapeHtml(names)} ${roots.length > 1 ? "allow" : "allows"} admin commands without a password. That alone doesn't mean you want root.`}</p>
      <p class="ah-text">A root infraternal agent can manage packages, services and containers, and can read every file on the host. ${directRoot ? "To install as a user, go Back and change the SSH sign-in user." : "You can also install as a user now and switch to root later."}</p>
      <label class="ah-consent check"><input type="checkbox" data-consent /><span>I trust infraternal with root on ${escapeHtml(subject)}</span></label>`;
    for (const input of page.querySelectorAll<HTMLInputElement>(".ah-consent input")) springCheckbox(input);
    this.setFoot(`<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="back">Back</button>${directRoot ? "" : '<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="as-user">Install as user</button>'}<button class="ui-button ah-primary" data-button="primary" type="button" data-ah="as-root" disabled>${svg(ICON.shieldCheck)}<span>Install as root</span></button>`);
  }

  // ── Runs and jobs ──────────────────────────────────────────────────────────
  private addressOf(entry: Entry): StartTarget["address"] {
    if (entry.discovered && !this.typed.includes(entry)) return { kind: "discovered", value: entry.discovered.id };
    return { kind: "manual", value: `${entry.user ? `${entry.user}@` : ""}${entry.address}${entry.port ? `:${entry.port}` : ""}` };
  }

  /** Ids unique within the batch: two entries may share a host with different logins. */
  private targetIds(entries: Entry[]): string[] {
    const seen = new Set<string>();
    return entries.map((entry) => {
      let id = targetIdFor(entry.id);
      for (let n = 2; seen.has(id); n++) id = `${targetIdFor(entry.id).slice(0, 120)}-${n}`;
      seen.add(id);
      return id;
    });
  }

  private startBatch(root: boolean): void {
    if (!this.authorityReady && this.deps.service.authorityStatus) { void this.prepareAuthority(root); return; }
    this.beginBatch(root);
  }

  /** Check the CA before enrolling: unlock it when locked or unknown, otherwise start the batch. */
  private async prepareAuthority(root: boolean): Promise<void> {
    if (this.busy) return;
    this.setBusy(true);
    try {
      const status = await this.deps.service.authorityStatus!();
      if (!this.alive || this.closing) return;
      this.authorityRoot = root;
      this.authorityInitialized = status.initialized;
      if (status.locked !== false) this.go("authority");
      else { this.authorityReady = true; this.beginBatch(root); }
    } catch (error: unknown) {
      if (this.alive && !this.closing) this.showError(error instanceof ServiceError ? error.message : "Host connections could not be checked. Try again.");
    } finally { this.setBusy(false); }
  }

  private renderAuthority(page: HTMLElement): void {
    page.innerHTML = `${this.hero(ICON.shield)}<h1 class="ah-title">${this.authorityInitialized ? "Unlock" : "Set up"} host connections</h1>
      <p class="ah-lede">${this.authorityInitialized ? "Confirm with your administrator passkey to let this server connect new hosts." : "Host connections have not been set up yet. Confirm with your administrator passkey to create the certificate authority for your hosts."}</p>
      <p class="ah-text">${this.authorityInitialized ? "" : "The certificate authority signs the short-lived logins to your hosts. It is created once. "}Your account key stays in your browser. New hosts receive a certificate valid for seven days.</p>`;
    this.setFoot(`<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="back">Back</button><button class="ui-button ah-primary" data-button="primary" type="button" data-ah="unlock-authority">${svg(ICON.shieldCheck)}<span>Confirm with passkey</span></button>`);
  }

  private async unlockAuthority(): Promise<void> {
    if (this.busy || !this.deps.service.unlockAuthority) return;
    this.setBusy(true);
    try {
      // The same call and failure wording as the palette row and Settings → Hosts (authority-unlock.ts).
      const result = await runUnlock(this.deps.service);
      if (!this.alive || this.closing) return;
      if (!result.ok) { this.showError(result.message); return; }
      this.authorityReady = true;
      this.beginBatch(this.authorityRoot);
    } finally { this.setBusy(false); }
  }

  private beginBatch(root: boolean): void {
    this.closeAllRuns();
    const ids = this.targetIds(this.selected);
    const rootIds = new Set(root ? this.rootCandidates().map((entry) => entry.id) : []);
    const targets = this.selected.map((entry, index): StartTarget => {
      const target: StartTarget = { id: ids[index]!, address: this.addressOf(entry) };
      // Root needs explicit consent; the consent page asked for it, and only for hosts that offer sudo.
      if (rootIds.has(entry.id)) { target.mode = "root"; target.root_consent = true; }
      return target;
    });
    this.jobs = this.selected.map((entry, index) => ({ entry, target: ids[index]!, view: pendingTarget(), run: undefined, root: rootIds.has(entry.id) }));
    this.go("progress");
    const run = this.openRun();
    for (const job of this.jobs) job.run = run;
    run.start(targets);
  }

  private openRun(credential?: string): ProvisioningRun {
    this.deps.sink.prepareTerminal?.();
    const run: ProvisioningRun = this.deps.service.open({
      onEvent: (event) => this.onEvent(run, event),
      onError: (error) => this.onCommandError(run, error.message),
      onClose: () => this.onRunClosed(run),
    }, credential ? { credential } : {});
    return run;
  }

  private closeAllRuns(): void {
    const runs = new Set(this.jobs.map((job) => job.run).filter((run): run is ProvisioningRun => !!run));
    for (const run of runs) run.close();
    for (const job of this.jobs) job.run = undefined;
  }

  /** Closes a run nobody uses any more (a host moved to a fresh run). */
  private releaseRun(run: ProvisioningRun | undefined): void {
    // A failed host may still want a retry on this run; keep it while any host refers to it.
    if (run && !this.jobs.some((job) => job.run === run)) run.close();
  }

  /** The one way progress changes: a server event, folded into that host's view. */
  private onEvent(run: ProvisioningRun, event: BootstrapEvent): void {
    if (!this.alive) return;
    const job = this.jobs.find((item) => item.run === run && item.target === event.target);
    if (!job) return;
    const was = job.view.state;
    job.view = foldEvent(job.view, event);
    this.paint(job);
    this.summarise();
    if (job.view.state === "done" && was !== "done") {
      this.deps.sink.enrolled([this.enrolledOf(job)], this.current?.querySelector(`[data-job="${CSS.escape(job.target)}"] .ah-mark`) ?? undefined);
      // A new host window takes the camera; the wizard stays where the person is looking while it still has work to show.
      if (this.jobs.some((item) => item.view.state === "pending" || item.view.state === "running" || item.view.state === "failed")) this.surface.reveal?.();
    }
    if (job.view.state === "done" || shownState(job) === "failed" || awaitingKey(job.view)) this.settle();
  }

  /** A refused command (for example the server's batch limit): shown on the hosts that had not started. */
  private onCommandError(run: ProvisioningRun, message: string): void {
    for (const job of this.jobs) {
      if (job.run !== run || job.view.state !== "pending") continue;
      // The server's words are kept for the details; the person reads a plain sentence.
      job.view = { ...job.view, state: "failed", message, failure: undefined };
      this.paint(job);
    }
    this.summarise();
    this.settle();
  }

  /** A lost socket requests cancellation; the browser cannot assert that remote cleanup finished. */
  private onRunClosed(run: ProvisioningRun): void {
    if (!this.alive || this.closing) return;
    let changed = false;
    for (const job of this.jobs) {
      if (job.run !== run) continue;
      job.run = undefined;
      if (job.view.state === "pending" || job.view.state === "running") {
        const message = "The connection to the server ended before setup finished.";
        job.view = { ...job.view, state: "failed", message, failure: { kind: "install", message, log_tail: [] }, leftovers: undefined };
        this.paint(job);
        changed = true;
      }
    }
    if (changed) { this.summarise(); this.settle(); }
  }

  private enrolledOf(job: Job): EnrolledHost {
    return { id: job.entry.id, ...(job.view.hostId ? { hostId: job.view.hostId } : {}), ...(job.view.sessionId ? { sessionId: job.view.sessionId } : {}), address: this.addressText(job.entry), name: job.entry.label, user: job.entry.user, os: job.entry.os, mode: job.root ? "root" : "rootless" };
  }

  /** Runs one attempt for a failed host again: on its open run, or on a fresh run when that ended. */
  private retryJob(job: Job, credential?: string): void {
    this.fixing = undefined;
    // A fresh run numbers its attempts from one again; a retry on the same run continues the server's count.
    const fresh = !!credential || !job.run?.open;
    job.view = { ...pendingTarget(), attempt: fresh ? 0 : job.view.attempt };
    if (fresh) {
      const old = job.run;
      const run = this.openRun(credential);
      job.run = run;
      const start: StartTarget = { id: job.target, address: this.addressOf(job.entry), ...(credential ? { credential } : {}) };
      if (job.root) { start.mode = "root"; start.root_consent = true; }
      run.start([start]);
      this.releaseRun(old);
    } else job.run?.retry(job.target);
    if (this.page !== "progress") this.go("progress", -1);
    else { this.paint(job); this.summarise(); }
    this.setFoot("");
  }

  /**
   * Removes what an earlier setup left on this host and continues the same attempt (#169). No confirmation: the
   * server removes only what infraternal provably created. Without an open run (the connection ended) there is no
   * attempt to continue, so a fresh run starts and finds the leftovers again with a new handle.
   */
  private startFresh(job: Job): void {
    const leftovers = job.view.leftovers;
    if (!leftovers || !job.run?.open) { this.retryJob(job); return; }
    this.fixing = undefined;
    // Same attempt number, and the sign-in that already succeeded stays on screen while the cleanup runs.
    job.view = { ...pendingTarget(), attempt: job.view.attempt, authentication: job.view.authentication };
    job.run.startFresh(job.target, leftovers.challenge);
    if (this.page !== "progress") this.go("progress", -1);
    else { this.paint(job); this.summarise(); }
    this.setFoot("");
  }

  // ── Progress: every host, every stage ──────────────────────────────────────
  private renderProgress(page: HTMLElement): void {
    const one = this.jobs.length === 1;
    page.innerHTML = `${this.hero(ICON.rocket)}<h1 class="ah-title">${one ? `Adding ${escapeHtml(this.jobs[0]!.entry.label)}` : `Adding ${this.jobs.length} hosts`}</h1>
      <p class="ah-lede ah-summary" aria-live="polite"></p>
      <ol class="ah-jobs">${this.jobs.map((job) => `<li class="ah-run" data-job="${escapeHtml(job.target)}" data-open="${one}">
        <div class="ah-run-head">
          <button class="ah-run-toggle" type="button" aria-expanded="${one}" data-ah="toggle-job">
            ${job.entry.discovered ? hostIconMarkup(job.entry.os, "ah-os-mark") : svg(ICON.typed, "ah-os-mark is-line")}
            <span class="ah-main"><span class="ah-name">${escapeHtml(job.entry.label)}</span><span class="ah-meta ah-job-step"></span></span>
          </button>
          <button class="ah-link ah-job-fix" type="button" data-ah="fix-job" hidden>Fix</button>
          <button class="ah-icon-button ah-job-retry" type="button" data-ah="retry-job" aria-label="Retry ${escapeHtml(job.entry.label)}" data-tip="Retry" hidden>${svg(ICON.retry)}</button>
          <span class="ah-mark"></span>
        </div>
        <span class="ah-seg" aria-hidden="true">${STAGES.map(() => "<span></span>").join("")}</span>
        <div class="ah-stages"><ol class="ah-stages-in" aria-label="Steps for ${escapeHtml(job.entry.label)}">${STAGES.map((stage) => `<li class="ah-stage-row" data-stage="${stage.id}" data-state="pending">
          <span class="ah-stage-mark"></span><span class="ah-stage-text"><span class="ah-stage-name">${stage.label}</span><span class="ah-stage-detail"></span></span></li>`).join("")}</ol></div>
      </li>`).join("")}</ol>`;
    this.marks = new Map();
    this.stageMarks = new Map();
    for (const job of this.jobs) {
      const row = page.querySelector<HTMLElement>(`[data-job="${CSS.escape(job.target)}"]`)!;
      this.marks.set(job.target, mountStepStatus(row.querySelector<HTMLElement>(".ah-mark")!, job.view.state));
      for (const stage of row.querySelectorAll<HTMLElement>(".ah-stage-row")) {
        this.stageMarks.set(`${job.target}/${stage.dataset.stage}`, mountStepStatus(stage.querySelector<HTMLElement>(".ah-stage-mark")!, "pending"));
      }
    }
    this.setFoot("");
    for (const job of this.jobs) this.paint(job, page);
    this.summarise(page);
    this.footForProgress();
  }

  private footForProgress(): void {
    if (this.page !== "progress") return;
    const settled = !this.jobs.some(working);
    if (!settled) { this.setFoot(""); return; }
    const failed = this.jobs.some((job) => shownState(job) === "failed" || awaitingKey(job.view));
    const done = this.jobs.some((job) => job.view.state === "done");
    this.setFoot(failed
      ? `<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="${done ? "finish" : "back"}">${done ? "Close" : "Back"}</button>`
      : `<button class="ui-button ah-primary" data-button="primary" type="button" data-ah="finish"><span>Done</span></button>`);
  }

  /**
   * Redraws one host's row on the progress page from its view: state and tone, its one-line status, each stage,
   * and the row's retry and fix buttons. Does nothing when the progress page isn't showing.
   */
  private paint(job: Job, page: HTMLElement | undefined = this.current): void {
    const row = page?.dataset.page === "progress" ? page.querySelector<HTMLElement>(`[data-job="${CSS.escape(job.target)}"]`) : null;
    if (!row) return;
    const state = shownState(job);
    const stages = stagesOf(job.view);
    row.dataset.state = state;
    const active = stages.find((stage) => stage.state === "running" || stage.state === "failed");
    // The server's own text for the latest event; a host with no event yet is queued.
    row.querySelector<HTMLElement>(".ah-job-step")!.textContent = awaitingKey(job.view) ? "Waiting for you to check the key" : state === "pending" ? "Waiting" : state === "done" ? "Ready" : state === "failed" ? failureLine(job.view.failure) : RUNNING_TEXT[active?.id ?? "detect"];
    stages.forEach((stage, index) => {
      const stageRow = row.querySelector<HTMLElement>(`[data-stage="${stage.id}"]`)!;
      stageRow.dataset.state = stage.state;
      stageRow.querySelector<HTMLElement>(".ah-stage-detail")!.textContent = stage.detail;
      this.stageMarks.get(`${job.target}/${stage.id}`)?.set(stage.state);
      row.querySelectorAll<HTMLElement>(".ah-seg > span")[index]!.dataset.state = stage.state;
    });
    // "Fix" opens the page that can mend this failure; plain retries and dead ends have only the retry button.
    // Retrying a host with leftovers would only find them again, so it is offered "Start fresh" instead.
    const fix = state === "failed" || awaitingKey(job.view) ? guideFor(job.entry.label, job.view.failure).fix : "none";
    // A dead end ("none") has no retry either: it would only meet the same refusal (J314 P2-1).
    row.querySelector<HTMLElement>(".ah-job-retry")!.hidden = state !== "failed" || fix === "start-fresh" || fix === "replace-stuck-install" || fix === "none" || fix === "take-over";
    // The row tells the news in the page's tone: neutral news is never red here (TASTE: the icon matches the news).
    row.dataset.tone = state === "failed" ? guideFor(job.entry.label, job.view.failure).tone : "";
    const fixButton = row.querySelector<HTMLElement>(".ah-job-fix")!;
    fixButton.hidden = fix === "none" || fix === "retry";
    // The button names what it opens or does.
    fixButton.textContent = fix === "choose-method" ? "Sign in another way" : fix === "host-key" ? "Check the key" : fix === "replace-stuck-install" ? "Replace the stuck install" : fix === "start-fresh" ? "Start fresh" : fix === "take-over" ? "Take over" : "Install from the host";
    this.marks.get(job.target)?.set(state);
    // A failure opens its steps so the reason sits next to the step that failed.
    if (state === "failed" && !row.dataset.touched) { row.dataset.open = "true"; row.querySelector(".ah-run-toggle")?.setAttribute("aria-expanded", "true"); }
  }

  private summarise(page: HTMLElement | undefined = this.current): void {
    const summary = page?.querySelector<HTMLElement>(".ah-summary");
    if (!summary) return;
    const done = this.jobs.filter((job) => job.view.state === "done").length;
    const failed = this.jobs.filter((job) => shownState(job) === "failed").length;
    const asking = this.jobs.filter((job) => awaitingKey(job.view)).length;
    const running = this.jobs.length - done - failed - asking;
    summary.textContent = this.jobs.length === 1
      ? (running ? "Working out how to sign in, then installing." : asking ? "Check this host's key to continue." : done ? "Ready. The host is in your sidebar." : "This host needs attention.")
      : `${done} of ${this.jobs.length} ready${failed ? `, ${failed} ${failed === 1 ? "needs" : "need"} attention` : ""}${asking ? `, ${asking} ${asking === 1 ? "needs" : "need"} a key check` : ""}${running ? "" : "."}`;
  }

  /** When nothing is running: a lone failure gets its own page; a clean batch closes itself. */
  private settle(): void {
    if (this.jobs.some(working)) return;
    this.footForProgress();
    const failed = this.jobs.filter((job) => shownState(job) === "failed");
    const asking = this.jobs.filter((job) => awaitingKey(job.view));
    // A new key is the next step of the flow: a lone host goes straight to it, a batch keeps its row's button.
    if (!failed.length && asking.length) {
      if (this.jobs.length === 1 && this.page === "progress") this.later(0, () => { if (this.page === "progress" && awaitingKey(asking[0]!.view)) this.openFix(asking[0]!); });
      return;
    }
    if (!failed.length) { this.later(700, () => this.finish()); return; }
    if (this.jobs.length === 1 && this.page === "progress") this.later(500, () => { if (this.page === "progress") this.openFix(failed[0]!); });
  }

  /** The page that fixes this host's failure. */
  private openFix(job: Job): void {
    this.fixing = job;
    const fix = guideFor(job.entry.label, job.view.failure).fix;
    if (fix === "choose-method") this.go("choose");
    else if (fix === "host-key") this.go("hostkey");
    else this.go("failure");
  }

  // ── Failure, host key, choose a method, install ────────────────────────────
  private detailsOf(job: Job): string {
    const failure = job.view.failure;
    const lines = [...(job.view.leftovers?.findings ?? []), failure?.failed_step ? `Failed step: ${FAILED_STEP_LABELS[failure.failed_step]}` : "", ...failureDiagnostics(failure, guideFor(job.entry.label, failure)).map((line) => line === failure?.message ? `The server said: ${line}` : line)].filter(Boolean);
    return lines.join("\n");
  }

  /** The Details disclosure, or nothing when there is nothing to disclose (TASTE: no empty sections). */
  private detailsBlock(job: Job): string {
    const text = this.detailsOf(job);
    return text ? `
      <details class="ah-details"><summary>${svg(ICON.caret)}<span>Details</span></summary><pre>${escapeHtml(text)}</pre></details>` : "";
  }

  /** The page for one failed host: what happened, what to do, Details, and the one action that fixes it. */
  private renderFailure(page: HTMLElement): void {
    const job = this.fixing!;
    const hostId = job.view.failure?.already_added ? job.view.failure.host_id : undefined;
    const openId = hostId && this.deps.sink.hasHost?.(hostId) !== false ? hostId : undefined;
    const guide: Guide = guideFor(job.entry.label, job.view.failure, openId !== undefined, job.entry.user);
    const replaceStuck = guide.fix === "replace-stuck-install";
    if (replaceStuck) guide.fix = "start-fresh";
    // Leftovers and a running setup are news to act on, not errors: a neutral icon, no red. Only a running
    // setup, which the person waits for, gets the clock (TASTE: the icon matches the news, #394).
    const icon = guide.fix === "start-fresh" || guide.fix === "take-over" || (guide.fix === "none" && guide.tone === "info") ? ICON.info : guide.fix === "retry" && guide.tone === "info" ? (job.view.failure?.kind === "setup_running" ? ICON.pending : ICON.info) : ICON.warning;
    page.innerHTML = `${this.hero(icon, guide.tone === "danger" ? "danger" : "")}<h1 class="ah-title">${escapeHtml(guide.title)}</h1>
      <p class="ah-lede">${escapeHtml(guide.happened)}</p>${guide.next ? `
      <p class="ah-text">${escapeHtml(guide.next)}</p>` : ""}${this.detailsBlock(job)}`;
    const open = openId ? `<button class="ui-button ah-primary" data-button="primary" type="button" data-ah="open-terminal" data-host-id="${escapeHtml(openId)}">${svg(ICON.terminal)}<span>Open a terminal</span></button>` : "";
    const install = guide.fix === "install-command" ? `<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="install">Install from the host</button>` : "";
    const takeOver = guide.fix === "take-over" ? `<button class="ui-button ah-primary" data-button="primary" type="button" data-ah="review-take-over"><span>Take over</span></button>` : "";
    this.setFoot(`<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="back-progress">Back</button>${install}${open}${takeOver}${guide.fix === "none" || guide.fix === "take-over" ? "" : guide.fix === "start-fresh" ? `<button class="ui-button ah-primary" data-button="primary" type="button" data-ah="start-fresh"><span>Start fresh</span></button>` : `<button class="ui-button ah-primary" data-button="primary" type="button" data-ah="retry">${svg(ICON.retry)}<span>${guide.tone === "info" ? "Try again" : "Retry"}</span></button>`}`);
    if (replaceStuck) {
      const label = this.foot.querySelector<HTMLElement>('[data-ah="start-fresh"] span');
      const lock = job.view.failure?.setup_lock;
      if (label) label.textContent = lock?.set_aside ? "Put it back" : lock?.enrolled_with !== undefined ? lock.live ? "Disconnect and join here" : "Join as a new host" : "Replace the stuck install";
    }
  }

  /**
   * D359: the confirmation for taking over a finished install of another server. It names the old install's id
   * (the person compares it with the machine's), says what happens to it, and only its Take over button sends the
   * paused attempt's challenge. The server offers this in root mode only; anything else goes back to the failure.
   */
  private renderTakeOver(page: HTMLElement): void {
    const job = this.fixing!;
    const offer = job.view.failure?.takeover;
    const name = escapeHtml(job.entry.label);
    page.innerHTML = `${this.hero(ICON.servers)}<h1 class="ah-title">Take over ${name}?</h1>
      <p class="ah-lede">Its old infraternal agent is ${offer?.live ? "stopped and " : ""}set aside, and a new one is installed for this server.</p>
      <div class="ah-keyblock" data-kv></div>
      <p class="ah-text">If setup fails, the old one is put back as it was. Once ${name} has joined, the old one is deleted.</p>${this.detailsBlock(job)}`;
    const list = createKeyValueList("The install that is taken over");
    list.set(offer ? [{ key: "Old install", value: offer.install }] : []);
    page.querySelector<HTMLElement>("[data-kv]")!.append(list.root);
    this.setFoot(`<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="back-failure">Back</button><button class="ui-button ah-primary" data-button="primary" type="button" data-ah="take-over"><span>Take over</span></button>`);
  }

  /** Confirmed on the Take over page: continue the paused attempt, only for a root-mode offer (D359). */
  private takeOver(job: Job): void {
    if (!job.view.failure?.takeover || job.view.leftovers?.mode !== "root") { this.go("failure", -1); return; }
    this.startFresh(job);
  }

  private renderHostKey(page: HTMLElement): void {
    const job = this.fixing!;
    const print = job.view.failure?.fingerprints?.[0];
    const key = hostKeyPresentation(job.view.failure?.host_key_type);
    const changed = job.view.failure?.host_key_changed === true;
    // A new key is an ordinary question (neutral icon). Only a changed pin is a warning (TASTE: the icon matches the news).
    page.innerHTML = `${changed ? this.hero(ICON.warning, "danger") : this.hero(ICON.fingerprint)}<h1 class="ah-title">Check ${escapeHtml(job.entry.label)}'s key</h1>
      <p class="ah-lede">${changed ? "Warning: this host’s trusted key changed. Replace it only after you verify the new fingerprint on the host." : "Compare this fingerprint with the one on the host before trusting it."}</p>
      <div class="ah-keyblock" data-kv></div>
      <p class="ah-text">${key.command ? `On the host, run <span class="ah-code">${escapeHtml(key.command)}</span> and compare.` : "Ask the host’s owner to verify this fingerprint through a trusted connection."}</p>${this.detailsBlock(job)}`;
    const list = createKeyValueList("Host key fingerprint");
    list.set(print ? [{ key: "Host key", value: `${key.label} · ${print}` }] : []);
    page.querySelector<HTMLElement>("[data-kv]")!.append(list.root);
    this.setFoot(`<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="${changed ? "back-progress" : "back"}">${changed ? "Back" : "Cancel"}</button><button class="ui-button ah-primary" data-button="primary" type="button" data-ah="trust-key">${svg(ICON.shieldCheck)}<span>${changed ? "Replace trusted key" : "Trust and continue"}</span></button>`);
  }

  private renderChoose(page: HTMLElement): void {
    const job = this.fixing!;
    const name = escapeHtml(job.entry.label);
    const first = this.serverKey ? "server" : this.savedKey ? "saved" : "key";
    const option = (value: string, title: string, hint: string): string => `<label class="ah-option"><input type="radio" name="ah-method" value="${value}" ${value === first ? "checked" : ""} /><span class="ah-radio" aria-hidden="true"></span>
      <span class="ah-option-text"><span>${title}</span><span class="ah-option-hint">${hint}</span></span></label>`;
    const reveal = (value: string, inner: string): string => `<div class="ah-reveal" data-reveal="${value}" data-open="${value === first}"><div class="ah-reveal-in">${inner}</div></div>`;
    page.innerHTML = `${this.hero(ICON.key)}<h1 class="ah-title">Sign in to ${name}</h1>
      <p class="ah-lede">${escapeHtml(guideFor(job.entry.label, job.view.failure).happened)} Choose how to sign in.</p>
      <div class="ah-options" role="radiogroup" aria-label="How to sign in">
        ${this.serverKey ? option("server", "Use this server's key", "SSH public key in ~/.ssh/authorized_keys. Add it to the host, then try again.") + reveal("server", `<div class="ah-keyblock" data-kv="server"></div><p class="ah-text">Add this line to <span class="ah-code">~/.ssh/authorized_keys</span> on ${name}, then choose Try again.${this.serverKey.locked ? " The server's key is locked until an administrator unlocks it with a passkey." : ""}</p>`) : ""}
        ${this.savedKey ? option("saved", `Use ${escapeHtml(this.savedKey.label)}`, "Unlocked with your passkey, used for this one connection.") : ""}
        ${option("key", "Use a key from your computer", "SSH private key. Sent once for this connection, not stored.")}
        ${reveal("key", `<textarea class="ah-secret" data-secret="key" rows="4" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Private key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" tabindex="-1"></textarea>
          <input class="ah-input" data-secret="passphrase" type="password" autocomplete="off" aria-label="Key passphrase, if it has one" placeholder="Passphrase, if the key has one" tabindex="-1" />`)}
        ${option("password", "Sign in with a password", "SSH password authentication. Sent once for this connection, not stored.")}
        ${reveal("password", `<input class="ah-input" data-secret="password" type="password" autocomplete="off" aria-label="Password for ${name}" placeholder="Password" tabindex="-1" />`)}
      </div>
      <button class="ah-link ah-alt" type="button" data-ah="install">Or install from the host instead</button>`;
    if (this.serverKey) {
      const list = createKeyValueList("This server's key");
      list.set([{ key: "Public key", value: this.serverKey.publicKey }, { key: "Fingerprint", value: this.serverKey.fingerprint }]);
      page.querySelector<HTMLElement>("[data-kv='server']")!.append(list.root);
    }
    this.chosen = first;
    this.setFoot(this.chooseFoot(first));
  }

  private chosen = "key";

  private chooseFoot(method: string): string {
    const label = method === "server" ? "Try again" : "Sign in";
    return `<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="back-progress">Back</button><button class="ui-button ah-primary" data-button="primary" type="button" data-ah="submit-method"><span>${label}</span></button>`;
  }

  private selectMethod(value: string): void {
    this.chosen = value;
    for (const reveal of this.current?.querySelectorAll<HTMLElement>(".ah-reveal") ?? []) {
      const open = reveal.dataset.reveal === value;
      reveal.dataset.open = String(open);
      for (const field of reveal.querySelectorAll<HTMLElement>("textarea, input")) field.tabIndex = open ? 0 : -1;
    }
    const primary = this.foot.querySelector<HTMLElement>("[data-ah='submit-method'] span");
    if (primary) primary.textContent = value === "server" ? "Try again" : "Sign in";
    this.current?.querySelector(".ah-error")?.remove();
  }

  /** Clears every secret field, returning what was typed. The DOM never keeps it after submit. */
  private takeSecrets(): { key: string; passphrase: string; password: string } {
    const read = (name: string): string => {
      const field = this.current?.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[data-secret="${name}"]`);
      const value = field?.value ?? "";
      if (field) field.value = "";
      return value;
    };
    return { key: read("key"), passphrase: read("passphrase"), password: read("password") };
  }

  private async submitMethod(): Promise<void> {
    const job = this.fixing;
    if (!job || this.busy) return;
    if (this.chosen === "server") { this.retryJob(job); return; }
    this.setBusy(true);
    try {
      let reference: string;
      if (this.chosen === "saved" && this.savedKey) {
        const text = await this.savedKey.unwrap();
        if (!this.alive || this.closing) return;
        reference = await this.deps.service.mintCredential({ kind: "private-key", text }, job.target, this.addressText(job.entry));
      } else {
        const secrets = this.takeSecrets();
        if (this.chosen === "password") {
          if (!secrets.password) { this.showError("Type the password first."); return; }
          reference = await this.deps.service.mintCredential({ kind: "password", text: secrets.password }, job.target, this.addressText(job.entry));
        } else {
          if (!secrets.key.trim()) { this.showError("Paste the private key first."); return; }
          reference = await this.deps.service.mintCredential({ kind: "private-key", text: secrets.key, ...(secrets.passphrase ? { passphrase: secrets.passphrase } : {}) }, job.target, this.addressText(job.entry));
        }
      }
      if (!this.alive || this.closing) { this.deps.service.dispose?.(); return; }
      this.retryJob(job, reference);
    } catch (error: unknown) {
      this.showError(error instanceof ServiceError ? error.message : "That sign-in couldn't be sent. Try again.");
    } finally {
      this.setBusy(false);
    }
  }

  private async trustKey(): Promise<void> {
    const job = this.fixing;
    const print = job?.view.failure?.fingerprints?.[0];
    if (!job || !print || this.busy) return;
    this.setBusy(true);
    try {
      await this.deps.service.trustHostKey(this.addressText(job.entry), print);
      this.retryJob(job);
    } catch (error: unknown) {
      this.showError(error instanceof ServiceError ? error.message : "The key couldn't be trusted. Try again.");
    } finally {
      this.setBusy(false);
    }
  }

  private addressText(entry: Entry): string {
    const address = this.addressOf(entry);
    return address.value;
  }

  private setBusy(busy: boolean): void {
    this.busy = busy;
    for (const button of this.foot.querySelectorAll<HTMLButtonElement>("button")) button.disabled = busy;
  }

  private renderInstall(page: HTMLElement): void {
    const job = this.fixing;
    const name = escapeHtml(job?.entry.label ?? "the host");
    page.innerHTML = `${this.hero(ICON.terminal)}<h1 class="ah-title">Install from ${name}</h1>
      <p class="ah-lede">Run this on the host. It connects out to this server, so the server never needs to reach it.</p>
      <div class="ah-install" aria-live="polite"></div>`;
    this.setFoot(`<button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="back-install">Back</button><button class="ui-button ah-primary" data-button="primary" type="button" data-ah="finish"><span>Done</span></button>`);
    this.install = { state: "loading" };
    this.paintInstall();
    const host = job ? this.addressText(job.entry) : "";
    void this.deps.service.installCommand(host).then((command) => {
      this.install = command ? { state: "ready", command } : { state: "unavailable" };
    }, (error: unknown) => {
      this.install = { state: "failed", message: error instanceof ServiceError ? error.message : "The command couldn't be made." };
    }).finally(() => { if (this.alive && this.page === "install") this.paintInstall(); });
  }

  private paintInstall(): void {
    const slot = this.current?.querySelector<HTMLElement>(".ah-install") ?? this.pages.querySelector<HTMLElement>(".ah-install");
    if (!slot) return;
    slot.replaceChildren();
    if (this.install.state === "loading") {
      const note = document.createElement("p");
      note.className = "ah-note ah-loading";
      note.append(createSpinner(), Object.assign(document.createElement("span"), { textContent: "Making a one-time command…" }));
      slot.append(note);
    } else if (this.install.state === "ready" && this.install.command) {
      const list = createKeyValueList("Install command");
      list.set([{ key: "Command", value: this.install.command.command }]);
      const minutes = Math.max(1, Math.round(this.install.command.expiresInSeconds / 60));
      const hint = document.createElement("p");
      hint.className = "ah-text";
      hint.textContent = `Valid for ${minutes} minutes and works once. The host appears in your sidebar when it joins.`;
      slot.append(list.root, hint);
    } else {
      const note = document.createElement("p");
      note.className = "ah-note";
      note.setAttribute("role", "alert");
      note.innerHTML = svg(ICON.warning);
      note.append(Object.assign(document.createElement("span"), { textContent: this.install.state === "failed" ? this.install.message ?? "The command couldn't be made." : "This server can't make an install command yet." }));
      slot.append(note);
    }
  }

  // ── Finishing and closing ──────────────────────────────────────────────────
  /** Everything that could finish has; leave the card and say so once. */
  private finish(): void {
    if (this.closing) return;
    const done = this.jobs.filter((job) => job.view.state === "done");
    const running = this.jobs.some((job) => job.view.state === "pending" || job.view.state === "running");
    if (running) return;
    this.dismiss(() => {
      if (!done.length) return;
      // A host whose setup continues in its machine pill carries its own news there (D255): no "ready" toast on top of it.
      if (this.deps.sink.setupInPill && done.length === this.jobs.length) return;
      const failed = this.jobs.length - done.length;
      this.deps.toast.show({
        ...(failed ? { tone: "error" as const } : {}),
        message: failed ? `${done.length} ${done.length === 1 ? "host is" : "hosts are"} ready. ${failed} didn't finish.` : done.length > 1 ? `${done.length} hosts are ready` : `${done[0]!.entry.label} is ready`,
      });
    });
  }

  private requestClose(): void {
    const running = this.jobs.some((job) => job.view.state === "pending" || job.view.state === "running");
    if (!running) { this.dismiss(); return; }
    // Cancellation asks for rollback; losing SSH can leave cleanup pending.
    this.setFoot(`<span class="ah-count">Closing stops installation and asks the server to undo this attempt. Cleanup can remain pending if the host is unavailable.</span><button class="ui-button ah-secondary" data-button="secondary" type="button" data-ah="keep">Keep installing</button><button class="ui-button ah-primary" data-button="primary" type="button" data-ah="cancel-install">Stop installing</button>`);
  }

  private dismiss(after?: () => void): void {
    if (this.closing) return;
    this.closing = true;
    this.clearTimers();
    // Closing a run is the cancel; hosts already done are enrolled and stay.
    this.closeAllRuns();
    this.deps.service.dispose?.();
    this.root.removeEventListener("click", this.onClick);
    this.root.removeEventListener("change", this.onChange);
    document.removeEventListener("keydown", this.onKeyDown, true);
    this.root.removeEventListener("paste", this.onPaste, true);
    const gone = (): void => { this.teardown(); after?.(); };
    if (reducedMotion()) { gone(); return; }
    this.float.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(6px) scale(0.98)" }], { duration: 160, easing: EASE, fill: "forwards" });
    this.scrim.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 200, delay: 40, easing: EASE, fill: "forwards" }).onfinish = gone;
  }

  private teardown(): void {
    if (!this.alive) return;
    this.alive = false;
    this.resize.disconnect();
    this.release();
    this.surface.remove();
    if (this.opener instanceof HTMLElement && this.opener.isConnected) this.opener.focus({ preventScroll: true });
    this.deps.onClosed();
  }

  /** Ends the wizard without animation (the canvas is going away). */
  dispose(): void {
    this.closing = true;
    this.clearTimers();
    this.closeAllRuns();
    this.deps.service.dispose?.();
    this.root.removeEventListener("click", this.onClick);
    this.root.removeEventListener("change", this.onChange);
    document.removeEventListener("keydown", this.onKeyDown, true);
    this.root.removeEventListener("paste", this.onPaste, true);
    if (this.alive) { this.alive = false; this.resize.disconnect(); this.release(); this.surface.remove(); }
  }

  private release(): void {
    for (const sibling of this.inerted) sibling.removeAttribute("inert");
    this.inerted.length = 0;
  }

  get isClosing(): boolean { return this.closing; }

  focus(): void { this.focusField(); }

  // ── Events ─────────────────────────────────────────────────────────────────
  private readonly onClick = (event: MouseEvent): void => {
    const target = event.target instanceof Element ? event.target.closest<HTMLElement>("[data-ah]") : null;
    if (!target) return;
    const action = target.dataset.ah;
    const jobOf = (): Job | undefined => this.jobs.find((item) => item.target === target.closest<HTMLElement>("[data-job]")?.dataset.job);
    if (action === "close") this.requestClose();
    else if (action === "continue") this.proceed();
    else if (action === "unlock-authority") void this.unlockAuthority();
    else if (action === "as-root") this.startBatch(true);
    else if (action === "as-user") this.startBatch(false);
    else if (action === "back") this.go("discovery", -1);
    else if (action === "back-progress") { this.fixing = undefined; this.go("progress", -1); }
    else if (action === "finish") this.finish();
    else if (action === "open-terminal") { const id = target.dataset.hostId; if (id) this.dismiss(() => this.deps.sink.openHost?.(id)); }
    else if (action === "keep") this.footForProgress();
    else if (action === "cancel-install") this.dismiss();
    else if (action === "reload") void this.loadDiscovery();
    else if (action === "retry") { if (this.fixing) this.retryJob(this.fixing); }
    else if (action === "start-fresh") { if (this.fixing) this.startFresh(this.fixing); }
    else if (action === "review-take-over") { if (this.fixing) this.go("takeover"); }
    else if (action === "take-over") { if (this.fixing) this.takeOver(this.fixing); }
    else if (action === "back-failure") this.go("failure", -1);
    else if (action === "install") { this.installFrom = this.page === "choose" ? "choose" : "failure"; this.go("install"); }
    else if (action === "back-install") this.go(this.installFrom, -1);
    else if (action === "trust-key") void this.trustKey();
    else if (action === "submit-method") void this.submitMethod();
    else if (action === "retry-job") { const job = jobOf(); if (job) this.retryJob(job); }
    else if (action === "fix-job") {
      const job = jobOf();
      // Leftovers are cleared right from the row; every other fix opens its own page. A Take over always asks
      // first, on its own page (D359).
      if (job) { if (job.view.leftovers && !job.view.failure?.takeover) this.startFresh(job); else this.openFix(job); }
    }
    else if (action === "toggle-job") {
      const row = target.closest<HTMLElement>(".ah-run");
      if (!row) return;
      const open = row.dataset.open !== "true";
      row.dataset.open = String(open);
      row.dataset.touched = "true";
      target.setAttribute("aria-expanded", String(open));
    }
  };

  private readonly onChange = (event: Event): void => {
    const input = event.target;
    if (!(input instanceof HTMLInputElement)) return;
    if (input.closest(".ah-row[data-host]")) {
      const entry = this.find(input.value);
      if (!entry || !this.chips) return;
      if (input.checked) this.chips.add(this.chipFor(entry)); else this.chips.remove(entry.id);
    } else if (input.matches("[data-consent]")) {
      const primary = this.foot.querySelector<HTMLButtonElement>("[data-ah='as-root']");
      if (primary) primary.disabled = !input.checked;
    } else if (input.name === "ah-method") this.selectMethod(input.value);
  };

  private readonly onKeyDown = (event: KeyboardEvent): void => {
    if (this.closing) return;
    if (event.key === "Escape") { event.stopPropagation(); event.preventDefault(); this.requestClose(); return; }
    // Only an overlay is modal; a canvas flow participates in ordinary focus order.
    if (event.key === "Tab" && this.root.classList.contains("ah-overlay")) {
      const focusable = [...this.float.querySelectorAll<HTMLElement>("button:not([disabled]):not([hidden]), input:not([disabled]):not([tabindex='-1']), textarea:not([tabindex='-1']), summary, [tabindex='0']")]
        .filter((item) => item.offsetParent !== null);
      if (!focusable.length) return;
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  };
}
