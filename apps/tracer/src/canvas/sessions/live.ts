/**
 * The product sessions service: terminal windows bound to real sessions, all on the one WebSocket (D183).
 *
 * Each terminal window gets its own `TerminalClient` (its own renderer, cursors and input queue) riding one
 * stream of the shared `MuxConnection`. Opening a window opens a new shell on the server; a window restored from
 * the canvas document re-attaches to the session it names. Closing a window detaches its stream and never ends
 * the session (D178).
 *
 * A session the host no longer has is final (the server's Close 4404, #158): its terminal stops attaching and the
 * window shows the ended state, with one action that starts a new shell on the same host in the same window.
 *
 * Costs, because several terminals live on one page:
 * - A binding starts its terminal when the window first exists, but a window that is off screen or in another
 *   view is suspended (`setVisible(false)`): no drawing and no canvas backing store, so a phone holds about one
 *   screen of pixels. Output keeps flowing into the terminal state and credit keeps returning.
 * - Only the active window's terminal takes the keys (`core.setActiveTerminal`); all of them follow the theme
 *   and font (`core.registerTerminal`).
 * - The first window uses the screen's own terminal host element, so the page still has one `#terminal-host`.
 */
import { isCanonicalUuid, randomUuid } from "../../identifiers";
import { captureFocusIntent } from "../../../../../packages/ui/src/focus-intent";
import type { CoreScreen } from "../../core-screen";
import type { ConnectionPool, MuxConnection } from "../../connection";
import type { TerminalClient, TerminalHooks } from "../../terminal";
import { el } from "../dom";
import { createStatusRelay } from "../status";
import type { WindowModel } from "../model/types";
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import { onDemand, whenIdle } from "../../on-demand";
import type { HostEntry, LinkInfo, SessionBinding, SessionService } from "./adapter";
import type { ScreenCache } from "./screen-cache.on-demand";

export interface LiveSessionsOptions {
  core: CoreScreen;
  connection: MuxConnection;
  /** The sockets terminals share (the server takes 32 terminals per socket); without it every terminal uses `connection`. */
  pool?: ConnectionPool;
  /** The embedded host: its name, the person's login and, once the host has said, its system (the pill's mark). Remote hosts are registered only after admission. */
  host: { name: string; user?: string; os?: HostPlatform };
  /** `?predict=1`: the opt-in predictive echo. */
  predictiveEcho?: boolean;
  /** Extra terminal hooks (the latency probe) for the first terminal. */
  firstHooks?: TerminalHooks;
  /** Called with the first terminal once it is ready (the probe binds to it). */
  onFirstClient?: (client: TerminalClient) => void;
  /** Deferred account data starts after a terminal paints, or the initial terminal cannot open. */
  onFirstTerminalSettled?: () => void;
  /** Called when the window shows a session (restored or new). */
  onSessionCreated?: (sessionId: string) => void;
  /** Read-only startup discovery for a newly opened shell; never runs on reattachment. */
  onStartupSession?: (sessionId: string, hostId: string | undefined, host: string) => void;
  /** The host no longer has a window's session (#158): the inventory marks it ended and the window paints that. */
  onSessionGone?: (host: string, sessionId: string, status?: number) => void;
  /** Reads saved retirement before an asynchronously loaded stream attaches. */
  getEndedSession?: (host: string, sessionId: string) => { status?: number } | undefined;
}

export interface LiveSessions extends SessionService {
  /** The terminal of the active window, for callers outside the canvas. */
  activeClient(): TerminalClient | undefined;
  /** Applies an authoritative inventory removal to every open window for the session. */
  markGone(host: string, sessionId: string, status?: number): void;
  /** Registers a known UUID that this page may open; readable labels never become routing authority. */
  registerHost(host: HostEntry & { address?: string }): void;
  forgetHost(id: string): void;
  /** Replaces remote admission while keeping locally enrolled hosts whose setup has not finished; returns removed identities. */
  replaceHosts(hosts: (HostEntry & { address?: string })[], keepWhileSettingUp?: readonly string[]): string[];
  dispose(): void;
}

export function createLiveSessions(options: LiveSessionsOptions): LiveSessions {
  const { core, connection, host, pool } = options;
  const listeners = new Set<() => void>();
  const bindings = new Set<Binding>();
  const remotes = new Map<string, HostEntry & { address?: string }>();
  let firstHostUsed = false;
  let firstReported = false;
  let firstSettled = false;
  const settle = (): void => { if (!firstSettled) { firstSettled = true; options.onFirstTerminalSettled?.(); } };
  let active: Binding | undefined;
  let serial = 0;
  // The last known screens (screen-cache.on-demand.ts) load at idle; until then a switch simply has no picture to show.
  let cache: ScreenCache | undefined;
  let cacheRequested = false;
  const warmCache = (): void => {
    if (cacheRequested) return;
    cacheRequested = true;
    whenIdle(() => { void onDemand(() => import("./screen-cache.on-demand")).then((m) => { cache = m.createScreenCache(); }, () => { cacheRequested = false; }); });
  };

  class Binding implements SessionBinding {
    client: TerminalClient | undefined;
    private hostEl: HTMLElement | undefined;
    private readonly status = createStatusRelay(core.toast);
    private unregister: (() => void) | undefined;
    private disposed = false;
    private visible = true;
    private activeNow = false;
    private painted = false;
    private retired: { status?: number } | undefined;
    private dropGhost: (() => void) | undefined;
    private ghostTimer = 0;
    private connectionStabilityTimer = 0;
    private connectedNow = false;
    /** The host link missed a reply but is kept (#234): the pill reads reconnecting until it answers or retires. */
    private doubted = false;
    get connected(): boolean { return this.connectedNow && !this.doubted; }
    // The finer state of the link for the window's connection indicator (adapter.ts `LinkInfo`).
    private everConnected = false;
    private resumedAt: number | undefined;
    private approximateAt: number | undefined;
    private heldKeys = 0;
    get link(): LinkInfo { return { everConnected: this.everConnected, resumedAt: this.resumedAt, approximateAt: this.approximateAt, heldKeys: this.heldKeys }; }
    private setDoubted(doubted: boolean): void {
      if (doubted === this.doubted) return;
      const before = this.connected;
      this.doubted = doubted;
      if (before !== this.connected) this.connectionChanged?.();
    }
    private setConnected(connected: boolean, settleMs = 0): void {
      if (!connected) {
        window.clearTimeout(this.connectionStabilityTimer);
        this.connectionStabilityTimer = 0;
      } else if (!this.connectedNow && settleMs > 0) {
        // A resumed stream must survive a short settle window before its pill turns live; failed retries
        // therefore leave one steady connecting state instead of a one-frame green flash.
        if (this.connectionStabilityTimer === 0) {
          this.connectionStabilityTimer = window.setTimeout(() => {
            this.connectionStabilityTimer = 0;
            if (!this.disposed) this.setConnected(true);
          }, settleMs);
        }
        return;
      }
      if (connected === this.connectedNow) return;
      const before = this.connected;
      this.connectedNow = connected;
      // A dropped or retargeted link replaces the doubt; a fresh attach starts undoubted.
      if (!connected) { this.doubted = false; this.approximateAt = undefined; this.resumedAt = undefined; }
      else { if (this.everConnected) this.resumedAt = performance.now(); this.everConnected = true; }
      if (before !== this.connected) this.connectionChanged?.();
    }
    /** Marks for the switch timeline (`sw:<n>:<step>`); a few microseconds each, read by the real specs. */
    private readonly n = ++serial;
    private mark(step: string): void { performance.mark(`sw:${this.n}:${step}`); }

    constructor(private readonly model: WindowModel, private readonly changed: () => void, private readonly exited: ((status: number) => void) | undefined, private readonly showSessions?: (event?: MouseEvent) => void, private readonly refused?: (message: string) => boolean, private readonly connectionChanged?: () => void) {}

    /** Keeps a picture of this terminal's screen as its session's last known one (only while it is drawn). */
    private keepScreen(): void {
      const id = this.client?.sessionUuid;
      const canvas = this.client?.canvas;
      if (cache && id && canvas && this.painted && this.visible) cache.capture(id, canvas);
    }
    /** Puts the last known screen of the session this binding is about to show over its terminal, in the same frame. */
    private showGhost(): void {
      this.endGhost();
      const id = this.model.sessionId;
      if (!cache || !id || !this.hostEl) return;
      this.dropGhost = cache.ghost(id, this.hostEl);
      if (this.dropGhost) this.ghostTimer = window.setTimeout(() => this.endGhost(), 6000);
      if (this.dropGhost) { this.mark("ghosted"); requestAnimationFrame(() => this.mark("ghost")); }
    }
    private endGhost(): void { window.clearTimeout(this.ghostTimer); this.dropGhost?.(); this.dropGhost = undefined; }

    retarget(model: WindowModel): boolean {
      const client = this.client;
      if (!client || !model.sessionId || this.disposed || model.hostId !== this.model.hostId) return false;
      this.retired = undefined;
      this.setConnected(false);
      this.keepScreen();
      this.painted = false;
      this.mark("retarget");
      this.showGhost();
      client.retarget(model.sessionId);
      return true;
    }

    mount(body: HTMLElement): void {
      let hostEl: HTMLElement;
      if (!firstHostUsed) {
        // The screen's own host keeps the page's one #terminal-host.
        firstHostUsed = true;
        hostEl = core.terminalHost;
        hostEl.replaceChildren();
      } else {
        hostEl = el("div", "terminal-host");
        hostEl.setAttribute("role", "application");
        hostEl.setAttribute("aria-label", "Remote terminal");
        hostEl.tabIndex = 0;
        hostEl.setAttribute("data-captures-keys", "");
      }
      this.hostEl = hostEl;
      body.append(hostEl);
      this.mark("mount");
      this.showGhost();
      void this.start();
    }

    /** The socket this window's terminal uses (taken from the pool, given back on dispose). */
    private conn: MuxConnection | undefined;

    private async start(): Promise<void> {
      const hostEl = this.hostEl;
      if (!hostEl) return;
      const first = !firstReported;
      firstReported = true;
      // A silent attached session needs inventory too; a one-shot grace lets an initial prompt paint first.
      const hooks: TerminalHooks = {
        ...(first ? options.firstHooks : {}),
        onAttached: (resumed, terminal) => { this.setConnected(true, resumed ? 300 : 0); this.mark("attached"); if (!firstSettled) window.setTimeout(() => requestAnimationFrame(() => requestAnimationFrame(settle)), 1000); if (first) options.firstHooks?.onAttached?.(resumed, terminal); },
        onPaintedOutput: (bytes, at, sequence) => { if (!firstSettled && this.client?.readScreenText().trim()) settle(); if (!this.painted) { this.painted = true; this.mark("painted"); this.endGhost(); } if (first) options.firstHooks?.onPaintedOutput?.(bytes, at, sequence); },
        onLinkDoubt: (doubted) => this.setDoubted(doubted),
        onApproximate: () => { this.approximateAt = performance.now(); this.connectionChanged?.(); },
        onInputHeld: (keys) => { if (keys !== this.heldKeys) { this.heldKeys = keys; this.connectionChanged?.(); } },
        onDisconnected: (forced) => { this.setConnected(false); if (first) options.firstHooks?.onDisconnected?.(forced); },
        onExited: (status) => { this.exited?.(status); if (first) options.firstHooks?.onExited?.(status); },
        // The ghost of the last screen sits in the host element, which the ended state hides.
        onSessionGone: (status) => { if (first) settle(); options.onSessionGone?.(this.model.host, this.model.sessionId ?? "", status); },
        onOpenRefused: (message, sessionList) => {
          if (this.disposed) return true;
          if (first) settle();
          // A window whose strip asked for this shell says why itself, where the person is looking.
          if (this.refused?.(message)) return true;
          core.toast.show({ message, tone: "error", ...(sessionList ? { duration: 0 } : {}),
            ...(sessionList && this.showSessions ? { action: { label: "Sessions", onSelect: this.showSessions } } : {}),
          });
          return true;
        },
        onSessionCreated: (id) => {
          this.retired = undefined;
          this.model.sessionId = id;
          this.changed();
          options.onSessionCreated?.(id);
          options.onStartupSession?.(id, this.model.hostId, this.model.host);
        },
      };
      // Reserved before the module loads: windows restored together all ask now, and each must count against its socket.
      const conn = this.conn = pool && !this.disposed ? pool.acquire() : connection;
      // Capture before the dynamic import too: typing into another surface
      // while the terminal module loads must cancel restore focus permanently.
      const focusIntent = captureFocusIntent(document);
      try {
        const { TerminalClient } = await import("../../terminal");
        if (this.disposed) return;
        const client = await TerminalClient.open({
          // Only the currently selected window may take initial focus. open()
          // also cancels this intent if the person interacts during its waits.
          shouldFocusOnOpen: () => focusIntent.isCurrent() && this.activeNow && !this.disposed,
          host: hostEl,
          hostName: this.model.host,
          screen: core.stage,
          status: this.status.element,
          theme: core.theme(),
          font: core.font(),
          connection: conn,
          hooks,
          ...(this.model.hostId ? { hostId: this.model.hostId } : {}),
          ...(options.predictiveEcho ? { predictiveEcho: true } : {}),
          ...(this.model.sessionId ? { attachSessionId: this.model.sessionId } : {}),
          getEndedSession: () => {
            if (this.retired) return this.retired;
            const id = this.model.sessionId;
            const ended = id ? options.getEndedSession?.(this.model.host, id) : undefined;
            if (ended) this.retired = ended;
            return this.retired;
          },
          onInputActivity: () => core.onInputActivity(),
          onScroll: (scrolled) => { if (active === this) core.setScrolled(scrolled); },
        });
        if (this.disposed) { client.dispose(); return; }
        this.client = client;
        this.mark("client");
        warmCache();
        this.unregister = core.registerTerminal(client);
        if (this.activeNow) core.setActiveTerminal(client);
        if (!this.visible) client.setSuspended(true);
        if (this.retired) { client.markSessionGone(this.retired.status); if (first) settle(); }
        if (first) options.onFirstClient?.(client);
      } catch {
        if (first && !this.disposed) settle();
        if (!this.disposed) core.toast.show({ message: "Could not open the terminal. Try again.", tone: "error", duration: 5000 });
      } finally {
        focusIntent.dispose();
      }
    }

    focus(): void {
      this.client?.focus();
    }

    markGone(host: string, sessionId: string, status?: number): void {
      if (this.model.host !== host || this.model.sessionId !== sessionId) return;
      this.retired = status === undefined ? {} : { status };
      this.setConnected(false);
      this.client?.markSessionGone(status);
    }

    setActive(isActive: boolean): void {
      this.activeNow = isActive;
      if (isActive) {
        active = this;
        this.client?.setFrozen(false);
        if (this.client) core.setActiveTerminal(this.client);
      } else if (active === this) {
        active = undefined;
        core.setActiveTerminal(undefined);
      }
    }

    /** Holds the terminal's drawing while the camera moves (the active window is never held). */
    setFrozen(frozen: boolean): void { this.client?.setFrozen(frozen && active !== this); }

    setVisible(visible: boolean): void {
      this.visible = visible;
      // A picture is a canvas that holds pixels: off screen it goes (the terminal repaints from its own state when shown).
      if (!visible) this.endGhost();
      this.client?.setSuspended(!visible);
    }

    refit(): void { this.client?.refit(); }

    openNew(): void {
      this.retired = undefined;
      this.setConnected(false);
      this.painted = false;
      this.client?.openNewSession();
    }

    dispose(): void {
      this.keepScreen();
      this.endGhost();
      window.clearTimeout(this.connectionStabilityTimer);
      this.connectionStabilityTimer = 0;
      this.disposed = true;
      bindings.delete(this);
      if (active === this) { active = undefined; core.setActiveTerminal(undefined); }
      this.unregister?.();
      if (pool && this.conn) { pool.release(this.conn); this.conn = undefined; }
      this.client?.dispose();
      this.client = undefined;
      this.status.dispose();
      // The screen's own host goes back to its parking place so the next first window can use it.
      if (this.hostEl === core.terminalHost) { firstHostUsed = false; this.hostEl.remove(); } else this.hostEl?.remove();
    }
  }

  return {
    bind(model, env): SessionBinding {
      const b = new Binding(model, env.changed, env.exited, env.showSessions, env.refused, env.connectionChanged);
      bindings.add(b);
      return b;
    },
    open(hostName, opts): WindowModel {
      // Explicit UUIDs and splits preserve affinity even when host labels are duplicated.
      const explicit = opts?.from?.hostId ?? (isCanonicalUuid(hostName) ? hostName : undefined);
      const embeddedTarget = hostName === "embedded" || Boolean(opts?.from && !opts.from.hostId && !opts.from.noAccess && opts.from.host === host.name);
      const matches = [...remotes.values()].filter((entry) => entry.name === hostName);
      const remote = explicit ? remotes.get(explicit) : !embeddedTarget && matches.length === 1 && hostName !== host.name ? matches[0] : undefined;
      const local = !explicit && (embeddedTarget || hostName === host.name && matches.length === 0);
      return {
        id: `t-${randomUuid()}`, kind: "terminal", host: remote?.name ?? (local ? host.name : hostName),
        ...(remote ? { hostId: remote.id, ...(remote.user ? { user: remote.user } : {}), ...(remote.os ? { os: remote.os } : {}), ...(remote.address ? { address: remote.address } : {}) } : local ? { ...(host.user ? { user: host.user } : {}), ...(host.os ? { os: host.os } : {}) } : { noAccess: true }),
        ...(opts?.from ? { splitOf: opts.from.id } : {}),
        ...(opts?.session ? { sessionId: opts.session } : {}),
      };
    },
    registerHost(entry) {
      if (!isCanonicalUuid(entry.id)) throw new Error("Host identity is not valid.");
      remotes.set(entry.id, { ...entry });
      for (const listener of listeners) listener();
    },
    replaceHosts(entries, keepWhileSettingUp = []) {
      const ids = new Set(entries.map((entry) => entry.id));
      if (entries.some((entry) => !isCanonicalUuid(entry.id)) || ids.size !== entries.length) throw new Error("Host inventory is not valid.");
      const keeping = new Set(keepWhileSettingUp.filter(isCanonicalUuid));
      const retained = [...remotes].filter(([id]) => keeping.has(id) && !ids.has(id));
      const removed = [...remotes.keys()].filter((id) => !ids.has(id) && !keeping.has(id));
      remotes.clear();
      for (const entry of entries) remotes.set(entry.id, { ...entry });
      for (const [id, entry] of retained) remotes.set(id, entry);
      for (const listener of listeners) listener();
      return removed;
    },
    forgetHost(id) { remotes.delete(id); for (const listener of listeners) listener(); },
    hosts(): HostEntry[] { return [{ id: "embedded", name: host.name, ...(host.user ? { user: host.user } : {}), ...(host.os ? { os: host.os } : {}) }, ...remotes.values()]; },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    activeClient: () => active?.client,
    markGone(host, sessionId, status) { for (const binding of bindings) binding.markGone(host, sessionId, status); },
    freeze(frozen) { for (const b of bindings) b.setFrozen(frozen); },
    dispose() { for (const b of [...bindings]) b.dispose(); bindings.clear(); },
  };
}
