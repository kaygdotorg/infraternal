/**
 * The product sessions service: terminal windows bound to real sessions, all on the one WebSocket (D183).
 *
 * Each terminal window gets its own `TerminalClient` (its own renderer, cursors and input queue) riding one
 * stream of the shared `MuxConnection`. Opening a window opens a new shell on the server; a window restored from
 * the canvas document re-attaches to the session it names. Closing a window detaches its stream and never ends
 * the session (D178).
 *
 * Costs, because several terminals live on one page:
 * - A binding starts its terminal when the window first exists, but a window that is off screen or in another
 *   view is suspended (`setVisible(false)`): no drawing and no canvas backing store, so a phone holds about one
 *   screen of pixels. Output keeps flowing into the terminal state and credit keeps returning.
 * - Only the active window's terminal takes the keys (`core.setActiveTerminal`); all of them follow the theme
 *   and font (`core.registerTerminal`).
 * - The first window uses the screen's own terminal host element, so the page still has one `#terminal-host`.
 */
import type { CoreScreen } from "../../core-screen";
import type { MuxConnection } from "../../connection";
import type { TerminalClient, TerminalHooks } from "../../terminal";
import { el } from "../dom";
import { createStatusRelay } from "../status";
import type { WindowModel } from "../model/types";
import { onDemand, whenIdle } from "../../on-demand";
import type { HostEntry, SessionBinding, SessionService } from "./adapter";
import type { ScreenCache } from "./screen-cache.on-demand";

export interface LiveSessionsOptions {
  core: CoreScreen;
  connection: MuxConnection;
  /** The embedded host: its name and the person's login. Remote hosts join the list as #78 lands. */
  host: { name: string; user?: string };
  /** `?predict=1`: the opt-in predictive echo. */
  predictiveEcho?: boolean;
  /** Extra terminal hooks (the latency probe) for the first terminal. */
  firstHooks?: TerminalHooks;
  /** Called with the first terminal once it is ready (the probe binds to it). */
  onFirstClient?: (client: TerminalClient) => void;
  /** Called when the window shows a session (restored or new). */
  onSessionCreated?: (sessionId: string) => void;
}

export interface LiveSessions extends SessionService {
  /** The terminal of the active window, for callers outside the canvas. */
  activeClient(): TerminalClient | undefined;
  dispose(): void;
}

export function createLiveSessions(options: LiveSessionsOptions): LiveSessions {
  const { core, connection, host } = options;
  const listeners = new Set<() => void>();
  const bindings = new Set<Binding>();
  let firstHostUsed = false;
  let firstReported = false;
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
    private wantsFocus = false;
    private visible = true;
    private activeNow = false;
    private painted = false;
    private dropGhost: (() => void) | undefined;
    private ghostTimer = 0;
    /** Marks for the switch timeline (`sw:<n>:<step>`); a few microseconds each, read by the real specs. */
    private readonly n = ++serial;
    private mark(step: string): void { performance.mark(`sw:${this.n}:${step}`); }

    constructor(private readonly model: WindowModel, private readonly changed: () => void) {}

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
      if (!client || !model.sessionId || this.disposed) return false;
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

    private async start(): Promise<void> {
      const hostEl = this.hostEl;
      if (!hostEl) return;
      const first = !firstReported;
      firstReported = true;
      const hooks: TerminalHooks = {
        ...(first ? options.firstHooks : {}),
        onAttached: (resumed, terminal) => { this.mark("attached"); if (first) options.firstHooks?.onAttached?.(resumed, terminal); },
        onPaintedOutput: (bytes, at, sequence) => { if (!this.painted) { this.painted = true; this.mark("painted"); this.endGhost(); } if (first) options.firstHooks?.onPaintedOutput?.(bytes, at, sequence); },
        onSessionCreated: (id) => {
          this.model.sessionId = id;
          this.changed();
          options.onSessionCreated?.(id);
        },
      };
      try {
        const { TerminalClient } = await import("../../terminal");
        if (this.disposed) return;
        const client = await TerminalClient.open({
          host: hostEl,
          screen: core.stage,
          status: this.status.element,
          theme: core.theme(),
          font: core.font(),
          connection,
          hooks,
          ...(options.predictiveEcho ? { predictiveEcho: true } : {}),
          ...(this.model.sessionId ? { attachSessionId: this.model.sessionId } : {}),
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
        if (this.wantsFocus) client.focus();
        if (first) options.onFirstClient?.(client);
      } catch {
        if (!this.disposed) core.toast.show({ message: "Could not open the terminal. Try again.", tone: "error", duration: 5000 });
      }
    }

    focus(): void {
      if (this.client) this.client.focus(); else this.wantsFocus = true;
    }

    setActive(isActive: boolean): void {
      this.activeNow = isActive;
      if (isActive) {
        active = this;
        if (this.client) core.setActiveTerminal(this.client);
      } else if (active === this) {
        active = undefined;
        core.setActiveTerminal(undefined);
      }
    }

    setVisible(visible: boolean): void {
      this.visible = visible;
      // A picture is a canvas that holds pixels: off screen it goes (the terminal repaints from its own state when shown).
      if (!visible) this.endGhost();
      this.client?.setSuspended(!visible);
    }

    refit(): void { this.client?.refit(); }

    dispose(): void {
      this.keepScreen();
      this.endGhost();
      this.disposed = true;
      bindings.delete(this);
      if (active === this) { active = undefined; core.setActiveTerminal(undefined); }
      this.unregister?.();
      this.client?.dispose();
      this.client = undefined;
      this.status.dispose();
      // The screen's own host goes back to its parking place so the next first window can use it.
      if (this.hostEl === core.terminalHost) { firstHostUsed = false; this.hostEl.remove(); } else this.hostEl?.remove();
    }
  }

  return {
    bind(model, env): SessionBinding {
      const b = new Binding(model, env.changed);
      bindings.add(b);
      return b;
    },
    open(hostName, opts): WindowModel {
      // A new window, a new shell: the server opens it when the window is bound (a split never reuses a session).
      return {
        id: `t-${crypto.randomUUID()}`, kind: "terminal", host: hostName,
        ...(host.user ? { user: host.user } : {}),
        ...(opts?.from ? { splitOf: opts.from.id } : {}),
        // Showing a session that already exists: the window attaches to it instead of opening a new shell.
        ...(opts?.session ? { sessionId: opts.session } : {}),
      };
    },
    hosts(): HostEntry[] { return [{ id: "embedded", name: host.name, ...(host.user ? { user: host.user } : {}) }]; },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    activeClient: () => active?.client,
    dispose() { for (const b of [...bindings]) b.dispose(); bindings.clear(); },
  };
}
