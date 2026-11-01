/**
 * The sessions adapter: how terminal windows meet real sessions (D178, D183).
 *
 * The canvas never talks to the protocol. It asks a `SessionService` to bind a window's model to a session and
 * gets a `SessionBinding` back. The product service (`live.ts`) binds to terminal streams of the one WebSocket;
 * the mockups' service shows previews. Either way the canvas rules are the same:
 *
 * - Closing a window disposes its binding and never ends the session (D178): the session keeps running,
 *   detached, and can be reopened from the sidebar or the palette.
 * - A split asks the service to open a new shell on the same host (no prompt); the model it returns is shown at
 *   once, and its binding connects in the background, so a split never waits for the network.
 * - A window outside the live level of detail, on another view or off screen is told `setVisible(false)`; the
 *   service then stops its live bytes (D183: hidden windows get a "changed" marker, a snapshot when shown).
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import type { ViewId, WindowModel } from "../model/types";

/**
 * What the window's connection indicator needs beyond "connected or not" (#212). Times are `performance.now()` values so
 * a repaint can tell a moment that just happened from one that is over.
 */
export interface LinkInfo {
  /** The window has been attached at least once, so a lost link is "reconnecting" rather than the first "connecting". */
  readonly everConnected: boolean;
  /** When the link came back after being lost (undefined: it did not, or not since the last loss). */
  readonly resumedAt: number | undefined;
  /** When the screen came back rebuilt from the latest state, so some scrollback may be approximate. */
  readonly approximateAt: number | undefined;
  /** Keys typed while the link could not carry them, kept to be sent. Only a count; what was typed is never exposed. */
  readonly heldKeys: number;
}

export interface SessionBinding {
  /** Runtime attachment readiness; surviving inventory alone does not prove typing reaches the shim. */
  readonly connected?: boolean;
  /** The finer state of the link, for the window's connection indicator. */
  readonly link?: LinkInfo;
  /** Puts the window's content (a live renderer, or a preview) into the card body. Called once. */
  mount(body: HTMLElement): void;
  /** Input focus: the next key goes to this session. */
  focus(): void;
  /** The window became the active one (or stopped being it). */
  setActive(active: boolean): void;
  /** The window is on screen and live (true), or hidden, thumbnailed or far away (false). */
  setVisible(visible: boolean): void;
  /**
   * Shows the session `model.sessionId` names in this same binding, without tearing the renderer down (#128): the
   * last known screen of that session paints at once and the stream attaches; returns false when the binding cannot
   * (its terminal is not ready yet), and the caller then disposes it and binds a new one.
   */
  retarget?(model: WindowModel): boolean;
  /**
   * Starts a new shell on the same host in this binding, after its session ended (the ended state's one action).
   * The renderer stays; the new session's id arrives through `changed`, as for any new shell.
   */
  openNew?(): void;
  /** The window's box changed; the renderer refits to the new cell grid. */
  refit(): void;
  /** The window closed. The session is not ended. */
  dispose(): void;
}

export interface HostEntry {
  id: string;
  name: string;
  /** The person's login on the host, for the pill. */
  user?: string;
  os?: HostPlatform;
  /** Last server-observed infraternal agent connectivity; offline hosts remain available in inventory. */
  online?: boolean;
}

export interface SessionService {
  /** Binds a terminal window's model to its session (opening one when the model names none). */
  bind(model: WindowModel, env: { view: ViewId; /** Repaints readiness without persisting connection state in layouts. */ connectionChanged?(): void; /** Open the existing window-header session picker. */ showSessions?: (event?: MouseEvent) => void; /** The model gained something worth saving (a session id). */ changed(): void; /** The shell exited after its final output painted. */ exited?(status: number): void; /** The host refused to open a shell here; true when the window shows the reason itself (no toast then). */ refused?(message: string): boolean }): SessionBinding;
  /** A model for a new shell on `host` (a split, a sidebar open, the palette). The shell starts when it is bound. */
  open(host: string, options?: { container?: string; from?: WindowModel; /** An existing session of the host to show (the sidebar, the palette, the manager). */ session?: string }): WindowModel;
  /** Hosts the person can open shells on. */
  hosts(): HostEntry[];
  /** Called when the set of hosts or sessions changes (a host appears, a session exits). */
  onChange(listener: () => void): () => void;
  /** The camera is moving at a small scale: terminals other than the active one hold their drawing until it rests (#121). Optional: test doubles draw nothing real. */
  freeze?(frozen: boolean): void;
}
