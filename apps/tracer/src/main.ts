/** Starts auth and the terminal, keeping the terminal bundle off the unauthenticated path. */
import { AuthError, checkStatus, checkSession } from "./auth";
import { mountFaultyTerminal, type FaultyTerminal } from "../../../packages/ui/src/faulty-terminal";
import { glitchText } from "../../../packages/ui/src/glitch";
import { installTooltips } from "../../../packages/ui/src/tooltip";
import { mountOnboarding } from "./onboarding";
import { PerformanceProbe, type ProbeTraceSample } from "./perf-probe";
// Ghostty and its WASM are fetched only once an authenticated user reaches the terminal.
import type { TerminalClient } from "./terminal";

declare global {
  interface Window {
    __tracerTestDouble?: {
      isConnected: () => boolean;
      dropConnection: () => void;
      screenText: () => string;
      graphemeText: () => string;
      rendererMetrics: () => {
        cols: number;
        rows: number;
        cellWidth: number;
        cellHeight: number;
        configuredScrollback: number;
        receivedSequence: string;
        outputSequence: string;
        scrollbackRows: number;
        viewportY: number;
        fontSize: number;
        wasmMemoryBytes: number;
      } | undefined;
      trace: () => ProbeTraceSample[];
    };
  }
}

const app = document.querySelector<HTMLElement>("#app") ?? missingMount();
type UiFont = "sans" | "mono";

const uiFont = uiFontPreference();
document.documentElement.dataset.uiFont = uiFont;

let activeUserId: string | undefined;
let checkingResume = false;
let currentTerminal: TerminalClient | undefined;
let coreScreen: import("./core-screen").CoreScreen | undefined;
let performanceProbe: PerformanceProbe | undefined;
let backdrop: FaultyTerminal | undefined;
let welcomeEffect: ReturnType<typeof glitchText> | undefined;
let welcomeTimer = 0;
let foregroundListenerInstalled = false;
let backdropTimer = 0;

void start();

async function start(): Promise<void> {
  installForegroundListener();
  const fontsReady = Promise.race([
    document.fonts.load('450 14px "Geist Mono"').then(() => undefined),
    new Promise<void>((resolve) => window.setTimeout(resolve, 800)),
  ]).catch(() => undefined);
  try {
    const [setupRequired] = await Promise.all([
      checkStatus(),
      fontsReady,
    ]);
    installTooltips();
    await showAuthState(setupRequired);
  } catch (error: unknown) {
    await fontsReady;
    installTooltips();
    renderUnavailable(safeMessage(error));
  }
}

async function refreshAuth(): Promise<void> {
  try {
    await showAuthState(await checkStatus());
  } catch (error: unknown) {
    renderUnavailable(safeMessage(error));
  }
}

async function showAuthState(setupRequired: boolean): Promise<void> {
  const session = setupRequired ? undefined : await checkSession();
  if (session) {
    activeUserId = session.user_id;
    await showTerminal(sessionHostname(session));
  } else {
    renderAuth(setupRequired);
  }
}

/** Narrows additive server metadata from the authenticated session response. */
type SessionWithHostname = NonNullable<Awaited<ReturnType<typeof checkSession>>> & { hostname?: unknown };

function sessionHostname(session: Awaited<ReturnType<typeof checkSession>>): string | undefined {
  if (!session) return undefined;
  const hostname = (session as SessionWithHostname).hostname;
  return typeof hostname === "string" && hostname.trim() ? hostname.trim() : undefined;
}

function installForegroundListener(): void {
  if (foregroundListenerInstalled) return;
  foregroundListenerInstalled = true;
  let wasHidden = document.hidden;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      wasHidden = true;
    } else if (wasHidden) {
      wasHidden = false;
      void checkForegroundSession();
    }
  });
}

function renderUnavailable(message: string): void {
  document.documentElement.removeAttribute("data-ui-font");
  app.innerHTML = `<section class="auth-screen"><section class="auth-card auth-signin">
    <div class="auth-mark">infraternal</div><h1>Could not reach the server</h1>
    <p id="status-error" class="auth-message" role="alert"></p>
    <button id="retry-status" class="auth-primary" type="button">Try again</button></section></section>`;
  mustGet<HTMLElement>("#status-error").textContent = message;
  mustGet<HTMLButtonElement>("#retry-status").addEventListener("click", () => { void refreshAuth(); }, { once: true });
  scheduleBackdrop();
}

function renderAuth(setupRequired: boolean, message = ""): void {
  document.documentElement.removeAttribute("data-ui-font");
  mountOnboarding(app, setupRequired, message, (userId, firstSetup, welcomeName, instant) => {
    saveBrowserId("tracer.user-id", userId);
    activeUserId = userId;
    if (firstSetup) showWelcome(welcomeName ?? "", instant);
    else void showTerminal(undefined, instant);
  });
  scheduleBackdrop();
}

function showWelcome(displayName: string, instant = false): void {
  document.documentElement.removeAttribute("data-ui-font");
  window.clearTimeout(welcomeTimer);
  welcomeEffect?.destroy();
  app.innerHTML = `<section class="auth-screen auth-welcome" aria-live="polite"><div class="welcome-copy"><h1 id="welcome-title"></h1><p></p></div></section>`;
  const screen = mustGet<HTMLElement>(".auth-welcome");
  screen.toggleAttribute("data-no-motion", instant);
  mustGet<HTMLElement>(".welcome-copy p").textContent = `signed in as ${displayName}`;
  const title = mustGet<HTMLElement>("#welcome-title");
  if (instant) title.textContent = "Welcome to infraternal";
  else welcomeEffect = glitchText(title, "Welcome to infraternal", { speed: 0.5, settleAfter: 1600 });
  welcomeTimer = window.setTimeout(() => {
    welcomeEffect?.destroy();
    welcomeEffect = undefined;
    void showTerminal();
  }, 2600);
}

function startBackdrop(): void {
  let canvas = document.querySelector<HTMLCanvasElement>("#faulty-field");
  if (!canvas) {
    canvas = document.createElement("canvas");
    canvas.id = "faulty-field";
    canvas.setAttribute("aria-hidden", "true");
    app.before(canvas);
  }
  canvas.style.opacity = "1";
  canvas.style.transition = "none";
  backdrop?.destroy();
  backdrop = mountFaultyTerminal(canvas);
}

function scheduleBackdrop(): void {
  if (backdrop || backdropTimer) return;
  // Keep WebGL shader compilation off the auth screenshot/first-paint path. The field
  // begins its 1.2 s intro reveal after 600 ms, while setup is still in progress.
  backdropTimer = window.setTimeout(() => {
    backdropTimer = 0;
    if (app.querySelector(".auth-screen")) startBackdrop();
  }, 600);
}

function stopBackdrop(instant = false): void {
  window.clearTimeout(backdropTimer);
  backdropTimer = 0;
  const canvas = document.querySelector<HTMLCanvasElement>("#faulty-field");
  if (!canvas) return;
  if (instant) {
    canvas.style.transition = "none";
    canvas.style.opacity = "0";
    backdrop?.destroy();
    backdrop = undefined;
    canvas.remove();
    return;
  }
  canvas.style.transition = "opacity 240ms ease-out";
  canvas.style.opacity = "0";
  const stopped = backdrop;
  backdrop = undefined;
  window.setTimeout(() => {
    stopped?.destroy();
    if (canvas === document.querySelector("#faulty-field")) canvas.remove();
  }, 260);
}

async function showTerminal(serverHostname?: string, instant = false): Promise<void> {
  const hostName = serverHostname ?? sessionHostname(await checkSession());
  if (!hostName) {
    renderUnavailable("The authenticated session did not include the server hostname.");
    return;
  }
  window.clearTimeout(welcomeTimer);
  welcomeEffect?.destroy();
  welcomeEffect = undefined;
  stopBackdrop(instant);
  currentTerminal?.dispose();
  coreScreen?.dispose();
  performanceProbe?.dispose();
  currentTerminal = undefined;
  coreScreen = undefined;
  performanceProbe = undefined;
  const query = new URLSearchParams(location.search);
  const mockMode = query.get("mock") === "1";
  const probeMode = query.get("probe") === "1";
  const scrollbackLimit = mockMode ? testScrollbackLimit(query.get("scrollback")) : undefined;
  let screen: import("./core-screen").CoreScreen | undefined;
  try {
    const { mountCoreScreen } = await import("./core-screen");
    // The screen mounts only after its selected face is ready, preventing a one-frame
    // fallback and keeping the mobile layout stable while the font loads.
    await document.fonts.load(uiFont === "mono" ? '450 13px "Geist Mono"' : '450 14px "Geist Sans"');
    // Auth keeps its existing monospace tooltips; this preference owns the core screen only.
    document.documentElement.dataset.uiFont = uiFont;
    screen = mountCoreScreen(app, { hostName, mockMode, probeMode });
  } catch (error: unknown) {
    renderUnavailable(safeMessage(error));
    return;
  }
  coreScreen = screen;
  if (probeMode) performanceProbe = new PerformanceProbe(screen.probePanel, probeCount(query.get("n")));
  const probeHooks = performanceProbe?.hooks();
  // Session continuity across reloads (integration, #34): the tab remembers its
  // public session id so a reload reattaches to the same terminal.
  const sessionKey = activeUserId ? `tracer.session.${activeUserId}` : undefined;
  const initialSessionId = query.get("session") ?? (sessionKey ? loadTabSession(sessionKey) : undefined);
  const hooks = {
    ...probeHooks,
    onSessionCreated: (sessionId: string): void => {
      // Public session ids are scoped to the authenticated owner, not input
      // writers. The server still authorizes every attachment [50]. No pending
      // keystrokes or bearer resume credentials enter tab storage or the URL.
      if (sessionKey) saveBrowserId(sessionKey, sessionId, true);
      const url = new URL(location.href);
      url.searchParams.set("session", sessionId);
      history.replaceState(null, "", url);
    },
    onAttached: (resumed: boolean, terminal: import("./terminal").TerminalClient) => {
      screen.setConnection(true);
      probeHooks?.onAttached?.(resumed, terminal);
    },
    onDisconnected: (forced: boolean) => {
      screen.setConnection(false);
      probeHooks?.onDisconnected?.(forced);
    },
  };
  try {
    const { TerminalClient } = await import("./terminal");
    const client = await TerminalClient.open({
      host: screen.terminalHost,
      screen: screen.stage,
      status: screen.status,
      theme: screen.theme(),
      hooks,
      onRoundTrip: (milliseconds) => screen?.setRoundTrip(milliseconds),
      onConnectionChange: (connected) => screen?.setConnection(connected),
      onScroll: (scrolled) => screen?.setScrolled(scrolled),
      onInputActivity: () => screen?.onInputActivity(),
      traceMockServer: probeMode && mockMode,
      ...(scrollbackLimit === undefined ? {} : { scrollbackLimit }),
      ...(initialSessionId ? { initialSessionId } : {}),
    });
    currentTerminal = client;
    screen.bindTerminal(client);
    performanceProbe?.bind(client);
    if (mockMode) {
      window.__tracerTestDouble = {
        isConnected: () => currentTerminal?.isConnected === true,
        dropConnection: () => currentTerminal?.forceDrop(),
        screenText: () => currentTerminal?.readScreenText() ?? "",
        graphemeText: () => currentTerminal?.readGraphemeText() ?? "",
        rendererMetrics: () => currentTerminal?.rendererMetrics,
        trace: () => performanceProbe?.traceSamples() ?? [],
      };
    }
  } catch (error: unknown) {
    const status = document.querySelector<HTMLElement>("#connection-status");
    if (status) status.textContent = safeMessage(error);
  }
}

/** URL choices win and are remembered when storage is available; private mode still works. */
function uiFontPreference(): UiFont {
  const requested = new URLSearchParams(location.search).get("ui");
  if (requested === "sans" || requested === "mono") {
    try { window.localStorage.setItem("tracer.ui-font", requested); } catch { /* The URL remains the preference without storage. */ }
    return requested;
  }
  try {
    return window.localStorage.getItem("tracer.ui-font") === "mono" ? "mono" : "sans";
  } catch {
    return "sans";
  }
}

function testScrollbackLimit(value: string | null): number | undefined {
  if (value === null) return undefined;
  const limit = Number(value);
  return Number.isInteger(limit) && limit >= 0 && limit <= 100_000 ? limit : undefined;
}

function probeCount(value: string | null): number {
  if (!value) return 500;
  const count = Number(value);
  return Number.isInteger(count) && count >= 1 && count <= 5_000 ? count : 500;
}

async function checkForegroundSession(): Promise<void> {
  if (checkingResume || !activeUserId) return;
  checkingResume = true;
  try {
    const session = await checkSession();
    if (!session) {
      currentTerminal?.dispose();
      currentTerminal = undefined;
      performanceProbe?.dispose();
      performanceProbe = undefined;
      coreScreen?.dispose();
      coreScreen = undefined;
      delete window.__tracerTestDouble;
      activeUserId = undefined;
      renderAuth(false, "Your session ended. Sign in again to reconnect.");
    }
  } catch (error: unknown) {
    const status = document.querySelector<HTMLElement>("#connection-status");
    if (status) status.textContent = safeMessage(error);
  } finally {
    checkingResume = false;
  }
}

function saveBrowserId(key: string, value: string, tab = false): void {
  try { (tab ? sessionStorage : localStorage).setItem(key, value); }
  catch { /* public identifiers are conveniences; authorization stays on the server */ }
}

function loadTabSession(key: string): string | undefined {
  try { return sessionStorage.getItem(key) ?? undefined; }
  catch { return undefined; }
}

function safeMessage(error: unknown): string {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "The passkey prompt was cancelled or timed out. Try again when you are ready.";
  }
  return error instanceof AuthError ? error.message : "The request could not be completed. Try again.";
}

function mustGet<ElementType extends HTMLElement = HTMLElement>(selector: string): ElementType {
  const element = document.querySelector<ElementType>(selector);
  if (!element) throw new Error(`Required tracer element is missing: ${selector}`);
  return element;
}

function missingMount(): never {
  throw new Error("tracer mount point is missing");
}
