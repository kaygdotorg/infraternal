/** Starts auth and the terminal, keeping the terminal bundle off the unauthenticated path. */
import { AuthError, checkStatus, checkSession, recoveryAuth } from "./auth";
import { mountFaultyTerminal, type FaultyTerminal } from "../../../packages/ui/src/faulty-terminal";
import { glitchText } from "../../../packages/ui/src/glitch";
import { installTooltips } from "../../../packages/ui/src/tooltip";
import { installFocusRing } from "../../../packages/ui/src/focus-ring";
import { applyFontVars, loadFont } from "../../../packages/ui/src/fonts";
import { initialFont } from "./font-preference";
import { mountOnboarding } from "./onboarding";
import { BRAND_MARK } from "./auth-marks";
import { loading } from "../../../packages/ui/src/countup";
import { releaseAuthScheme, useAuthScheme } from "./auth-scheme";
import { recoveryUiEnabled } from "./recovery-ui";
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
      injectInput: (data: string) => void;
      seedPrompt: () => Promise<void>;
      setPredictiveEcho: (enabled: boolean) => void;
      baselineScreenText: (bytes: number[]) => Promise<string>;
      predictiveEcho: () => import("./predictive-echo").PredictiveEchoState | undefined;
      themeHistoryColors: () => { rows: number; indexed: number[]; truecolor: number[] };
      rendererMetrics: () => {
        cols: number;
        rows: number;
        cellWidth: number;
        cellHeight: number;
        naturalCellWidth: number;
        configuredScrollback: number;
        cursorX: number;
        cursorY: number;
        renderCursorX: number;
        renderCursorY: number;
        renderCursorVisible: boolean;
        receivedSequence: string;
        outputSequence: string;
        scrollbackRows: number;
        viewportY: number;
        cursorVisible: boolean;
        fontSize: number;
        fontFamily: string;
        fontId: string;
        wasmMemoryBytes: number;
        themeColorsMs: number;
        themeRenderMs: number;
        terminalColors?: { background: { r: number; g: number; b: number }; foreground: { r: number; g: number; b: number } };
      } | undefined;
      benchmarkFullRedraw: (iterations: number) => number[] | undefined;
      freezeCursorForTest: () => void;
      benchmarkOutputAt10MBps: () => Promise<{
        bytes: number;
        elapsedMs: number;
        writeCpuMs: number;
        p95FrameMs: number;
        maxFrameMs: number;
        wasmMemoryBytes: number;
      }> | undefined;
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

/** True only in builds made with INFRATERNAL_CLUSTERS_PREVIEW=1 (see build.ts); false removes the mockup from the bundle. */
declare const __CLUSTERS_PREVIEW__: boolean;

void start();

async function start(): Promise<void> {
  installFocusRing();
  installForegroundListener();
  // The chosen font applies to the whole app, sign-in card included, before the first paint.
  // The default is already declared in CSS and preloaded; another font is fetched here.
  const font = initialFont();
  applyFontVars(font, document.documentElement);
  const fontsReady = Promise.race([
    loadFont(font),
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
    await showTerminal(session);
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

/**
 * A mockup preview (`?mock=1&proto=...`) re-creates its mock session by loading the page again: the
 * test double hands the session cookie out on that load. After the double restarts, a tab that
 * was open lands here instead of on a dead "Could not reach the server".
 */
const previewProto = (): boolean => { const q = new URLSearchParams(location.search); return q.get("mock") === "1" && !!q.get("proto"); };
let healTimer = 0;
function healPreview(): void {
  if (!previewProto()) return;
  window.clearInterval(healTimer);
  healTimer = window.setInterval(() => {
    void fetch("/health", { cache: "no-store" }).then((r) => { if (r.ok) location.reload(); }).catch(() => undefined);
  }, 2000);
}

/** Applies the sign-in scheme (light or dark); the backdrop follows later scheme changes live. */
const authLight = (): boolean => useAuthScheme((light) => backdrop?.setLight(light));

/**
 * The access card for a server that cannot be reached. It is the sign-in card with different words:
 * the same mark, title, lede and full-width primary, through the sign-in card's own classes, so the
 * mark, the lede-to-action gap and the padding cannot drift from it. The explanation is the lede (it is
 * what the person reads next); pressing "Try again" shows the shared wait counter on the button.
 */
function renderUnavailable(message: string): void {
  authLight();
  document.documentElement.removeAttribute("data-ui-font");
  app.innerHTML = `<section class="auth-screen" aria-label="Server unavailable"><section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="unavailable-title">
    <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
    <h1 id="unavailable-title">Could not reach the server</h1>
    <p id="status-error" class="auth-lede" role="alert"></p>
    <button id="retry-status" class="auth-primary auth-login" type="button"><span>Try again</span><span class="busy-count" hidden></span></button></section></section>`;
  mustGet<HTMLElement>("#status-error").textContent = message;
  const retry = mustGet<HTMLButtonElement>("#retry-status");
  retry.addEventListener("click", () => {
    if (previewProto()) { location.reload(); return; }
    retry.disabled = true;
    loading(retry.querySelector<HTMLElement>(".busy-count")!, 400);
    void refreshAuth();
  }, { once: true });
  healPreview();
  scheduleBackdrop();
}

function renderAuth(setupRequired: boolean, message = ""): void {
  authLight();
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
  authLight();
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
  backdrop = mountFaultyTerminal(canvas, authLight());
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

async function showTerminal(knownSession?: Awaited<ReturnType<typeof checkSession>>, instant = false): Promise<void> {
  // Startup already authenticated this snapshot. Reuse it rather than adding
  // another network round trip; the socket still checks authority on connection.
  const identity = knownSession ?? await checkSession();
  const hostName = sessionHostname(identity);
  if (!hostName) {
    renderUnavailable("The authenticated session did not include the server hostname.");
    return;
  }
  window.clearTimeout(welcomeTimer);
  welcomeEffect?.destroy();
  welcomeEffect = undefined;
  stopBackdrop(instant);
  // The app paints its own theme; the sign-in scheme lets go once the backdrop has faded out.
  window.setTimeout(() => { if (!app.querySelector(".auth-screen")) releaseAuthScheme(); }, instant ? 0 : 260);
  currentTerminal?.dispose();
  canvasPrototype?.dispose();
  canvasPrototype = undefined;
  coreScreen?.dispose();
  performanceProbe?.dispose();
  currentTerminal = undefined;
  coreScreen = undefined;
  performanceProbe = undefined;
  const query = new URLSearchParams(location.search);
  const mockMode = query.get("mock") === "1";
  // One combined preview (D160): `?proto=windows` is the canvas, and the add-host flow opens
  // on it. `?proto=addhost` is an alias that opens the same preview with the wizard open.
  const proto = query.get("proto");
  const canvasMode = mockMode && (proto === "windows" || proto === "addhost");
  // Concept mockup for views on one canvas (#89): it brings its own windows and no live terminal.
  const clustersMode = __CLUSTERS_PREVIEW__ && mockMode && proto === "clusters";
  const probeMode = query.get("probe") === "1";
  const predictiveEcho = query.get("predict") === "1";
  const scrollbackLimit = mockMode ? testScrollbackLimit(query.get("scrollback")) : undefined;
  let screen: import("./core-screen").CoreScreen | undefined;
  try {
    const { mountCoreScreen } = await import("./core-screen");
    // The screen mounts only after its selected face is ready, preventing a one-frame
    // fallback and keeping the mobile layout stable while the font loads.
    await (uiFont === "mono" ? loadFont(initialFont()) : document.fonts.load('450 14px "Geist Sans"'));
    // Auth keeps its existing monospace tooltips; this preference owns the core screen only.
    document.documentElement.dataset.uiFont = uiFont;
    screen = mountCoreScreen(app, { hostName, mockMode, probeMode,
      addHostPrototype: canvasMode || clustersMode,
      ...(clustersMode ? { settingsView: true } : {}),
      ...(identity?.display_name ? { displayName: identity.display_name } : {}),
      ...(identity?.username ? { username: identity.username } : {}),
      ...(query.get("footer") === "b" ? { footerVariant: "b" as const } : {}),
      ...(recoveryUiEnabled() ? {
        onRecovery: () => { void showRecovery(); },
        onCancelRecovery: async () => { await recoveryAuth.post("recovery-cancel", {}); await checkForegroundSession(); },
      } : {}),
    });
  } catch (error: unknown) {
    screen?.dispose();
    renderUnavailable(safeMessage(error));
    return;
  }
  coreScreen = screen;
  if (clustersMode) {
    const { mountClusters } = await import("./canvas/controller");
    const scene = Number(query.get("scene"));
    const roleParam = query.get("role");
    let clusters: Awaited<ReturnType<typeof mountClusters>>;
    try {
      clusters = await mountClusters(screen, {
      ...(scene ? { scene } : {}),
      ...(roleParam === "viewer" || roleParam === "operator" || roleParam === "new" || roleParam === "asha" ? { role: roleParam } : {}),
    });
    } catch (error: unknown) { console.error("clusters mockup failed", error); screen.dispose(); renderUnavailable(safeMessage(error)); return; }
    canvasPrototype = clusters;
    // The flow carries on: the live terminal opens into the build-01 window the mockup hosts it in.
  }
  if (canvasMode) {
    // Gated mockup (D162): the window canvas and the add-host flow on it, built against the
    // test double only. The canvas mounts first; the flow hangs its windows on the canvas.
    const { mountCanvas } = await import("./canvas/mock/windows-proto/canvas");
    const { mountAddHostPrototype } = await import("./add-host-prototype");
    const canvas = mountCanvas(screen, hostName);
    let addHost: { dispose(): void } | undefined;
    try { addHost = await mountAddHostPrototype(screen, canvas, query.get("empty") === "1", proto === "addhost" || query.get("wizard") === "1"); }
    catch (error: unknown) { canvas.dispose(); screen.dispose(); renderUnavailable(safeMessage(error)); return; }
    canvasPrototype = { dispose() { addHost?.dispose(); canvas.dispose(); } };
  }
  if (probeMode) performanceProbe = new PerformanceProbe(screen.probePanel, probeCount(query.get("n")));
  const probeHooks = performanceProbe?.hooks();
  // Session continuity across reloads (integration, #34): the tab remembers its
  // public session id so a reload reattaches to the same terminal.
  screen.setRecoveryPending(identity?.recovery_pending?.ready_at);
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
      font: screen.font(),
      hooks,
      predictiveEcho,
      onRoundTrip: (milliseconds) => screen?.setRoundTrip(milliseconds),
      onConnectionChange: (connected) => screen?.setConnection(connected),
      onScroll: (scrolled) => screen?.setScrolled(scrolled),
      onInputActivity: () => screen?.onInputActivity(),
      onRecoveryPending: (readyAt) => { recoveryNoticeGeneration++; screen?.setRecoveryPending(readyAt); },
      traceMockServer: probeMode && mockMode,
      ...(scrollbackLimit === undefined ? {} : { scrollbackLimit }),
      ...(initialSessionId ? { initialSessionId } : {}),
    });
    currentTerminal = client;
    screen.bindTerminal(client);
    if (canvasMode && mockMode && query.get("fixture") !== "none") void seedItalicFixture(client);
    performanceProbe?.bind(client);
    if (mockMode) {
      window.__tracerTestDouble = {
        isConnected: () => currentTerminal?.isConnected === true,
        dropConnection: () => currentTerminal?.forceDrop(),
        screenText: () => currentTerminal?.readScreenText() ?? "",
        graphemeText: () => currentTerminal?.readGraphemeText() ?? "",
        injectInput: (data) => currentTerminal?.injectInput(data),
        seedPrompt: () => currentTerminal?.seedPromptForTest() ?? Promise.resolve(),
        setPredictiveEcho: (enabled) => currentTerminal?.setPredictiveEchoForTest(enabled),
        baselineScreenText: (bytes) => currentTerminal?.baselineScreenText(Uint8Array.from(bytes)) ?? Promise.resolve(""),
        predictiveEcho: () => currentTerminal?.predictiveEchoState,
        themeHistoryColors: () => currentTerminal?.readThemeHistoryColors() ?? { rows: 0, indexed: [], truecolor: [] },
        rendererMetrics: () => currentTerminal?.rendererMetrics,
        benchmarkFullRedraw: (iterations) => {
          if (!currentTerminal) return undefined;
          return (currentTerminal as unknown as { benchmarkFullRedraw: (count: number) => number[] }).benchmarkFullRedraw(iterations);
        },
        freezeCursorForTest: () => currentTerminal?.freezeCursorForTest(),
        benchmarkOutputAt10MBps: () => {
          if (!currentTerminal) return undefined;
          return (currentTerminal as unknown as {
            benchmarkOutputAt10MBps: () => Promise<{
              bytes: number;
              elapsedMs: number;
              writeCpuMs: number;
              p95FrameMs: number;
              maxFrameMs: number;
              wasmMemoryBytes: number;
            }>;
          }).benchmarkOutputAt10MBps();
        },
        trace: () => performanceProbe?.traceSamples() ?? [],
      };
    }
  } catch (error: unknown) {
    const status = document.querySelector<HTMLElement>("#connection-status");
    if (status) status.textContent = safeMessage(error);
  }
}

/** Opens same-device recovery without revoking the live cookie that authorizes D113. */
async function showRecovery(): Promise<void> {
  if (!recoveryUiEnabled()) return;
  const { mountRecovery } = await import("./recovery");
  currentTerminal?.dispose(); currentTerminal = undefined;
  coreScreen?.dispose(); coreScreen = undefined;
  performanceProbe?.dispose(); performanceProbe = undefined;
  delete window.__tracerTestDouble;
  document.documentElement.removeAttribute("data-ui-font");
  mountRecovery(app, () => { void showTerminal(); }, (userId, _, displayName, instant) => {
    activeUserId = userId;
    saveBrowserId("tracer.user-id", userId);
    showWelcome(displayName ?? "", instant);
  });
  scheduleBackdrop();
}

/** URL choices win and are remembered when storage is available; private mode still works. */
function uiFontPreference(): UiFont {
  // The canvas mockup is monospace throughout (owner rule, docs/design/TASTE.md §2).
  const proto = new URLSearchParams(location.search).get("proto");
  if (proto === "windows" || proto === "addhost" || proto === "clusters") return "mono";
  const requested = new URLSearchParams(location.search).get("ui");
  if (requested === "sans" || requested === "mono") {
    try { window.localStorage.setItem("tracer.ui-font", requested); } catch { /* The URL remains the preference without storage. */ }
    return requested;
  }
  try {
    // Monospace is the product face (TASTE.md section 2); sans stays an explicit opt-in.
    return window.localStorage.getItem("tracer.ui-font") === "sans" ? "sans" : "mono";
  } catch {
    return "mono";
  }
}

function testScrollbackLimit(value: string | null): number | undefined {
  if (value === null) return undefined;
  const limit = Number(value);
  return Number.isInteger(limit) && limit >= 0 && limit <= 64_000_000 ? limit : undefined;
}

function probeCount(value: string | null): number {
  if (!value) return 500;
  const count = Number(value);
  return Number.isInteger(count) && count >= 1 && count <= 5_000 ? count : 500;
}

let recoveryNoticeGeneration = 0;
let canvasPrototype: { dispose(): void } | undefined;

async function checkForegroundSession(): Promise<void> {
  if (checkingResume || !activeUserId) return;
  checkingResume = true;
  const noticeGeneration = recoveryNoticeGeneration;
  try {
    const session = await checkSession();
    // A delayed HTTP snapshot must not overwrite a newer WebSocket state event.
    if (session && noticeGeneration === recoveryNoticeGeneration) coreScreen?.setRecoveryPending(session.recovery_pending?.ready_at);
    if (!session && previewProto()) { location.reload(); return; }
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
  } catch {
    // The session check is background housekeeping, not something the person asked for. When it
    // cannot complete (the server restarting, the link dropping, a proxy answering with a page)
    // nothing is said: the terminal's own reconnection shows state through the status icon, and
    // the next return to the tab checks again. Only a definite "no session" (401) changes the UI.
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

/**
 * Preview only: writes a prompt line and italic, bold and bold-italic output into the fresh mock
 * terminal, so every font in the picker can be judged on slanted text (a font without a real italic
 * is slanted by the browser, which is part of what the owner compares). `?fixture=none` skips it.
 */
async function seedItalicFixture(client: import("./terminal").TerminalClient): Promise<void> {
  for (let attempt = 0; attempt < 40 && !client.isConnected; attempt++) await new Promise((resolve) => setTimeout(resolve, 100));
  const text = [
    "infraternal-dev:~$ printf '\\e[3mitalic\\e[0m'",
    "\u001b[3mitalic: the quick brown fox jumps over the lazy dog\u001b[0m",
    "\u001b[1mbold\u001b[0m regular \u001b[1;3mbold italic\u001b[0m \u001b[3m0123456789 -> => != ===\u001b[0m",
    "",
    "infraternal-dev:~$ ",
  ].join("\r\n");
  try {
    await fetch("/__mock/text-output", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
  } catch { /* a resumed session or a closed socket: the fixture is a convenience, never an error */ }
}
