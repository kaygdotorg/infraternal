/** Starts auth and the terminal, keeping the terminal bundle off the unauthenticated path. */
import { AuthError, checkStatus, checkSession, recoveryAuth, isDeviceUserCode, type AuthStatus } from "./auth";
import { readApprovalLink, type ApprovalKind, type ApprovalLink } from "./approval-link";
import { registerSignOut } from "./sign-out";
import { warmOfflineShell } from "./offline-cache";
import type { DrawingIdentity } from "./offline-drawing";
import { forgetAccountWork, sessionNotifications } from "./account-lifetime";
import { recordSignIn } from "./hints";
import { mountFaultyTerminal, type FaultyTerminal } from "../../../packages/ui/src/faulty-terminal";
import { glitchText } from "../../../packages/ui/src/glitch";
import { installTooltips } from "../../../packages/ui/src/tooltip";
import { installFocusRing } from "../../../packages/ui/src/focus-ring";
import { installInputSource } from "../../../packages/ui/src/input-source";
import { installAutoScrollbars } from "../../../packages/ui/src/scrollbars";
import { applyFontVars, loadFont } from "../../../packages/ui/src/fonts";
import { applyStoredUiSize } from "../../../packages/ui/src/ui-scale";
import { initialFont } from "./font-preference";
import { mountOnboarding } from "./onboarding";
import { BRAND_MARK } from "./auth-marks";
import { loading } from "../../../packages/ui/src/countup";
import { releaseAuthScheme, useAuthScheme } from "./auth-scheme";
import { recoveryUiEnabled } from "./recovery-ui";
import { PerformanceProbe, type ProbeTraceSample } from "./perf-probe";
import { onDemand } from "./on-demand";
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
      writeText: (text: string) => Promise<void>;
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
        synchronizedOutputHoldsPaint: boolean;
        synchronizedTimeoutReleasedAt: number;
        lastPaintedOutputAt: number;
        terminalColors?: { background: { r: number; g: number; b: number }; foreground: { r: number; g: number; b: number } };
      } | undefined;
      benchmarkFullRedraw: (iterations: number) => number[] | undefined;
      freezeCursorForTest: () => void;
      cursorLayerState: () => TerminalClient["cursorLayerState"] | undefined;
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
    /** The product-canvas mock exposes the first PTY for replay regression assertions. */
    __tracerProductTestDouble?: {
      isConnected: () => boolean;
      dropConnection: () => void;
      screenText: () => string;
      terminalLinks: () => readonly { target: string; openable: boolean }[];
      rendererMetrics: () => TerminalClient["rendererMetrics"] | undefined;
      currentView: () => string;
    };
    /** Controlled shared-layout hooks for mock-browser break-it specs. */
    __tracerLayoutReviewDouble?: {
      revisions: () => { server: number; client: number };
      currentView: () => string;
      viewIds: () => string[];
      removeConsole: () => number;
      skipRevision: () => number;
    };
  }
}

const app = document.querySelector<HTMLElement>("#app") ?? missingMount();
let deviceApprovalLink: ApprovalLink = consumeDeviceApprovalLink();
let deviceApprovalComplete = false;
type UiFont = "sans" | "mono";

const uiFont = uiFontPreference();
document.documentElement.dataset.uiFont = uiFont;

let activeUserId: string | undefined;
let checkingResume = false;
let currentTerminal: TerminalClient | undefined;
let coreScreen: import("./core-screen").CoreScreen | undefined;
let performanceProbe: PerformanceProbe | undefined;
let backdrop: FaultyTerminal | undefined;
let perfHud: { dispose(): void } | undefined;
let perfHudGeneration = 0;
let welcomeEffect: ReturnType<typeof glitchText> | undefined;
let welcomeTimer = 0;
let foregroundListenerInstalled = false;
let backdropTimer = 0;

/** True only in builds made with INFRATERNAL_CLUSTERS_PREVIEW=1 (see build.ts); false removes the mockup from the bundle. */
declare const __CLUSTERS_PREVIEW__: boolean;

/**
 * Preview builds only: the frame meter and frame-drop recorder (issue #116) load after the first idle, so they add
 * nothing to the first screen's work or to the critical and deferred transfer budgets. `requestIdleCallback` has a
 * timeout, and Safari, which has none, falls back to a timer.
 */
function startPerfHud(bench: boolean): void {
  if (!__CLUSTERS_PREVIEW__) return;
  const generation = ++perfHudGeneration;
  const load = (): void => {
    if (generation !== perfHudGeneration) return;
    void onDemand(() => import("./perf-hud.on-demand")).then((mod) => {
      if (generation !== perfHudGeneration) return;
      perfHud = mod.mountPerfHud({ bench });
    }).catch((error: unknown) => { console.warn("frame meter failed to load", error); });
  };
  if (typeof requestIdleCallback === "function") requestIdleCallback(load, { timeout: 2000 });
  else window.setTimeout(load, 1200);
}

void start();

async function start(): Promise<void> {
  // First, so its capture listeners run before any shortcut handler registered later (#427).
  installInputSource();
  installFocusRing();
  installAutoScrollbars();
  installForegroundListener();
  // The chosen font applies to the whole app, sign-in card included, before the first paint.
  // The default is already declared in CSS and preloaded; another font is fetched here.
  const font = initialFont();
  applyFontVars(font, document.documentElement);
  // The remembered UI size (#283) applies before the first paint too; 100 % (the default) changes nothing.
  applyStoredUiSize();
  const fontsReady = Promise.race([
    loadFont(font),
    new Promise<void>((resolve) => window.setTimeout(resolve, 800)),
  ]).catch(() => undefined);
  if (deviceApprovalLink && "error" in deviceApprovalLink) {
    await fontsReady;
    installTooltips();
    await showDeviceApproval(deviceApprovalLink.kind, undefined, deviceApprovalLink.error);
    return;
  }
  try {
    const [status] = await Promise.all([
      checkStatus(),
      fontsReady,
    ]);
    installTooltips();
    await showAuthState(status);
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

async function showAuthState(status: AuthStatus): Promise<void> {
  if (deviceApprovalComplete) {
    await showDeviceApprovalSuccess();
    return;
  }
  if (deviceApprovalLink && "code" in deviceApprovalLink) {
    const { code, kind } = deviceApprovalLink;
    if (!isDeviceUserCode(code)) {
      await showDeviceApproval(kind, code);
      return;
    }
    const session = status.setupRequired ? undefined : await checkSession();
    if (session) {
      activeUserId = session.user_id;
      await showDeviceApproval(kind, code);
    } else {
      renderAuth(status.setupRequired, "", status.setupTokenCommand);
    }
    return;
  }
  const session = status.setupRequired ? undefined : await checkSession();
  if (session) {
    activeUserId = session.user_id;
    await showTerminal(session);
  } else {
    renderAuth(status.setupRequired, "", status.setupTokenCommand);
  }
}

function sessionHostname(session: DrawingIdentity | undefined): string | undefined {
  if (!session) return undefined;
  const hostname = session.hostname;
  return typeof hostname === "string" && hostname.trim() ? hostname.trim() : undefined;
}

function installForegroundListener(): void {
  if (foregroundListenerInstalled) return;
  foregroundListenerInstalled = true;
  window.addEventListener("online", () => { void checkForegroundSession(); });
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
const previewProto = (): boolean => { if (!__CLUSTERS_PREVIEW__) return false; const q = new URLSearchParams(location.search); return q.get("mock") === "1" && !!q.get("proto"); };
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
    <h1 id="unavailable-title">Connect to load your layout</h1>
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

function renderAuth(
  setupRequired: boolean,
  message = "",
  setupTokenCommand = "infraternal server setup-token",
): void {
  authLight();
  document.documentElement.removeAttribute("data-ui-font");
  mountOnboarding(app, setupRequired, message, (userId, firstSetup, welcomeName, instant) => {
    recordSignIn(userId);
    peerSessions.forget(userId);
    activeUserId = userId;
    if (deviceApprovalLink && "code" in deviceApprovalLink) {
      void showDeviceApproval(deviceApprovalLink.kind, deviceApprovalLink.code);
      return;
    }
    if (firstSetup) showWelcome(welcomeName ?? "", instant);
    else void showTerminal(undefined, instant);
  }, setupTokenCommand);
  scheduleBackdrop();
}

/** Shows the request and requires a separate, user-initiated fresh passkey tap to approve it. */
async function showDeviceApproval(kind: ApprovalKind, code?: string, error?: string): Promise<void> {
  authLight();
  document.documentElement.removeAttribute("data-ui-font");
  try {
    const { mountDeviceApproval } = await onDemand(() => import("./device-approval.on-demand"));
    await mountDeviceApproval(app, kind, code ?? null, error, {
      onApproved: () => { deviceApprovalComplete = true; },
      // Leaving a pending request is not a decision: it stays unapproved until it expires, and the person lands in the app.
      onCancel: () => {
        deviceApprovalLink = undefined;
        void showTerminal(undefined, true);
      },
    });
  } catch {
    renderUnavailable("Could not load device sign-in. Check your connection and reopen the link.");
    return;
  }
  scheduleBackdrop();
}

async function showDeviceApprovalSuccess(): Promise<void> {
  authLight();
  document.documentElement.removeAttribute("data-ui-font");
  try {
    const { mountDeviceApprovalSuccess } = await onDemand(() => import("./device-approval.on-demand"));
    mountDeviceApprovalSuccess(app);
  } catch {
    renderUnavailable("The device was approved. Return to the terminal to finish sign-in.");
    return;
  }
  scheduleBackdrop();
}

/**
 * Synchronously removes every approval code (query or fragment) from the address bar before `start` can issue any
 * request. A link that cannot be cleared is refused: a code left in the bar would sit in history and screenshots.
 */
function consumeDeviceApprovalLink(): ApprovalLink {
  const { link, cleaned } = readApprovalLink(location);
  if (cleaned === undefined) return link;
  try {
    history.replaceState(history.state, "", cleaned);
  } catch {
    return { error: "This link could not be cleared from the address bar. Close this page and open the link again.", kind: link?.kind ?? "sign_in" };
  }
  return link;
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

async function showTerminal(knownSession?: DrawingIdentity, instant = false): Promise<void> {
  // Startup already authenticated this snapshot. Reuse it rather than adding
  // another network round trip; the socket still checks authority on connection.
  const generation = ++sessionGeneration;
  sessionStarted = performance.timeOrigin + performance.now();
  const identity = knownSession ?? await checkSession();
  if (generation !== sessionGeneration) return;
  const hostName = sessionHostname(identity);
  if (!hostName) {
    renderUnavailable("Could not read this server's name. Try again.");
    return;
  }
  warmOfflineShell();
  window.clearTimeout(welcomeTimer);
  welcomeEffect?.destroy();
  welcomeEffect = undefined;
  stopBackdrop(instant);
  // The app paints its own theme; the sign-in scheme lets go once the backdrop has faded out.
  window.setTimeout(() => { if (!app.querySelector(".auth-screen")) releaseAuthScheme(); }, instant ? 0 : 260);
  currentTerminal?.dispose();
  canvasPrototype?.dispose();
  canvasPrototype = undefined;
  productCanvas?.dispose();
  productCanvas = undefined;
  coreScreen?.dispose();
  performanceProbe?.dispose();
  perfHudGeneration++;
  perfHud?.dispose();
  perfHud = undefined;
  currentTerminal = undefined;
  coreScreen = undefined;
  performanceProbe = undefined;
  const query = new URLSearchParams(location.search);
  const mockMode = query.get("mock") === "1";
  // One combined preview (D160): `?proto=windows` is the canvas, and the add-host flow opens
  // on it. `?proto=addhost` is an alias that opens the same preview with the wizard open.
  const proto = query.get("proto");
  // Browser regressions can exercise the real product canvas over the test-double PTY.
  const productTestMode = __CLUSTERS_PREVIEW__ && mockMode && proto === "product";
  const canvasMode = __CLUSTERS_PREVIEW__ && mockMode && (proto === "windows" || proto === "addhost");
  // Concept mockup for views on one canvas (#89): it brings its own windows and no live terminal.
  const clustersMode = __CLUSTERS_PREVIEW__ && mockMode && proto === "clusters";
  const probeMode = query.get("probe") === "1";
  const predictiveEcho = query.get("predict") === "1";
  const reviewLayout = productTestMode && query.get("reviewLayout") === "1";
  // The canvas is the product screen. The test double's plain page and the latency probe keep the single
  // terminal screen: the terminal specs and the probe drive that one terminal.
  const useCanvas = (!mockMode || productTestMode) && !probeMode;
  const scrollbackLimit = mockMode ? testScrollbackLimit(query.get("scrollback")) : undefined;
  let screen: import("./core-screen").CoreScreen | undefined;
  try {
    const { mountCoreScreen } = await import("./core-screen");
    // The screen mounts only after its selected face is ready, preventing a one-frame
    // fallback and keeping the mobile layout stable while the font loads.
    await (uiFont === "mono" ? loadFont(initialFont()) : document.fonts.load('450 14px "Geist Sans"'));
    if (generation !== sessionGeneration) return;
    // Auth keeps its existing monospace tooltips; this preference owns the core screen only.
    document.documentElement.dataset.uiFont = uiFont;
    screen = mountCoreScreen(app, { hostName, mockMode, probeMode,
      canvas: canvasMode || clustersMode || useCanvas,
      // The clusters canvas and the product canvas register their own "Add hosts" row with the wizard (canvas/addhost).
      addHostEntry: canvasMode,
      ...(clustersMode || useCanvas ? { settingsView: true } : {}),
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
  if ((clustersMode || canvasMode) && query.get("fps") !== "0") startPerfHud(query.get("fps") === "bench");
  if (clustersMode) {
    const { mountMockup } = await import("./canvas/mock");
    const scene = Number(query.get("scene"));
    const roleParam = query.get("role");
    let clusters: Awaited<ReturnType<typeof mountMockup>>;
    try {
      clusters = await mountMockup(screen, {
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
  if (useCanvas) {
    screen.setRecoveryPending(identity?.recovery_pending?.ready_at);
    try {
      const { mountProductCanvas } = await import("./canvas/product");
      const layoutReview = reviewLayout
        ? await import("./canvas/model/layout-review-double").then(({ createLayoutReviewDouble }) => createLayoutReviewDouble(
          activeUserId ?? "account", hostName, query.get("reviewSession") ?? "review-session", query.get("reviewWide") === "1",
        ))
        : undefined;
      if (generation !== sessionGeneration) return;
      const mounted = await mountProductCanvas(screen, {
        host: { name: hostName },
        accountId: activeUserId ?? "account",
        ...(identity && "session_incarnation" in identity && identity.session_incarnation ? { sessionIncarnation: identity.session_incarnation } : {}),
        predictiveEcho,
        isCurrent: () => generation === sessionGeneration,
        onSessionCheck: () => { void checkForegroundSession(); },
        onSessionRevoked: (work) => {
          if (generation !== sessionGeneration) return;
          // Receipt-confirmed edits are committed and come back on sign-in; never call them lost.
          endSession(work === "unsent"
            ? "Not saved. Changes waiting to save were lost. Sign in again to continue."
            : work === "unconfirmed"
              ? "Your sign-in changed. Your last changes may not have saved. Sign in again to check."
              : "Your sign-in changed. Sign in again to continue.");
        },
        ...(identity?.username ? { person: { name: identity.display_name ?? "", username: identity.username } } : {}),
        // Reload/reconnect regressions can select the real server store while retaining preview-only probes.
        ...(__CLUSTERS_PREVIEW__ && productTestMode && query.get("layout") !== "server" ? { previewStore: layoutReview?.store ?? new (await import("./canvas/model/store")).LocalCanvasStore(activeUserId ?? "account") } : {}),
        ...(productTestMode ? { onFirstClient: (client: TerminalClient) => {
          window.__tracerProductTestDouble = {
            isConnected: () => client.isConnected,
            dropConnection: () => client.forceDrop(),
            screenText: () => client.readScreenText(),
            terminalLinks: () => client.linksOnScreen(),
            rendererMetrics: () => client.rendererMetrics,
            currentView: () => (productCanvas as unknown as { canvas?: { cx?: { state?: { currentView?: string } } } } | undefined)
              ?.canvas?.cx?.state?.currentView ?? "",
          };
        } } : {}),
        onRecoveryPending: (readyAt) => { recoveryNoticeGeneration++; screen.setRecoveryPending(readyAt); },
        onRecoveryCompleted: (message) => { if (generation === sessionGeneration) endSession(message); },
      });
      if (generation !== sessionGeneration) { mounted.dispose(); return; }
      productCanvas = mounted;
      if (layoutReview) window.__tracerLayoutReviewDouble = {
        revisions: layoutReview.revision,
        currentView: () => (productCanvas as unknown as { canvas?: { cx?: { state?: { currentView?: string }; views?: Map<string, unknown> } } } | undefined)?.canvas?.cx?.state?.currentView ?? "",
        viewIds: () => [...((productCanvas as unknown as { canvas?: { cx?: { views?: Map<string, unknown> } } } | undefined)?.canvas?.cx?.views?.keys() ?? [])],
        removeConsole: layoutReview.removeConsole,
        skipRevision: layoutReview.skipRevision,
      };
    } catch (error: unknown) {
      if (generation !== sessionGeneration) return;
      console.error("canvas failed to start", error);
      screen.dispose();
      renderUnavailable(safeMessage(error));
    }
    return;
  }
  if (probeMode) performanceProbe = new PerformanceProbe(screen.probePanel, probeCount(query.get("n")));
  const probeHooks = performanceProbe?.hooks();
  // Session continuity across reloads (integration, #34): the tab remembers its
  // public session id so a reload reattaches to the same terminal.
  screen.setRecoveryPending(identity?.recovery_pending?.ready_at);
  const initialSessionId = query.get("session") ?? undefined;
  const hooks = {
    ...probeHooks,
    onSessionCreated: (sessionId: string): void => {
      // Public session ids are scoped to the authenticated owner, not input
      // writers. The server still authorizes every attachment [50]. No pending
      // keystrokes or bearer resume credentials enter tab storage or the URL.
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
      onRecoveryCompleted: (message) => { if (generation === sessionGeneration) endSession(message); },
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
        writeText: (text) => currentTerminal?.writeTextForTest(text) ?? Promise.resolve(),
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
        cursorLayerState: () => currentTerminal?.cursorLayerState,
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
  productCanvas?.dispose(); productCanvas = undefined;
  coreScreen?.dispose(); coreScreen = undefined;
  performanceProbe?.dispose(); performanceProbe = undefined;
  delete window.__tracerTestDouble;
  document.documentElement.removeAttribute("data-ui-font");
  mountRecovery(app, () => { void showTerminal(); }, (userId, _, displayName, instant) => {
    peerSessions.forget(userId);
    activeUserId = userId;
    recordSignIn(userId);
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
/** The product canvas: Console on real sessions (a lazy chunk, loaded after sign-in). */
let productCanvas: { dispose(): void } | undefined;

/**
 * Lets go of the signed-in app and shows the sign-in screen: the terminals' connections, the canvas (with its inbox
 * and overlays), the core screen, the frame meter and the test double's handle. Used when the server says the session
 * is gone and when the person signs out (sign-out.ts). Local preferences stay; sign-out
 * removes the account's stored data afterwards (sign-out.ts).
 */
let sessionGeneration = 0;
let sessionStarted = 0;
const peerSessions = sessionNotifications((account, before) => {
  if (activeUserId === account && sessionStarted <= before) endSession("Your session ended. Sign in again to reconnect.");
});
function endSession(message = ""): void {
  sessionGeneration++; forgetAccountWork(activeUserId);
  welcomeEffect?.destroy();
  welcomeEffect = undefined;
  window.clearTimeout(welcomeTimer);
  currentTerminal?.dispose();
  currentTerminal = undefined;
  canvasPrototype?.dispose();
  canvasPrototype = undefined;
  productCanvas?.dispose();
  productCanvas = undefined;
  performanceProbe?.dispose();
  performanceProbe = undefined;
  perfHudGeneration++;
  perfHud?.dispose();
  perfHud = undefined;
  coreScreen?.dispose();
  coreScreen = undefined;
  delete window.__tracerTestDouble;
  activeUserId = undefined;
  renderAuth(false, message);
}
registerSignOut(() => endSession(), () => activeUserId, (value) => { if (coreScreen) coreScreen.stage.inert = value; }, (account) => peerSessions.forget(account), () => sessionGeneration);

async function checkForegroundSession(): Promise<void> {
  if (checkingResume || !activeUserId) return;
  checkingResume = true;
  const noticeGeneration = recoveryNoticeGeneration, generation = sessionGeneration, account = activeUserId;
  try {
    const session = await checkSession();
    if (generation !== sessionGeneration || account !== activeUserId) return;
    // A delayed HTTP snapshot must not overwrite a newer WebSocket state event.
    if (session && noticeGeneration === recoveryNoticeGeneration) coreScreen?.setRecoveryPending(session.recovery_pending?.ready_at);
    if (!session && previewProto()) { location.reload(); return; }
    if (!session) endSession("Your session ended. Sign in again to reconnect.");
  } catch {
    // The session check is background housekeeping, not something the person asked for. When it
    // cannot complete (the server restarting, the link dropping, a proxy answering with a page)
    // nothing is said: the terminal's own reconnection shows state through the status icon, and
    // the next return to the tab checks again. Only a definite "no session" (401) changes the UI.
  } finally {
    checkingResume = false;
  }
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
