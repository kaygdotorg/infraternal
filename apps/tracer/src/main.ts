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
      screenText: () => string;
      rendererMetrics: () => {
        cols: number;
        rows: number;
        cellWidth: number;
        cellHeight: number;
        configuredScrollback: number;
        outputSequence: string;
        scrollbackRows: number;
        wasmMemoryBytes: number;
      } | undefined;
      trace: () => ProbeTraceSample[];
    };
  }
}

const app = document.querySelector<HTMLElement>("#app") ?? missingMount();

let activeUserId: string | undefined;
let checkingResume = false;
let currentTerminal: TerminalClient | undefined;
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
    showTerminal();
  } else {
    renderAuth(setupRequired);
  }
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
  app.innerHTML = `<section class="auth-screen"><section class="auth-card auth-signin">
    <div class="auth-mark">infraternal</div><h1>Could not reach the server</h1>
    <p id="status-error" class="auth-message" role="alert"></p>
    <button id="retry-status" class="auth-primary" type="button">Try again</button></section></section>`;
  mustGet<HTMLElement>("#status-error").textContent = message;
  mustGet<HTMLButtonElement>("#retry-status").addEventListener("click", () => { void refreshAuth(); }, { once: true });
  scheduleBackdrop();
}

function renderAuth(setupRequired: boolean, message = ""): void {
  mountOnboarding(app, setupRequired, message, (userId, firstSetup, welcomeName) => {
    saveLocal("tracer.user-id", userId);
    activeUserId = userId;
    if (firstSetup) showWelcome(welcomeName ?? "");
    else showTerminal();
  });
  scheduleBackdrop();
}

function showWelcome(displayName: string): void {
  window.clearTimeout(welcomeTimer);
  welcomeEffect?.destroy();
  app.innerHTML = `<section class="auth-screen auth-welcome" aria-live="polite"><div class="welcome-copy"><h1 id="welcome-title"></h1><p></p></div></section>`;
  mustGet<HTMLElement>(".welcome-copy p").textContent = `signed in as ${displayName}`;
  welcomeEffect = glitchText(mustGet<HTMLElement>("#welcome-title"), "Welcome to infraternal", { speed: 0.5, settleAfter: 1600 });
  welcomeTimer = window.setTimeout(() => {
    welcomeEffect?.destroy();
    welcomeEffect = undefined;
    showTerminal();
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
  canvas.dataset.ready = "true";
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

function stopBackdrop(): void {
  window.clearTimeout(backdropTimer);
  backdropTimer = 0;
  const canvas = document.querySelector<HTMLCanvasElement>("#faulty-field");
  if (!canvas) return;
  canvas.style.transition = "opacity 400ms ease";
  canvas.style.opacity = "0";
  const stopped = backdrop;
  backdrop = undefined;
  window.setTimeout(() => {
    stopped?.destroy();
    if (canvas === document.querySelector("#faulty-field")) canvas.remove();
  }, 450);
}

function showTerminal(): void {
  window.clearTimeout(welcomeTimer);
  welcomeEffect?.destroy();
  welcomeEffect = undefined;
  stopBackdrop();
  currentTerminal?.dispose();
  performanceProbe?.dispose();
  currentTerminal = undefined;
  performanceProbe = undefined;
  const query = new URLSearchParams(location.search);
  const mockMode = query.get("mock") === "1";
  const probeMode = query.get("probe") === "1";
  const scrollbackLimit = mockMode ? testScrollbackLimit(query.get("scrollback")) : undefined;
  app.innerHTML = `
    <section class="terminal-screen" aria-label="Terminal">
      <div class="terminal-host" id="terminal-host" role="application" aria-label="Remote terminal"></div>
      <p id="connection-status" class="connection-status" role="status">Starting terminal…</p>
      <span id="test-double-badge" class="test-double-badge" hidden>TEST DOUBLE</span>
      <aside id="probe-panel" class="probe-panel" aria-label="Terminal latency probe" hidden>
        <h2>Latency probe</h2>
        <label for="probe-count">Synthetic keys</label>
        <input id="probe-count" type="number" min="1" max="5000" inputmode="numeric" />
        <div class="probe-actions">
          <button id="probe-run" type="button">Run probe</button>
          <button id="probe-drop" type="button">Drop socket</button>
          <button id="probe-copy" type="button">Copy results</button>
        </div>
        <pre id="probe-results" aria-live="polite">Waiting for terminal.</pre>
        <p id="probe-message" role="status"></p>
      </aside>
    </section>`;
  mustGet<HTMLElement>("#test-double-badge").hidden = !mockMode;
  const probePanel = mustGet<HTMLElement>("#probe-panel");
  probePanel.hidden = !probeMode;
  if (probeMode) performanceProbe = new PerformanceProbe(probePanel, probeCount(query.get("n")));
  const hooks = performanceProbe?.hooks();
  void import("./terminal").then(({ TerminalClient }) => TerminalClient.open({
    host: mustGet<HTMLElement>("#terminal-host"),
    status: mustGet<HTMLElement>("#connection-status"),
    traceMockServer: probeMode && mockMode,
    ...(scrollbackLimit === undefined ? {} : { scrollbackLimit }),
    ...(hooks ? { hooks } : {}),
  })).then((client) => {
    currentTerminal = client;
    performanceProbe?.bind(client);
    if (mockMode) {
      window.__tracerTestDouble = {
        isConnected: () => currentTerminal?.isConnected === true,
        screenText: () => currentTerminal?.readScreenText() ?? "",
        rendererMetrics: () => currentTerminal?.rendererMetrics,
        trace: () => performanceProbe?.traceSamples() ?? [],
      };
    }
  }).catch((error: unknown) => {
    const status = document.querySelector<HTMLElement>("#connection-status");
    if (status) status.textContent = safeMessage(error);
  });
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

function saveLocal(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* account id is a convenience, not a secret */ }
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
