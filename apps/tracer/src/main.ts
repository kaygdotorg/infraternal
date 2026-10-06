/** Renders first-run and login screens, then hands an authenticated user to the terminal. */
import { AuthError, checkStatus, checkSession, loginWithPasskey, registerOwner } from "./auth";
import { PerformanceProbe, type ProbeTraceSample } from "./perf-probe";
// The terminal (ghostty-web with its WASM, ~640 KB) loads only after sign-in, so the
// sign-in screen paints at once. A static import made every visitor wait for it.
import type { TerminalClient } from "./terminal";

declare global {
  interface Window {
    __tracerTestDouble?: {
      isConnected: () => boolean;
      screenText: () => string;
      trace: () => ProbeTraceSample[];
    };
  }
}

const app = document.querySelector<HTMLElement>("#app") ?? missingMount();

let activeUserId: string | undefined;
let checkingResume = false;
let currentTerminal: TerminalClient | undefined;
let performanceProbe: PerformanceProbe | undefined;

void start();

async function start(): Promise<void> {
  try {
    const setupRequired = await checkStatus();
    const session = setupRequired ? undefined : await checkSession();
    if (session) {
      activeUserId = session.user_id;
      showTerminal();
    } else {
      renderAccess(setupRequired);
    }
  } catch (error: unknown) {
    renderUnavailable(safeMessage(error));
  }
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
  app.innerHTML = '<section class="access"><h1>infraternal</h1><p id="status-error" role="alert"></p><button id="retry-status" class="primary" type="button">Try again</button></section>';
  mustGet("#status-error").textContent = message;
  mustGet("#retry-status").addEventListener("click", () => { void start(); }, { once: true });
}

function renderAccess(showSetup: boolean, message = ""): void {
  app.replaceChildren();
  app.innerHTML = `
    <section class="access" aria-label="Sign in">
      <h1>infraternal</h1>
      <p class="lead">Open your terminal.</p>
      ${showSetup ? `
      <form id="setup-form" autocomplete="off">
        <label for="setup-token">One-time setup token</label>
        <input id="setup-token" name="token" type="password" autocomplete="off" required />
        <label for="owner-name">Your name</label>
        <input id="owner-name" name="name" autocomplete="name" maxlength="128" required />
        <button class="primary" type="submit">Register a passkey</button>
      </form>` : `
      <form id="login-form">
        <button class="primary" type="submit">Continue with passkey</button>
      </form>`}
      <p id="auth-error" class="message" role="status" aria-live="polite"></p>
    </section>`;

  const error = mustGet<HTMLElement>("#auth-error");
  error.textContent = message;
  const form = mustGet<HTMLFormElement>(showSetup ? "#setup-form" : "#login-form");
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void (showSetup ? submitSetup(form, error) : submitLogin(form, error));
  });
}

async function submitLogin(form: HTMLFormElement, error: HTMLElement): Promise<void> {
  setDisabled(form, true);
  error.textContent = "Touch your passkey to continue…";
  try {
    const userId = await loginWithPasskey(deviceName());
    saveLocal("tracer.user-id", userId);
    activeUserId = userId;
    showTerminal();
  } catch (cause: unknown) {
    setDisabled(form, false);
    error.textContent = safeMessage(cause);
  }
}

async function submitSetup(form: HTMLFormElement, error: HTMLElement): Promise<void> {
  const data = new FormData(form);
  setDisabled(form, true);
  error.textContent = "Preparing your passkey…";
  try {
    const userId = await registerOwner(
      String(data.get("token") ?? ""),
      String(data.get("name") ?? ""),
      showRecoveryWords,
    );
    saveLocal("tracer.user-id", userId);
    activeUserId = userId;
    showTerminal();
  } catch (cause: unknown) {
    renderAccess(true, safeMessage(cause));
  }
}

function showRecoveryWords(words: string, userId: string): Promise<void> {
  app.innerHTML = `
    <section class="access recovery" aria-label="Recovery key">
      <h1>Save your recovery key</h1>
      <p class="lead">These 24 words are shown once. Keep them somewhere private and offline.</p>

      <pre id="recovery-words" class="recovery-words"></pre>
      <button id="copy-recovery" class="quiet" type="button">Copy recovery key</button>
      <label class="check-row"><input id="recovery-saved" type="checkbox" /> I saved these words somewhere safe</label>
      <button id="finish-recovery" class="primary" type="button" disabled>Finish setup</button>
      <p id="recovery-message" class="message" role="status"></p>
    </section>`;
  mustGet<HTMLElement>("#recovery-words").textContent = words;
  const saved = mustGet<HTMLInputElement>("#recovery-saved");
  const finish = mustGet<HTMLButtonElement>("#finish-recovery");
  saved.addEventListener("change", () => { finish.disabled = !saved.checked; });

  mustGet("#copy-recovery").addEventListener("click", () => {
    void navigator.clipboard?.writeText(words).then(() => {
      mustGet<HTMLElement>("#recovery-message").textContent = "Copied. Store the words somewhere private.";
    }).catch(() => {
      mustGet<HTMLElement>("#recovery-message").textContent = "Copy is unavailable here. Select and copy the words.";
    });
  });
  return new Promise((resolve) => finish.addEventListener("click", () => resolve(), { once: true }));
}

function showTerminal(): void {
  currentTerminal?.dispose();
  performanceProbe?.dispose();
  currentTerminal = undefined;
  performanceProbe = undefined;
  const query = new URLSearchParams(location.search);
  const mockMode = query.get("mock") === "1";
  const probeMode = query.get("probe") === "1";
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
  mustGet("#test-double-badge").hidden = !mockMode;
  const probePanel = mustGet("#probe-panel");
  probePanel.hidden = !probeMode;
  if (probeMode) {
    performanceProbe = new PerformanceProbe(probePanel, probeCount(query.get("n")));
  }
  const hooks = performanceProbe?.hooks();
  void import("./terminal").then(({ TerminalClient }) => TerminalClient.open({
    host: mustGet("#terminal-host"),
    status: mustGet("#connection-status"),
    traceMockServer: probeMode && mockMode,
    ...(hooks ? { hooks } : {}),
  })).then((client) => {
    currentTerminal = client;
    performanceProbe?.bind(client);
    if (mockMode) {
      window.__tracerTestDouble = {
        isConnected: () => currentTerminal?.isConnected === true,
        screenText: () => currentTerminal?.readScreenText() ?? "",
        trace: () => performanceProbe?.traceSamples() ?? [],
      };
    }
  }).catch((error: unknown) => {
    const status = document.querySelector<HTMLElement>("#connection-status");
    if (status) status.textContent = safeMessage(error);
  });
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
      renderAccess(false, "Your session ended. Sign in again to reconnect.");
    }
  } catch (error: unknown) {
    const status = document.querySelector<HTMLElement>("#connection-status");
    if (status) status.textContent = safeMessage(error);
  } finally {
    checkingResume = false;
  }
}

function deviceName(): string {
  try {
    return localStorage.getItem("tracer.device-name") || `${navigator.platform || "Browser"} device`;
  } catch {
    return "Browser device";
  }
}

function saveLocal(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* account id is a convenience, not a secret */ }
}

function setDisabled(form: HTMLFormElement, disabled: boolean): void {
  form.querySelectorAll<HTMLButtonElement | HTMLInputElement>("button, input").forEach((item) => { item.disabled = disabled; });
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
