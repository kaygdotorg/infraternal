/** Renders first-run and login screens, then hands an authenticated user to the terminal. */
import { AuthError, checkSession, loginWithPasskey, registerOwner } from "./auth";
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
    const session = await checkSession();
    if (session) {
      activeUserId = session.user_id;
      showTerminal();
    } else {
      renderAccess(new URLSearchParams(location.search).get("setup") === "1");
    }
  } catch (error: unknown) {
    renderAccess(false, safeMessage(error));
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

function renderAccess(showSetup: boolean, message = ""): void {
  app.replaceChildren();
  app.innerHTML = `
    <section class="access" aria-label="Sign in">
      <h1>infraternal</h1>
      <p class="lead">Open your terminal.</p>
      <form id="login-form" autocomplete="on">
        <label for="account-id">Account ID</label>
        <input id="account-id" name="username" autocomplete="username webauthn" autocapitalize="off" spellcheck="false" required />
        <label for="device-name">This device</label>
        <input id="device-name" name="device" autocomplete="nickname" maxlength="128" required />
        <button class="primary" type="submit">Continue with passkey</button>
      </form>
      <button id="show-setup" class="quiet" type="button">Set up the first owner</button>
      <form id="setup-form" autocomplete="off" hidden>
        <label for="setup-token">One-time setup token</label>
        <input id="setup-token" name="token" type="password" autocomplete="off" required />
        <label for="owner-name">Your name</label>
        <input id="owner-name" name="name" autocomplete="name" maxlength="128" required />
        <button class="primary" type="submit">Register a passkey</button>
        <button id="back-to-login" class="quiet" type="button">Back to sign in</button>
      </form>
      <p id="auth-error" class="message" role="status" aria-live="polite"></p>
    </section>`;

  const loginForm = mustGet<HTMLFormElement>("#login-form");
  const setupForm = mustGet<HTMLFormElement>("#setup-form");
  const error = mustGet<HTMLElement>("#auth-error");
  const savedUser = readLocal("tracer.user-id");
  mustGet<HTMLInputElement>("#account-id").value = savedUser ?? "";
  mustGet<HTMLInputElement>("#device-name").value = deviceName();
  loginForm.hidden = showSetup;
  mustGet("#show-setup").hidden = showSetup;
  setupForm.hidden = !showSetup;
  error.textContent = message;

  mustGet("#show-setup").addEventListener("click", () => renderAccess(true));
  mustGet("#back-to-login").addEventListener("click", () => renderAccess(false));
  loginForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitLogin(loginForm, error);
  });
  setupForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitSetup(setupForm, error);
  });
}

async function submitLogin(form: HTMLFormElement, error: HTMLElement): Promise<void> {
  const data = new FormData(form);
  setDisabled(form, true);
  error.textContent = "Touch your passkey to continue…";
  try {
    const userId = await loginWithPasskey(String(data.get("username") ?? ""), String(data.get("device") ?? ""));
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
      <div class="account-copy"><span>Account ID</span><code id="account-id-value"></code><button id="copy-account-id" class="quiet" type="button">Copy ID</button></div>
      <pre id="recovery-words" class="recovery-words"></pre>
      <button id="copy-recovery" class="quiet" type="button">Copy recovery key</button>
      <label class="check-row"><input id="recovery-saved" type="checkbox" /> I saved these words somewhere safe</label>
      <button id="finish-recovery" class="primary" type="button" disabled>Finish setup</button>
      <p id="recovery-message" class="message" role="status"></p>
    </section>`;
  mustGet<HTMLElement>("#account-id-value").textContent = userId;
  mustGet<HTMLElement>("#recovery-words").textContent = words;
  const saved = mustGet<HTMLInputElement>("#recovery-saved");
  const finish = mustGet<HTMLButtonElement>("#finish-recovery");
  saved.addEventListener("change", () => { finish.disabled = !saved.checked; });
  mustGet("#copy-account-id").addEventListener("click", () => {
    void navigator.clipboard?.writeText(userId).then(() => {
      mustGet<HTMLElement>("#recovery-message").textContent = "Account ID copied.";
    }).catch(() => {
      mustGet<HTMLElement>("#recovery-message").textContent = "Copy is unavailable here. Select and copy the account ID.";
    });
  });
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

function readLocal(key: string): string | undefined {
  try { return localStorage.getItem(key) ?? undefined; } catch { return undefined; }
}

function saveLocal(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* account id is a convenience, not a secret */ }
}

function setDisabled(form: HTMLFormElement, disabled: boolean): void {
  form.querySelectorAll<HTMLButtonElement | HTMLInputElement>("button, input").forEach((item) => { item.disabled = disabled; });
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function mustGet<ElementType extends HTMLElement = HTMLElement>(selector: string): ElementType {
  const element = document.querySelector<ElementType>(selector);
  if (!element) throw new Error(`Required tracer element is missing: ${selector}`);
  return element;
}

function missingMount(): never {
  throw new Error("tracer mount point is missing");
}
