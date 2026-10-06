/** Renders the real setup wizard and discoverable passkey sign-in for the tracer. */
import { AuthError, loginWithPasskey, registerOwner } from "./auth";
import { copyFeedback, confirmAction, swapIcon, CLIPBOARD, DOWNLOAD } from "../../../packages/ui/src/copy-feedback";
import { loading, type Loading } from "../../../packages/ui/src/countup";
import { springCheckbox, tick } from "../../../packages/ui/src/tick";

const BRAND_MARK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M12 3v7M12 10 5 17M12 10l7 7"/><circle cx="12" cy="3" r="1.2" fill="currentColor"/><circle cx="5" cy="18" r="1.2" fill="currentColor"/><circle cx="19" cy="18" r="1.2" fill="currentColor"/></svg>`;
const KEY_MARK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M17 12v3M20 12v2"/></svg>`;
const SETUP_STEPS = [
  { title: "Make this server yours", lede: "Paste the one-time setup token. It is shown only on the server, so only you can claim it." },
  { title: "Who are you?", lede: "Your username labels your passkey and the audit log. Your display name is what the app shows." },
  { title: "Create your passkey", lede: "Face ID, Touch ID or a security key. No password, ever. Your SSH keys are sealed with it, so only your devices can open them." },
  { title: "Save your recovery key", lede: "If you ever lose your passkeys, these 24 words get you back in. Store them somewhere safe and offline." },
] as const;

interface SetupState {
  token: string;
  username: string;
  displayName: string;
  displayTouched: boolean;
  saved: boolean;
  busy: boolean;
  error: string;
  recoveryWords: string[];
  finishRegistration?: () => Promise<void>;
  completeRecovery?: () => void;
}

/** Mounts one auth flow and calls onAuthenticated after the server sets its cookie. */
export function mountOnboarding(
  host: HTMLElement,
  setupRequired: boolean,
  message: string,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string) => void,
): void {
  if (setupRequired) mountSetup(host, message, onAuthenticated);
  else mountSignIn(host, message, onAuthenticated);
}

function mountSetup(
  host: HTMLElement,
  message: string,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string) => void,
): void {
  const state: SetupState = {
    token: "", username: "", displayName: "", displayTouched: false,
    saved: false, busy: false, error: "", recoveryWords: [],
  };
  let index = 0;
  let completedStep = -1;
  host.innerHTML = `<section class="auth-screen" aria-label="Set up infraternal">
    <section class="auth-card" id="setup-card" aria-labelledby="setup-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <ol class="auth-steps" id="setup-steps" aria-label="Setup progress"></ol>
      <div class="auth-viewport" id="setup-viewport"></div>
      <div class="auth-footer" id="setup-footer"></div>
      <p class="auth-message" id="auth-error" role="alert"></p>
    </section>
  </section>`;
  const initialMessage = host.querySelector<HTMLElement>("#auth-error")!;
  initialMessage.textContent = message;

  function ready(): boolean {
    if (index === 0) return state.token.trim().length >= 8;
    if (index === 1) return validUsername(state.username) && [...state.displayName].length <= 64;
    if (index === 2) return true;
    return state.saved;
  }

  function renderSteps(): void {
    const steps = host.querySelector<HTMLOListElement>("#setup-steps")!;
    steps.innerHTML = SETUP_STEPS.map((_, i) => {
      const done = i < index;
      const active = i === index;
      return `<li class="${done ? "is-done" : active ? "is-current" : ""}">
        <button class="auth-dot" data-goto="${i}" data-tip="${done ? `Go back to step ${i + 1}` : `Step ${i + 1}`}" ${done && !state.busy ? "" : "disabled"} aria-label="Step ${i + 1}${done ? ", done" : ""}" ${active ? 'aria-current="step"' : ""}>${done ? `<span class="tick-host" data-completed="${i}"></span>` : `<span>${i + 1}</span>`}</button>
        ${i < SETUP_STEPS.length - 1 ? "<span class=\"auth-step-bar\"></span>" : ""}</li>`;
    }).join("");
    steps.querySelectorAll<HTMLElement>(".tick-host").forEach((element) => {
      const step = Number(element.dataset.completed);
      const check = tick(element, step !== completedStep);
      if (step === completedStep) requestAnimationFrame(() => check.set(true));
    });
    completedStep = -1;
    steps.querySelectorAll<HTMLButtonElement>("[data-goto]").forEach((button) => {
      button.addEventListener("click", () => moveTo(Number(button.dataset.goto)));
    });
  }

  function renderPane(direction: "forward" | "back" | "none"): void {
    const { title, lede } = SETUP_STEPS[index]!;
    const viewport = host.querySelector<HTMLElement>("#setup-viewport")!;
    const pane = document.createElement("div");
    pane.className = "auth-pane";
    pane.dataset.direction = direction;
    pane.innerHTML = `<p class="auth-eyebrow">step ${index + 1} of ${SETUP_STEPS.length}</p><h1 id="setup-title"></h1><p class="auth-lede"></p><div class="auth-pane-body" id="setup-body"></div>`;
    pane.querySelector<HTMLElement>("#setup-title")!.textContent = title;
    pane.querySelector<HTMLElement>(".auth-lede")!.textContent = lede;
    viewport.replaceChildren(pane);
    const body = pane.querySelector<HTMLElement>("#setup-body")!;
    if (index === 0) renderTokenStep(body);
    else if (index === 1) renderIdentityStep(body);
    else if (index === 2) renderPasskeyStep(body);
    else renderRecoveryStep(body);
  }

  function renderFooter(): void {
    const footer = host.querySelector<HTMLElement>("#setup-footer")!;
    const nextText = index === 2 ? "Create passkey" : index === 3 ? "Open infraternal" : "Continue";
    const busyLabel = state.busy && index === 2 ? "Creating passkey" : nextText;
    footer.innerHTML = `<button class="auth-back" id="setup-back" ${index === 0 || state.busy ? "hidden" : ""}>← back</button>
      <button class="auth-primary" id="setup-next" ${ready() && !state.busy ? "" : "disabled"}>${index === 2 ? KEY_MARK : ""}<span>${busyLabel}</span>${state.busy ? '<span class="busy-count" hidden aria-live="off"></span>' : ""}</button>`;
    footer.querySelector<HTMLButtonElement>("#setup-back")!.addEventListener("click", () => moveTo(index - 1));
    footer.querySelector<HTMLButtonElement>("#setup-next")!.addEventListener("click", () => {
      if (state.busy || !ready()) return;
      if (index === 0) moveTo(1);
      else if (index === 1) moveTo(2);
      else if (index === 2) void createPasskey();
      else void finishSetup();
    });
  }

  function updateReady(): void {
    const next = host.querySelector<HTMLButtonElement>("#setup-next");
    if (next) next.disabled = state.busy || !ready();
  }

  function moveTo(next: number): void {
    if (next < 0 || next >= SETUP_STEPS.length || next === index || next > index + 1) return;
    completedStep = index;
    const direction = next < index ? "back" : "forward";
    index = next;
    state.error = "";
    host.querySelector<HTMLElement>("#auth-error")!.textContent = "";
    renderSteps();
    renderPane(direction);
    renderFooter();
  }

  function renderTokenStep(body: HTMLElement): void {
    body.innerHTML = `<label class="auth-label" for="setup-token">setup token</label>
      <input id="setup-token" class="auth-input auth-mono" type="text" autocomplete="off" spellcheck="false" placeholder="paste token" />
      <div class="auth-command"><code>infraternal server setup-token</code><button class="icon-action" type="button" aria-label="Copy setup token command" data-copy-command>${swapIcon(CLIPBOARD)}</button></div>`;
    const token = body.querySelector<HTMLInputElement>("#setup-token")!;
    token.value = state.token;
    token.addEventListener("input", () => { state.token = token.value; updateReady(); });
    token.addEventListener("keydown", enterToContinue);
    wireCopy(body.querySelector<HTMLButtonElement>("[data-copy-command]")!, "infraternal server setup-token");
    token.focus({ preventScroll: true });
  }

  function renderIdentityStep(body: HTMLElement): void {
    body.innerHTML = `<label class="auth-label" for="setup-username">username</label>
      <input id="setup-username" class="auth-input auth-mono" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="32" placeholder="ada" />
      <p class="auth-hint" id="username-hint" aria-live="polite"></p>
      <label class="auth-label" for="setup-display-name">display name</label>
      <input id="setup-display-name" class="auth-input" type="text" autocomplete="name" maxlength="256" placeholder="Ada Lovelace" />`;
    const username = body.querySelector<HTMLInputElement>("#setup-username")!;
    const displayName = body.querySelector<HTMLInputElement>("#setup-display-name")!;
    const hint = body.querySelector<HTMLElement>("#username-hint")!;
    username.value = state.username;
    displayName.value = state.displayName;
    const refreshHint = () => {
      hint.textContent = state.username && !validUsername(state.username)
        ? "Use 2–32 lowercase letters, digits, _ or -."
        : state.displayName && [...state.displayName].length > 64
          ? "Display names can be at most 64 characters."
          : " ";
      updateReady();
    };
    username.addEventListener("input", () => {
      state.username = username.value.toLowerCase().replace(/\s+/g, "");
      username.value = state.username;
      if (!state.displayTouched) displayName.value = state.displayName = state.username;
      refreshHint();
    });
    displayName.addEventListener("input", () => {
      state.displayName = displayName.value;
      state.displayTouched = true;
      refreshHint();
    });
    username.addEventListener("keydown", enterToContinue);
    displayName.addEventListener("keydown", enterToContinue);
    refreshHint();
    username.focus({ preventScroll: true });
  }

  function renderPasskeyStep(body: HTMLElement): void {
    body.innerHTML = state.error ? '<p class="auth-error-line" id="passkey-error"></p>' : "";
    const error = body.querySelector<HTMLElement>("#passkey-error");
    if (error) error.textContent = state.error;
  }

  function renderRecoveryStep(body: HTMLElement): void {
    body.innerHTML = `<ol class="auth-words" id="recovery-words"></ol>
      <div class="auth-actions"><button class="icon-action" id="copy-recovery" type="button" aria-label="Copy recovery key">${swapIcon(CLIPBOARD)}</button>
        <button class="icon-action" id="download-recovery" type="button" aria-label="Download recovery key">${swapIcon(DOWNLOAD)}</button></div>
      <p class="auth-recovery-message" id="recovery-message" role="status"></p>
      <label class="auth-check"><input id="recovery-saved" type="checkbox" /><span>I stored them somewhere safe</span></label>`;
    const list = body.querySelector<HTMLOListElement>("#recovery-words")!;
    state.recoveryWords.forEach((word, i) => {
      const item = document.createElement("li");
      const number = document.createElement("span");
      number.className = "auth-word-number";
      number.textContent = String(i + 1);
      const value = document.createElement("span");
      value.textContent = word;
      item.append(number, value);
      list.append(item);
    });
    const serializedWords = state.recoveryWords.join(" ");
    body.querySelector<HTMLButtonElement>("#copy-recovery")!.addEventListener("click", async (event) => {
      const button = event.currentTarget as HTMLButtonElement;
      const copied = await copyFeedback(button, serializedWords);
      body.querySelector<HTMLElement>("#recovery-message")!.textContent = copied
        ? "Copied. Store the words somewhere private."
        : "Copy is unavailable here. Select and copy the words.";
      button.blur();
    });
    body.querySelector<HTMLButtonElement>("#download-recovery")!.addEventListener("click", (event) => {
      const button = event.currentTarget as HTMLButtonElement;
      confirmAction(button, "Downloaded");
      const contents = state.recoveryWords.map((word, i) => `${i + 1}. ${word}`).join("\n") + "\n";
      const url = URL.createObjectURL(new Blob([contents], { type: "text/plain;charset=utf-8" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "infraternal-recovery-key.txt";
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      button.blur();
    });
    const checkbox = body.querySelector<HTMLInputElement>("#recovery-saved")!;
    checkbox.checked = state.saved;
    springCheckbox(checkbox);
    checkbox.addEventListener("change", () => { state.saved = checkbox.checked; updateReady(); });
  }

  async function createPasskey(): Promise<void> {
    state.busy = true;
    state.error = "";
    renderPane("none");
    renderFooter();
    const count = host.querySelector<HTMLElement>("#setup-next .busy-count")!;
    const waiting = loading(count, 400);
    try {
      const displayName = state.displayName.trim() ? state.displayName : state.username;
      const userId = await registerOwner(state.token.trim(), state.username, displayName, async (words, finishRegistration) => {
        waiting.done();
        state.busy = false;
        state.recoveryWords = words.trim().split(/\s+/);
        state.saved = false;
        completedStep = 2;
        index = 3;
        state.finishRegistration = finishRegistration;
        renderSteps();
        renderPane("forward");
        renderFooter();
        await new Promise<void>((resolve) => { state.completeRecovery = resolve; });
      });
      onAuthenticated(userId, true, displayName);
    } catch (error: unknown) {
      waiting.done();
      state.busy = false;
      state.error = safeAuthMessage(error);
      host.querySelector<HTMLElement>("#auth-error")!.textContent = "";
      renderPane("none");
      renderFooter();
    }
  }

  async function finishSetup(): Promise<void> {
    if (!state.saved || state.busy || !state.finishRegistration) return;
    state.busy = true;
    renderFooter();
    const button = host.querySelector<HTMLButtonElement>("#setup-next")!;
    const waiting = loading(button.querySelector<HTMLElement>(".busy-count")!, 400);
    try {
      await state.finishRegistration();
      waiting.done();
      state.completeRecovery?.();
    } catch (error: unknown) {
      waiting.done();
      state.busy = false;
      host.querySelector<HTMLElement>("#auth-error")!.textContent = safeAuthMessage(error);
      renderFooter();
    }
  }

  function wireCopy(button: HTMLButtonElement, text: string): void {
    button.addEventListener("click", async () => {
      const copied = await copyFeedback(button, text);
      if (!copied) host.querySelector<HTMLElement>("#auth-error")!.textContent = "Copy is unavailable here.";
      button.blur();
    });
  }

  function enterToContinue(event: KeyboardEvent): void {
    if (event.key !== "Enter") return;
    const next = host.querySelector<HTMLButtonElement>("#setup-next");
    if (next && !next.disabled) { event.preventDefault(); next.click(); }
  }

  renderSteps();
  renderPane("none");
  reserveViewport();
  renderFooter();

  function reserveViewport(): void {
    const viewport = host.querySelector<HTMLElement>("#setup-viewport")!;
    const probe = document.createElement("div");
    probe.className = "auth-pane auth-measure";
    // Measure the 320 px phone content width even when enrollment begins on desktop;
    // wider viewports render the same words in fewer rows and cannot clip the pane.
    probe.style.width = `${Math.min(viewport.clientWidth - 12, 234)}px`;
    // A changing card height moves every edge in Layout Instability even when its
    // center is anchored. Recovery is the tallest pane (24 words in two phone
    // columns), so measure that one template once before first paint and reuse it.
    const recovery = SETUP_STEPS[3]!;
    probe.innerHTML = `<p class="auth-eyebrow">step 4 of ${SETUP_STEPS.length}</p><h1>${recovery.title}</h1><p class="auth-lede">${recovery.lede}</p><div class="auth-pane-body">
      <ol class="auth-words">${Array.from({ length: 24 }, (_, i) => `<li><span class="auth-word-number">${i + 1}</span><span>institution</span></li>`).join("")}</ol>
      <div class="auth-actions"><button class="icon-action">${swapIcon(CLIPBOARD)}</button><button class="icon-action">${swapIcon(DOWNLOAD)}</button></div>
      <p class="auth-recovery-message">Copied. Store the words somewhere private.</p>
      <label class="auth-check"><span class="tick"></span><span>I stored them somewhere safe</span></label></div>`;
    viewport.append(probe);
    const height = Math.ceil(probe.getBoundingClientRect().height);
    viewport.removeChild(probe);
    viewport.style.height = `${height}px`;
  }
}

function mountSignIn(
  host: HTMLElement,
  message: string,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string) => void,
): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Sign in">
    <section class="auth-card auth-signin" aria-labelledby="signin-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="signin-title">Welcome back</h1>
      <p class="auth-lede">Your passkey is all you need.</p>
      <button class="auth-primary auth-login" id="login-passkey" type="button">${KEY_MARK}<span>Continue with passkey</span></button>
      <div class="auth-signin-secondary"><button class="auth-text-button" id="login-other" type="button">use a different passkey…</button></div>
      <p class="auth-loading" id="login-loading" role="status" aria-live="polite"><span class="busy-count" hidden></span></p>
      <p class="auth-message" id="auth-error" role="alert"></p>
    </section>
  </section>`;
  host.querySelector<HTMLElement>("#auth-error")!.textContent = message;
  const buttons = [host.querySelector<HTMLButtonElement>("#login-passkey")!, host.querySelector<HTMLButtonElement>("#login-other")!];
  for (const button of buttons) button.addEventListener("click", () => { void beginLogin(buttons, host, onAuthenticated); });
}

async function beginLogin(
  buttons: HTMLButtonElement[],
  host: HTMLElement,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string) => void,
): Promise<void> {
  if (buttons[0]!.disabled) return;
  buttons.forEach((button) => { button.disabled = true; });
  host.querySelector<HTMLElement>("#auth-error")!.textContent = "";
  const counter = host.querySelector<HTMLElement>("#login-loading .busy-count")!;
  const waiting: Loading = loading(counter, 400);
  try {
    const userId = await loginWithPasskey(deviceName());
    waiting.done();
    onAuthenticated(userId, false);
  } catch (error: unknown) {
    waiting.done();
    buttons.forEach((button) => { button.disabled = false; });
    host.querySelector<HTMLElement>("#auth-error")!.textContent = safeAuthMessage(error);
  }
}

function validUsername(value: string): boolean {
  return /^[a-z0-9_-]{2,32}$/.test(value);
}

function safeAuthMessage(error: unknown): string {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "The passkey prompt was cancelled or timed out. Try again when you are ready.";
  }
  return error instanceof AuthError ? error.message : "The request could not be completed. Try again.";
}

function deviceName(): string {
  try { return localStorage.getItem("tracer.device-name") || `${navigator.platform || "Browser"} device`; }
  catch { return "Browser device"; }
}
