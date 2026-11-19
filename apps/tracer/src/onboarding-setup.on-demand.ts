/**
 * The first-run setup wizard (token, name, passkey, recovery key). It is shown once per server, so it loads on demand:
 * the sign-in card that every later visit needs stays in the first-screen chunk (D188, #247).
 */
import { recoveryWords } from "./recovery-words";
import { swapCard } from "./auth-motion";
import { AuthError, checkSetupToken, registerOwner } from "./auth";
import { safeAuthMessage, deviceName, validUsername } from "./onboarding";
import { copyFeedback, swapIcon, CLIPBOARD } from "../../../packages/ui/src/copy-feedback";
import { loading, type Loading } from "../../../packages/ui/src/countup";
import { tick } from "../../../packages/ui/src/tick";
import { BRAND_MARK, KEY_MARK } from "./auth-marks";

/** The longest display name, in characters: the input's maxlength, the validation and the hint all read this. */
const DISPLAY_NAME_MAX = 64;
/** Shown under the username field from the start, so the rule is known before the first wrong key. */
const USERNAME_RULE = "Use 2–32 lowercase letters, digits, _ or -.";

/** The four setup steps with their title and the sentence under it, in order. */
const SETUP_STEPS = [
  { title: "Make this server yours", lede: "Paste the one-time setup token. It is shown only on the server, so only you can claim it." },
  { title: "Who are you?", lede: "Your username labels your passkey and the audit log. Your display name is what the app shows." },
  { title: "Create your passkey", lede: "Face ID, Touch ID or a security key. No password, ever. Your SSH keys are sealed with it, so only your devices can open them." },
  { title: "Save your recovery key", lede: "If you ever lose your passkeys, these 24 words get you back in. Store them somewhere safe and offline." },
] as const;

/** Everything the wizard knows while it runs; values the user typed, progress, and the pending registration callbacks. */
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
  /** Carries the final button's activation source across the awaited recovery callback. */
  instantCompletion?: boolean;
}

/**
 * Draws the first-run setup wizard in `host`: paste the setup token, choose a name, create a passkey, save the recovery key.
 * Called through {@link loadSetup}, which fetches this module only when a server needs setup.
 * @param message text for the card's message line
 * @param setupTokenCommand the command that prints the token on the server
 * @param onAuthenticated called when the owner account exists and the browser is signed in; `firstSetup` is then true
 */
export function mountSetup(
  host: HTMLElement,
  message: string,
  setupTokenCommand: string,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string, instant?: boolean) => void,
): void {
  const state: SetupState = {
    token: "", username: "", displayName: "", displayTouched: false,
    saved: false, busy: false, error: "", recoveryWords: [],
  };
  let index = 0;
  let completedStep = -1;
  const events = new AbortController();
  host.innerHTML = `<section class="auth-screen" aria-label="Set up infraternal">
    <section class="auth-card ui-overlay-surface" id="setup-card" aria-labelledby="setup-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <ol class="auth-steps" id="setup-steps" aria-label="Setup progress"></ol>
      <div class="auth-viewport" id="setup-viewport"></div>
      <div class="auth-footer" id="setup-footer"></div>
      <div class="auth-note"><div><p class="auth-message" id="auth-error" role="alert"></p></div></div>
    </section>
  </section>`;
  const initialMessage = host.querySelector<HTMLElement>("#auth-error")!;
  initialMessage.textContent = message;

  let focusingProgrammatically = false;
  const focusInput = (input: HTMLInputElement): void => {
    // Autofocus follows the step's activation source instead of browser focus heuristics.
    focusingProgrammatically = true;
    input.focus({ preventScroll: true });
    focusingProgrammatically = false;
  };
  const markMotion = (instant: boolean): void => {
    host.querySelector<HTMLElement>("#setup-card")!.toggleAttribute("data-no-motion", instant);
  };
  host.addEventListener("pointerdown", () => markMotion(false), { capture: true, signal: events.signal });
  host.addEventListener("focusin", (event) => {
    if (focusingProgrammatically) return;
    const target = event.target;
    if (target instanceof HTMLElement && target.matches("input, button")) {
      markMotion(target.matches(":focus-visible"));
    }
  }, { signal: events.signal });

  function ready(): boolean {
    if (index === 0) return state.token.trim().length >= 8;
    if (index === 1) return validUsername(state.username) && [...state.displayName].length <= DISPLAY_NAME_MAX;
    if (index === 2) return true;
    return state.saved;
  }

  function renderSteps(instant = false): void {
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
      if (step === completedStep) {
        if (instant) check.set(true, true);
        else requestAnimationFrame(() => check.set(true));
      }
    });
    completedStep = -1;
    steps.querySelectorAll<HTMLButtonElement>("[data-goto]").forEach((button) => {
      button.addEventListener("click", (event) => moveTo(Number(button.dataset.goto), event.detail === 0));
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
    fitViewport(viewport, pane, direction !== "none");
    // The approved pointer step glide is the only expected asynchronous layout shift.
    performance.mark("auth-step");
  }

  function renderFooter(): void {
    const footer = host.querySelector<HTMLElement>("#setup-footer")!;
    const nextText = index === 2 ? "Create passkey" : index === 3 ? "Open infraternal" : "Continue";
    const busyLabel = state.busy && index === 2 ? "Creating passkey" : nextText;
    footer.innerHTML = `<button class="auth-back" id="setup-back" ${index === 0 || state.busy ? "hidden" : ""}>← back</button>
      <button class="auth-primary" id="setup-next" ${ready() && !state.busy ? "" : "disabled"}>${index === 2 ? KEY_MARK : ""}<span>${busyLabel}</span>${state.busy ? '<span class="busy-count" hidden aria-live="off"></span>' : ""}</button>`;
    footer.querySelector<HTMLButtonElement>("#setup-back")!.addEventListener("click", (event) => moveTo(index - 1, event.detail === 0));
    footer.querySelector<HTMLButtonElement>("#setup-next")!.addEventListener("click", (event) => {
      const instant = event.detail === 0;
      markMotion(instant);
      if (state.busy || !ready()) return;
      if (index === 0) void validateSetupToken(instant);
      else if (index === 1) moveTo(2, instant);
      else if (index === 2) void createPasskey();
      else void finishSetup(instant);
    });
  }

  function updateReady(): void {
    const next = host.querySelector<HTMLButtonElement>("#setup-next");
    if (next) next.disabled = state.busy || !ready();
  }

  function moveTo(next: number, instant = false): void {
    if (next < 0 || next >= SETUP_STEPS.length || next === index || next > index + 1) return;
    markMotion(instant);
    completedStep = index;
    const direction = next < index ? "back" : "forward";
    index = next;
    state.error = "";
    host.querySelector<HTMLElement>("#auth-error")!.textContent = "";
    renderSteps(instant);
    renderPane(instant ? "none" : direction);
    renderFooter();
  }

  function renderTokenStep(body: HTMLElement): void {
    body.innerHTML = `<label class="auth-label" for="setup-token">setup token</label>
      <input id="setup-token" class="auth-input auth-mono" type="text" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="paste token" />
      <p class="auth-error-line" id="setup-token-error" role="alert" hidden></p>
      <div class="auth-command"><code data-setup-token-command></code><button class="icon-action" type="button" aria-label="Copy setup token command" data-copy-command>${swapIcon(CLIPBOARD)}</button></div>
      <p class="auth-hint">Run the command on the server. The token expires after 24 hours.</p>`;
    const token = body.querySelector<HTMLInputElement>("#setup-token")!;
    const tokenError = body.querySelector<HTMLElement>("#setup-token-error")!;
    body.querySelector<HTMLElement>("[data-setup-token-command]")!.textContent = setupTokenCommand;
    token.value = state.token;
    token.addEventListener("input", () => {
      markMotion(token.matches(":focus-visible"));
      state.token = token.value;
      tokenError.hidden = true;
      token.removeAttribute("aria-invalid");
      token.removeAttribute("aria-describedby");
      updateReady();
    });
    token.addEventListener("keydown", enterToContinue);
    wireCopy(body.querySelector<HTMLButtonElement>("[data-copy-command]")!, setupTokenCommand);
    focusInput(token);
  }

  async function validateSetupToken(instant: boolean): Promise<void> {
    const token = host.querySelector<HTMLInputElement>("#setup-token")!;
    const tokenError = host.querySelector<HTMLElement>("#setup-token-error")!;
    tokenError.hidden = true;
    tokenError.replaceChildren();
    token.removeAttribute("aria-invalid");
    token.removeAttribute("aria-describedby");
    markMotion(true);
    state.busy = true;
    host.querySelector<HTMLElement>("#auth-error")!.textContent = "";
    renderFooter();
    const count = host.querySelector<HTMLElement>("#setup-next .busy-count")!;
    const waiting = loading(count, 400);
    try {
      await checkSetupToken(state.token.trim());
      waiting.done();
      state.busy = false;
      moveTo(1, instant);
    } catch (error: unknown) {
      waiting.done();
      state.busy = false;
      renderFooter();
      if (error instanceof AuthError && error.status === 401) {
        tokenError.textContent = "That token doesn't match. Run the command shown above on the server.";
        tokenError.hidden = false;
        token.setAttribute("aria-invalid", "true");
        token.setAttribute("aria-describedby", "setup-token-error");
        focusInput(token);
      } else {
        host.querySelector<HTMLElement>("#auth-error")!.textContent = safeAuthMessage(error);
      }
    }
  }

  function renderIdentityStep(body: HTMLElement): void {
    body.innerHTML = `<label class="auth-label" for="setup-username">username</label>
      <input id="setup-username" class="auth-input auth-mono" type="text" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="32" placeholder="ada" />
      <p class="auth-hint" id="username-hint" aria-live="polite"></p>
      <label class="auth-label" for="setup-display-name">display name</label>
      <input id="setup-display-name" class="auth-input" type="text" autocomplete="name" maxlength="${DISPLAY_NAME_MAX}" placeholder="Ada Lovelace" />`;
    const username = body.querySelector<HTMLInputElement>("#setup-username")!;
    const displayName = body.querySelector<HTMLInputElement>("#setup-display-name")!;
    const hint = body.querySelector<HTMLElement>("#username-hint")!;
    username.value = state.username;
    displayName.value = state.displayName;
    const refreshHint = () => {
      markMotion(username.matches(":focus-visible") || displayName.matches(":focus-visible"));
      hint.textContent = state.username && !validUsername(state.username)
        ? USERNAME_RULE
        : state.displayName && [...state.displayName].length > DISPLAY_NAME_MAX
          ? `Display names can be at most ${DISPLAY_NAME_MAX} characters.`
          : USERNAME_RULE;
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
    focusInput(username);
  }

  function renderPasskeyStep(body: HTMLElement): void {
    body.innerHTML = state.error ? '<p class="auth-error-line" id="passkey-error"></p>' : "";
    const error = body.querySelector<HTMLElement>("#passkey-error");
    if (error) error.textContent = state.error;
  }

  function renderRecoveryStep(body: HTMLElement): void {
    recoveryWords(body, state.recoveryWords, state.saved, (saved) => {
      state.saved = saved;
      updateReady();
    }, markMotion);
  }

  async function createPasskey(): Promise<void> {
    markMotion(true);
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
        markMotion(true);
        renderSteps(true);
        renderPane("none");
        renderFooter();
        await new Promise<void>((resolve) => { state.completeRecovery = resolve; });
      });
      // The app host survives authentication; listeners must not retain setup secrets
      // or address its removed card when terminal controls receive focus/touches.
      events.abort();
      paneObserver?.disconnect();
      state.token = "";
      state.recoveryWords = [];
      delete state.finishRegistration;
      delete state.completeRecovery;
      onAuthenticated(userId, true, displayName, state.instantCompletion);
    } catch (error: unknown) {
      waiting.done();
      state.busy = false;
      state.error = safeAuthMessage(error);
      host.querySelector<HTMLElement>("#auth-error")!.textContent = "";
      renderPane("none");
      renderFooter();
    }
  }

  async function finishSetup(instant: boolean): Promise<void> {
    if (!state.saved || state.busy || !state.finishRegistration) return;
    markMotion(true);
    state.busy = true;
    renderFooter();
    const button = host.querySelector<HTMLButtonElement>("#setup-next")!;
    const waiting = loading(button.querySelector<HTMLElement>(".busy-count")!, 400);
    try {
      await state.finishRegistration();
      waiting.done();
      state.instantCompletion = instant;
      state.completeRecovery?.();
    } catch (error: unknown) {
      waiting.done();
      state.busy = false;
      host.querySelector<HTMLElement>("#auth-error")!.textContent = safeAuthMessage(error);
      renderFooter();
    }
  }

  function wireCopy(button: HTMLButtonElement, text: string): void {
    button.addEventListener("click", async (event) => {
      markMotion(true); // status text changes snap so a frequent copy action cannot tween layout
      const copied = await copyFeedback(button, text, event.detail === 0);
      if (!copied) host.querySelector<HTMLElement>("#auth-error")!.textContent = "Copy is unavailable here.";
      button.blur();
    });
  }

  function enterToContinue(event: KeyboardEvent): void {
    if (event.key !== "Enter") return;
    const next = host.querySelector<HTMLButtonElement>("#setup-next");
    if (next && !next.disabled) { event.preventDefault(); next.click(); }
  }

  // A focused keyboard action can change readiness, move the pane, and schedule a
  // completed-step spring in one turn. Keep those changes immediate until a pointer
  // action takes over; pointer-driven setup keeps the approved glide.

  let paneObserver: ResizeObserver | undefined;
  renderSteps();
  renderPane("none");
  renderFooter();

  /** Keeps the card fitted to its pane; only deliberate pointer step changes glide. */
  function fitViewport(viewport: HTMLElement, pane: HTMLElement, animate: boolean): void {
    viewport.style.transition = animate ? "" : "none";
    viewport.style.height = `${pane.offsetHeight}px`;
    if (!animate) void viewport.offsetHeight; // commit the jump before transitions resume
    viewport.style.transition = "";
    paneObserver?.disconnect();
    paneObserver = new ResizeObserver(() => { viewport.style.height = `${pane.offsetHeight}px`; });
    paneObserver.observe(pane);
  }
}
