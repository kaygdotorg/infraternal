/** Runs the onboarding-styled recovery flow, holding words and capabilities only in this mount [D113]. */
import { validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { AuthError } from "./auth";
import { startRecovery, getRecoveryStatus, replacePasskey, type RecoveryRequest } from "./recovery-auth";
import { recoveryWords } from "./recovery-words";
import { recoveryUiEnabled } from "./recovery-ui";
import { swapCard } from "./auth-motion";
import { loading } from "../../../packages/ui/src/countup";
import { tick, springCheckbox } from "../../../packages/ui/src/tick";

/** The valid recovery words, for checking what the user types. */
const dictionary = new Set(wordlist);
/** The title of each of the four steps: enter the key, wait, create a passkey, save the new key. */
const titles = ["Use your recovery key", "Recovery started", "Create a new passkey", "Save your new recovery key"];

/** Words are derived with Web Crypto and the passkey needs WebAuthn; browsers hide both on plain http
 * (anything but https or localhost). Without them no step can work, so say so instead of failing
 * with a generic message. */
export const SECURE_CONNECTION_MESSAGE = "Recovery needs a secure connection (https)";
/** True when the page can run recovery: a secure context with Web Crypto. */
export function secureConnection(): boolean {
  return window.isSecureContext && typeof crypto !== "undefined" && crypto.subtle !== undefined;
}

/**
 * Draws the four-step recovery card in `host` and runs it. Words, the passkey request and other capabilities live only in
 * this call's variables and are cleared when the user goes back. It reuses the auth card, pane motion, stepper ticks and
 * saved-word controls from onboarding.
 * @param back called when the user leaves the card to return to sign-in
 * @param complete called when recovery has finished and the device is signed in, like {@link mountOnboarding}'s callback
 */
export function mountRecovery(host: HTMLElement, back: () => void,
  complete: (userId: string, firstSetup: boolean, displayName?: string, instant?: boolean) => void,
): void {
  if (!recoveryUiEnabled()) { back(); return; }
  let step = 0, busy = false, instant = false, saved = false;
  let words = Array<string>(24).fill(""), username = "", nextWords: string[] = [];
  let request: RecoveryRequest | undefined;
  let finish: (() => Promise<void>) | undefined, acknowledged: (() => void) | undefined;
  let rejectAcknowledgement: ((failure: unknown) => void) | undefined;
  let readyTimer = 0, readyClock = 0, serverReady = false, refreshing = false;
  const lifecycle = new AbortController();
  let renderedStep = -1;
  let paneObserver: ResizeObserver | undefined;
  swapCard(host, 1, () => { host.innerHTML = `<section class="auth-screen" aria-label="Recover your account"><section class="auth-card" id="recovery-card">
    <div class="auth-mark"><span>infraternal</span></div><ol class="auth-steps" aria-label="Recovery progress"></ol>
    <div class="auth-viewport"><div class="auth-pane"><p class="auth-eyebrow"></p><h1></h1><p class="auth-lede"></p><div class="auth-pane-body"></div></div></div>
    <div class="auth-footer"><button class="auth-back" type="button">← sign in</button><button class="auth-primary" id="recovery-next" type="button"><span></span><span class="busy-count" hidden></span></button></div>
    <p class="auth-message" id="auth-error" role="alert"></p></section></section>`; });
  const card = host.querySelector<HTMLElement>("#recovery-card")!;
  let body = card.querySelector<HTMLElement>(".auth-pane-body")!;
  const button = card.querySelector<HTMLButtonElement>("#recovery-next")!;
  const error = card.querySelector<HTMLElement>("#auth-error")!;
  const markMotion = (value: boolean): void => { card.toggleAttribute("data-no-motion", value); };
  card.querySelector<HTMLButtonElement>(".auth-back")!.addEventListener("click", () => {
    if (busy || finish) return;
    lifecycle.abort(); window.clearTimeout(readyTimer); paneObserver?.disconnect(); words.fill(""); request = undefined; back();
  });
  // This local estimate schedules status reads only. Readiness comes exclusively
  // from a server reply, since its measured uptime can pause across restarts.
  function remainingMs(): number { return Math.max(0, readyClock - performance.now()); }
  function ready(): boolean {
    if (step === 0) return /^[a-z0-9_-]{2,32}$/.test(username) && validWords();
    if (step === 1) return request !== undefined && serverReady;
    return step !== 3 || saved;
  }
  function validWords(): boolean { return words.every((word) => dictionary.has(word)) && validateMnemonic(words.join(" "), wordlist); }
  function update(): void { button.disabled = busy || refreshing || !ready(); }
  function render(): void {
    markMotion(instant);
    const viewport = card.querySelector<HTMLElement>(".auth-viewport")!;
    const changed = renderedStep !== step;
    const animate = changed && renderedStep >= 0 && !instant;
    viewport.style.transition = animate ? "" : "none";
    if (animate) {
      viewport.style.height = getComputedStyle(viewport).height; // the content height now, mid-glide included (not the padded box)
      void viewport.offsetHeight; // Capture an interrupted glide before retargeting it.
    }
    const steps = card.querySelector<HTMLOListElement>(".auth-steps")!;
    steps.innerHTML = titles.map((_, i) => `<li class="${i < step ? "is-done" : i === step ? "is-current" : ""}"><span class="auth-dot" ${i === step ? 'aria-current="step"' : ""} aria-label="Step ${i + 1}${i < step ? ", done" : ""}">${i < step ? '<span class="tick-host"></span>' : i + 1}</span>${i < 3 ? '<span class="auth-step-bar"></span>' : ""}</li>`).join("");
    steps.querySelectorAll<HTMLElement>(".tick-host").forEach((element, i) => {
      const check = tick(element, i < step - 1);
      if (i === step - 1) check.set(true, instant);
    });
    const pane = document.createElement("div");
    pane.className = "auth-pane";
    pane.dataset.direction = animate ? "forward" : "none";
    pane.innerHTML = '<p class="auth-eyebrow"></p><h1></h1><p class="auth-lede"></p><div class="auth-pane-body"></div>';
    viewport.replaceChildren(pane);
    body = pane.querySelector<HTMLElement>(".auth-pane-body")!;
    pane.querySelector<HTMLElement>(".auth-eyebrow")!.textContent = `step ${step + 1} of 4`;
    pane.querySelector<HTMLElement>("h1")!.textContent = titles[step]!;
    pane.querySelector<HTMLElement>(".auth-lede")!.textContent = [
      "Enter your username and the 24 words you saved. You can paste the whole key into any word field.",
      serverReady ? "Recovery is ready. You can now create a replacement passkey." : "Recovery waits 24 hours. A signed-in device can cancel it. You can close this page and resume with your words in any browser. The original deadline stays the same.",
      "Your new passkey will protect the same account key. Your saved SSH keys stay accessible.",
      "Your old recovery key will stop working. Store these new words somewhere safe and offline.",
    ][step]!;
    if (step === 0) renderEntry();
    else if (step === 1) {
      body.innerHTML = '<p id="recovery-ready-time" role="status"></p>';
      paintWait();
    } else if (step === 2) body.replaceChildren();
    else recoveryWords(body, nextWords, saved, (value) => { saved = value; update(); }, markMotion);
    button.querySelector<HTMLElement>("span")!.textContent = ["Start recovery", "Continue recovery", "Create passkey", "Open infraternal"][step]!;
    viewport.style.height = `${pane.offsetHeight}px`;
    paneObserver?.disconnect();
    paneObserver = new ResizeObserver(() => {
      if (!card.isConnected) { paneObserver?.disconnect(); return; }
      viewport.style.height = `${pane.offsetHeight}px`;
    });
    paneObserver.observe(pane);
    renderedStep = step;
    update();
    scheduleStatus();
  }
  function paintWait(): void {
    const remaining = body.querySelector<HTMLElement>("#recovery-ready-time");
    if (remaining) remaining.textContent = serverReady ? "Ready now" : remainingMs() === 0
      ? "Checking recovery time…"
      : `Available ${new Date(request!.ready_at * 1000).toLocaleString()} · ${Math.ceil(remainingMs() / 60_000)} minutes remaining`;
    update();
  }
  function scheduleStatus(): void {
    window.clearTimeout(readyTimer);
    if (step !== 1 || serverReady || !card.isConnected) return;
    readyTimer = window.setTimeout(() => { void refreshStatus(); },
      remainingMs() > 0 ? Math.min(60_000, remainingMs()) : 60_000);
  }
  async function refreshStatus(): Promise<void> {
    if (!card.isConnected || step !== 1 || busy || refreshing || !request) return;
    const previous = request;
    refreshing = true; serverReady = false; paintWait();
    // An earlier ready reply must not survive a failed foreground refresh.
    card.querySelector<HTMLElement>(".auth-lede")!.textContent = "Checking recovery time with the server.";
    try {
      const status = await getRecoveryStatus(previous.token);
      if (!card.isConnected || step !== 1 || request !== previous) return;
      request = { ...previous, delay_seconds: status.delay_seconds, ready_at: status.ready_at };
      serverReady = status.ready;
      readyClock = performance.now() + status.delay_seconds * 1000;
      error.textContent = "";
    } catch {
      if (card.isConnected) error.textContent = "The recovery time could not be refreshed. We will check again shortly.";
    } finally {
      refreshing = false;
      if (card.isConnected && step === 1) render();
    }
  }
  function renderEntry(): void {
    body.innerHTML = `<label class="auth-label" for="recovery-username">username</label><input class="auth-input" id="recovery-username" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="32" />
      <p class="auth-label recovery-word-label">recovery words</p><ol class="auth-word-inputs"></ol><p class="auth-hint" id="recovery-word-error" role="status"></p>
      `;
    const identity = body.querySelector<HTMLInputElement>("#recovery-username")!;
    identity.value = username;
    identity.addEventListener("input", () => { username = identity.value.trim().toLowerCase(); error.textContent = ""; update(); });
    const list = body.querySelector<HTMLOListElement>("ol")!;
    for (let i = 0; i < 24; i++) {
      const item = document.createElement("li");
      item.innerHTML = `<span aria-hidden="true">${i + 1}</span><input aria-label="Word ${i + 1}" maxlength="8" autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="recovery-word-error" />`;
      const input = item.querySelector<HTMLInputElement>("input")!;
      input.value = words[i]!;
      input.addEventListener("input", () => { words[i] = input.value.trim().toLowerCase(); validate(); });
      input.addEventListener("paste", (event) => {
        const text = event.clipboardData?.getData("text/plain");
        if (!text) return;
        if (text.length > 2048) { event.preventDefault(); error.textContent = "Paste a 24-word recovery key."; return; }
        const pasted = text.toLowerCase().replace(/\b\d+[.)]\s*/g, "").trim().split(/[\s,]+/);
        if (pasted.length <= 1) return;
        event.preventDefault();
        const offset = pasted.length === 24 ? 0 : i;
        if (offset + pasted.length > 24) { error.textContent = "Enter exactly 24 words."; return; }
        pasted.forEach((word, index) => { words[offset + index] = word; });
        list.querySelectorAll<HTMLInputElement>("input").forEach((field, index) => { field.value = words[index]!; });
        validate();
      });
      list.append(item);
    }
    function validate(): void {
      error.textContent = "";
      let invalid = -1;
      list.querySelectorAll<HTMLInputElement>("input").forEach((field, index) => {
        const bad = Boolean(words[index]) && !dictionary.has(words[index]!);
        field.setAttribute("aria-invalid", String(bad));
        if (bad && invalid < 0) invalid = index;
      });
      body.querySelector<HTMLElement>("#recovery-word-error")!.textContent = invalid >= 0 ? `Word ${invalid + 1} is not in the recovery word list.` : words.every(Boolean) && !validWords() ? "These words do not make a valid recovery key. Check their order." : "";
      update();
    }
  }
  button.addEventListener("click", (event) => {
    if (busy || !ready()) return;
    instant = event.detail === 0;
    void advance();
  });
  async function advance(): Promise<void> {
    if ((step === 0 || step === 2) && !secureConnection()) { error.textContent = SECURE_CONNECTION_MESSAGE; return; }
    busy = true; update(); markMotion(true); error.textContent = "";
    const waiting = loading(button.querySelector<HTMLElement>(".busy-count")!, 400);
    try {
      if (step === 0) { request = await startRecovery(username, words.join(" ")); readyClock = performance.now() + request.delay_seconds * 1000; serverReady = request.delay_seconds === 0; step = 1; }
      else if (step === 1) { step = 2; }
      else if (step === 2) {
        const result = await replacePasskey(request!.token, words.join(" "), async (rotated, commit) => {
          waiting.done(); busy = false; step = 3; nextWords = rotated.split(" "); finish = commit; render();
          await new Promise<void>((resolve, reject) => { acknowledged = resolve; rejectAcknowledgement = reject; });
        });
        words.fill(""); nextWords.fill(""); request = undefined; finish = undefined;
        lifecycle.abort(); window.clearTimeout(readyTimer); paneObserver?.disconnect();
        complete(result.userId, true, result.displayName, instant);
        return;
      } else {
        try { await finish!(); }
        catch (failure) {
          // Finish consumes its ceremony even on failure; recreate it for a safe retry.
          step = 2; finish = undefined; saved = false; nextWords.fill("");
          rejectAcknowledgement?.(failure); throw failure;
        }
        acknowledged?.(); return;
      }
    } catch (failure: unknown) {
      error.textContent = failure instanceof AuthError && failure.status === 401
        ? step === 0 ? "Recovery could not start. Check the username and recovery key. Older recovery words need replacing from a signed-in device." : "Recovery is not ready, expired or was cancelled. Check the available time or start again."
        : failure instanceof DOMException && failure.name === "InvalidStateError" ? "This device already has a passkey for this account. Choose another passkey provider or remove the old passkey from your device."
        : failure instanceof DOMException && failure.name === "NotAllowedError" ? "The passkey prompt was cancelled. Try again when you are ready."
        : failure instanceof AuthError ? failure.message : "Recovery could not be completed. Try again.";
    } finally { waiting.done(); busy = false; if (card.isConnected) render(); }
  }
  document.addEventListener("visibilitychange", () => {
    if (!card.isConnected) { lifecycle.abort(); words.fill(""); return; }
    if (!document.hidden) void refreshStatus();
  }, { signal: lifecycle.signal });
  render();
}
