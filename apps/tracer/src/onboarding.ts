/** Renders the discoverable passkey sign-in for the tracer and hands first-run setup to its on-demand module. */
import { recoveryUiEnabled } from "./recovery-ui";
import { swapCard } from "./auth-motion";
import { AuthError, loginWithPasskey } from "./auth";
import { loading, type Loading } from "../../../packages/ui/src/countup";
import { BRAND_MARK, KEY_MARK } from "./auth-marks";
import { onDemand } from "./on-demand";

/** Mounts one auth flow and calls onAuthenticated after the server sets its cookie. */
export function mountOnboarding(
  host: HTMLElement,
  setupRequired: boolean,
  message: string,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string, instant?: boolean) => void,
): void {
  if (setupRequired) {
    // Shown once per server, so its code is fetched only when it is needed (see onboarding-setup.on-demand.ts).
    void onDemand(() => import("./onboarding-setup.on-demand")).then(({ mountSetup }) => mountSetup(host, message, onAuthenticated));
  } else mountSignIn(host, message, onAuthenticated);
}

function mountSignIn(
  host: HTMLElement,
  message: string,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string, instant?: boolean) => void,
  /** -1 when arriving from the recovery card, so the swap slides the other way. */
  from: 0 | -1 = 0,
): void {
  swapCard(host, from, () => { host.innerHTML = `<section class="auth-screen" aria-label="Sign in">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="signin-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="signin-title">Welcome back</h1>
      <p class="auth-lede">Your passkey is all you need.</p>
      <div class="auth-note"><div><p class="auth-message" id="auth-error" role="alert"></p></div></div>
      <button class="auth-primary auth-login" id="login-passkey" type="button">${KEY_MARK}<span>Continue with passkey</span></button>
      ${recoveryUiEnabled() ? '<button class="auth-text-button" id="use-recovery" type="button">use recovery key</button>' : ""}
      <div class="auth-note"><div><p class="auth-loading" id="login-loading" role="status" aria-live="polite"><span class="busy-count" hidden></span></p></div></div>
    </section>
  </section>`; });
  host.querySelector<HTMLElement>("#auth-error")!.textContent = message;
  // Fetch the recovery code while the person is still reading, so pressing the action never waits.
  if (recoveryUiEnabled()) window.setTimeout(() => { void import("./recovery"); }, 0);
  const events = new AbortController();
  const button = host.querySelector<HTMLButtonElement>("#login-passkey")!;
  host.querySelector<HTMLButtonElement>("#use-recovery")?.addEventListener("click", () => {
    if (button.disabled || !recoveryUiEnabled()) return;
    void import("./recovery").then(({ mountRecovery }) => {
      events.abort();
      mountRecovery(host, () => mountSignIn(host, "", onAuthenticated, -1), onAuthenticated);
    });
  });
  const card = host.querySelector<HTMLElement>(".auth-card")!;
  host.addEventListener("pointerdown", () => card.removeAttribute("data-no-motion"), { capture: true, signal: events.signal });
  host.addEventListener("focusin", (event) => {
    if (event.target instanceof HTMLElement && event.target.matches("button")) {
      card.toggleAttribute("data-no-motion", event.target.matches(":focus-visible"));
    }
  }, { signal: events.signal });
  button.addEventListener("click", (event) => {
    void beginLogin(button, host, (...args) => {
      events.abort();
      onAuthenticated(...args);
    }, event.detail === 0);
  });
}

async function beginLogin(
  button: HTMLButtonElement,
  host: HTMLElement,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string, instant?: boolean) => void,
  instant: boolean,
): Promise<void> {
  if (button.disabled) return;
  host.querySelector<HTMLElement>(".auth-card")!.toggleAttribute("data-no-motion", instant);
  button.disabled = true;
  host.querySelector<HTMLElement>("#auth-error")!.textContent = "";
  const counter = host.querySelector<HTMLElement>("#login-loading .busy-count")!;
  const waiting: Loading = loading(counter, 400);
  try {
    const userId = await loginWithPasskey(deviceName());
    waiting.done();
    onAuthenticated(userId, false, undefined, instant);
  } catch (error: unknown) {
    waiting.done();
    button.disabled = false;
    host.querySelector<HTMLElement>("#auth-error")!.textContent = safeAuthMessage(error);
  }
}

export function validUsername(value: string): boolean {
  return /^[a-z0-9_-]{2,32}$/.test(value);
}

export function safeAuthMessage(error: unknown): string {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "The passkey prompt was cancelled or timed out. Try again when you are ready.";
  }
  return error instanceof AuthError ? error.message : "The request could not be completed. Try again.";
}

export function deviceName(): string {
  try { return localStorage.getItem("tracer.device-name") || `${navigator.platform || "Browser"} device`; }
  catch { return "Browser device"; }
}
