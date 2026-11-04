/** Renders the discoverable passkey sign-in for the tracer and hands first-run setup to its on-demand module. */
import { recoveryUiEnabled } from "./recovery-ui";
import { swapCard } from "./auth-motion";
import { AuthError, loginWithPasskey } from "./auth";
import { loading, type Loading } from "../../../packages/ui/src/countup";
import { BRAND_MARK, KEY_MARK } from "./auth-marks";
import { onDemand } from "./on-demand";

/**
 * Mounts one auth flow into `host`: first-run setup when the server says `setupRequired`, passkey sign-in otherwise.
 * @param message text shown in the card's message line (for example why the user was signed out); may be empty
 * @param onAuthenticated called once the server has set its session cookie. `firstSetup` is true after setup;
 * `instant` is true when a keyboard started the flow, so the next screen skips its entrance animation.
 * @param setupTokenCommand the command the setup card tells the user to run on the server
 */
export function mountOnboarding(
  host: HTMLElement,
  setupRequired: boolean,
  message: string,
  onAuthenticated: (userId: string, firstSetup: boolean, welcomeName?: string, instant?: boolean) => void,
  setupTokenCommand = "infraternal server setup-token",
): void {
  if (setupRequired) loadSetup(host, message, onAuthenticated, setupTokenCommand);
  else mountSignIn(host, message, onAuthenticated);
}

/** The shape of the lazily loaded setup module. */
type SetupModule = typeof import("./onboarding-setup.on-demand");
/** The callback every auth flow ends in; see {@link mountOnboarding}. */
type Authenticated = (userId: string, firstSetup: boolean, welcomeName?: string, instant?: boolean) => void;

/**
 * Setup is shown once per server, so its code is fetched on demand. The fetch starts the moment the server reports
 * that setup is required (the person is already looking at the backdrop; an idle delay would only make it slower),
 * and a failure is not final: this is the first screen a person ever sees, often on a poor connection. The card says
 * what happened in the message line sign-in uses for errors, offers "Try again", and retries once by itself when the
 * browser comes back online (the session manager's on-demand load recovers the same way, #249).
 */
export function loadSetup(
  host: HTMLElement,
  message: string,
  onAuthenticated: Authenticated,
  setupTokenCommand = "infraternal server setup-token",
): void {
  onDemand((): Promise<SetupModule> => import("./onboarding-setup.on-demand")).then(
    ({ mountSetup }) => mountSetup(host, message, setupTokenCommand, onAuthenticated),
    () => {
      host.innerHTML = `<section class="auth-screen" aria-label="Set up infraternal"><section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="setup-title">
        <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
        <h1 id="setup-title">Make this server yours</h1>
        <div class="auth-note"><div><p class="auth-message" id="auth-error" role="alert"></p></div></div>
        <button class="auth-primary auth-login" id="retry-setup" type="button"><span>Try again</span></button>
      </section></section>`;
      host.querySelector<HTMLElement>("#auth-error")!.textContent = SETUP_LOAD_FAILED;
      // A failed dynamic import stays failed in the page's module map, so importing again would fail again even on a
      // good network. The retry reloads the page instead; nothing is typed yet on this first card, so nothing is lost.
      const retry = (): void => location.reload();
      host.querySelector<HTMLButtonElement>("#retry-setup")!.addEventListener("click", retry, { once: true });
      window.addEventListener("online", retry, { once: true });
    },
  );
}

/** Shown when the setup code could not be fetched. */
export const SETUP_LOAD_FAILED = "Could not load setup. Check your connection; it will retry.";

/**
 * Draws the sign-in card and wires it. The recovery card (when the build enables it) is fetched while the person reads,
 * and returns here through `mountSignIn` with `from` -1 so the swap slides the other way.
 */
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

/**
 * Runs the passkey sign-in for the button that was pressed. Ignores a press while one is running. A wait longer than
 * 400 ms shows a count-up; a failure puts a plain-language message in the card and re-enables the button.
 * @param instant true for keyboard activation, which skips motion
 */
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

/** True for a username of 2 to 32 characters from a to z, 0 to 9, underscore and hyphen. */
export function validUsername(value: string): boolean {
  return /^[a-z0-9_-]{2,32}$/.test(value);
}

/**
 * The message to show for a failed sign-in. A cancelled or timed-out passkey prompt gets a friendly sentence, a known
 * {@link AuthError} keeps its own text, and anything else gets a generic line, so internal error text never reaches the page.
 */
export function safeAuthMessage(error: unknown): string {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "The passkey prompt was cancelled or timed out. Try again when you are ready.";
  }
  return error instanceof AuthError ? error.message : "The request could not be completed. Try again.";
}

/** The name this device is registered under: the saved `tracer.device-name`, else the platform name plus "device". */
export function deviceName(): string {
  try { return localStorage.getItem("tracer.device-name") || `${navigator.platform || "Browser"} device`; }
  catch { return "Browser device"; }
}
