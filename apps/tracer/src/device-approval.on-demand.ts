/** Reviews one CLI device request and approves it only after a fresh passkey tap. */
import { approveDeviceApproval, inspectDeviceApproval, isDeviceUserCode, loginWithPasskey } from "./auth";
import { deviceName, safeAuthMessage } from "./onboarding";
import { loading, type Loading } from "../../../packages/ui/src/countup";
import { springCheckbox } from "../../../packages/ui/src/tick";
import { BRAND_MARK, KEY_MARK } from "./auth-marks";

/** Loads the device facts only after a signed-in browser session exists. */
export async function mountDeviceApproval(
  host: HTMLElement,
  code: string | null,
  linkError: string | undefined,
  onApproved: () => void,
): Promise<void> {
  if (linkError) {
    renderError(host, linkError);
    return;
  }
  if (!code || !isDeviceUserCode(code)) {
    renderError(host, "This sign-in link is incomplete. Ask the person who started it to run infraternal sign-in again.");
    return;
  }

  renderChecking(host);
  try {
    const review = await inspectDeviceApproval(code);
    renderReview(host, code, review, onApproved);
  } catch (error: unknown) {
    renderError(host, safeAuthMessage(error));
  }
}

/** Keeps the approved link on its success screen if the page resumes from the background. */
export function mountDeviceApprovalSuccess(host: HTMLElement): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Device sign-in approved">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">Device approved</h1>
      <p class="auth-lede">Return to the terminal. It will finish saving this device's credential.</p>
    </section>
  </section>`;
}

function renderChecking(host: HTMLElement): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Device sign-in approval">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">Approve device sign-in</h1>
      <p class="auth-lede">Checking the requested device and access…</p>
      <p class="auth-loading" role="status" aria-live="polite">Please wait</p>
    </section>
  </section>`;
}

function renderReview(
  host: HTMLElement,
  code: string,
  review: { device: string; scopes: string[] },
  onApproved: () => void,
): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Device sign-in approval">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">Approve device sign-in</h1>
      <p class="auth-lede">Review this computer and the access it is requesting.</p>
      <label class="auth-label" for="device-approval-code">Code</label>
      <output class="auth-input auth-mono device-approval-code" id="device-approval-code"></output>
      <p class="auth-hint">Match this code with the code in your terminal before you approve.</p>
      <label class="auth-check"><input id="device-approval-code-match" type="checkbox" /><span>I checked that this code matches the code in my terminal</span></label>
      <dl class="device-approval-facts">
        <div><dt>Device</dt><dd id="device-approval-device"></dd></div>
      </dl>
      <section class="device-approval-access" aria-labelledby="device-approval-access-title">
        <h2 id="device-approval-access-title">Access</h2>
        <ul class="device-approval-scopes"></ul>
      </section>
      <p class="device-approval-note">Only approve a request you started on this device. Closing this page leaves it pending until it expires.</p>
      <div class="auth-note"><div><p class="auth-message" id="device-approval-error" role="alert"></p></div></div>
      <button class="auth-primary auth-login" id="device-approval-approve" type="button">${KEY_MARK}<span>Approve with passkey</span><span class="busy-count" hidden></span></button>
      <div class="auth-note"><div><p class="auth-loading" id="device-approval-status" role="status" aria-live="polite"></p></div></div>
    </section>
  </section>`;

  host.querySelector<HTMLOutputElement>("#device-approval-code")!.textContent = code;
  host.querySelector<HTMLElement>("#device-approval-device")!.textContent = review.device;
  const scopes = host.querySelector<HTMLUListElement>(".device-approval-scopes")!;
  for (const scope of review.scopes) {
    const item = document.createElement("li");
    item.textContent = scope;
    scopes.append(item);
  }

  const button = host.querySelector<HTMLButtonElement>("#device-approval-approve")!;
  const codeMatch = host.querySelector<HTMLInputElement>("#device-approval-code-match")!;
  const error = host.querySelector<HTMLElement>("#device-approval-error")!;
  const status = host.querySelector<HTMLElement>("#device-approval-status")!;
  let approving = false;
  springCheckbox(codeMatch);
  button.disabled = true;
  codeMatch.addEventListener("change", () => {
    button.disabled = approving || !codeMatch.checked;
  });
  button.addEventListener("click", () => {
    if (approving || !codeMatch.checked) return;
    approving = true;
    button.disabled = true;
    codeMatch.disabled = true;
    error.textContent = "";
    status.textContent = "Waiting for your passkey…";
    const waiting: Loading = loading(button.querySelector<HTMLElement>(".busy-count")!, 400);
    void (async () => {
      try {
        await loginWithPasskey(deviceName());
        await approveDeviceApproval(code);
        onApproved();
        mountDeviceApprovalSuccess(host);
      } catch (failure: unknown) {
        approving = false;
        codeMatch.disabled = false;
        button.disabled = !codeMatch.checked;
        status.textContent = "";
        error.textContent = safeAuthMessage(failure);
      } finally {
        waiting.done();
      }
    })();
  });
}

function renderError(host: HTMLElement, message: string): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Device sign-in unavailable">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">Device sign-in unavailable</h1>
      <p class="auth-lede" id="device-approval-error" role="alert"></p>
    </section>
  </section>`;
  host.querySelector<HTMLElement>("#device-approval-error")!.textContent = message;
}
