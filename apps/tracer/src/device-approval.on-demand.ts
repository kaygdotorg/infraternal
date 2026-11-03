/** Reviews one CLI device request and approves it only after a fresh passkey tap. */
import {
  AuthError,
  approveDeviceApproval,
  approveRemovalApproval,
  declineRemovalApproval,
  inspectDeviceApproval,
  inspectRemovalApproval,
  isDeviceUserCode,
  keyLifetimeLabel,
  loginWithPasskey,
  recoveryAuth,
  type DeviceApprovalReview,
  type RemovalApprovalReview,
} from "./auth";
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

/** Reviews one action-bound host removal and requires a new passkey tap to approve it. */
export async function mountRemovalApproval(
  host: HTMLElement,
  code: string | null,
  linkError: string | undefined,
  onApproved: () => void,
  onDeclined: () => void,
): Promise<void> {
  if (linkError) {
    renderRemovalError(host, linkError);
    return;
  }
  if (!code || !isDeviceUserCode(code)) {
    renderRemovalError(host, "This removal link is incomplete. Ask the person who started it to try again.");
    return;
  }
  renderRemovalChecking(host);
  try {
    const review = await inspectRemovalApproval(code);
    renderRemovalReview(host, code, review, onApproved, onDeclined);
  } catch (error: unknown) {
    renderRemovalError(host, safeAuthMessage(error));
  }
}

/** Shows the terminal-facing result while keeping a resumed approval link safe to revisit. */
export function mountRemovalApprovalResult(host: HTMLElement, approved: boolean): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Host removal request updated">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="removal-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="removal-approval-title">${approved ? "Removal approved" : "Request declined"}</h1>
      <p class="auth-lede" id="removal-approval-result"></p>
    </section>
  </section>`;
  host.querySelector<HTMLElement>("#removal-approval-result")!.textContent = approved
    ? "The host removal is running. Return to the terminal to see its result."
    : "The host will stay connected. Return to the terminal to finish.";
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
  review: DeviceApprovalReview,
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
        <div><dt>Valid for</dt><dd id="device-approval-lifetime"></dd></div>
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
  host.querySelector<HTMLElement>("#device-approval-lifetime")!.textContent = keyLifetimeLabel(review.lifetimeSeconds);
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

function renderRemovalChecking(host: HTMLElement): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Host removal approval">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="removal-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="removal-approval-title">Review host removal</h1>
      <p class="auth-lede">Checking the host and what removal will uninstall…</p>
      <p class="auth-loading" role="status" aria-live="polite">Please wait</p>
    </section>
  </section>`;
}

function renderRemovalError(host: HTMLElement, message: string): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Host removal unavailable">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="removal-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="removal-approval-title">Removal request unavailable</h1>
      <p class="auth-lede" id="removal-approval-error" role="alert"></p>
    </section>
  </section>`;
  host.querySelector<HTMLElement>("#removal-approval-error")!.textContent = message;
}

function renderRemovalReview(
  host: HTMLElement,
  code: string,
  review: RemovalApprovalReview,
  onApproved: () => void,
  onDeclined: () => void,
): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Host removal approval">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="removal-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="removal-approval-title"></h1>
      <p class="auth-lede">Review this host and the effect before approving removal.</p>
      <label class="auth-label" for="removal-approval-code">Code</label>
      <output class="auth-input auth-mono device-approval-code" id="removal-approval-code"></output>
      <p class="auth-hint">Match this code with the code in your terminal before you approve.</p>
      <label class="auth-check"><input id="removal-approval-code-match" type="checkbox" /><span>I checked that this code matches the code in my terminal</span></label>
      <dl class="device-approval-facts"><div><dt>Host</dt><dd id="removal-approval-host"></dd></div></dl>
      <section class="device-approval-access" aria-labelledby="removal-approval-effect-title">
        <h2 id="removal-approval-effect-title">What happens</h2>
        <p class="device-approval-note" id="removal-approval-effect"></p>
      </section>
      <p class="device-approval-note">A fresh passkey tap is required for every removal. Declining leaves the request unexecuted.</p>
      <div class="auth-note"><div><p class="auth-message" id="removal-approval-error" role="alert"></p></div></div>
      <button class="auth-primary auth-login" id="removal-approval-approve" type="button">${KEY_MARK}<span>Approve removal with passkey</span><span class="busy-count" hidden></span></button>
      <button class="auth-text-button" id="removal-approval-decline" type="button">Decline</button>
      <div class="auth-note"><div><p class="auth-loading" id="removal-approval-status" role="status" aria-live="polite"></p></div></div>
    </section>
  </section>`;

  host.querySelector<HTMLElement>("#removal-approval-title")!.textContent = review.label;
  host.querySelector<HTMLOutputElement>("#removal-approval-code")!.textContent = code;
  host.querySelector<HTMLElement>("#removal-approval-host")!.textContent = review.host;
  host.querySelector<HTMLElement>("#removal-approval-effect")!.textContent = review.uninstallEffect;
  bindRemovalApproval(host, code, review, onApproved, onDeclined);
}

function bindRemovalApproval(
  host: HTMLElement,
  code: string,
  review: RemovalApprovalReview,
  onApproved: () => void,
  onDeclined: () => void,
): void {
  const button = host.querySelector<HTMLButtonElement>("#removal-approval-approve")!;
  const decline = host.querySelector<HTMLButtonElement>("#removal-approval-decline")!;
  const codeMatch = host.querySelector<HTMLInputElement>("#removal-approval-code-match")!;
  const error = host.querySelector<HTMLElement>("#removal-approval-error")!;
  const status = host.querySelector<HTMLElement>("#removal-approval-status")!;
  let currentReview = review;
  let working = false;
  springCheckbox(codeMatch);
  button.disabled = true;
  codeMatch.addEventListener("change", () => { button.disabled = working || !codeMatch.checked; });
  button.addEventListener("click", () => {
    if (working || !codeMatch.checked) return;
    working = true;
    button.disabled = true;
    decline.disabled = true;
    codeMatch.disabled = true;
    error.textContent = "";
    status.textContent = "Waiting for your passkey…";
    const waiting: Loading = loading(button.querySelector<HTMLElement>(".busy-count")!, 400);
    void approveRemoval(
      host,
      code,
      currentReview,
      (next) => { currentReview = next; },
      button,
      decline,
      codeMatch,
      error,
      status,
      waiting,
      onApproved,
      () => { working = false; },
    );
  });
  decline.addEventListener("click", () => {
    if (working) return;
    working = true;
    button.disabled = true;
    decline.disabled = true;
    codeMatch.disabled = true;
    error.textContent = "";
    status.textContent = "Sending refusal…";
    void declineRemoval(host, code, button, decline, codeMatch, error, status, onDeclined, () => { working = false; });
  });
}

async function approveRemoval(
  host: HTMLElement,
  code: string,
  review: RemovalApprovalReview,
  replaceReview: (next: RemovalApprovalReview) => void,
  button: HTMLButtonElement,
  decline: HTMLButtonElement,
  codeMatch: HTMLInputElement,
  error: HTMLElement,
  status: HTMLElement,
  waiting: Loading,
  onApproved: () => void,
  release: () => void,
): Promise<void> {
  let submitted = false;
  try {
    const assertion = await navigator.credentials.get({
      publicKey: recoveryAuth.requestOptions(review.options.publicKey),
    });
    if (!(assertion instanceof PublicKeyCredential)) {
      throw new AuthError("This browser did not return a passkey assertion. Try again.");
    }
    const proof = recoveryAuth.credentialProof(assertion);
    submitted = true;
    await approveRemovalApproval(code, review.ceremony, proof);
    onApproved();
    mountRemovalApprovalResult(host, true);
  } catch (failure: unknown) {
    if (submitted) {
      try {
        replaceReview(await inspectRemovalApproval(code));
      } catch {
        // Keep the original safe error; inspection may fail after refusal or expiry.
      }
    }
    release();
    codeMatch.disabled = false;
    decline.disabled = false;
    button.disabled = !codeMatch.checked;
    status.textContent = "";
    error.textContent = safeAuthMessage(failure);
  } finally {
    waiting.done();
  }
}

async function declineRemoval(
  host: HTMLElement,
  code: string,
  button: HTMLButtonElement,
  decline: HTMLButtonElement,
  codeMatch: HTMLInputElement,
  error: HTMLElement,
  status: HTMLElement,
  onDeclined: () => void,
  release: () => void,
): Promise<void> {
  try {
    await declineRemovalApproval(code);
    onDeclined();
    mountRemovalApprovalResult(host, false);
  } catch (failure: unknown) {
    release();
    codeMatch.disabled = false;
    decline.disabled = false;
    button.disabled = !codeMatch.checked;
    status.textContent = "";
    error.textContent = safeAuthMessage(failure);
  }
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
