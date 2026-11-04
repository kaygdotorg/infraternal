/**
 * Reviews one pending request and approves it only after a fresh passkey tap. Two kinds share this screen, the same
 * card and the same approval steps (D311, #263):
 * - `sign_in`: a computer asks for a CLI credential (`infraternal sign-in`);
 * - `join_machine`: a machine asks to be added to this server (`infraternal up`), shown as "Add <name> to <server>"
 *   with how it will run and the fingerprint of its key.
 *
 * Nothing approves by itself. The person matches the code with their terminal, ticks that they did, and taps their
 * passkey; each machine needs its own tap. On the join screen Escape returns to the app, and the browser's Back leaves
 * the page; neither decides anything, so the request simply expires.
 */
import {
  approveDeviceApproval,
  inspectDeviceApproval,
  isDeviceUserCode,
  keyLifetimeLabel,
  type DeviceApprovalReview,
  type JoinApprovalReview,
} from "./auth";
import type { ApprovalKind } from "./approval-link";
import { shortFingerprint } from "./key-fingerprint";
import { safeAuthMessage } from "./onboarding";
import { loading, type Loading } from "../../../packages/ui/src/countup";
import { createKeyValueList } from "../../../packages/ui/src/kv-list";
import { springCheckbox } from "../../../packages/ui/src/tick";
import { BRAND_MARK, KEY_MARK } from "./auth-marks";

export interface ApprovalHooks {
  /** The server accepted the approval. */
  onApproved: () => void;
  /** The person left without deciding (Escape). The request stays pending until it expires. */
  onCancel: () => void;
}

/** Loads the request facts only after a signed-in browser session exists. */
export async function mountDeviceApproval(
  host: HTMLElement,
  kind: ApprovalKind,
  code: string | null,
  linkError: string | undefined,
  hooks: ApprovalHooks,
): Promise<void> {
  const join = kind === "join_machine";
  if (linkError) {
    renderError(host, join, linkError);
    return;
  }
  if (!code || !isDeviceUserCode(code)) {
    renderError(host, join, join
      ? "This link is incomplete. Run infraternal up again on the machine you want to add."
      : "This sign-in link is incomplete. Ask the person who started it to run infraternal sign-in again.");
    return;
  }

  renderChecking(host, join);
  try {
    if (join) {
      const review = await inspectDeviceApproval(code, "join_machine");
      renderJoinReview(host, code, review, hooks);
    } else {
      const review = await inspectDeviceApproval(code, "sign_in");
      renderReview(host, code, review, hooks);
    }
  } catch (error: unknown) {
    renderError(host, join, safeAuthMessage(error));
  }
}

/** Keeps the approved link on its success screen if the page resumes from the background. */
export function mountDeviceApprovalSuccess(host: HTMLElement, kind: ApprovalKind = "sign_in"): void {
  const join = kind === "join_machine";
  host.innerHTML = `<section class="auth-screen" aria-label="${join ? "Machine approved" : "Device sign-in approved"}">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">${join ? "Machine approved" : "Device approved"}</h1>
      <p class="auth-lede">${join
        ? "Return to the terminal. It will finish adding this machine."
        : "Return to the terminal. It will finish saving this device's credential."}</p>
    </section>
  </section>`;
}

function renderChecking(host: HTMLElement, join: boolean): void {
  host.innerHTML = `<section class="auth-screen" aria-label="${join ? "Add machine approval" : "Device sign-in approval"}">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">${join ? "Add a machine" : "Approve device sign-in"}</h1>
      <p class="auth-lede">${join ? "Checking the machine that asked to join…" : "Checking the requested device and access…"}</p>
      <p class="auth-loading" role="status" aria-live="polite">Please wait</p>
    </section>
  </section>`;
}

/** The parts both kinds share, from the code down to the passkey button. `facts` is what differs. */
const CODE_BLOCK = `<label class="auth-label" for="device-approval-code">Code</label>
      <output class="auth-input auth-mono device-approval-code" id="device-approval-code"></output>
      <p class="auth-hint">Match this code with the code in your terminal before you approve.</p>`;
const ACTION_BLOCK = `<div class="auth-note"><div><p class="auth-message" id="device-approval-error" role="alert"></p></div></div>
      <button class="auth-primary auth-login" id="device-approval-approve" type="button">${KEY_MARK}<span>Approve with passkey</span><span class="busy-count" hidden></span></button>
      <div class="auth-note"><div><p class="auth-loading" id="device-approval-status" role="status" aria-live="polite"></p></div></div>`;

function renderReview(
  host: HTMLElement,
  code: string,
  review: DeviceApprovalReview,
  hooks: ApprovalHooks,
): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Device sign-in approval">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">Approve device sign-in</h1>
      <p class="auth-lede">Review this computer and the access it is requesting.</p>
      ${CODE_BLOCK}
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
      ${ACTION_BLOCK}
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
  wireApproval(host, code, "sign_in", hooks);
}

/**
 * "Add <name> to <server>": what is being approved, in plain words. The name is the machine's own claim, so it is only
 * ever set as text; the server is the page's own address, which the machine cannot choose.
 */
function renderJoinReview(host: HTMLElement, code: string, review: JoinApprovalReview, hooks: ApprovalHooks): void {
  host.innerHTML = `<section class="auth-screen" aria-label="Add machine approval">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title" class="device-approval-title"></h1>
      <p class="auth-lede">A machine asked to join. Check it is yours, then approve it with your passkey.</p>
      ${CODE_BLOCK}
      <div class="device-approval-kv" id="device-approval-facts"></div>
      <label class="auth-check"><input id="device-approval-code-match" type="checkbox" /><span>I checked that the code and key match my terminal</span></label>
      <p class="device-approval-note">Only approve a machine you started this on. Closing this page leaves it pending until it expires.</p>
      ${ACTION_BLOCK}
    </section>
  </section>`;

  host.querySelector<HTMLElement>("#device-approval-title")!.textContent = `Add ${review.hostname} to ${location.host}`;
  host.querySelector<HTMLOutputElement>("#device-approval-code")!.textContent = code;
  const facts = createKeyValueList("Machine to add");
  facts.set([
    { key: "Runs as", value: review.mode === "system" ? "System service" : "User service" },
    { key: "Machine key", value: shortFingerprint(review.keyFingerprint), copy: review.keyFingerprint },
  ]);
  host.querySelector<HTMLElement>("#device-approval-facts")!.append(facts.root);
  wireApproval(host, code, "join_machine", hooks, facts.dispose);
}

/**
 * The approval steps, identical for both kinds: the match tick enables the button, the button asks for a fresh passkey
 * and only then approves. A passkey given for one request is never reused for the next. `leave` frees what the screen
 * holds; Escape is ignored while the passkey prompt is open because the system prompt owns that key.
 */
function wireApproval(host: HTMLElement, code: string, kind: ApprovalKind, hooks: ApprovalHooks, dispose?: () => void): void {
  const button = host.querySelector<HTMLButtonElement>("#device-approval-approve")!;
  const codeMatch = host.querySelector<HTMLInputElement>("#device-approval-code-match")!;
  const error = host.querySelector<HTMLElement>("#device-approval-error")!;
  const status = host.querySelector<HTMLElement>("#device-approval-status")!;
  let approving = false;
  const leave = (): void => {
    document.removeEventListener("keydown", escape);
    dispose?.();
  };
  const escape = (event: KeyboardEvent): void => {
    if (event.key !== "Escape" || event.defaultPrevented || approving) return;
    if (!host.contains(button)) { leave(); return; }
    leave();
    hooks.onCancel();
  };
  // The CLI sign-in screen keeps its old behaviour; only the new join screen answers Escape.
  if (kind === "join_machine") document.addEventListener("keydown", escape);
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
        // The approval is its own passkey tap, bound to this code.
        await approveDeviceApproval(code, kind);
        leave();
        hooks.onApproved();
        mountDeviceApprovalSuccess(host, kind);
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

function renderError(host: HTMLElement, join: boolean, message: string): void {
  const title = join ? "Can't add this machine" : "Device sign-in unavailable";
  host.innerHTML = `<section class="auth-screen" aria-label="${title}">
    <section class="auth-card auth-signin ui-overlay-surface" aria-labelledby="device-approval-title">
      <div class="auth-mark">${BRAND_MARK}<span>infraternal</span></div>
      <h1 id="device-approval-title">${title}</h1>
      <p class="auth-lede" id="device-approval-error" role="alert"></p>
    </section>
  </section>`;
  host.querySelector<HTMLElement>("#device-approval-error")!.textContent = message;
}
