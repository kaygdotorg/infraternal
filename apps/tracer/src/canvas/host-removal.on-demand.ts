/**
 * Registry-labelled host removal for both machine details and the palette [D16, D168]. The server
 * dry-runs it, then removes it inside the 15-minute admin window, with no passkey of its own (D339).
 * Pending cleanup keeps both the host row and the manual uninstall copy action available.
 * Forget stops pending cleanup for a revoked host within the same admin window (D369, #591).
 * Different hosts are removed in parallel (the server admits eight at once); the same host is never worked on twice, and
 * removals that find the window closed share one passkey prompt (#519).
 */
import { ICON_INFO } from "../../../../packages/ui/src/icons";
import { mountConfirmTip } from "../../../../packages/ui/src/tooltip";
import { recoveryAuth as auth, type AuthStart } from "../auth";
import { confirmHostForget, confirmHostRemoval } from "./host-removal-confirm";
import type { CoreScreen } from "../core-screen";
import type { RemovalOutcome } from "./context";
import { isCanonicalUuid } from "../identifiers";
interface RemovalStart { review: string; action: { host_id: string; host: string; uninstall: boolean } }
/**
 * `manual` carries the command that removes a leftover install. While `host_cleanup` is `pending` the
 * server asks the host when it next connects and this is only the fallback (#409); otherwise the host
 * could not uninstall itself.
 */
interface Result { state: string; host_id: string; host_cleanup: string; message: string; manual?: string | null }
/** Retain the response status so only an expired admin window triggers a passkey request. */
class RemovalError extends Error {
  /** A safe user-facing reason and the protocol status, never the response body. */
  constructor(message: string, readonly status: number) { super(message); }
}
/** Send a bounded host-management step with the browser session and same-origin checks. */
async function post<T>(path: string, body: unknown, failure = "Couldn't remove this host. Check your connection and try again."): Promise<T> {
  const response = await fetch(`/remote/hosts/${path}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new RemovalError(response.status === 401 ? "Your session has ended. Sign in again, then try again."
    : response.status === 403 ? "Your account doesn't have permission for this host. Refresh the host list and try again."
    : response.status === 429 ? "Too many host removals are running at once. Wait a moment, then try again."
    : response.status >= 500 ? "Server error while updating this host. Wait a moment and try again." : failure, response.status);
  return await response.json() as T;
}

/**
 * How many times the admin window has been renewed in this page. A removal that met a closed window compares it with the
 * value it saw before asking, so one that was refused just before a renewal landed retries at once and never prompts again.
 */
let renewals = 0;
/** The passkey renewal in progress, shared so that removals running in parallel open one prompt, not one each (#519). */
let renewing: Promise<void> | undefined;
/** Hosts whose removal waits on the renewal in progress, by id, in the order they asked; the prompt's title names them. */
const waiting = new Map<string, string>();
/** Redraws the open prompt's title when another host joins it. */
let retitle: (() => void) | undefined;
/**
 * The question the shared prompt asks, for everyone it unblocks: the host's name when one waits, both names when two
 * short ones wait, otherwise how many (a long list of names would not fit a compact card).
 */
export function renewalTitle(names: readonly string[]): string {
  const named = names.join(" and ");
  return names.length === 1 || (names.length === 2 && named.length <= 40) ? `Confirm removal of ${named}` : `Confirm removal of ${names.length} hosts`;
}
/** Renew the admin window once for everyone who needs it now; the prompt is titled for every host that has joined it. */
function renewOnce(id: string, name: string): Promise<void> {
  waiting.set(id, name);
  retitle?.();
  return renewing ??= renewWindow(id).then(() => { renewals += 1; }).finally(() => { renewing = undefined; waiting.clear(); retitle = undefined; });
}

/** Prepare first, then invoke WebAuthn directly from a fresh tap so mobile browsers keep user activation. */
async function renewWindow(id: string): Promise<void> {
  const start = await post<AuthStart>("reauth/start", { host_id: id });
  const publicKey = auth.requestOptions(start.options.publicKey);
  await new Promise<void>((resolve, reject) => {
    const title = document.createElement("span");
    const draw = (): void => { title.textContent = renewalTitle([...waiting.values()]); };
    draw();
    retitle = draw;
    mountConfirmTip(null, {
      titleNode: title,
      effect: "Confirm with your passkey to continue. This opens 15 minutes of admin actions.",
      named: true, confirmLabel: "Confirm with passkey", cancelLabel: "Keep host",
      onCancel: () => reject(new Error("Passkey confirmation was cancelled. The host was not removed.")),
      onConfirm: () => {
        // No await before this call: the click itself starts the platform passkey prompt.
        void navigator.credentials.get({ publicKey }).then(async assertion => {
          if (!(assertion instanceof PublicKeyCredential)) throw new Error("Passkey confirmation was cancelled. The host was not removed.");
          await post("reauth/finish", { host_id: id, ceremony: start.ceremony, proof: auth.credentialProof(assertion) }, "Couldn't verify your passkey. Try again.");
          resolve();
        }).catch((error: unknown) => reject(error instanceof DOMException
          ? new Error(error.name === "NotAllowedError" ? "Passkey confirmation was cancelled or timed out. The host was not removed." : "This browser could not confirm your passkey. Try again.") : error));
      },
    });
  });
}

/** Remove only the reviewed host, renewing authority once if the admin window closes at either step. */
async function removeReviewed(id: string, name: string): Promise<Result> {
  /** A new review always binds the selected host to the current session before removal. */
  let seen = renewals;
  const run = async (): Promise<Result> => {
    seen = renewals;
    const start = await post<RemovalStart>("remove/start", { host_id: id, uninstall: true });
    if (start.action.host_id !== id || start.action.uninstall !== true || typeof start.review !== "string") throw new Error("Host confirmation changed. Try again.");
    return post<Result>("remove/finish", { host_id: id, review: start.review });
  };
  try { return await run(); }
  catch (error) {
    if (!(error instanceof RemovalError) || error.status !== 428) throw error;
    // Someone else's renewal finished while this request was in flight: the window is already open again.
    if (renewals === seen) await renewOnce(id, name);
    return run();
  }
}
/** Forget one host, renewing the admin window once if it has closed (#563), like a removal does. */
async function forgetReviewed(id: string, name: string): Promise<{ host_id: string; state: string; message: string }> {
  const seen = renewals;
  const run = (): Promise<{ host_id: string; state: string; message: string }> =>
    post("forget", { host_id: id }, "Couldn't forget this host. Refresh the host list or sign in again, then try again.");
  try { return await run(); }
  catch (error) {
    if (!(error instanceof RemovalError) || error.status !== 428) throw error;
    // A renewal that finished while this request was in flight already reopened the window.
    if (renewals === seen) await renewOnce(id, name);
    return run();
  }
}
/** Confirm a host removal and keep pending cleanup visible until server delivery. */
export async function createHostRemoval(core: CoreScreen, removed: (id: string) => void) {
  // The server's `label` is a sentence describing the action; rows and buttons use this short name instead.
  let label: string | undefined;
  try { const action = await post<{ id: string; label: string }>("actions", {}); if (action.id === "remote.host.remove" && typeof action.label === "string") label = "Remove host"; } catch { /* The optional remote component or owner authority is unavailable. */ }
  /** Hosts with a removal or forget under way. Per host, so two different hosts never wait for each other (#519). */
  const running = new Set<string>();
  /**
   * Errors already said aloud. Removals that waited on one shared passkey renewal all fail with that one error; it gets a
   * single toast, not one per waiting host, while each host still reports its own failed outcome.
   */
  const toasted = new WeakSet<Error>();
  return {
    label: () => label,
    /** Forget a revoked host after the owner confirms the remaining cleanup is theirs. */
    forget(id: string, name: string, anchor: HTMLElement | null, returnFocus?: () => void): void {
      if (!label || !isCanonicalUuid(id)) return;
      /** Said aloud like a removal's refusals (#486): a silent no-op looks like a broken button. */
      const again = (): boolean => { if (!running.has(id)) return false; core.toast.show({ message: `${name} is already being removed or forgotten.`, tone: "error", duration: 6000 }); return true; };
      if (again()) return;
      confirmHostForget(name, anchor, () => {
        if (again()) return;
        running.add(id);
        void forgetReviewed(id, name).then((result) => {
          if (result.host_id !== id || result.state !== "forgotten") throw new Error("Couldn't confirm that this host was forgotten. Refresh the host list to check its state.");
          removed(id);
          core.toast.show({ message: result.message, duration: 5000 });
        }).catch((error: unknown) => core.toast.show({ message: error instanceof Error ? error.message : "Couldn't forget this host. Check your connection and try again.", tone: "error", duration: 6000 })).finally(() => { running.delete(id); });
      }, returnFocus);
    },
    /**
     * Review and persist denial; pending acceptance leaves the host in inventory.
     *
     * It never returns silently (#486): when it cannot start (the account cannot manage hosts, the id is not a host's, or a
     * removal is already running) it says so, by a toast for the card and the sidebar, and in the outcome for the panel's
     * own question. `confirmed` means the panel already asked, so the work starts at once and the outcome is returned for
     * the panel to show inline (pending, removed, failed); otherwise the confirmation card asks first and resolves
     * `undefined`, the card and toasts being its whole answer.
     */
    remove(id: string, name: string, anchor: HTMLElement | null, returnFocus?: () => void, confirmed = false): Promise<RemovalOutcome | undefined> {
      const refusal = !label ? "Removing hosts is not available to this account." : !isCanonicalUuid(id) ? `${name} can't be removed from here.` : running.has(id) ? `${name} is already being removed.` : undefined;
      if (refusal !== undefined) {
        if (!confirmed) core.toast.show({ message: refusal, tone: "error", duration: 6000 });
        return Promise.resolve({ state: "refused", message: refusal });
      }
      const go = async (): Promise<RemovalOutcome> => {
        running.add(id);
        try {
          const result = await removeReviewed(id, name);
          if (!["removed", "pending"].includes(result.state) || result.host_id !== id) throw new Error("Couldn't confirm host removal. Refresh the host list to check its state.");
          if (result.state === "removed") removed(id);
          const manual = result.manual;
          // Pending delivery must keep the same local uninstall action as a completed removal with a leftover installation
          // (#235). A `pending` cleanup is not a failure: the server asks the host to uninstall itself when it next connects,
          // and the command is only the fallback for a machine that never comes back (#409).
          const asking = result.state === "pending" && result.host_cleanup === "pending";
          if (typeof manual === "string" && manual) {
            core.toast.show({
              message: asking
                ? `${name}: access revoked. It uninstalls infraternal as soon as it connects. If it never comes back, copy the command and run it there.`
                : result.state === "pending"
                  ? `${name}: revoked, cleanup pending. infraternal is still installed on it. Copy the command and run it there.`
                  : `${name} was removed here, but infraternal is still installed on it. Copy the command and run it there.`,
              // Waiting, not done: the shared info mark, never the success tick a toast shows by default (#409).
              ...(asking ? { icon: ICON_INFO } : { tone: "error" as const }),
              dismissible: true,
              action: { label: "Copy command", onSelect: () => { void navigator.clipboard.writeText(manual).then(() => core.toast.show({ message: `Command copied. Run it on ${name}.`, duration: 5000 }), () => core.toast.show({ message: result.message, tone: "error", dismissible: true })); } },
            });
          } else {
            core.toast.show({ message: result.message, duration: 5000 });
          }
          return { state: result.state === "removed" ? "removed" : "pending", message: asking ? `${name}: access revoked. It uninstalls infraternal as soon as it connects.` : result.state === "pending" ? `${name}: access revoked. The uninstall is still pending.` : `${name} was removed.` };
        } catch (error) {
          const message = error instanceof Error ? error.message : "Host removal failed. Try again.";
          if (!(error instanceof Error) || !toasted.has(error)) core.toast.show({ message, tone: "error", duration: 6000 });
          if (error instanceof Error) toasted.add(error);
          return { state: "failed", message };
        } finally {
          running.delete(id);
        }
      };
      if (confirmed) return go();
      confirmHostRemoval(name, anchor, () => { void go(); }, returnFocus);
      return Promise.resolve(undefined);
    },
  };
}
