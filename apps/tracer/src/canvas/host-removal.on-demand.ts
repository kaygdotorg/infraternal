/**
 * Registry-labelled host removal for both machine details and the palette [D16, D168]. The server
 * dry-runs it, then removes it inside the 15-minute admin window, with no passkey of its own (D339).
 * Pending cleanup keeps both the host row and the manual uninstall copy action available.
 * D369 Forget cancels an unreachable retirement here, in that same window, without touching the machine.
 */
import { ICON_INFO } from "../../../../packages/ui/src/icons";
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
/** Send a bounded host-management step with the browser session and same-origin checks. */
async function post<T>(path: string, body: unknown, failure = "The host could not be removed. Sign in again, then try again."): Promise<T> {
  const response = await fetch(`/remote/hosts/${path}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(failure);
  return await response.json() as T;
}
/** Confirm a host removal and keep pending cleanup visible until server delivery. */
export async function createHostRemoval(core: CoreScreen, removed: (id: string) => void) {
  // The server's `label` is a sentence describing the action; rows and buttons use this short name instead.
  let label: string | undefined;
  try { const action = await post<{ id: string; label: string }>("actions", {}); if (action.id === "remote.host.remove" && typeof action.label === "string") label = "Remove host"; } catch { /* The optional remote component or owner authority is unavailable. */ }
  let busy = false;
  return {
    label: () => label,
    /** Forget an unreachable retirement here without sending anything to the machine. */
    forget(id: string, name: string, anchor: HTMLElement | null, returnFocus?: () => void): void {
      if (!label || !isCanonicalUuid(id) || busy) return;
      confirmHostForget(name, anchor, () => {
        busy = true;
        void post<{ host_id: string; state: string; message: string }>("forget", { host_id: id }, "The host could not be forgotten. Refresh the list or sign in again, then try again.").then((result) => {
          if (result.host_id !== id || result.state !== "forgotten") throw new Error("Host forgetting could not be confirmed.");
          removed(id);
          core.toast.show({ message: result.message, duration: 5000 });
        }).catch((error: unknown) => core.toast.show({ message: error instanceof Error ? error.message : "The host could not be forgotten. Try again.", tone: "error", duration: 6000 })).finally(() => { busy = false; });
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
      const refusal = !label ? "Removing hosts is not available to this account." : !isCanonicalUuid(id) ? `${name} can't be removed from here.` : busy ? "Another host removal is still running. Try again in a moment." : undefined;
      if (refusal !== undefined) {
        if (!confirmed) core.toast.show({ message: refusal, tone: "error", duration: 6000 });
        return Promise.resolve({ state: "refused", message: refusal });
      }
      const go = async (): Promise<RemovalOutcome> => {
        busy = true;
        try {
          const start = await post<RemovalStart>("remove/start", { host_id: id, uninstall: true });
          // The dry run must name the host the person confirmed; its review removes exactly that one.
          if (start.action.host_id !== id || start.action.uninstall !== true || typeof start.review !== "string") throw new Error("Host confirmation changed. Try again.");
          const result = await post<Result>("remove/finish", { host_id: id, review: start.review });
          if (!["removed", "pending"].includes(result.state) || result.host_id !== id) throw new Error("Host removal could not be confirmed.");
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
          core.toast.show({ message, tone: "error", duration: 6000 });
          return { state: "failed", message };
        } finally {
          busy = false;
        }
      };
      if (confirmed) return go();
      confirmHostRemoval(name, anchor, () => { void go(); }, returnFocus);
      return Promise.resolve(undefined);
    },
  };
}
