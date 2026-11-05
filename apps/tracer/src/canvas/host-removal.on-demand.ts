/**
 * Registry-labelled host removal for both machine details and the palette [D16, D168]. The server
 * dry-runs it, then removes it inside the 15-minute admin window, with no passkey of its own (D339).
 */
import { mountConfirmTip } from "../../../../packages/ui/src/tooltip";
import type { CoreScreen } from "../core-screen";
import { isCanonicalUuid } from "../identifiers";
interface RemovalStart { review: string; action: { host_id: string; host: string; uninstall: boolean } }
/** `manual` carries the command that removes a leftover install, when the host could not uninstall itself. */
interface Result { state: string; host_id: string; host_cleanup: string; message: string; manual?: string | null }
async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`/remote/hosts/${path}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error("The host could not be removed. Sign in again, then try again.");
  return await response.json() as T;
}
export async function createHostRemoval(core: CoreScreen, removed: (id: string) => void) {
  let label: string | undefined;
  try { const action = await post<{ id: string; label: string }>("actions", {}); if (action.id === "remote.host.remove" && typeof action.label === "string") label = action.label; } catch { /* The optional remote component or owner authority is unavailable. */ }
  let busy = false;
  return {
    label: () => label,
    remove(id: string, name: string, anchor: HTMLElement): void {
      if (!label || !isCanonicalUuid(id) || busy) return;
      mountConfirmTip(anchor, { label: `${label}: ${name}`, title: `Remove ${name}?`, effect: "Revoke its access, forget its SSH key and uninstall the infraternal agent.", named: true, confirmLabel: label, cancelLabel: "Keep host", onConfirm: () => {
        busy = true;
        void (async () => {
          const start = await post<RemovalStart>("remove/start", { host_id: id, uninstall: true });
          // The dry run must name the host the person confirmed; its review removes exactly that one.
          if (start.action.host_id !== id || start.action.uninstall !== true || typeof start.review !== "string") throw new Error("Host confirmation changed. Try again.");
          const result = await post<Result>("remove/finish", { host_id: id, review: start.review });
          if (result.state !== "removed" || result.host_id !== id) throw new Error("Host removal could not be confirmed.");
          removed(id);
          const manual = result.manual;
          if (typeof manual === "string" && manual) {
            // The record is gone, so nothing here can retry: say so by name and hand over the commands (#235).
            core.toast.show({
              message: `${name} was removed here, but infraternal is still installed on it. Copy the command and run it there.`,
              tone: "error",
              dismissible: true,
              action: { label: "Copy command", onSelect: () => { void navigator.clipboard.writeText(manual).then(() => core.toast.show({ message: `Command copied. Run it on ${name}.`, duration: 5000 }), () => core.toast.show({ message: result.message, tone: "error", dismissible: true })); } },
            });
          } else {
            core.toast.show({ message: result.message, duration: 5000 });
          }
        })().catch((error: unknown) => core.toast.show({ message: error instanceof Error ? error.message : "Host removal failed. Try again.", tone: "error", duration: 6000 })).finally(() => { busy = false; });
      } });
    },
  };
}
