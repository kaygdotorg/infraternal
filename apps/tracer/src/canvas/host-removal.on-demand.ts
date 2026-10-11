/** Registry-labelled, freshly authenticated host removal for both machine details and the palette [D16, D168]. */
import { mountConfirmTip } from "../../../../packages/ui/src/tooltip";
import { recoveryAuth as auth, type AuthStart } from "../auth";
import type { CoreScreen } from "../core-screen";
import { isCanonicalUuid } from "../identifiers";
interface RemovalStart extends AuthStart { action: { host_id: string; host: string; uninstall: boolean } }
interface Result { state: string; host_id: string; host_cleanup: string; message: string }
async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`/remote/hosts/${path}`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error("The host could not be removed. Confirm with the owner's passkey and try again.");
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
      mountConfirmTip(anchor, { label: `${label}: ${name}`, title: `Remove ${name}?`, effect: "Revoke its access, forget its SSH key and uninstall the infraternal agent. A fresh passkey confirmation is required.", named: true, confirmLabel: label, cancelLabel: "Keep host", onConfirm: () => {
        busy = true;
        void (async () => {
          const start = await post<RemovalStart>("remove/start", { host_id: id, uninstall: true });
          if (start.action.host_id !== id || start.action.uninstall !== true) throw new Error("Host confirmation changed. Try again.");
          const proof = await navigator.credentials.get({ publicKey: auth.requestOptions(start.options.publicKey) });
          if (!(proof instanceof PublicKeyCredential)) throw new Error("Passkey confirmation was cancelled.");
          const result = await post<Result>("remove/finish", { host_id: id, ceremony: start.ceremony, proof: auth.credentialProof(proof) });
          if (result.state !== "removed" || result.host_id !== id) throw new Error("Host removal could not be confirmed.");
          removed(id);
          core.toast.show({ message: result.message, duration: result.host_cleanup === "requested" ? 5000 : 12000 });
        })().catch((error: unknown) => core.toast.show({ message: error instanceof Error ? error.message : "Host removal failed. Try again.", tone: "error", duration: 6000 })).finally(() => { busy = false; });
      } });
    },
  };
}
