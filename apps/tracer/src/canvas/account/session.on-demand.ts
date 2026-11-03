// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The signed-in person's account state, loaded on demand (D188, #322, #330): the model that the card and Settings →
 * Account read, and the two security rows of Settings → Account (passkeys, recovery key).
 *
 * Why its own chunk: product.ts used to import `identityModel` and build these rows itself, which put about 5 KB gzip
 * into the critical class for a card and a Settings pane nobody opens before the first paint. product.ts now holds only
 * thin shells for the rows (Settings reads them synchronously) and fetches this module when the canvas is up, or at once
 * when Settings → Account opens first.
 *
 * Invariant: everything that imports this file must itself load on demand or through a dynamic import, or the bundler
 * moves it back into the critical class.
 */
import type { StatusActionPref } from "../../../../../packages/ui/src/settings-panels";
import type { ToastController } from "../../../../../packages/ui/src/toast";
import { identityModel, type AccountModel } from "./model";

export interface AccountSessionEnv {
  person: { name: string; username: string };
  accountId: string;
  sessionIncarnation?: string;
  toast: ToastController;
}

export interface AccountSession {
  model: AccountModel;
  /** The Settings → Account rows: same order and ids as the shells in product.ts. */
  statuses: StatusActionPref[];
}

export function createAccountSession(env: AccountSessionEnv): AccountSession {
  const model = identityModel(env.person, env.accountId, env.sessionIncarnation);
  let busy = false;
  const listeners = new Set<() => void>();
  const changed = (): void => { for (const listener of listeners) listener(); };
  const onChange = (listener: () => void): (() => void) => {
    listeners.add(listener);
    const off = model.onChange(listener);
    return () => { listeners.delete(listener); off(); };
  };
  const statuses: StatusActionPref[] = [{
    id: "passkeys", title: "Passkeys",
    text: () => busy ? "Follow the passkey prompts" : model.person().passkeys === undefined ? "Unavailable" : `${model.person().passkeys} set up`,
    action: () => !busy && model.person().passkeys === 1 ? "Add a second" : undefined,
    act: () => {
      if (busy) return;
      busy = true;
      changed();
      void import("../../auth").then((auth) => auth.addSecondPasskey(env.accountId))
        .then(() => { window.location.reload(); })
        .catch(() => {
          busy = false;
          changed();
          env.toast.show({ message: "The passkey could not be added. Reload before trying again.", tone: "error", action: { label: "Reload", onSelect: () => { window.location.reload(); } } });
        });
    },
    refresh: () => undefined, onChange,
  }, {
    id: "recovery", title: "Recovery key",
    text: () => model.person().recovery ? `${model.person().recovery?.setUp ? "Set up" : "Not set up"}; verification history unavailable` : undefined,
    action: () => undefined, act: () => undefined,
    refresh: () => undefined, onChange,
  }];
  return { model, statuses };
}
