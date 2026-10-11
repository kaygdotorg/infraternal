/**
 * The mockup's `ProvisioningService`: the product adapter pointed at the test double.
 *
 * The test double serves the same wire protocol and the proposed endpoints (`test/provisioning-double.ts`), so
 * everything the wizard does in a mockup goes through the real adapter code. CA readiness is scripted for setup/unlock screenshots and the saved
 * key is synthetic: the browser keeps no passkey-wrapped key yet, so a mockup can switch one on (`&savedkey=1`) to show
 * that path. Its text is not a key.
 */
import { createRealProvisioning } from "../addhost/real";
import type { ProvisioningService } from "../addhost/service";

export function createMockProvisioning(options: { savedKey: boolean; authority?: string }): ProvisioningService {
  const real = createRealProvisioning();
  // A scripted lock stays unlocked for the rest of the tab's life, as a real server's does until it restarts, so a
  // reload after unlocking (a new sign-in) finds it open. Session storage is per tab and gone with it.
  const UNLOCKED_KEY = "mock-ca-unlocked";
  const remembered = (): boolean => { try { return sessionStorage.getItem(UNLOCKED_KEY) === "1"; } catch { return false; } };
  const scripted = options.authority === "fresh" || options.authority === "locked";
  const isLocked = (): boolean => scripted && !remembered();
  return {
    ...real,
    authorityStatus: async () => ({ initialized: options.authority !== "fresh", locked: isLocked() }),
    unlockAuthority: async () => { try { sessionStorage.setItem(UNLOCKED_KEY, "1"); } catch { /* the double stays locked */ } },
    async savedKey() {
      return options.savedKey ? { label: "work laptop key", unwrap: async () => "mock-saved-key-text" } : undefined;
    },
  };
}
