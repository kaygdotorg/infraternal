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
  let locked = options.authority === "fresh" || options.authority === "locked";
  return {
    ...real,
    authorityStatus: async () => ({ initialized: options.authority !== "fresh", locked }),
    unlockAuthority: async () => { locked = false; },
    async savedKey() {
      return options.savedKey ? { label: "work laptop key", unwrap: async () => "mock-saved-key-text" } : undefined;
    },
  };
}
