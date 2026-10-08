/**
 * The mockup's `ProvisioningService`: the product adapter pointed at the test double.
 *
 * The test double serves the same wire protocol and the proposed endpoints (`test/provisioning-double.ts`), so
 * everything the wizard does in a mockup goes through the real adapter code. The only fake here is the saved
 * key: the browser keeps no passkey-wrapped key yet, so a mockup can switch one on (`&savedkey=1`) to show
 * that path. Its text is not a key.
 */
import { createRealProvisioning } from "../addhost/real";
import type { ProvisioningService } from "../addhost/service";

export function createMockProvisioning(options: { savedKey: boolean }): ProvisioningService {
  const real = createRealProvisioning();
  return {
    ...real,
    async savedKey() {
      return options.savedKey ? { label: "work laptop key", unwrap: async () => "mock-saved-key-text" } : undefined;
    },
  };
}
