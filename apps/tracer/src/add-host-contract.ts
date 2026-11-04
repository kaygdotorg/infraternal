/** Read-only mock discovery data shared by the add-host window and its test double. */
import type { HostSource } from "../../../packages/ui/src/source-icons";

/**
 * One host the add-host window can show during discovery, as the mock data describes it.
 * - `sources`: where the host was found (see `HostSource`); a host can have several.
 * - `reachability`: `ready` can be connected to now, `unreachable` did not answer, `mesh-policy` is blocked by mesh access rules.
 * - `evidence`: the short text shown to explain the reachability.
 * - `alreadyAdded`: the host is already in the user's list.
 * - `rootAvailable`: the wizard may offer to set up root access.
 * - `credentialRequired`: the user must give a credential before connecting.
 * - `authentication`: what the mock host answers to the credential: `accepted` or `refused`.
 */
export interface AddHostFixture {
  id: string;
  user: string;
  address: string;
  operatingSystem: string;
  architecture: string;
  sources: HostSource[];
  reachability: "ready" | "unreachable" | "mesh-policy";
  evidence: string;
  alreadyAdded: boolean;
  rootAvailable: boolean;
  credentialRequired: boolean;
  authentication: "accepted" | "refused";
}
