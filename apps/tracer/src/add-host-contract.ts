/** Read-only mock discovery data shared by the add-host window and its test double. */
import type { HostSource } from "../../../packages/ui/src/source-icons";

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
