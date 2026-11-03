/**
 * What the privileged-access consent (windows/access-level.on-demand.ts, #215, D286) needs from an instance: whether the
 * infraternal agent on a machine already has full access, how this person can become privileged there (sudo, doas, or only
 * the root password), and a try with a secret. The instance supplies it as `Adapters.privilege`; where it is absent the
 * machine's details show no "Access level" row and nothing about privileges is drawn.
 *
 * There is no server endpoint behind this yet (it needs one that raises the agent's privileges with a secret that is used
 * once and never stored or logged). The test double in the tracer's mock implements it for the specs.
 */
export type Method = "sudo" | "doas" | "root";

/** How a machine answers "can this person become privileged here?". */
export interface Probe {
  method: Method;
  /** Sudo is installed but this person may not use it: the root password is asked directly. */
  denied: boolean;
  reachable: boolean;
}

export type Outcome = { ok: true } | { ok: false; reason: "wrong" | "timeout" | "offline" };

export interface PrivilegeService {
  /** Machines the person has selected together with this one (bulk consent), otherwise just this one. */
  selection(host: string): string[];
  /** Those of the selection that allow sudo ("apply to all N hosts that allow sudo"). */
  sudoHosts(host: string): string[];
  /** The infraternal agent on the machine already runs with full access. */
  isFull(host: string): boolean;
  /** Asks the machine how this person becomes privileged there. */
  probe(host: string): Promise<Probe>;
  /**
   * Tries to give the infraternal agent on `host` full access with this secret. The secret is used for this call only:
   * implementations must not keep, log or put it in argv. Resolves after the machine's own time.
   */
  attempt(host: string, method: Method, secret: string): Promise<Outcome>;
  /** Called when any machine's level changes (the row repaints). Returns the remover. */
  onChange(listener: () => void): () => void;
}
