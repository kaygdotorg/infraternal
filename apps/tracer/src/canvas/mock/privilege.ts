/**
 * The test double behind the privileged-access consent (#215, D286): what a machine reports about how the person may become
 * privileged on it, and what happens when they try. `?privilege=<scenario>` turns the "Access level" row on in the test
 * double and picks the scenario for every machine, so each branch of the flow can be walked on any window:
 * sudo, doas, root (only the root password), denied (sudo exists but this person may not use it), wrong (the first password
 * is refused), offline, timeout (no answer for 5 seconds), bulk (three machines selected, two allow sudo).
 *
 * The double never keeps a password: `attempt` reads its length and forgets it, as the product's service must.
 */
import type { Method, Outcome, PrivilegeService, Probe } from "../sessions/privilege";

/** The scenario names that `?privilege=` accepts. */
export const SCENARIOS = ["sudo", "doas", "root", "denied", "wrong", "offline", "timeout", "bulk"] as const;
/** One of the scenario names. */
export type Scenario = (typeof SCENARIOS)[number];

/** The machines a "bulk" run covers, and which of them allow sudo. */
const SELECTION = ["build-01", "nix-cache", "edge-arm"];
/** Which machines of the bulk selection allow sudo. */
const ALLOWS_SUDO = new Set(["build-01", "nix-cache"]);

/** True when `value` is a scenario name. Use it to check a query parameter. */
export const isScenario = (value: string | null): value is Scenario => SCENARIOS.includes(value as Scenario);

/** Makes a privilege service that behaves like `scenario` on every machine. It forgets each secret as soon as it has read its length. */
export function createPrivilegeDouble(scenario: Scenario): PrivilegeService {
  const full = new Set<string>();
  const wrongOnce = new Set<string>();
  const listeners = new Set<() => void>();
  const delay = (ms: number): Promise<void> => new Promise((resolve) => window.setTimeout(resolve, ms));
  const probe = (host: string): Probe => {
    const reachable = scenario !== "offline";
    if (scenario === "doas") return { method: "doas", denied: false, reachable };
    if (scenario === "root") return { method: "root", denied: false, reachable };
    if (scenario === "denied") return { method: "root", denied: true, reachable };
    if (scenario === "bulk") return ALLOWS_SUDO.has(host) ? { method: "sudo", denied: false, reachable } : { method: "root", denied: true, reachable };
    return { method: "sudo", denied: false, reachable };
  };
  return {
    selection: (host) => (scenario === "bulk" && SELECTION.includes(host) ? SELECTION : [host]),
    sudoHosts: (host) => (scenario === "bulk" && SELECTION.includes(host) ? SELECTION.filter((h) => ALLOWS_SUDO.has(h) && !full.has(h)) : [host]),
    isFull: (host) => full.has(host),
    probe: (host) => Promise.resolve(probe(host)),
    async attempt(host: string, method: Method, secret: string): Promise<Outcome> {
      void secret.length; // read and forgotten: the double keeps nothing
      if (scenario === "timeout") { await delay(5200); return { ok: false, reason: "timeout" }; }
      if (scenario === "offline") { await delay(400); return { ok: false, reason: "offline" }; }
      await delay(method === "root" ? 1300 : 1000);
      if (scenario === "wrong" && !wrongOnce.has(host)) { wrongOnce.add(host); return { ok: false, reason: "wrong" }; }
      full.add(host);
      for (const listener of listeners) listener();
      return { ok: true };
    },
    onChange(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
}
