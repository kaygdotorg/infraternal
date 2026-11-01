/**
 * Test double of the version area (#216, `?mock=1&proto=clusters&version=1`). It decides nothing the real server will: it holds
 * one state at a time (the version, every host's agent version, the licence) and answers a check from a script, so every
 * message of the panel can be reached and photographed. Hosts are asked together, as the real check will (`checkFleet`).
 *
 * Dates are computed from today, so "ends in 7 days" is always 7 days from the day the double is opened.
 */
import { checkFleet } from "../../version/updates";
import type { CheckResult, HostVersion, Licence, Target, VersionFacts, VersionSource } from "../../version/source";

const VERSION = "0.4.2";
const NEXT = "0.5.0";
const SERVER = "this server";
/** The release after this one: the worst case runs a release candidate of a later line. */
const nextOf = (version: string): string => (version.startsWith("0.12") ? "0.13.0-rc.1" : NEXT);
const COMMUNITY: Licence = { tier: "community" };
const current = (): HostVersion[] => [{ name: "build-01", version: VERSION }, { name: "monitor01", version: VERSION }, { name: "mac-studio", version: VERSION }, { name: "nas", version: VERSION }];
const behind = (): HostVersion[] => [{ name: "build-01", version: "0.4.0" }, { name: "monitor01", version: VERSION }, { name: "mac-studio", version: VERSION }, { name: "nas", version: "0.3.9" }];

/** What a check finds in a scenario: nothing, one thing on a host, or that the release server did not answer. */
type Script = "clean" | "finds" | "fails";

export interface Scenario {
  id: string;
  label: string;
  hint: string;
  facts: Omit<VersionFacts, "version" | "copy"> & { version?: string };
  /** What the next check finds. */
  script: Script;
}

const facts = (over: Partial<VersionFacts>): Scenario["facts"] => ({ hosts: current(), licence: COMMUNITY, updates: { kind: "current" }, ...over });

export const SCENARIOS: Scenario[] = [
  { id: "current", label: "up to date", hint: "tick · CE · a press checks and finds nothing", script: "clean", facts: facts({}) },
  { id: "unknown", label: "never checked", hint: "no mark · a press checks", script: "clean", facts: facts({ updates: { kind: "unknown" } }) },
  { id: "finds", label: "a check finds one update", hint: "a press: spinner, then 1 update available", script: "finds", facts: facts({}) },
  { id: "behind", label: "two hosts behind", hint: "shows by itself: 2 updates available — proceed?", script: "clean", facts: facts({ hosts: behind(), updates: { kind: "unknown" } }) },
  { id: "failed", label: "cannot check", hint: "cross · Couldn't check — try again", script: "fails", facts: facts({ updates: { kind: "failed", reason: "The release server did not answer within 10 seconds." } }) },
  { id: "homelab", label: "Homelab licence", hint: "one-time · about 10 people", script: "clean", facts: facts({ licence: { tier: "homelab", holder: "kayg", people: { used: 3, max: 10 } } }) },
  { id: "team-full", label: "Team licence, seats nearly full", hint: "9 of 10 people", script: "clean", facts: facts({ licence: { tier: "team", holder: "Northwind Labs", people: { used: 9, max: 10 }, days: 79 } }) },
  { id: "expiring", label: "licence ends in 7 days", hint: "amber EE", script: "clean", facts: facts({ licence: { tier: "team", holder: "Northwind Labs", people: { used: 6, max: 10 }, days: 7 } }) },
  { id: "expired", label: "licence ended", hint: "Community keeps working", script: "clean", facts: facts({ licence: { tier: "community", holder: "Northwind Labs", people: { used: 6, max: 10 }, days: -7, endedTier: "team" } }) },
  // The worst case: a release-candidate version, forty hosts that lag (one with a very long name), and a company with a very long name.
  { id: "worst", label: "worst case", hint: "40 hosts behind, long names, release candidate", script: "finds", facts: facts({
    version: "0.12.104-rc.3",
    hosts: [{ name: "build-agent-eu-central-1a-ephemeral-0042.internal.example.com", version: "0.12.3" }, ...Array.from({ length: 39 }, (_, i): HostVersion => ({ name: `fleet-${String(i + 1).padStart(4, "0")}`, version: i % 5 === 0 ? "0.11.0" : "0.12.97" }))],
    licence: { tier: "enterprise", holder: "Northwind Industries Holdings International (EMEA Platform Infrastructure)", people: { used: 1284, max: 1500 }, days: 6 },
    updates: { kind: "unknown" },
  }) },
];

const wait = (ms: number): Promise<void> => new Promise((resolve) => { window.setTimeout(resolve, ms); });

export interface VersionDouble extends VersionSource {
  scenario(): string;
  setScenario(id: string): Scenario;
  /** How many probes were in flight at once during the last check (the specs prove the hosts are asked together). */
  lastParallelism(): number;
}

export function createVersionDouble(initial = "current"): VersionDouble {
  const find = (id: string): Scenario => SCENARIOS.find((s) => s.id === id) ?? SCENARIOS[0]!;
  let scenario = find(initial);
  let state: VersionFacts = materialise(scenario);
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const run of listeners) run(); };
  let parallel = 0;

  function materialise(s: Scenario): VersionFacts {
    const version = s.facts.version ?? VERSION;
    return { ...structuredClone(s.facts), version, copy: `${version}-3f9c2ab` };
  }

  return {
    facts: () => state,
    scenario: () => scenario.id,
    setScenario(id) { scenario = find(id); state = materialise(scenario); emit(); return scenario; },
    lastParallelism: () => parallel,
    async check(): Promise<CheckResult> {
      // The server and every host are asked together; the server is one more probe beside the hosts.
      const names = [SERVER, ...state.hosts.map((h) => h.name)];
      let inFlight = 0;
      parallel = 0;
      const probe = async (name: string): Promise<Target | null> => {
        inFlight++;
        parallel = Math.max(parallel, inFlight);
        await wait(500);
        inFlight--;
        if (scenario.script === "fails") throw new Error("The release server did not answer within 10 seconds.");
        if (name === SERVER) return scenario.script === "finds" ? { name: SERVER, server: true, from: state.version, to: nextOf(state.version) } : null;
        const host = state.hosts.find((h) => h.name === name);
        return host?.version !== undefined && host.version !== state.version ? { name, from: host.version, to: state.version } : null;
      };
      return checkFleet(names, probe);
    },
    async proceed(targets): Promise<void> {
      await wait(900);
      // An agent runs the version of the server it joined (lockstep), so updating the server moves every host with it.
      const server = targets.find((t) => t.server);
      const version = server ? server.to : state.version;
      const done = new Set(targets.map((t) => t.name));
      state = { ...state, version, copy: `${version}-3f9c2ab`, hosts: state.hosts.map((h) => (server || done.has(h.name) ? { ...h, version } : h)), updates: { kind: "current" } };
      scenario = { ...scenario, script: "clean" };
      emit();
    },
    onChange(run) { listeners.add(run); return () => { listeners.delete(run); }; },
  };
}
