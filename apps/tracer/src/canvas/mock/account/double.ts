/**
 * Test double of the person's card (D283, `?account=1`). It holds one person at a time and decides nothing the real server
 * will. It is also the regression fixture of the card: the data sets of the toggle (data-ids.ts) are the realistic worst
 * case, the empty case and the case of exactly one of everything, and the card is tested against all of them.
 *
 * The fixtures carry what the product cannot say yet (passkeys, the recovery key, devices, the machines each account logs in
 * to, with their tags), so the whole card can be seen before the server can say it. Every machine has tags except a few on
 * purpose: a tag is a colour (TASTE: named things are chips), and a card where every machine has the same colour tells nothing.
 */
import type { AccountModel, Login, LoginHost, Person } from "../../account/model";
import type { HostPlatform } from "../../../../../../packages/ui/src/host-icons";
import { DATA_IDS, type DataId } from "../data-ids";
export { DATA_IDS, type DataId };

const DAY = 86_400_000;
/** A recovery key last verified `days` days ago. */
const verified = (days: number): { setUp: true; verifiedAt: number } => ({ setUp: true, verifiedAt: Date.now() - days * DAY });

const host = (name: string, platform: HostPlatform, ...tags: string[]): LoginHost => ({ name, platform, tags });
const linux = (name: string, ...tags: string[]): LoginHost => host(name, "ubuntu", ...tags);
const mac = (name: string, ...tags: string[]): LoginHost => host(name, "apple", ...tags);

/** kayg alone on a Community server: twelve machines as themselves (tagged), two as root. */
const MANY: LoginHost[] = [
  linux("build-01", "ci", "prod"), linux("monitor01", "ops"), linux("nas", "storage", "home"), host("edge-arm", "debian", "edge", "prod"),
  linux("db-01", "db", "prod"), linux("ci-02", "ci"), linux("gpu-01", "lab", "gpu"), linux("proxy", "edge", "prod"), host("backup", "debian", "storage"),
  linux("lab-01", "lab"), linux("lab-02", "lab", "gpu"), linux("lab-03"),
];

const KAYG: Person = {
  name: "Kay G", username: "kayg", email: "",
  loginAs: [{ account: "kayg", hosts: MANY }, { account: "root", hosts: [MANY[0]!, MANY[2]!] }],
  passkeys: 2, recovery: verified(6), devices: 4,
};

export interface Scenario {
  id: string;
  label: string;
  hint: string;
  keywords?: string;
  person: Person;
}

export const SCENARIOS: Scenario[] = [
  { id: "community", label: "Community, one person", hint: "no organisation, no role, no email", keywords: "community ce one person single empty email", person: KAYG },
  { id: "member", label: "Team member (EE)", hint: "Northwind Labs · Member · email set", keywords: "team member ee organisation role northwind",
    person: { name: "Asha Verma", username: "asha", email: "asha@northwind.example", org: { name: "Northwind Labs", role: "Member" }, loginAs: [{ account: "asha", hosts: [MANY[0]!, MANY[1]!, mac("mac-studio", "design"), MANY[2]!, MANY[5]!] }], passkeys: 2, recovery: verified(21), devices: 3 } },
  { id: "admin", label: "Admin (EE)", hint: "Northwind Labs · Admin", keywords: "admin administrator ee organisation role northwind",
    person: { name: "Ravi Menon", username: "ravi", email: "ravi@northwind.example", org: { name: "Northwind Labs", role: "Admin" }, loginAs: [{ account: "ravi", hosts: MANY.slice(0, 9) }, { account: "root", hosts: [MANY[0]!, MANY[4]!, MANY[2]!] }, { account: "deploy", hosts: [MANY[5]!, MANY[7]!] }], passkeys: 3, recovery: verified(2), devices: 5 } },
  { id: "recovery", label: "recovery key never verified", hint: "the value says it; amber mark on the pill", keywords: "attention recovery key never verified amber concern",
    person: { ...KAYG, recovery: { setUp: true, verifiedAt: null } } },
  { id: "recovery-stale", label: "recovery key not verified for months", hint: "\"Not verified since <date>, verify now\"", keywords: "attention recovery key stale old verify date amber concern",
    person: { ...KAYG, recovery: verified(200) } },
  { id: "recovery-none", label: "no recovery key", hint: "\"Not set up\"", keywords: "attention recovery key not set up missing amber concern",
    person: { ...KAYG, recovery: { setUp: false, verifiedAt: null } } },
  { id: "one-passkey", label: "one passkey only", hint: "the value says it; amber mark on the pill", keywords: "attention passkey one only amber concern",
    person: { ...KAYG, passkeys: 1, devices: 1 } },
  { id: "long", label: "a long name and a long email", hint: "truncation", keywords: "long name email truncation",
    person: { ...KAYG, name: "Alexandria Montgomery-Featherstonehaugh", username: "alexandria.montgomery-featherstonehaugh", email: "alexandria.montgomery-featherstonehaugh@a-very-long-company-domain.example.org" } },
];

// ---- the toggle's data sets ----------------------------------------------------------------------------------------------
// Each value is a real shape, or the real limit: a username is at most 32 characters, a company name is free text
// (unbounded), a fleet of about a thousand machines is ordinary for the people this product is for.

/** The tags of the worst-case fleet: fourteen, one of them as long as a real customer tag. */
export const FLEET_TAGS = ["prod", "staging", "dev", "db", "web", "cache", "queue", "edge", "gpu", "storage", "monitoring", "ci", "eu-central", "customer-acme-corporation-emea-production-tier-1"];

/** `count` machines, each carrying one to four of the fleet's tags (some none), spread evenly and reproducibly. */
const fleet = (count: number, from = 1): LoginHost[] => Array.from({ length: count }, (_, i) => {
  const n = from + i;
  const tags = n % 11 === 0 ? [] : Array.from({ length: 1 + (n % 4) }, (_, k) => FLEET_TAGS[(n * 3 + k * 5) % FLEET_TAGS.length]!);
  return linux(`fleet-${String(n).padStart(4, "0")}`, ...new Set(tags));
});

/**
 * Long names, an unbreakable email, a company name with a bracket, twelve accounts, one with 1,202 machines over fourteen
 * tags (more tag cards than the card draws) and one with a single machine; a recovery key last verified over a year ago.
 */
const WORST: Person = {
  name: "Aleksandra Wiśniewska-Kowalczyk",
  username: "aleksandra.wisniewska-kowalczyk2",
  email: "aleksandra.wisniewska-kowalczyk+billing-notifications@northwind-industries-holdings.example.com",
  org: { name: "Northwind Industries Holdings International (EMEA Platform Infrastructure)", role: "Admin" },
  loginAs: [
    { account: "aleksandra.wisniewska-kowalczyk2", hosts: [linux("build-agent-eu-central-1a-ephemeral-0042.internal.example.com", "ci", "customer-acme-corporation-emea-production-tier-1", "eu-central", "prod"), mac("mac-studio-design-floor-3-east", "dev"), ...fleet(1200)] },
    { account: "root", hosts: fleet(41, 100) },
    { account: "deploy-production-eu-central", hosts: fleet(12, 300) },
    { account: "postgres", hosts: [linux("db-primary-eu-central-1a", "db", "prod")] },
    { account: "www-data", hosts: fleet(3, 500) },
    { account: "svc-backup-nightly-restic", hosts: fleet(8, 600) },
    { account: "ci-runner-ephemeral", hosts: fleet(5, 700) },
    { account: "grafana", hosts: fleet(2, 800) },
    { account: "ops", hosts: fleet(4, 900) },
    { account: "ubuntu", hosts: fleet(6, 1000) },
    { account: "admin", hosts: fleet(2, 1100) },
    { account: "j", hosts: [linux("nas")] },
  ],
  passkeys: 12, recovery: verified(420), devices: 38,
};

/** Nothing set: no name, no email, no organisation, no machines, no passkey, no recovery key, no devices. */
const EMPTY: Person = { name: "", username: "kayg", email: "", loginAs: [], passkeys: 0, recovery: { setUp: false, verifiedAt: null }, devices: 0 };

/** Everything at exactly one: a one-letter name, the shortest realistic email, one account on one tagged machine, one passkey, one device. */
const ONE: Person = { name: "J", username: "jay", email: "j@b.co", loginAs: [{ account: "jay", hosts: [linux("nas", "home")] }], passkeys: 1, recovery: verified(1), devices: 1 };

export const FIXTURES: Record<DataId, Person> = { demo: KAYG, worst: WORST, empty: EMPTY, one: ONE };

export interface AccountDouble extends AccountModel {
  patch(next: Partial<Pick<Person, "name" | "email" | "picture">>): void;
  scenario(): string;
  setScenario(id: string): Scenario;
  /** Replaces the person with one of the toggle's data sets. */
  setData(id: DataId): void;
}

export function createAccountDouble(initial = "community"): AccountDouble {
  const find = (id: string): Scenario => SCENARIOS.find((s) => s.id === id) ?? SCENARIOS[0]!;
  let id = find(initial).id;
  let person: Person = structuredClone(find(id).person);
  const listeners = new Set<() => void>();
  const emit = (): void => { for (const run of listeners) run(); };
  return {
    person: () => person,
    scenario: () => id,
    setScenario(next) { const s = find(next); id = s.id; person = structuredClone(s.person); emit(); return s; },
    setData(next) { id = `data:${next}`; person = structuredClone(FIXTURES[next]); emit(); },
    patch(next) { person = { ...person, ...next }; emit(); },
    onChange(run) { listeners.add(run); return () => { listeners.delete(run); }; },
  };
}

/** Whether a login's machine list carries tags (the tests ask: a fixture of one colour proves nothing). */
export const tagsOf = (logins: readonly Login[]): Set<string> => new Set(logins.flatMap((l) => l.hosts.flatMap((h) => h.tags)));
