/**
 * Where the version area gets its facts (#216): the version this server runs, the version of every host's
 * infraternal agent, the licence, and the answer to "is anything newer?". The pill, the panel and the palette read
 * only this interface, so the product, the test double (canvas/mock/version/double.ts) and the future live source differ
 * in where the numbers come from and never in how they are told.
 *
 * "Infraternal agent" always means the host daemon. A host's version is `undefined` when it is not known (the host has not
 * reported one); an unknown version is never shown as a number and never counts as behind.
 */

export type Tier = "community" | "homelab" | "team" | "enterprise";

export interface Licence {
  tier: Tier;
  /** Who a paid licence is for. */
  holder?: string;
  people?: { used: number; max: number };
  /** Days from today until it ends; undefined = never (a one-time licence). Negative = ended that many days ago. */
  days?: number;
  /** What the person had before the licence ended, for the sentence "Team licence ended". */
  endedTier?: Tier;
}

/** One host and the version of its infraternal agent (`undefined`: not reported). */
export interface HostVersion { name: string; version: string | undefined }

/** One thing that can be updated: this server (`server: true`) or a host's infraternal agent. */
export interface Target { name: string; server?: true; from: string | undefined; to: string }

/** The answer of a check across the server and every host. */
export type CheckResult =
  | { kind: "current" }
  | { kind: "available"; targets: Target[] }
  /** `reason` is a plain sentence, shown on hover only. */
  | { kind: "failed"; reason: string };

export interface VersionFacts {
  /** What the pill and the panel's heading show. */
  version: string;
  /** What the heading copies (the whole commit id when `version` is its short form). */
  copy: string;
  hosts: HostVersion[];
  licence: Licence;
  /** The last answer the source has (a retained update state); `unknown` until something checked. */
  updates: { kind: "unknown" } | CheckResult;
  /** Where the release notes are, when the source knows. Without it the panel has no "What's new" row. */
  releaseNotes?: string;
}

export interface VersionSource {
  facts(): VersionFacts;
  /**
   * Asks the server and every host at once whether something newer exists. All hosts are asked together, never one after
   * another (`checkFleet` in updates.ts does that for a source that has to ask each host).
   */
  check(): Promise<CheckResult>;
  /**
   * Starts the update of these targets. Absent while the source cannot update anything; the panel then never offers it.
   * It resolves when the update has been handed over, not when every host has restarted.
   */
  proceed?(targets: Target[]): Promise<void>;
  /** Calls `run` when `facts()` would answer differently. Returns the remover. */
  onChange(run: () => void): () => void;
}

/** Thrown by a source that cannot check at all (yet); its message is the reason shown on hover. */
export class UpdatesUnavailable extends Error {
  constructor(message = "Checking for updates is not available in this build yet.") {
    super(message);
    this.name = "UpdatesUnavailable";
  }
}

export interface ProductSourceInput {
  /** The build's short id: the only version the web app has. */
  version: string;
  commit: string;
  /** The hosts this person can reach. Their agent versions are not reported to the web app yet. */
  hosts(): string[];
}

/**
 * The product's source today.
 *
 * TODO(#211): automatic updates (D251) are backend only so far: no update check, no per-host agent version and no
 * licence reach the web app. Until its state and events exist, this source answers from what the build itself knows: the
 * build's id, the hosts by name (their versions unknown), and the Community edition (the build has no `ee/` code). `check`
 * says it cannot, which the panel tells in plain words ("Couldn't check"), and there is no `proceed`. When #211 lands,
 * only this function changes: `check` calls the server (which asks every host together), `proceed` starts the update, and
 * `facts` reads the retained update state; the pill, the panel and the palette stay as they are.
 */
export function createProductVersionSource(input: ProductSourceInput): VersionSource {
  return {
    facts: () => ({
      version: input.version,
      copy: input.commit,
      hosts: input.hosts().map((name) => ({ name, version: undefined })),
      licence: { tier: "community" },
      updates: { kind: "unknown" },
    }),
    check: () => Promise.reject(new UpdatesUnavailable()),
    onChange: () => () => undefined,
  };
}
