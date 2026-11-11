/**
 * What the window details popover shows (#127). The canvas never knows where the facts come from: an adapter answers
 * for a window, in plain words, as sections of key/value rows. The product reads them from its real data (the host,
 * the connection, the session inventory); the mockups invent them. A row with an empty value is not drawn.
 */
import type { HostPlatform } from "../../../../../packages/ui/src/host-icons";
import type { KeyValueRow } from "../../../../../packages/ui/src/kv-list";
import type { WinRec } from "../context";

export interface DetailsSection {
  id: string;
  label: string;
  /** Inner markup of a 24 x 24 stroke icon for the tab. */
  icon: string;
  rows: KeyValueRow[];
}

export interface DetailsFacts {
  /** The mark in the header (the operating system). */
  os?: HostPlatform;
  /** The big line: the operating system and its version, or the host's name. */
  title: string;
  /** The small line: who and where ("kayg@build-01 · x86_64"). */
  subtitle: string;
  sections: DetailsSection[];
  /** The machine's facts are still being read: the rows that will fill hold their place so the panel keeps one height (details-facts.ts). */
  loading?: boolean;
}

/** A bounded snapshot returned by the host.facts.read plugin action. */
export interface HostFactsSnapshot {
  os: string;
  version: string;
  kernel: string;
  architecture: string;
  model?: string;
  cpuModel?: string;
  logicalCpus: number;
  memory?: { usedBytes: number; totalBytes: number };
  rootDisk?: { usedBytes: number; totalBytes: number };
  uptimeSeconds?: number;
  loadAverage?: [number, number, number];
  mode: "embedded" | "remote";
  executionUid: number;
  engines: string[];
  init?: string;
  virtualization?: string;
  shell?: string;
  locale?: string;
}

export interface DetailsSource {
  /** Called when the popover opens and each time a tab is shown, so the connection's numbers are current. */
  /** The facts for a window, or nothing for a window with no machine behind it (a settings section, a node): its pill opens nothing. */
  facts(rec: WinRec): DetailsFacts | undefined;
  /** Starts facts refresh while a popover is open; the returned disposer runs on close. */
  open?(rec: WinRec, refresh: () => void): () => void;
}

/** Loads a details source only after a window pill is pressed. */
export type DetailsSourceLoader = () => Promise<DetailsSource>;
