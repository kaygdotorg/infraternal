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
}

export interface DetailsSource {
  /** Load formatting at the popover boundary while keeping live subscriptions active. */
  prepare?(): Promise<void>;
  /** Called when the popover opens and each time a tab is shown, so the connection's numbers are current. */
  /** The facts for a window, or nothing for a window with no machine behind it (a settings section, a node): its pill opens nothing. */
  facts(rec: WinRec): DetailsFacts | undefined;
}
