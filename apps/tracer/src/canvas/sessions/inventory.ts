/**
 * The session inventory: what the canvas needs to know about a host's sessions beyond binding a window to one
 * (D178, D183). `SessionService` (adapter.ts) opens and binds; the inventory lists, names and ends.
 *
 * States follow D178: `open` has a window on the account's canvas, `detached` is running without one, and
 * `exited` keeps its final screen and exit code for 7 days or until dismissed. A detached session can carry one
 * activity marker: new output (a quiet dot), or the result of a command that finished (ok or fail). Names are
 * automatic (the foreground command or the folder) until someone renames one, which pins it. When another device
 * typed last it decides the session's size; this device shows it scaled to fit (D183).
 *
 * The canvas drives the lifecycle through these verbs (a window binds: `attach`; a window closes: `detach`), so
 * the product implementation can answer them from the host's session shim (#99, #100) and the mockup from the
 * test double. An instance without an inventory simply does not offer the manager, the markers or the strip.
 */

import type { CanvasDocument } from "../model/document";

export type SessionState = "open" | "detached" | "exited";
export type SessionActivity = "output" | "ok" | "fail";

export interface SessionRecord {
  id: string;
  name: string;
  /** A rename pins the name; an unpinned name follows the foreground command or the folder. */
  pinned: boolean;
  state: SessionState;
  /** What is running in the foreground, when something is ("apt upgrade"). Named by the end confirmation. */
  running?: string;
  lastOutput: string;
  /** How long ago the session was last used or finished, as a short label. */
  age: string;
  viewers: number;
  /** Columns by rows of the device that typed last. */
  size: string;
  /** Recent use, weighted towards the last days: orders sessions within a state. */
  frecency: number;
  activity?: SessionActivity;
  exit?: { code: number };
  /**
   * The host no longer has this session (#158). A retained exit record may carry a status, but cannot promise a final
   * screen to keep. Shown as exited ("Session ended"); the window offers a new shell on the same host.
   */
  gone?: boolean;
  /** The screen to show when no live renderer does (an exited session's final screen, a detached preview). */
  screen: string[];
}

export interface DeviceInfo { id: string; name: string; kind: "laptop" | "phone" }

export type InventoryStatus = "loading" | "ready" | "error";

/** What an inventory can do; the UI offers only these (a missing verb is not drawn, never greyed out). */
export interface InventoryCapabilities { rename?: boolean; end?: boolean; runAgain?: boolean; dismiss?: boolean }

export interface SessionInventory {
  /** Product membership follows the shared layout; previews may keep local attachment state. */
  setLayout?(document: CanvasDocument): void;
  /** Absent means everything. The product's client-side inventory (live-inventory.ts) cannot end sessions until #100. */
  readonly can?: InventoryCapabilities;
  status(): InventoryStatus;
  /** Asks the host again after a failure; resolves when the status has settled. */
  reload(): Promise<void>;
  /** Host ids that have sessions, in display order. */
  hosts(): string[];
  /** Every session of a host, in any state, unordered. */
  list(host: string): SessionRecord[];
  get(host: string, id: string): SessionRecord | undefined;
  /** A window shows this session: it is open (an exited one stays exited, read-only) and moves up the frecency order.
   *  A session the inventory has not heard of is registered (a window restored from the canvas document names one). */
  attach(host: string, id: string, hint?: { name?: string; pinned?: boolean }): void;
  /** The window that showed this session closed: an open session keeps running, detached. */
  detach(host: string, id: string): void;
  /** A new shell on the host (a split, no prompt). Its name follows the folder until it is renamed. */
  create?(host: string): SessionRecord;
  /** A rename pins the name. */
  rename(host: string, id: string, name: string): void;
  /** Ends the session (explicit, after the confirmation naming what is running). */
  end(host: string, id: string): void;
  /** Starts an exited session's command again (it becomes open). */
  runAgain(host: string, id: string): void;
  /** Removes an exited session's kept screen. */
  dismiss(host: string, id: string): void;
  /** The device that typed last, when it is not this one. */
  sizedFor(host: string, id: string): DeviceInfo | undefined;
  /** This device types: it takes the size over. */
  takeOver(host: string, id: string): void;
  /** Called when anything changes (state, name, activity, status). */
  onChange(listener: () => void): () => void;
}

/** Orders sessions the way every list shows them: most used first. */
export const byFrecency = (a: SessionRecord, b: SessionRecord): number => b.frecency - a.frecency || a.name.localeCompare(b.name);
