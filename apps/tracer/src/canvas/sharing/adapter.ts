/**
 * The sharing adapter (D182): how layouts reach other people. Product: the instance's own sharing API (#93).
 * Mockups: a test-double transport. Without an adapter the canvas offers no sharing at all.
 */
import type { ViewModel } from "../model/types";

/** A layout sent to this person, or a team layout they follow. */
export interface IncomingShare {
  id: string;
  from: string;
  to: string[];
  /** A published team layout: followers keep a linked, read-only copy that follows the publisher. */
  publish: boolean;
  /** Grows with every change the publisher makes. */
  rev: number;
  views: Array<{ key: string; name: string; snapshot: ViewModel }>;
}

/** What sharing needs from an instance: who the person is, who they can send to, and how to send, update and receive layouts. */
export interface SharingAdapter {
  /** The signed-in username. */
  me(): string;
  /** Who a layout can be sent to. */
  directory(): { people: readonly string[]; groups: Readonly<Record<string, readonly string[]>> };
  /** Whether this person may publish a team layout. */
  canPublish(): boolean;
  /** Hosts the signed-in person's own grants cover (a received layout connects through these). */
  allowedHosts(): readonly string[];
  send(message: { to: string[]; publish: boolean; views: Array<{ key: string; name: string; snapshot: ViewModel }> }): Promise<{ id: string }>;
  /** A published layout changed: followers get the new arrangement. */
  update(id: string, key: string, snapshot: ViewModel): Promise<void>;
  /** Calls the listener with everything addressed to this person, now and whenever it changes. Returns the stop function. */
  subscribe(listener: (shares: IncomingShare[]) => void): () => void;
}
