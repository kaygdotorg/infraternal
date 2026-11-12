// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Why an admitted host cannot be reached right now, in one place for every surface that lists hosts (#500, J528).
 *
 * After a server restart the certificate authority is locked until an administrator confirms with a passkey, and until then
 * the server cannot reach any added host: each one reads offline. A host that is simply offline needs nothing from the person;
 * one that is offline because the lock is on needs one passkey tap, so its row and the empty console say exactly that and carry
 * the way to do it. A host must never vanish from a list because it cannot be reached: it stays, with this note.
 */
import type { PaletteEntry } from "../core-screen";
import type { Ctx } from "./context";
import type { HostEntry } from "./sessions/adapter";

/** The words of a locked host's note: what is wrong, then what to do. */
export const LOCKED_NOTE = "locked: unlock to connect";
/** The note of a host that is offline for any other reason. */
export const OFFLINE_NOTE = "offline";

/** What stops a host from connecting: `locked` (the person can fix it now), `offline` (they cannot), or nothing. */
export type HostNote = "locked" | "offline" | undefined;

/**
 * The note for one admitted host. The embedded host has no `online` flag (it is the server itself) and never has one.
 * A viewer who cannot unlock (not an administrator) sees plain `offline`, because the lock is not theirs to open.
 */
export function hostNote(cx: Pick<Ctx, "adapters">, host: HostEntry): HostNote {
  if (host.online !== false) return undefined;
  const authority = cx.adapters.authority;
  return authority?.state() === "locked" && authority.canUnlock() ? "locked" : "offline";
}

/**
 * The palette rows "Open shell on <host>", one per admitted host, in the order given. The same rows are in the command palette and
 * in the palette the empty console's Open shell button opens, so a host is named and found one way everywhere. A host whose
 * agent is not connected says "offline" in the hint (it can be chosen: the window explains why it cannot open).
 */
export function openShellEntries(hosts: readonly HostEntry[]): PaletteEntry[] {
  return hosts.filter((host) => !host.state).map((host) => ({
    group: "Console", glyph: "›_", label: `Open shell on ${host.name}`,
    hint: `terminal · ssh · console${host.online === false ? " · offline" : ""}`, action: `canvas:open:${host.id}`,
  }));
}
