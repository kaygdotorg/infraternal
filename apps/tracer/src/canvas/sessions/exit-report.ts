/**
 * What a window tells the session inventory when its shell exits on its own (`exit`, Ctrl-D, a kill).
 *
 * The embedded host's session list is pushed by the server and retires an ended session by itself. A remote host has no such
 * push to this page, so the window is the only one that knows its shell ended: without this report the inventory keeps listing
 * the ended session as running, and the Console count stays at 1 until a reload.
 */

/** Tells `report` (the inventory's `gone`) that the shell of `sessionId` on `host` ended with `status`; a window with no session id has nothing to report. */
export function reportShellExit(report: ((host: string, sessionId: string, status?: number) => void) | undefined, host: string, sessionId: string | undefined, status: number): void {
  if (sessionId) report?.(host, sessionId, status);
}
