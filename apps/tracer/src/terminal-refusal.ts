/**
 * Public terminal-open reasons become plain guidance; server text is never interpolated into product copy.
 *
 * Every refusal names what happened and the one action that helps, so a window that could not open a shell never
 * waits silently: the window's strip shows `message` with that action (canvas/windows/session-ui.on-demand.ts).
 */
import { ActionRefused } from "./connection";

const ROOTLESS = "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.";

/** The one action that helps after a refusal: ask again, add another host, or none (only closing the window is left). */
export type RefusalAction = "retry" | "add-host" | "none";

/** What a refusal says (`message`), whether the sessions list helps (`sessionList`), and its one helpful `action`. */
export interface TerminalRefusal { message: string; sessionList: boolean; action: RefusalAction }

/** Turns a refused `ssh.session.open` into the words and the action its window shows. */
export function terminalRefusal(error: unknown, hostName?: string): TerminalRefusal {
  const host = hostName?.trim() || "This host";
  if (error instanceof ActionRefused) {
    switch (error.reason) {
      case "host_memory_low": {
        const memory = error.memory;
        const details = memory ? ` (${memory.availableMiB} MiB free, ${memory.sessionCount} ${memory.sessionCount === 1 ? "session" : "sessions"} running)` : "";
        return { message: `${host} is low on memory${details}. Close sessions you no longer need.`, sessionList: true, action: "none" };
      }
      case "invalid": return { message: "This terminal request is not valid. Try opening a new window.", sessionList: false, action: "none" };
      // A server that runs without root can only log in as its own user; say so and name the way forward (#327).
      // Both rootless reasons share one short sentence (D336): it must fit about three lines at 393 px.
      // Asking again cannot change the account, so the action is a host that can.
      case "permission":
      case "no_login": return { message: ROOTLESS, sessionList: false, action: "add-host" };
      // The account may not use this host: only its owner can change that, so there is nothing to retry.
      case "forbidden":
      case "denied": return { message: `You do not have access to ${hostName?.trim() || "this host"}. Ask an admin for access.`, sessionList: false, action: "none" };
      case "host_memory_unavailable": return { message: `${host} could not check its available memory. Try again.`, sessionList: false, action: "retry" };
      case "resource_unavailable": return { message: `${host} could not start a shell. Try again.`, sessionList: false, action: "retry" };
      case "unavailable": {
        const location = hostName?.trim();
        const subject = location ? `The infraternal agent on ${location}` : "The infraternal agent on this host";
        const fix = location ? `from ${location}` : "from that host";
        return { message: `${subject} cannot reach the server. Check that outbound TCP 443 is allowed ${fix}.`, sessionList: false, action: "retry" };
      }
    }
  }
  return { message: "The server could not open this terminal. Try again.", sessionList: false, action: "retry" };
}
