/**
 * Public terminal-open reasons become plain guidance; server text is never interpolated into product copy.
 *
 * Every refusal names what happened and the one action that helps, so a window that could not open a shell never
 * waits silently: the window's strip shows `message` with that action (canvas/windows/session-ui.on-demand.ts).
 */
import { ActionRefused } from "./connection";

const ROOTLESS = "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.";

/**
 * The one action that helps after a refusal: ask again, add another host, open the host's sessions (to close one), or none
 * (only closing the window is left).
 */
export type RefusalAction = "retry" | "add-host" | "sessions" | "none";

/** What a refusal says (`message`), whether the sessions list helps (`sessionList`), and its one helpful `action`, and `calm` when the state clears by itself and so is not an error (it gets the info icon, never the red cross; D393). */
export interface TerminalRefusal { message: string; sessionList: boolean; action: RefusalAction; calm?: true }

/** Turns a refused `ssh.session.open` into the words and the action its window shows. */
export function terminalRefusal(error: unknown, hostName?: string, remote = false): TerminalRefusal {
  const host = hostName?.trim() || "This host";
  if (error instanceof ActionRefused) {
    switch (error.reason) {
      case "host_memory_low": {
        const memory = error.memory;
        const details = memory ? ` (${memory.availableMiB} MiB free, ${memory.sessionCount} ${memory.sessionCount === 1 ? "session" : "sessions"} running)` : "";
        return { message: `${host} is low on memory${details}. Close sessions you no longer need.`, sessionList: true, action: "sessions" };
      }
      case "invalid": return { message: "This terminal request is not valid. Try opening a new window.", sessionList: false, action: "none" };
      case "permission":
      case "no_login": {
        if (!remote) return { message: ROOTLESS, sessionList: false, action: "add-host" };
        const account = error.executionUid === undefined ? "its own account" : `the account with user ID ${error.executionUid}`;
        return { message: `${host} couldn't open a shell as ${account}. Check the account on ${host}, then try again.`, sessionList: false, action: "retry" };
      }
      // The host has systemd but was too busy to answer when the login started: asking again usually works.
      case "probe_timeout": return { message: `${host} is too busy to start a shell. Try again in a moment.`, sessionList: false, action: "retry" };
      // A root host without systemd cannot prove a revoked login is gone, so it opens none (D354). Name the two ways
      // that work; the action is a host that can.
      case "no_systemd": return {
        message: `${host} has no systemd, so infraternal can't open logins there as root. Reinstall infraternal there without root, or add a host with systemd.`,
        sessionList: false, action: "add-host",
      };
      // The account may not use this host: only its owner can change that, so there is nothing to retry.
      case "forbidden":
      case "denied": return { message: `You do not have access to ${hostName?.trim() || "this host"}. Ask an admin for access.`, sessionList: false, action: "none" };
      case "host_memory_unavailable": return { message: `${host} could not check its available memory. Try again.`, sessionList: false, action: "retry" };
      case "resource_unavailable": return { message: `${host} could not start a shell. Try again.`, sessionList: false, action: "retry" };
      // A root upgrade (D376) holds the host's shells for a short while; it ends by itself, so name that and the way back (D393).
      case "host_upgrading": return { message: `${host} is being upgraded and will be back shortly.`, sessionList: false, action: "retry", calm: true };
      // Offline, never enrolled, or cut off from the server all arrive as this one reason, so the sentence names the two
      // things a person can check; the network detail for an expert belongs in the docs, not here.
      case "unavailable": return { message: `${host} is offline or cannot reach this server. Check its network, then try again.`, sessionList: false, action: "retry" };
    }
  }
  return { message: "Couldn't open this terminal. Check your connection and try again.", sessionList: false, action: "retry" };
}
