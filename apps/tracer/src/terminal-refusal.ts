/** Public terminal-open reasons become plain guidance; server text is never interpolated into product copy. */
import { ActionRefused } from "./connection";

export function terminalRefusal(error: unknown, hostName?: string): { message: string; sessionList: boolean } {
  const host = hostName?.trim() || "This host";
  if (error instanceof ActionRefused) {
    switch (error.reason) {
      case "host_memory_low": {
        const memory = error.memory;
        const details = memory ? ` (${memory.availableMiB} MiB free, ${memory.sessionCount} ${memory.sessionCount === 1 ? "session" : "sessions"} running)` : "";
        return { message: `${host} is low on memory${details}. Close sessions you no longer need.`, sessionList: true };
      }
      case "invalid": return { message: "This terminal request is not valid. Try opening a new window.", sessionList: false };
      // A server that runs without root can only log in as its own user; say so and name the way forward (#327).
      case "permission": return { message: "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.", sessionList: false };
      case "no_login": return { message: "This server runs without root and has no user account matching your name, so it cannot open a shell for you. Add a host to work elsewhere.", sessionList: false };
      case "host_memory_unavailable": return { message: `${host} could not check its available memory. Try again.`, sessionList: false };
      case "resource_unavailable": return { message: `${host} could not start a shell. Try again.`, sessionList: false };
      case "unavailable": {
        const location = hostName?.trim();
        const subject = location ? `The infraternal agent on ${location}` : "The infraternal agent on this host";
        const fix = location ? `from ${location}` : "from that host";
        return { message: `${subject} cannot reach the server. Check that outbound TCP 443 is allowed ${fix}.`, sessionList: false };
      }
    }
  }
  return { message: "The server could not open this terminal. Try again.", sessionList: false };
}
