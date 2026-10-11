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
      case "host_memory_unavailable": return { message: `${host} could not check its available memory. Try again.`, sessionList: false };
      case "resource_unavailable": return { message: `${host} could not start a shell. Try again.`, sessionList: false };
      case "unavailable": return { message: `${host} is unavailable. Check its connection and try again.`, sessionList: false };
    }
  }
  return { message: "The server could not open this terminal. Try again.", sessionList: false };
}
