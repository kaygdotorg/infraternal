/**
 * One toast, no second status surface: a terminal reports connection state and transient failures by writing
 * text into a status element. On the canvas that text is shown through the shared toast instead. Routine
 * connection states (starting, connecting, reconnecting, resuming, resumed, paused) never produce text: they
 * belong to the status icon. Only a real failure reaches the toast, and only a message this relay put up is taken
 * down again (a flow's own toast is not ours to dismiss).
 */
import type { ToastController } from "../../../../packages/ui/src/toast";

/** Formats the signed infraternal agent status without mistaking a signal for a shell exit code. */
export function exitStatusText(status: number): string {
  if (status === 0) return "Shell exited.";
  if (status > 0) return `Shell exited with status ${status}. Open a new shell to continue.`;
  return `Shell was stopped by signal ${-status}. Open a new shell to continue.`;
}

/** Names the recorded reason in an ended window; missing statuses mean the host vanished, and negative statuses name signals. */
export function endedStripText(status: number | undefined): string {
  if (status === undefined) return "Session ended";
  if (status < 0) return `Stopped by signal ${-status}`;
  return `Session ended · Exit ${status}`;
}

/** Creates a detached status element for one terminal and relays its text to the toast. Returns both. */
export function createStatusRelay(toast: ToastController): { element: HTMLElement; dispose(): void } {
  const element = document.createElement("p");
  element.hidden = true;
  let relaying = false;
  let lastMessage: string | undefined;
  let lastShownAt = 0;
  let nextToastIdentity = 0;
  let ownedToastIdentity: number | undefined;
  /** The stack's id for our toast: a bare dismiss spares errors, and this relay only shows errors. */
  let ownedToastId: string | undefined;
  let clearTimer: ReturnType<typeof setTimeout> | 0 = 0;
  const observer = new MutationObserver(() => {
    const message = element.textContent?.trim() ?? "";
    if (message && !message.startsWith("Shell exited") && !/(…|\.\.\.)$/.test(message) && !/reconnect|resum|connecting|starting|paused|approximate/i.test(message)) {
      clearTimeout(clearTimer);
      clearTimer = 0;
      relaying = true;
      const connectionFailure = message === "The connection to the server ended." || message === "The server closed the connection." || message === "The connection did not respond in time.";
      // A retry changes the hidden status several times. Keep its reason visible across those routine states, and
      // do not recreate the same toast on every immediate close. The toast's own timeout bounds each display.
      const repeatedConnectionReason = connectionFailure && message === lastMessage;
      if (!repeatedConnectionReason && (message !== lastMessage || ownedToastIdentity === undefined || Date.now() - lastShownAt >= 5000)) {
        lastMessage = message;
        lastShownAt = Date.now();
        const identity = ++nextToastIdentity;
        ownedToastIdentity = identity;
        // Whatever passes the filter is bad news (a lost connection, a refusal or an ended terminal), never a
        // confirmation. The old guess by wording missed "The connection to the server ended."
        // Keep a connection reason visible until the status clears after a stable attach.
        ownedToastId = toast.show({ message, tone: "error", duration: connectionFailure ? 0 : 5000, onClose: () => {
          if (ownedToastIdentity === identity) ownedToastIdentity = undefined;
        } });
      }
    } else if (!message && relaying) {
      clearTimeout(clearTimer);
      clearTimer = setTimeout(() => {
        clearTimer = 0;
        if (element.textContent?.trim() !== "") return;
        relaying = false;
        lastMessage = undefined;
        lastShownAt = 0;
        if (ownedToastIdentity !== undefined) toast.dismiss(ownedToastId);
        ownedToastIdentity = undefined;
      }, 300);
    } else {
      // A retry that starts before the settle window completes keeps the existing reason in place.
      clearTimeout(clearTimer);
      clearTimer = 0;
    }
  });
  observer.observe(element, { childList: true, characterData: true, subtree: true });
  return {
    element,
    dispose: () => {
      observer.disconnect();
      clearTimeout(clearTimer);
      clearTimer = 0;
      if (ownedToastIdentity !== undefined) toast.dismiss(ownedToastId);
      ownedToastIdentity = undefined;
    },
  };
}
