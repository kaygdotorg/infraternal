/**
 * One toast, no second status surface: a terminal reports connection state and transient failures by writing
 * text into a status element. On the canvas that text is shown through the shared toast instead. Routine
 * connection states (starting, connecting, reconnecting, resuming, resumed, paused) never produce text: they
 * belong to the status icon. Only a real failure reaches the toast, and only a message this relay put up is taken
 * down again (a flow's own toast is not ours to dismiss).
 */
import type { ToastController } from "../../../../packages/ui/src/toast";

/** Creates a detached status element for one terminal and relays its text to the toast. Returns both. */
export function createStatusRelay(toast: ToastController): { element: HTMLElement; dispose(): void } {
  const element = document.createElement("p");
  element.hidden = true;
  let relaying = false;
  const observer = new MutationObserver(() => {
    const message = element.textContent?.trim() ?? "";
    if (message && !/(…|\.\.\.)$/.test(message) && !/reconnect|resum|connecting|starting|paused|approximate/i.test(message)) {
      relaying = true;
      toast.show({ message, tone: /could not|failed|error|unavailable/i.test(message) ? "error" : "ok", duration: 5000 });
    } else if (relaying) {
      relaying = false;
      toast.dismiss();
    }
  });
  observer.observe(element, { childList: true, characterData: true, subtree: true });
  return { element, dispose: () => observer.disconnect() };
}
