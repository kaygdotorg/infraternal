/** One reusable, accessible status toast with an optional action for product surfaces. */
import { ICONS } from "./icons";
import { tick } from "./tick";

export interface ToastAction {
  label: string;
  /** Preserve pointer versus keyboard activation when an action opens another shared surface. */
  onSelect(event?: MouseEvent): void;
}

export interface ToastMessage {
  message: string;
  /** The message with entity chips in it (`entityText`); it replaces `message` on screen, which stays the plain text. */
  messageNode?: Node;
  action?: ToastAction;
  duration?: number;
  /** `error` drops the success tick: the message is a failure, not a confirmation. */
  tone?: "ok" | "error";
  /** Adds a dismiss control: for a message that waits on the person and should not vanish unread. */
  dismissible?: boolean;
  /**
   * Called once when this message leaves the screen for any reason: it expired, was dismissed, its action ran
   * (after the action) or another message replaced it. A pending item uses it to hand over to the inbox.
   */
  onClose?: () => void;
}

export interface ToastController {
  show(value: ToastMessage): void;
  dismiss(): void;
  dispose(): void;
}

/** Mounts the one shared toast surface into `parent`, usually the active app shell. */
export function mountToast(parent: HTMLElement): ToastController {
  const host = document.createElement("aside");
  host.className = "ui-toast ui-overlay-surface";
  host.hidden = true;
  host.setAttribute("aria-label", "Notification");
  host.setAttribute("role", "group");

  const marker = document.createElement("span");
  marker.className = "ui-toast-marker";
  marker.setAttribute("aria-hidden", "true");
  tick(marker, true);

  const label = document.createElement("span");
  label.className = "ui-toast-message";
  label.setAttribute("role", "status");
  label.setAttribute("aria-live", "polite");

  const action = document.createElement("button");
  action.type = "button";
  action.className = "ui-toast-action ui-button";
  action.hidden = true;

  const close = document.createElement("button");
  close.type = "button";
  close.className = "ui-toast-close ui-button";
  close.hidden = true;
  close.setAttribute("aria-label", "Dismiss");
  close.dataset.tip = "Dismiss";
  close.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">${ICONS.close}</svg>`;

  host.append(marker, label, action, close);
  parent.append(host);

  let hideTimer = 0;
  let selectAction: ToastAction["onSelect"] | undefined;
  let closeHandler: (() => void) | undefined;
  const finish = (): void => { const run = closeHandler; closeHandler = undefined; run?.(); };
  const dismiss = (): void => {
    window.clearTimeout(hideTimer);
    hideTimer = 0;
    selectAction = undefined;
    host.dataset.open = "false";
    window.setTimeout(() => {
      if (host.dataset.open === "false") host.hidden = true;
    }, 190);
    finish();
  };
  const onAction = (event: MouseEvent): void => {
    const run = selectAction;
    // The action runs before the close hand-over, so whoever listens sees what the action started.
    const handler = closeHandler;
    closeHandler = undefined;
    dismiss();
    run?.(event);
    handler?.();
  };
  action.addEventListener("click", onAction);
  close.addEventListener("click", dismiss);

  return {
    show(value) {
      window.clearTimeout(hideTimer);
      finish();
      closeHandler = value.onClose;
      close.hidden = !value.dismissible;
      if (value.messageNode) label.replaceChildren(value.messageNode); else label.textContent = value.message;
      selectAction = value.action?.onSelect;
      action.textContent = value.action?.label ?? "";
      action.hidden = !value.action;
      host.dataset.tone = value.tone ?? "ok";
      host.hidden = false;
      host.dataset.open = "false";
      requestAnimationFrame(() => { if (!host.hidden) host.dataset.open = "true"; });
      const duration = value.duration ?? 4200;
      if (duration > 0) hideTimer = window.setTimeout(dismiss, duration);
    },
    dismiss,
    dispose() {
      window.clearTimeout(hideTimer);
      action.removeEventListener("click", onAction);
      close.removeEventListener("click", dismiss);
      host.remove();
    },
  };
}
