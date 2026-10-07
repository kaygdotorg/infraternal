/** One reusable, accessible status toast with an optional action for product surfaces. */
import { tick } from "./tick";

export interface ToastAction {
  label: string;
  onSelect(): void;
}

export interface ToastMessage {
  message: string;
  action?: ToastAction;
  duration?: number;
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

  host.append(marker, label, action);
  parent.append(host);

  let hideTimer = 0;
  let selectAction: (() => void) | undefined;
  const dismiss = (): void => {
    window.clearTimeout(hideTimer);
    hideTimer = 0;
    selectAction = undefined;
    host.dataset.open = "false";
    window.setTimeout(() => {
      if (host.dataset.open === "false") host.hidden = true;
    }, 190);
  };
  const onAction = (): void => {
    const run = selectAction;
    dismiss();
    run?.();
  };
  action.addEventListener("click", onAction);

  return {
    show(value) {
      window.clearTimeout(hideTimer);
      label.textContent = value.message;
      selectAction = value.action?.onSelect;
      action.textContent = value.action?.label ?? "";
      action.hidden = !value.action;
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
      host.remove();
    },
  };
}
