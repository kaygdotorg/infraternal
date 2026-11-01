/** One reusable, accessible status toast with optional actions for product surfaces. */
import { ICONS } from "./icons";
import { tick } from "./tick";

export interface ToastAction {
  label: string;
  /** Preserve pointer versus keyboard activation when an action opens another shared surface. */
  onSelect(event?: MouseEvent): void;
}

/** A compact icon button beside the message (TASTE: icons with warm tooltips). `label` is both its tooltip and its accessible name. */
export interface ToastIconAction extends ToastAction {
  /** Inner SVG markup on the 24 px grid (the shared icons). */
  icon: string;
  /** Keep the notice up after the action runs: for help that opens elsewhere while the question still waits. */
  keepOpen?: boolean;
}

export interface ToastMessage {
  message: string;
  /** The message with entity chips in it (`entityText`); it replaces `message` on screen, which stays the plain text. */
  messageNode?: Node;
  action?: ToastAction;
  /** A second action beside the primary action, for a clear alternative such as Discard. */
  secondaryAction?: ToastAction;
  /** Icon buttons after the message, in order (a question answered by ✓ or ✗, with ? for help). Shown on one line, never stacked. */
  iconActions?: readonly ToastIconAction[];
  /** Accessible name for action choices that have a keyboard focus handoff. */
  actionGroupLabel?: string;
  /** ARIA shortcut value that focuses the action group, such as `Control+Shift+Space`. */
  actionGroupKeyShortcuts?: string;
  duration?: number;
  /** `error` replaces the success tick with a caution mark (TASTE: a tick only for success): the message is a failure or a lost connection. */
  tone?: "ok" | "error";
  /**
   * Inner SVG markup on the 24 px grid (the shared icons) shown in place of the success tick, for a message that is
   * waiting or neutral rather than done. Without it the tick shows for "ok" and the caution mark for "error".
   */
  icon?: string;
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
  /** Focuses an available action by visual order, returning false when none is available. */
  focusAction(index?: number): boolean;
  dismiss(): void;
  dispose(): void;
}

export interface ToastOptions {
  /** Window notices anchor to the inline start of a positioned, unscrolled parent. */
  placement?: "viewport" | "parent";
  /** Persistent status can sit above transient notifications without sharing their replacement slot. */
  aboveNotifications?: boolean;
}

/** Messages longer than this stack their actions beneath the text; shorter ones keep the actions beside it. */
const STACK_AFTER = 36;

/** Mounts the one shared toast surface into `parent`, usually the active app shell. */
export function mountToast(parent: HTMLElement, options: ToastOptions = {}): ToastController {
  const host = document.createElement("aside");
  host.className = "ui-toast ui-overlay-surface";
  if (options.placement === "parent") {
    host.style.position = "absolute";
    // Centering in a wide window can put the action beneath its neighboring
    // view. Parent notices stay at the window's inline start.
    host.style.marginInline = "0";
  }
  host.hidden = true;
  host.setAttribute("aria-label", "Notification");
  host.setAttribute("role", "group");

  const marker = document.createElement("span");
  marker.className = "ui-toast-marker";
  marker.setAttribute("aria-hidden", "true");
  tick(marker, true);

  const glyph = document.createElement("span");
  glyph.className = "ui-toast-glyph";
  glyph.setAttribute("aria-hidden", "true");
  glyph.hidden = true;

  const label = document.createElement("span");
  label.className = "ui-toast-message";
  label.setAttribute("role", "status");
  label.setAttribute("aria-live", "polite");

  const actions = document.createElement("div");
  actions.className = "ui-toast-actions";
  actions.setAttribute("role", "group");
  actions.hidden = true;

  const action = document.createElement("button");
  action.type = "button";
  action.className = "ui-toast-action ui-button";
  action.hidden = true;

  const secondaryAction = document.createElement("button");
  secondaryAction.type = "button";
  secondaryAction.className = "ui-toast-action ui-button";
  secondaryAction.hidden = true;

  const close = document.createElement("button");
  close.type = "button";
  close.className = "ui-toast-close ui-button";
  close.hidden = true;
  close.setAttribute("aria-label", "Dismiss");
  close.dataset.tip = "Dismiss";
  close.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><path d="m7 7 10 10M17 7 7 17"/></svg>`;

  // Icon actions are rebuilt per message: a handful of buttons, only while the question is on screen.
  const icons = document.createElement("div");
  icons.className = "ui-toast-icons";
  icons.setAttribute("role", "group");
  icons.hidden = true;

  actions.append(action, secondaryAction);
  host.append(marker, glyph, label, actions, icons, close);
  parent.append(host);
  // Wrapped text and touch targets change a notification's height. Reserve its
  // measured space using the same CSS anchor, including the mobile key tray.
  const neighbors = options.aboveNotifications ? [...parent.children].filter((el): el is HTMLElement => el !== host && el instanceof HTMLElement && el.classList.contains("ui-toast")) : [];
  const spacing = neighbors.length ? new ResizeObserver(() => {
    const height = Math.max(0, ...neighbors.map((el) => el.hidden ? 0 : el.offsetHeight));
    // The measured height is in pixels; the gap beside it is a length of the interface (rem), so it grows with the UI size.
    host.style.setProperty("--ui-toast-stack-offset", height ? `calc(${height}px + 0.75rem)` : "0px");
  }) : undefined;
  for (const neighbor of neighbors) spacing?.observe(neighbor);

  let hideTimer = 0;
  let generation = 0;
  let closeTimer = 0;
  let selectAction: ToastAction["onSelect"] | undefined;
  let selectSecondaryAction: ToastAction["onSelect"] | undefined;
  let closeHandler: (() => void) | undefined;
  let iconRuns: readonly ToastIconAction[] = [];
  const finish = (): void => { const run = closeHandler; closeHandler = undefined; run?.(); };
  const dismiss = (): void => {
    const epoch = ++generation;
    window.clearTimeout(hideTimer);
    hideTimer = 0;
    selectAction = undefined;
    selectSecondaryAction = undefined;
    // A second click on a leaving notice must not run an answer twice.
    iconRuns = [];
    host.dataset.open = "false";
    window.clearTimeout(closeTimer);
    closeTimer = window.setTimeout(() => {
      closeTimer = 0;
      if (epoch === generation && host.dataset.open === "false") host.hidden = true;
    }, 190);
    finish();
  };
  const onAction = (run: ToastAction["onSelect"] | undefined, event: MouseEvent): void => {
    // The action runs before the close hand-over, so whoever listens sees what the action started.
    const handler = closeHandler;
    closeHandler = undefined;
    dismiss();
    run?.(event);
    handler?.();
  };
  const primaryClick = (event: MouseEvent): void => onAction(selectAction, event);
  const secondaryClick = (event: MouseEvent): void => onAction(selectSecondaryAction, event);
  const iconClick = (event: MouseEvent): void => {
    const entry = iconRuns[Number((event.currentTarget as HTMLElement).dataset.index)];
    if (!entry) return;
    if (entry.keepOpen) entry.onSelect(event); else onAction(entry.onSelect, event);
  };
  const setIconActions = (list: readonly ToastIconAction[] = []): void => {
    iconRuns = list;
    icons.replaceChildren(...list.map((entry, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ui-toast-icon ui-button";
      button.dataset.index = String(index);
      button.setAttribute("aria-label", entry.label);
      button.dataset.tip = entry.label;
      button.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">${entry.icon}</svg>`;
      button.addEventListener("click", iconClick);
      return button;
    }));
    icons.hidden = list.length === 0;
    if (list.length) icons.setAttribute("aria-label", "Notification choices"); else icons.removeAttribute("aria-label");
  };
  action.addEventListener("click", primaryClick);
  secondaryAction.addEventListener("click", secondaryClick);
  close.addEventListener("click", dismiss);

  return {
    show(value) {
      const epoch = ++generation;
      window.clearTimeout(hideTimer);
      // A previous message's closing timer must not hide this one while its
      // opening frame waits for a busy renderer.
      window.clearTimeout(closeTimer);
      finish();
      closeHandler = value.onClose;
      close.hidden = !value.dismissible;
      // One rule for every caller: a failure never shows the green tick, whatever tone its caller guessed.
      const icon = value.icon ?? (value.tone === "error" ? ICONS.warning : undefined);
      glyph.hidden = !icon;
      host.dataset.icon = icon ? "true" : "false";
      if (icon) glyph.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18">${icon}</svg>`;
      if (value.messageNode) label.replaceChildren(value.messageNode); else label.textContent = value.message;
      selectAction = value.action?.onSelect;
      selectSecondaryAction = value.secondaryAction?.onSelect;
      action.textContent = value.action?.label ?? "";
      action.hidden = !value.action;
      secondaryAction.textContent = value.secondaryAction?.label ?? "";
      secondaryAction.hidden = !value.secondaryAction;
      setIconActions(value.iconActions);
      host.dataset.choices = String(Boolean(value.iconActions?.length));
      actions.hidden = !value.action && !value.secondaryAction;
      if (actions.hidden) {
        actions.removeAttribute("aria-label");
        actions.removeAttribute("aria-keyshortcuts");
      } else {
        actions.setAttribute("aria-label", value.actionGroupLabel ?? "Notification actions");
        if (value.actionGroupKeyShortcuts) actions.setAttribute("aria-keyshortcuts", value.actionGroupKeyShortcuts);
        else actions.removeAttribute("aria-keyshortcuts");
      }
      host.dataset.tone = value.tone ?? "ok";
      host.dataset.stacked = String(Boolean(value.action || value.secondaryAction) && value.message.length > STACK_AFTER);
      host.hidden = false;
      host.dataset.open = "false";
      // A fast receipt can dismiss this message before its first animation frame.
      requestAnimationFrame(() => { if (epoch === generation && !host.hidden) host.dataset.open = "true"; });
      const duration = value.duration ?? 4200;
      if (duration > 0) hideTimer = window.setTimeout(dismiss, duration);
    },
    focusAction(index = 0) {
      if (!Number.isInteger(index) || index < 0) return false;
      const available = [action, secondaryAction, ...icons.querySelectorAll<HTMLElement>("button")].filter((button) => !button.hidden);
      const target = available[index];
      if (!target || host.hidden) return false;
      target.focus({ preventScroll: true });
      return true;
    },
    dismiss,
    dispose() {
      generation++;
      window.clearTimeout(hideTimer);
      window.clearTimeout(closeTimer);
      action.removeEventListener("click", primaryClick);
      secondaryAction.removeEventListener("click", secondaryClick);
      close.removeEventListener("click", dismiss);
      spacing?.disconnect();
      host.remove();
    },
  };
}
