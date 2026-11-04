/**
 * The one shared toast surface (docs/design/toast.md, D336). Toasts stack instead of replacing each other:
 * the newest sits in front, older ones are compressed behind it and fan out while the pointer or keyboard
 * focus is on the stack. Each toast owns its clock; every clock stands still while the stack is held (pointer,
 * focus or a finger), so nobody misses an action. Touch swipes a toast down to dismiss it.
 *
 * Invariants:
 *  - `show` never removes or hides another toast to make room for an error: only the oldest non-error toasts
 *    leave the visible set (`hiddenByCap`); an error is gone only when its own clock ends or the person
 *    dismisses it. A bare `dismiss()` spares errors for the same reason.
 *  - A repeat with the same key (default: tone + message) updates its toast in place and counts (×N), so
 *    twelve identical events are one toast. Different messages, tones or keys stay separate.
 *  - Layout reads (heights) are batched into one animation frame; the stack's transforms come from CSS custom
 *    properties, so nothing runs per frame after a toast settles.
 */
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
  /**
   * Identity of this toast. A later `show` with the same key updates the toast in place (a repeat of the same
   * message counts ×N; a different message morphs it, such as a question turning into its answer).
   * Default: tone + message, so identical repeats merge without the caller doing anything.
   */
  key?: string;
  action?: ToastAction;
  /** A second action beside the primary action, for a clear alternative such as Discard. */
  secondaryAction?: ToastAction;
  /** Icon buttons after the message, in order (a question answered by ✓ or ✗, with ? for help). Shown on one line, never stacked. */
  iconActions?: readonly ToastIconAction[];
  /** Accessible name for action choices that have a keyboard focus handoff. */
  actionGroupLabel?: string;
  /** ARIA shortcut value that focuses the action group, such as `Control+Shift+Space`. */
  actionGroupKeyShortcuts?: string;
  /** Milliseconds on screen while not held; 0 stays until dismissed. Default 4200. */
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
   * (after the action) or an update with the same key replaced it. A pending item uses it to hand over to the inbox.
   */
  onClose?: () => void;
}

export interface ToastController {
  /** Shows a toast (or updates the one with the same key) and returns its id for `dismiss(id)`. */
  show(value: ToastMessage): string;
  /** Focuses an available action by visual order on the newest toast that has one, returning false when none is available. */
  focusAction(index?: number): boolean;
  /** Dismisses the toast `id`; without an id, every toast that is not an error (an error is dismissed by its own id or its Dismiss control). */
  dismiss(...id: [id?: string]): void;
  dispose(): void;
}

export interface ToastOptions {
  /** Window notices anchor to the inline start of a positioned, unscrolled parent. */
  placement?: "viewport" | "parent";
  /** Persistent status can sit above transient notifications without sharing their stack. */
  aboveNotifications?: boolean;
}

/** Messages longer than this stack their actions beneath the text; shorter ones keep the actions beside it. */
const STACK_AFTER = 36;
/** How many toasts are drawn at once. Older ones keep their clocks out of sight. */
const VISIBLE = 3;
const EXIT_MS = 190;
/** The pointer leaving a card for its neighbour must not collapse the fanned-out stack. */
const COLLAPSE_MS = 120;
/** A touch drag this far down dismisses the toast. */
const SWIPE_PX = 40;
const GAP_PX = 8;

/**
 * Which toasts (oldest first, `true` = error) fall out of the visible set. Only the oldest non-errors go; the
 * newest toast always shows. When only errors would be left over, the stack may exceed the cap for a newer
 * non-error, and a newer error pushes out the oldest error.
 */
export function hiddenByCap(errors: readonly boolean[], cap = VISIBLE): boolean[] {
  const hidden = errors.map(() => false);
  const last = errors.length - 1;
  let over = errors.length - cap;
  for (let i = 0; i < last && over > 0; i++) if (!errors[i]) { hidden[i] = true; over--; }
  if (errors[last]) for (let i = 0; i < last && over > 0; i++) if (!hidden[i]) { hidden[i] = true; over--; }
  return hidden;
}

interface Item {
  id: string;
  key: string;
  message: string;
  count: number;
  error: boolean;
  card: HTMLElement;
  label: HTMLElement;
  glyph: HTMLElement;
  close: HTMLElement;
  actions: HTMLElement;
  action: HTMLButtonElement;
  secondaryAction: HTMLButtonElement;
  icons: HTMLElement;
  height: number;
  /** Milliseconds still to run; infinity waits for a dismissal. */
  left: number;
  since: number;
  timer: number;
  exitTimer: number;
  leaving: boolean;
  selectAction?: ToastAction["onSelect"] | undefined;
  selectSecondaryAction?: ToastAction["onSelect"] | undefined;
  iconRuns: readonly ToastIconAction[];
  closeHandler?: (() => void) | undefined;
}

/** Mounts the one shared toast surface into `parent`, usually the active app shell. */
export function mountToast(parent: HTMLElement, options: ToastOptions = {}): ToastController {
  const wrap = document.createElement("div");
  wrap.className = "ui-toast-stack";
  wrap.dataset.expanded = "false";
  if (options.placement === "parent") {
    wrap.style.position = "absolute";
    // Centering in a wide window can put the action beneath its neighboring
    // view. Parent notices stay at the window's inline start.
    wrap.dataset.placement = "parent";
  }
  wrap.hidden = true;
  wrap.setAttribute("aria-label", "Notifications");
  wrap.setAttribute("role", "group");
  parent.append(wrap);

  // Wrapped text and touch targets change a notification's height. Reserve its
  // measured space using the same CSS anchor, including the mobile key tray.
  const neighbors = options.aboveNotifications ? [...parent.children].filter((el): el is HTMLElement => el !== wrap && el instanceof HTMLElement && el.classList.contains("ui-toast-stack")) : [];
  const spacing = neighbors.length ? new ResizeObserver(() => {
    const height = Math.max(0, ...neighbors.map((el) => el.hidden ? 0 : el.offsetHeight));
    // The measured height is in pixels; the gap beside it is a length of the interface (rem), so it grows with the UI size.
    wrap.style.setProperty("--ui-toast-stack-offset", height ? `calc(${height}px + 0.75rem)` : "0px");
  }) : undefined;
  for (const neighbor of neighbors) spacing?.observe(neighbor);

  const items: Item[] = [];
  /** Why the stack is held: "mouse", "focus" or "touch". Any hold fans the stack out and stops every clock. */
  const holds = new Set<string>();
  let serial = 0;
  let frame = 0;
  let leaveTimer = 0;
  let disposed = false;
  const live = (): Item[] => items.filter((it) => !it.leaving);

  const finish = (it: Item): void => { const run = it.closeHandler; it.closeHandler = undefined; run?.(); };
  const pause = (it: Item): void => {
    if (!it.timer) return;
    window.clearTimeout(it.timer);
    it.timer = 0;
    it.left -= performance.now() - it.since;
  };
  /** Starts or stops every clock to match the holds. */
  const clocks = (): void => {
    for (const it of live()) {
      if (holds.size) pause(it);
      else if (!it.timer && Number.isFinite(it.left)) {
        it.since = performance.now();
        it.timer = window.setTimeout(() => leave(it), Math.max(0, it.left));
      }
    }
  };
  const setHold = (why: string, on: boolean): void => {
    if (on) holds.add(why); else holds.delete(why);
    wrap.dataset.expanded = String(holds.size > 0);
    clocks();
    measure();
  };

  /** Order, cap and index are plain data, so they update at once; only heights wait for a frame. */
  const arrange = (): void => {
    const shown = live();
    const hidden = hiddenByCap(shown.map((it) => it.error));
    let depth = 0;
    for (let k = shown.length - 1; k >= 0; k--) {
      const it = shown[k]!;
      const behind = hidden[k]!;
      it.card.dataset.hidden = String(behind);
      it.card.dataset.front = String(!behind && depth === 0);
      it.card.style.setProperty("--i", String(Math.min(behind ? VISIBLE - 1 : depth, VISIBLE - 1)));
      it.card.style.setProperty("z-index", String(100 + k));
      if (!behind) depth++;
    }
    wrap.hidden = items.length === 0;
    measure();
  };
  /**
   * One batched frame for the fanned-out offsets and the stack's reserved height. Only the front card is read
   * here: a card behind it is clamped to the front's height by CSS, so its own natural height was taken once, in
   * `show`, while it was the front.
   */
  const measure = (): void => {
    if (frame || disposed) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      const visible = live().filter((it) => it.card.dataset.hidden !== "true").reverse();
      if (visible[0]) visible[0].height = visible[0].card.offsetHeight || visible[0].height;
      let lift = 0;
      for (const it of visible) { it.card.style.setProperty("--ey", `${-lift}px`); lift += it.height + GAP_PX; }
      const front = visible[0]?.height ?? 0;
      wrap.style.setProperty("--front-h", `${front}px`);
      // Collapsed, the cards behind are as wide as the front one, so only their top edge peeks out.
      if (visible[0]) wrap.style.setProperty("--front-w", `${visible[0].card.offsetWidth}px`);
    });
  };
  const leave = (it: Item): void => {
    if (it.leaving) return;
    it.leaving = true;
    window.clearTimeout(it.timer);
    it.timer = 0;
    // A second click on a leaving notice must not run an answer twice.
    it.selectAction = undefined;
    it.selectSecondaryAction = undefined;
    it.iconRuns = [];
    it.card.dataset.open = "false";
    it.exitTimer = window.setTimeout(() => {
      it.card.remove();
      items.splice(items.indexOf(it), 1);
      if (!live().length) { holds.clear(); wrap.dataset.expanded = "false"; }
      arrange();
    }, EXIT_MS);
    finish(it);
    arrange();
  };

  const onAction = (it: Item, run: ToastAction["onSelect"] | undefined, event: MouseEvent): void => {
    // The action runs before the close hand-over, so whoever listens sees what the action started.
    const handler = it.closeHandler;
    it.closeHandler = undefined;
    leave(it);
    run?.(event);
    handler?.();
  };

  const build = (): Item => {
    const card = document.createElement("aside");
    card.className = "ui-toast ui-overlay-surface";
    card.setAttribute("aria-label", "Notification");
    card.setAttribute("role", "group");

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

    const button = (): HTMLButtonElement => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "ui-toast-action ui-button";
      b.hidden = true;
      return b;
    };
    const action = button();
    const secondaryAction = button();

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
    card.append(marker, glyph, label, actions, icons, close);

    const it: Item = {
      id: `t${++serial}`, key: "", message: "", count: 1, error: false, card, label, glyph, close, actions, action,
      secondaryAction, icons, height: 0, left: 0, since: 0, timer: 0, exitTimer: 0, leaving: false, iconRuns: [],
    };
    action.addEventListener("click", (event) => onAction(it, it.selectAction, event as MouseEvent));
    secondaryAction.addEventListener("click", (event) => onAction(it, it.selectSecondaryAction, event as MouseEvent));
    close.addEventListener("click", () => leave(it));
    icons.addEventListener("click", (event) => {
      const target = (event.target as Element | null)?.closest?.<HTMLElement>("[data-index]");
      const entry = target ? it.iconRuns[Number(target.dataset.index)] : undefined;
      if (!entry) return;
      if (entry.keepOpen) entry.onSelect(event as MouseEvent); else onAction(it, entry.onSelect, event as MouseEvent);
    });
    swipe(it);
    return it;
  };

  /** Touch swipe down dismisses; a finger resting on the stack holds it (clocks stop, cards fan out). */
  const swipe = (it: Item): void => {
    const { card } = it;
    let y0: number | null = null;
    const rest = (): void => { card.removeAttribute("data-swiping"); card.style.removeProperty("--sw"); };
    card.addEventListener("pointerdown", (e) => {
      if (e.pointerType === "mouse") return;
      setHold("touch", true);
      if ((e.target as Element).closest("button,a")) return;
      y0 = e.clientY;
      card.setPointerCapture?.(e.pointerId);
    });
    card.addEventListener("pointermove", (e) => {
      if (y0 === null) return;
      card.dataset.swiping = "true";
      card.style.setProperty("--sw", `${Math.max(0, e.clientY - y0)}px`);
    });
    const end = (e: PointerEvent): void => {
      if (e.pointerType === "mouse") return;
      const far = y0 !== null && e.clientY - y0 > SWIPE_PX && e.type === "pointerup";
      y0 = null;
      setHold("touch", false);
      // The card fades out from where the finger left it; a short drag springs back.
      if (far) { card.removeAttribute("data-swiping"); leave(it); } else rest();
    };
    card.addEventListener("pointerup", end);
    card.addEventListener("pointercancel", end);
  };

  const fill = (it: Item, value: ToastMessage): void => {
    it.closeHandler = value.onClose;
    it.error = value.tone === "error";
    it.card.dataset.tone = value.tone ?? "ok";
    it.close.hidden = !value.dismissible;
    // One rule for every caller: a failure never shows the green tick, whatever tone its caller guessed.
    const icon = value.icon ?? (value.tone === "error" ? ICONS.warning : undefined);
    it.glyph.hidden = !icon;
    it.card.dataset.icon = icon ? "true" : "false";
    if (icon) it.glyph.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18">${icon}</svg>`;
    if (value.messageNode) it.label.replaceChildren(value.messageNode); else it.label.textContent = value.message;
    if (it.count > 1) {
      const count = document.createElement("span");
      count.className = "ui-toast-count";
      count.textContent = ` ×${it.count}`;
      it.label.append(count);
    }
    it.selectAction = value.action?.onSelect;
    it.selectSecondaryAction = value.secondaryAction?.onSelect;
    it.action.textContent = value.action?.label ?? "";
    it.action.hidden = !value.action;
    it.secondaryAction.textContent = value.secondaryAction?.label ?? "";
    it.secondaryAction.hidden = !value.secondaryAction;
    const list = value.iconActions ?? [];
    it.iconRuns = list;
    it.icons.replaceChildren(...list.map((entry, index) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "ui-toast-icon ui-button";
      b.dataset.index = String(index);
      b.setAttribute("aria-label", entry.label);
      b.dataset.tip = entry.label;
      b.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">${entry.icon}</svg>`;
      return b;
    }));
    it.icons.hidden = list.length === 0;
    if (list.length) it.icons.setAttribute("aria-label", "Notification choices"); else it.icons.removeAttribute("aria-label");
    it.card.dataset.choices = String(list.length > 0);
    it.actions.hidden = !value.action && !value.secondaryAction;
    if (it.actions.hidden) {
      it.actions.removeAttribute("aria-label");
      it.actions.removeAttribute("aria-keyshortcuts");
    } else {
      it.actions.setAttribute("aria-label", value.actionGroupLabel ?? "Notification actions");
      if (value.actionGroupKeyShortcuts) it.actions.setAttribute("aria-keyshortcuts", value.actionGroupKeyShortcuts);
      else it.actions.removeAttribute("aria-keyshortcuts");
    }
    it.card.dataset.stacked = String(Boolean(value.action || value.secondaryAction) && value.message.length > STACK_AFTER);
    const duration = value.duration ?? 4200;
    it.left = duration > 0 ? duration : Number.POSITIVE_INFINITY;
  };

  // Hover and keyboard focus fan the stack out. Touch holds come from the swipe handler.
  wrap.addEventListener("pointerover", (e) => {
    if (e.pointerType !== "mouse") return;
    window.clearTimeout(leaveTimer);
    leaveTimer = 0;
    if (!holds.has("mouse")) setHold("mouse", true);
  });
  wrap.addEventListener("pointerleave", (e) => {
    if (e.pointerType !== "mouse") return;
    window.clearTimeout(leaveTimer);
    leaveTimer = window.setTimeout(() => { leaveTimer = 0; setHold("mouse", false); }, COLLAPSE_MS);
  });
  wrap.addEventListener("focusin", (e) => {
    // Mouse clicks leave no ring (TASTE), so only keyboard focus fans the stack out.
    if ((e.target as Element).matches?.(":focus-visible")) setHold("focus", true);
  });
  wrap.addEventListener("focusout", (e) => {
    if (!wrap.contains(e.relatedTarget as Node | null)) setHold("focus", false);
  });

  return {
    show(value) {
      const key = value.key ?? `${value.tone ?? "ok"}|${value.message}`;
      let it = live().find((other) => other.key === key);
      if (it) {
        // An update in place: a repeat counts, a changed message morphs the same toast. Its clock starts again, and
        // it moves to the front because it is the newest news.
        it.count = it.message === value.message ? it.count + 1 : 1;
        pause(it);
        finish(it);
        items.splice(items.indexOf(it), 1);
      } else {
        it = build();
        it.key = key;
        wrap.append(it.card);
      }
      items.push(it);
      it.message = value.message;
      fill(it, value);
      it.card.dataset.open = it.card.dataset.open ?? "false";
      arrange();
      // The newest toast is unclamped (it is the front), so this is its natural height: one forced layout per toast.
      it.height = it.card.offsetHeight || it.height;
      clocks();
      // A fast receipt can dismiss this message before its first animation frame.
      const shown = it;
      requestAnimationFrame(() => { if (!shown.leaving && !disposed) shown.card.dataset.open = "true"; });
      return it.id;
    },
    focusAction(index = 0) {
      if (!Number.isInteger(index) || index < 0) return false;
      for (const it of live().reverse()) {
        const available = [it.action, it.secondaryAction, ...it.icons.querySelectorAll<HTMLElement>("button")].filter((button) => !button.hidden);
        const target = available[index];
        if (!target) continue;
        target.focus({ preventScroll: true });
        return true;
      }
      return false;
    },
    dismiss(...args) {
      // `dismiss(undefined)` (an owner whose toast is already gone) is a no-op, never "dismiss everything".
      for (const it of live()) if (args.length === 0 ? !it.error : it.id === args[0]) leave(it);
    },
    dispose() {
      disposed = true;
      window.clearTimeout(leaveTimer);
      if (frame) cancelAnimationFrame(frame);
      for (const it of items) { window.clearTimeout(it.timer); window.clearTimeout(it.exitTimer); }
      items.length = 0;
      spacing?.disconnect();
      wrap.remove();
    },
  };
}
