/**
 * The D315 notice itself: the question, its three icon choices, the confirmation and the undo (#251).
 *
 * It lives apart from `startup-hints.ts` because it is needed only when the server reports that tmux or Zellij
 * started by itself in a terminal, which most people never see. The controller (state, Settings switches, the
 * detection call) stays with the canvas; this module loads at that moment (D188, `*.on-demand.ts`), so the wording,
 * the icons and the confirmation wiring do not count against the deferred budget. Loading it adds one chunk fetch
 * (cached after the first visit) between the detection answer and the notice.
 */
import type { ToastController, ToastMessage } from "../../../../../packages/ui/src/toast";
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { ICON_CHECK, ICON_HELP, ICON_X, ICONS } from "../../../../../packages/ui/src/icons";

/** Everything the notice needs from the canvas, so this module stays free of canvas state. */
export interface StartupNoticeInput {
  toast: ToastController;
  confirm: typeof mountConfirmTip;
  /** The host's server call for `terminal.startup`; rejections are the caller's to report through `failure`. */
  call(input: Record<string, unknown>): Promise<unknown>;
  session: string;
  /** What the server found: the multiplexer's id, and the file edit it proposes (absent when it is not recognised). */
  multiplexer: string;
  /** The multiplexer as people know it ("tmux", "Zellij"). */
  other: string;
  proposal: { file: string; guard: string } | undefined;
  docsUrl: string;
  openDocs: (url: string) => void;
  /** True once the controller is disposed: nothing may show after that. */
  disposed: () => boolean;
  failure: () => void;
  /** Hands the open confirmation back so the controller can close it on dispose. */
  setTip: (tip: ReturnType<typeof mountConfirmTip>) => void;
}

/**
 * Shows the notice that another multiplexer started by itself in a terminal, with the choices to switch it off, keep it, or read about it.
 * Switching edits the named startup file after a confirmation (or, when the server proposed no edit, copies the line for the person to add);
 * the success toast has a button that restores the file. Nothing is shown once `disposed()` is true.
 */
export function showStartupNotice(input: StartupNoticeInput): void {
  const { toast, confirm, call, session, multiplexer, other, proposal, docsUrl, openDocs, disposed, failure, setTip } = input;
  const line = proposal?.guard ?? `[ -n "$INFRATERNAL_SESSION" ] || ${multiplexer}`;
  const change = async (op: "apply" | "undo"): Promise<void> => {
    try {
      await call({ op, session, proposal, confirmed: true });
      if (!disposed()) toast.show(op === "apply"
        ? { message: `Switched. ${other} no longer starts in Infraternal terminals (changed ${proposal?.file}).`,
            action: { label: `Restore ${proposal?.file}`, onSelect: () => { void change("undo"); } }, duration: 0, dismissible: true }
        : { message: `${proposal?.file} restored. ${other} starts automatically again.` });
    } catch { failure(); }
  };
  // ✓: with a recognised startup line the file is edited after a confirmation; otherwise the person gets the line to place themselves.
  const switchChoice = (event?: MouseEvent): void => {
    if (!proposal) {
      void navigator.clipboard.writeText(line).then(() => { if (!disposed()) toast.show({ message: `Copied the line that switches. Add it before ${other} starts in your startup file.` }); }, failure);
      return;
    }
    const anchor = event?.currentTarget as HTMLElement | undefined;
    if (disposed() || !anchor) return;
    const sentence = `${other} will stop starting in Infraternal terminals. This terminal keeps running, and you can undo it.`;
    setTip(confirm(anchor, { label: "Switch to the Infraternal Multiplexer", title: `Switch to the Infraternal Multiplexer in ${proposal.file}?`,
      // The line sits on its own row: the confirmation keeps a line break in its effect text.
      effect: `${proposal.guard}\n${sentence}`,
      confirmLabel: "Switch", cancelLabel: "Keep as is", onConfirm: () => { void change("apply"); },
      onCancel: () => { if (!disposed()) toast.show(notice); },
    }));
  };
  const notice: ToastMessage = { message: `${other} started automatically. Would you like to switch to the Infraternal Multiplexer instead?`,
    icon: ICONS.terminal, duration: 0, actionGroupLabel: "Switch to the Infraternal Multiplexer?",
    iconActions: [
      { label: proposal ? "Switch to the Infraternal Multiplexer" : "Copy the line that switches", icon: ICON_CHECK, onSelect: switchChoice },
      { label: `Keep ${other}, don't ask again on this host`, icon: ICON_X, onSelect() {} },
      { label: "About the Infraternal Multiplexer", icon: ICON_HELP, keepOpen: true, onSelect: () => { openDocs(docsUrl); } },
    ],
  };
  toast.show(notice);
}
