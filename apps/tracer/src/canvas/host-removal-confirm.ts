// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The question asked before a host is removed, in one place so the product and the test double word and place it alike.
 *
 * The buttons are plain verbs ("Remove" and "Keep"), never the server action's own text: the server's `label`
 * describes the action in a sentence and is for rows and hints, not for a button (owner, 2026-11-06: "wtf?"). The host's
 * full name lives only in the title, which wraps, so two similar names are never cut apart on a button.
 * Where it sits follows what it acts on: on the removed host's own row or pill, or centred when the removal started
 * from the palette and no element of that host is on screen. It never points at an unrelated window.
 */
import { mountConfirmTip, type ConfirmTipController } from "../../../../packages/ui/src/tooltip";

/**
 * What removing a host does, in the order it happens (D219, D273): access is revoked first, then the infraternal agent is
 * uninstalled. The one sentence every removal surface shows (the card here, the details panel's row and in-panel question).
 */
export const REMOVAL_EFFECT = "Revokes its access, then uninstalls the infraternal agent from it.";

/**
 * Ask whether to remove the host called `name`. `anchor` is that host's own row or pill, or `null` to centre the question.
 * `onConfirm` runs only after the person confirms. A centred question hands focus to `returnFocus` when it is dismissed.
 */
export function confirmHostRemoval(name: string, anchor: HTMLElement | null, onConfirm: () => void, returnFocus?: () => void): ConfirmTipController {
  return mountConfirmTip(anchor, {
    label: `Remove ${name}`,
    title: `Remove ${name}?`,
    effect: REMOVAL_EFFECT,
    named: true,
    confirmLabel: "Remove",
    cancelLabel: "Keep",
    onConfirm,
    ...(returnFocus ? { returnFocus } : {}),
  });
}

/** Confirm D369's server-only forgetting, explicitly distinguishing it from machine cleanup. */
export function confirmHostForget(name: string, anchor: HTMLElement | null, onConfirm: () => void, returnFocus?: () => void): ConfirmTipController {
  return mountConfirmTip(anchor, {
    label: `Forget ${name}`,
    title: `Forget ${name}?`,
    effect: "Remove this host from the list and stop its pending cleanup. Keep the audit record. This does not touch the machine itself or uninstall infraternal from it.",
    named: true,
    confirmLabel: "Forget",
    cancelLabel: "Keep",
    onConfirm,
    ...(returnFocus ? { returnFocus } : {}),
  });
}
