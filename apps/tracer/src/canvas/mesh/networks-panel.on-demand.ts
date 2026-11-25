// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The inside of Settings › Mesh › Networks (D197 M3, #580; mockup J1172, approved 2026-11-25): the networks machines
 * advertise, and what the owner decided about each. One block per network, in the source's order (waiting first, then
 * approved, then declined):
 *
 *   192.168.10.0/24                                  the network's address, as a heading
 *   Status     ✓ Approved                            "! Waiting for approval", or "Declined"
 *   Through    build-01                              the machine that carries it
 *   Arrows     2 end on it                           approved networks only
 *   [Approve] [Decline]                              a waiting advertisement; a refusal is said under them
 *   Keep Each Machine's Address   ( switch )         off (the default): the network sees the router's address
 *   [Revoke]                                         asks first: names the network and the arrows it deletes (D295)
 *   [Approve]                                        a declined network: the owner may change their mind
 *
 * Every change shows at once and the server's answer settles it (`RoutesSource` is optimistic): a refusal puts the block
 * back, says why under it, and in a toast. It repaints whenever the source changes, so the Mesh view's card and this
 * window never disagree. On a phone Settings gives this window the iOS-style header ("‹ Mesh") for free. On demand
 * (D188): Settings loads this with the window.
 */
import { createKeyValueList, type KeyValueRow } from "../../../../../packages/ui/src/kv-list";
import { createSettingRow, type SettingRow } from "../../../../../packages/ui/src/setting-row";
import { heading } from "../../../../../packages/ui/src/settings-panels";
import type { ValueSpec } from "../../../../../packages/ui/src/setting-value";
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import type { Ctx } from "../context";
import { el } from "../dom";
import type { MeshNetwork, RoutesSource } from "./networks";
import { approvedToast, declinedToast, revokeConfirm, revokedToast } from "./networks-words";

/** Whether the network's machines see the router's address (off, the default) or each machine's own (on). */
const KEEP_SOURCE: ValueSpec = { kind: "switch", default: false };

/** A button of the shared style with a plain verb as its label. */
function button(label: string, kind: "primary" | "secondary"): HTMLButtonElement {
  const b = el("button", "ui-button cl-up-button");
  b.type = "button";
  b.dataset.button = kind;
  b.textContent = label;
  return b;
}

/** What each state says in the Status row, and its mark. */
const STATUS: Record<MeshNetwork["state"], { value: string; mark?: "ok" | "warn" }> = {
  approved: { value: "Approved", mark: "ok" },
  pending: { value: "Waiting for approval", mark: "warn" },
  declined: { value: "Declined" },
};

/** Draws the Networks window into `pane`. Returns the cleanup. */
export function renderNetworks(cx: Ctx, pane: HTMLElement, source: RoutesSource): () => void {
  const root = el("div", "ui-sp cl-nets");
  pane.append(root);
  let cleanup: Array<() => void> = [];
  /** A change that failed: the source has put the network back and the sentence says why. */
  const failed = (error: unknown): void => { cx.toast.show({ message: error instanceof Error ? error.message : String(error), tone: "error", duration: 8000 }); };

  /** One network's block. */
  const block = (n: MeshNetwork): HTMLElement => {
    const section = el("section", "cl-net");
    section.dataset.network = n.cidr;
    section.dataset.state = n.state;
    section.toggleAttribute("data-saving", n.saving === true);
    const facts = createKeyValueList(`Network ${n.cidr}`);
    const arrows = source.arrowsTo(n.id);
    const status = n.state === "approved" && !n.advertised ? { value: `Approved, ${n.router} stopped offering it`, mark: "warn" as const } : STATUS[n.state];
    const rows: KeyValueRow[] = [{ key: "Status", ...status }, { key: "Through", value: n.router }];
    if (n.state === "approved") rows.push({ key: "Arrows", value: arrows === 0 ? "None yet" : `${arrows} end on it` });
    facts.set(rows);
    cleanup.push(() => facts.dispose());
    section.append(heading(n.cidr), facts.root);
    const approveButton = (): HTMLButtonElement => {
      const approve = button("Approve", "primary");
      approve.disabled = n.saving === true;
      approve.addEventListener("click", () => { void source.approve(n.id).then(() => cx.toast.show({ message: approvedToast(n.cidr) }), failed); });
      return approve;
    };

    if (n.state !== "approved") {
      const actions = el("div", "cl-up-actions");
      actions.append(approveButton());
      if (n.state === "pending") {
        const decline = button("Decline", "secondary");
        decline.disabled = n.saving === true;
        decline.addEventListener("click", () => { void source.decline(n.id).then(() => cx.toast.show({ message: declinedToast(n.cidr, n.router) }), failed); });
        actions.append(decline);
      }
      section.append(actions);
      if (n.refusal && n.state === "pending") {
        const refusal = el("p", "cl-up-refusal", n.refusal.sentence);
        refusal.setAttribute("role", "status");
        section.append(refusal);
      }
      return section;
    }

    const keep: SettingRow = createSettingRow({
      id: `keep-source-${n.routeId}`, title: "Keep Each Machine's Address", spec: KEEP_SOURCE, value: n.keepSource, caption: false,
      explain: `Off: the network sees ${n.router}'s address and needs nothing else. On: it sees each machine's own mesh address, and needs a route back to the mesh through ${n.router}.`,
      onSave: (v) => { void source.setKeepSource(n.id, v === true).catch(failed); },
    });
    cleanup.push(() => keep.dispose());
    const settings = el("div", "ui-setting-list");
    settings.append(keep.root);
    const actions = el("div", "cl-up-actions");
    const revoke = button("Revoke", "secondary");
    revoke.disabled = n.saving === true;
    actions.append(revoke);
    revoke.addEventListener("click", () => mountConfirmTip(revoke, {
      ...revokeConfirm(n, source.arrowsTo(n.id)), named: true,
      onConfirm: () => { void source.revoke(n.id).then(() => cx.toast.show({ message: revokedToast(n.cidr) }), failed); },
    }));
    section.append(settings, actions);
    return section;
  };

  /** What the window shows: every network but a declined one its machine no longer offers (it cannot be approved). */
  const shown = (): MeshNetwork[] => source.list().filter((n) => n.state !== "declined" || n.advertised);
  /** What the window was last drawn from; a change that leaves it the same (an arrow between two hosts) does not redraw it. */
  let drawn = "";
  const paint = (): void => {
    const list = shown();
    const now = JSON.stringify(list.map((n) => [n, source.arrowsTo(n.id)]));
    if (now === drawn) return;
    drawn = now;
    for (const run of cleanup) run();
    cleanup = [];
    root.replaceChildren();
    if (!list.length) {
      root.append(el("p", "cl-settings-later", "No machine advertises a network. When one does, it waits here for you to approve it."));
      return;
    }
    for (const n of list) root.append(block(n));
  };
  paint();
  const stop = source.onChange(paint);
  return () => { stop(); for (const run of cleanup) run(); root.remove(); };
}
