/**
 * Sharing layouts (D182): a layout (one or more views) is sent to users or groups. The recipient gets a copy that
 * is theirs, as a new view named after the sender, never replacing or merging into anything. Windows connect
 * through the recipient's own grants ("no access" where they have none). An operator can also publish to the team:
 * followers keep a linked, read-only copy that follows the publisher's arrangement until they unlink it.
 *
 * Transport is the sharing adapter (`adapter.ts`). This module owns the dialog (morphed out of the top pill),
 * the "arrived" handling, the follower's live updates and the unlink control.
 */
import { createPillMorph, type PillMorph } from "../../../../../packages/ui/src/pill-morph";
import type { Ctx, ViewRec } from "../context";
import { el } from "../dom";
import type { ViewModel, WindowModel } from "../model/types";
import { loadGroups } from "../layout/groups-handle";
import { copyForRecipient } from "./copy";
import { buildShareDialog, type ShareChoice } from "./dialog";
import type { IncomingShare, SharingAdapter } from "./adapter";

/** The sharing actions the canvas calls. */
export interface SharingModule {
  /** Opens (or closes) the share dialog with these views preselected. */
  open(preselect?: string[]): Promise<void>;
  /** Makes the current team layout the person's own copy. */
  unlinkCurrent(): void;
  /** Shows or hides the unlink control for the current view (called when the pill repaints). */
  paintUnlink(): void;
  /** Forgets which layouts already arrived (the mockup switched person). */
  reset(): void;
  /** A published view changed: followers get it (debounced). */
  schedulePublish(c: ViewRec): void;
  dispose(): void;
}

/** The loaded sharing implementation also accepts snapshots from its small handle. */
export interface SharingController extends SharingModule {
  receive(shares: IncomingShare[]): void;
}

/** A recipient id without its `user:` or `group:` prefix. */
const labelOfRecipient = (id: string): string => id.replace(/^(user|group):/, "");

/** Makes the loaded sharing implementation for `cx` over `adapter`. */
export function createSharing(cx: Ctx, adapter: SharingAdapter): SharingController {
  const { stage, signal, state, views, toast, flip } = cx;
  const received = new Set<string>();
  const revs = new Map<string, number>();
  const viewOfKey = new Map<string, string>();
  let morph: PillMorph | undefined;
  let dialog: ReturnType<typeof buildShareDialog> | undefined;
  let abort: AbortController | undefined;

  const close = (instant = false): void => {
    abort?.abort(); abort = undefined;
    morph?.close(instant);
  };
  const open = async (preselect?: string[]): Promise<void> => {
    if (morph?.isOpen) { close(); return; }
    cx.viewList.close(true);
    if (cx.float.isOpen()) cx.float.close(true);
    const shareable = [...views.values()].filter((c) => c.view.id !== "settings").map((c) => ({ id: c.view.id, name: c.view.name }));
    if (!shareable.length) return;
    const selected = (preselect ?? [state.currentView]).filter((id) => shareable.some((v) => v.id === id));
    const d = buildShareDialog({
      views: shareable, selected: selected.length ? selected : [shareable[0]!.id], sender: adapter.me(), directory: adapter.directory(),
      canPublish: adapter.canPublish(), onSend: (choice) => { void send(choice); close(); },
    });
    dialog = d;
    const capsule = cx.pill.capsule;
    morph = createPillMorph({ pill: capsule, stage, panel: d.panel, content: d.content, width: 400, onClosed: () => { d.dispose(); if (dialog === d) dialog = undefined; } });
    abort = new AbortController();
    const sig = abort.signal;
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); } }, { capture: true, signal: sig });
    document.addEventListener("pointerdown", (e) => { const t = e.target as Element; if (!d.panel.contains(t) && !capsule.contains(t) && !t.closest(".ui-confirm-tip, .tip")) close(); }, { capture: true, signal: sig });
    morph.open();
    window.setTimeout(() => d.focus(), 420);
  };

  const snapshotOf = (c: ViewRec): ViewModel => {
    cx.view.geometry(c);
    const { team: _team, published: _published, ...rest } = c.view;
    return JSON.parse(JSON.stringify(rest)) as ViewModel;
  };
  const send = async (choice: ShareChoice): Promise<void> => {
    const picked = choice.views.map((id) => views.get(id)).filter((c): c is ViewRec => !!c);
    if (!picked.length || !choice.to.length) return;
    try {
      const { id } = await adapter.send({ to: choice.to, publish: choice.publish, views: picked.map((c) => ({ key: c.view.id, name: c.view.name, snapshot: snapshotOf(c) })) });
      if (choice.publish) for (const c of picked) c.view.published = { shareId: id, key: c.view.id };
      toast.show({ message: `Shared ${picked.map((c) => c.view.name).join(", ")} with ${choice.to.map(labelOfRecipient).join(", ")}` });
    } catch { toast.show({ message: "Could not share the layout. Try again.", tone: "error" }); }
  };
  const publishTimers = new Map<string, number>();
  const schedulePublish = (c: ViewRec): void => {
    const pub = c.view.published;
    if (!pub) return;
    window.clearTimeout(publishTimers.get(c.view.id));
    publishTimers.set(c.view.id, window.setTimeout(() => {
      const { team: _t, published: _p, ...rest } = c.view;
      void adapter.update(pub.shareId, pub.key, JSON.parse(JSON.stringify(rest)) as ViewModel).catch(() => undefined);
    }, 300));
  };

  /** A team layout changed: the follower's copy takes the publisher's arrangement, moving there (FLIP on the shared spring). */
  const applyTeamSnapshot = (c: ViewRec, fresh: ViewModel): void => {
    // The arrangement, spans and bands included, goes into the DOM the one way every layout change does (D212). The
    // grouped module loads first: the whole change waits for it, so the measure, the change and the motion stay in order.
    void loadGroups().then((grouped) => {
      const before = flip.measure(flip.targets(c.colsEl));
      const keep = new Set<string>();
      for (const col of fresh.cols) for (const w of col.wins) {
        let rec = c.wins.get(w.id);
        if (!rec) { rec = cx.win.make(c, w as WindowModel); c.wins.set(w.id, rec); }
        keep.add(w.id);
      }
      for (const [id, rec] of [...c.wins]) if (!keep.has(id)) { rec.stopResize?.(); cx.visibility.unwatch(rec); rec.binding?.dispose(); rec.cleanup?.(); rec.card.dispose(); c.wins.delete(id); }
      grouped.applyCols(cx, c, fresh.cols);
      c.view.cols = fresh.cols;
      cx.view.geometry(c);
      cx.view.settle(c.view.id);
      flip.play(before, true);
      cx.tree.render();
      if (state.canvasLock && state.currentView === c.view.id) cx.nav.goStop(c, cx.nav.nearestStop(c, cx.camera.cam.cx));
    });
  };

  const onIncoming = (shares: IncomingShare[]): void => {
    const arrived: Array<{ from: string; name: string; id: string }> = [];
    for (const share of shares) {
      if (share.from === adapter.me()) continue;
      for (const v of share.views) {
        const key = `${share.id}:${v.key}`;
        const copy = copyForRecipient(v.snapshot, share.from, adapter.allowedHosts(), share.id);
        if (!received.has(key)) {
          received.add(key); revs.set(key, share.rev); viewOfKey.set(key, copy.id);
          if (share.publish) copy.team = { from: share.from, shareId: share.id, key: v.key, rev: share.rev };
          cx.view.addBeside(copy, "settings");
          arrived.push({ from: share.from, name: v.name, id: copy.id });
        } else if (share.publish && share.rev > (revs.get(key) ?? 0)) {
          revs.set(key, share.rev);
          const c = views.get(viewOfKey.get(key) ?? "");
          if (c?.view.team) applyTeamSnapshot(c, copy);
        }
      }
    }
    if (arrived.length) {
      const first = arrived[0]!;
      toast.show({ message: `${first.from} shared ${arrived.map((a) => a.name).join(", ")} with you`, action: { label: "Open", onSelect: () => cx.nav.flyView(first.id) } });
      cx.nav.flyView(first.id);
    }
  };
  // ---- unlinking a team layout ----------------------------------------------------------------------
  const unlinkBtn = el("button", "ui-pill cl-unlink");
  unlinkBtn.type = "button";
  unlinkBtn.hidden = true;
  unlinkBtn.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1M4 4l16 16"/></svg><span>Unlink to edit</span>';
  unlinkBtn.setAttribute("aria-label", "Unlink to edit");
  stage.append(unlinkBtn);
  const unlinkCurrent = (): void => {
    const c = views.get(state.currentView);
    if (!c?.view.team) return;
    delete c.view.team;
    cx.view.replace(c.view.id);
    toast.show({ message: `${c.view.name} is now your own copy` });
  };
  unlinkBtn.addEventListener("click", unlinkCurrent, { signal });
  const paintUnlink = (): void => {
    const c = views.get(state.currentView);
    const free = !state.canvasLock && cx.camera.lod === "thumb";
    const linked = Boolean(c?.view.team) && !free;
    if (linked && unlinkBtn.hidden) { unlinkBtn.hidden = false; requestAnimationFrame(() => { unlinkBtn.dataset.open = "true"; }); }
    else if (!linked && !unlinkBtn.hidden) { unlinkBtn.dataset.open = "false"; unlinkBtn.hidden = true; }
  };

  return {
    open, unlinkCurrent, paintUnlink, schedulePublish,
    receive: onIncoming,
    reset() { received.clear(); revs.clear(); viewOfKey.clear(); },
    dispose() { close(true); unlinkBtn.remove(); for (const t of publishTimers.values()) window.clearTimeout(t); },
  };
}
