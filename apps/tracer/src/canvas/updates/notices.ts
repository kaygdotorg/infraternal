// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The two places an update speaks outside Settings (#211, S5; D155 U5): the Inbox item "Update ready · <version>" while a
 * staged version waits for a quiet moment, and the toasts when an update is installed or undone. After an install the page
 * reloads once nothing is being typed, so the person lands on the new version without losing a half-written command.
 *
 * Invariants:
 *  - The Inbox item exists exactly while the state is `ready`; any other state withdraws it.
 *  - Each toast shows once per change: the first state a source reports is the baseline and says nothing.
 *  - The reload waits for `idle()` (nothing typed or unsent) and happens at most once per installed version.
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import type { InboxItem } from "../../../../../packages/ui/src/inbox";
import type { CoreScreen } from "../../core-screen";
import { inboxFor, existingInbox } from "../inbox-host";
import type { UpdatesSource, UpdateState } from "./source";
import { inboxBody, inboxTitle, undoneToast, updatedToast } from "./words";

/** The Inbox source id this module publishes under. */
const INBOX_SOURCE = "update";

/** What the notices need beyond the source: whether the page is idle, how to reload it, and a timer (injected so a test never waits). */
export interface NoticeOptions {
  /** True when nothing is being typed and no input is unsent. */
  idle(): boolean;
  reload(): void;
  /** Calls `run` after `ms`; returns a canceller. Default: the page's timer. */
  later?(run: () => void, ms: number): () => void;
  /** Also toast a version that is already waiting when the notices start. Off in the product (a page load must not toast); the mockup turns it on to show the toast. */
  announceReady?: boolean;
}

/** How often a pending reload looks again for a quiet page. */
const POLL_MS = 1500;

/** The Inbox item for a staged version: Update now, and a quiet way to leave it for the quiet window. */
export function inboxItemFor(version: string, quietMinutes: number, source: Pick<UpdatesSource, "apply">, say: (message: string) => void): InboxItem {
  return {
    id: "update-ready", icon: ICONS.overview, title: inboxTitle(version), body: inboxBody(version, quietMinutes),
    actions: [{ label: "Update now", primary: true, run: () => { void source.apply().catch((e: unknown) => say(e instanceof Error ? e.message : "The update did not start.")); } }],
  };
}

/** Watches `source` and raises the Inbox item and the toasts. Returns the remover (withdraws the item). */
export function mountUpdateNotices(core: CoreScreen, source: UpdatesSource, options: NoticeOptions): () => void {
  const later = options.later ?? ((run, ms) => { const id = window.setTimeout(run, ms); return () => window.clearTimeout(id); });
  let last: UpdateState = options.announceReady ? { kind: "never" } : source.facts().state;
  let running = source.facts().running;
  let cancelReload: (() => void) | undefined;
  const say = (message: string): void => core.toast.show({ message, tone: "error" });

  const reloadWhenIdle = (): void => {
    cancelReload?.();
    const tick = (): void => { if (options.idle()) { cancelReload = undefined; options.reload(); } else cancelReload = later(tick, POLL_MS); };
    tick();
  };

  const onChange = (): void => {
    const facts = source.facts();
    const state = facts.state;
    if (state.kind === "ready") {
      inboxFor(core).set(INBOX_SOURCE, [inboxItemFor(state.version, facts.quietMinutes, source, say)]);
      if (last.kind !== "ready") core.toast.show({ message: inboxTitle(state.version), action: { label: "Update now", onSelect: () => { void source.apply().catch(() => say("The update did not start.")); } }, dismissible: true });
    } else existingInbox(core)?.set(INBOX_SOURCE, []);
    if (facts.running !== running && state.kind !== "applying") {
      // A different version is running now: installed (or put back by a roll back).
      if (state.kind === "rolled-back") core.toast.show({ message: undoneToast(facts.running), tone: "error" });
      else { core.toast.show({ message: updatedToast(facts.running) }); reloadWhenIdle(); }
    } else if (state.kind === "rolled-back" && last.kind === "applying") core.toast.show({ message: undoneToast(facts.running), tone: "error" });
    running = facts.running;
    last = state;
  };
  const stop = source.onChange(onChange);
  onChange();
  return () => { stop(); cancelReload?.(); existingInbox(core)?.set(INBOX_SOURCE, []); };
}
