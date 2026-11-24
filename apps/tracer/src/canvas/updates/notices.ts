// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The one place an update speaks outside Settings (#211, S5; D155 U5): the Inbox item "Update ready · <version>" while a
 * staged version waits for a quiet moment. There are no toasts for updates at all (owner, 2026-11-22: "the Inbox item and the
 * sidebar indicator are enough"); the sidebar indicator is the version pill, which reads the same source (`version/product-source.ts`).
 * After an install the page reloads once nothing is being typed, so the person lands on the new version without losing a
 * half-written command.
 *
 * Invariants:
 *  - The Inbox item exists exactly while the state is `ready`; any other state withdraws it.
 *  - The reload waits for `idle()` (nothing typed or unsent) and happens at most once per installed version.
 *  - A refused "Update now" from the Inbox leaves the item and the state as they are; the Updates window is where the reason is read.
 */
import { ICONS } from "../../../../../packages/ui/src/icons";
import type { InboxItem } from "../../../../../packages/ui/src/inbox";
import type { CoreScreen } from "../../core-screen";
import { inboxFor, existingInbox } from "../inbox-host";
import type { UpdatesSource } from "./source";
import { inboxBody, inboxTitle } from "./words";

/** The Inbox source id this module publishes under. */
const INBOX_SOURCE = "update";

/** What the notices need beyond the source: whether the page is idle, how to reload it, and a timer (injected so a test never waits). */
export interface NoticeOptions {
  /** True when nothing is being typed and no input is unsent. */
  idle(): boolean;
  reload(): void;
  /** Calls `run` after `ms`; returns a canceller. Default: the page's timer. */
  later?(run: () => void, ms: number): () => void;
}

/** How often a pending reload looks again for a quiet page. */
const POLL_MS = 1500;

/** The Inbox item for a staged version: Update now, and a quiet way to leave it for the quiet window. A refusal is passed to `refused` (the window shows it). */
export function inboxItemFor(version: string, quietMinutes: number, source: Pick<UpdatesSource, "apply">, refused: (message: string) => void = () => undefined): InboxItem {
  return {
    id: "update-ready", icon: ICONS.overview, title: inboxTitle(version), body: inboxBody(version, quietMinutes),
    actions: [{ label: "Update now", primary: true, run: () => { void source.apply().catch((e: unknown) => refused(e instanceof Error ? e.message : "The update did not start.")); } }],
  };
}

/** Watches `source` and raises the Inbox item and the reload. Returns the remover (withdraws the item). */
export function mountUpdateNotices(core: CoreScreen, source: UpdatesSource, options: NoticeOptions): () => void {
  const later = options.later ?? ((run, ms) => { const id = window.setTimeout(run, ms); return () => window.clearTimeout(id); });
  let running = source.facts().running;
  let cancelReload: (() => void) | undefined;

  const reloadWhenIdle = (): void => {
    cancelReload?.();
    const tick = (): void => { if (options.idle()) { cancelReload = undefined; options.reload(); } else cancelReload = later(tick, POLL_MS); };
    tick();
  };

  const onChange = (): void => {
    const facts = source.facts();
    const state = facts.state;
    if (state.kind === "ready") inboxFor(core).set(INBOX_SOURCE, [inboxItemFor(state.version, facts.quietMinutes, source)]);
    else existingInbox(core)?.set(INBOX_SOURCE, []);
    // A different version is running now: installed, or put back by a roll back. Either way the page is the old build's, so it reloads when idle.
    if (facts.running !== running && state.kind !== "applying") reloadWhenIdle();
    running = facts.running;
  };
  const stop = source.onChange(onChange);
  onChange();
  return () => { stop(); cancelReload?.(); existingInbox(core)?.set(INBOX_SOURCE, []); };
}
