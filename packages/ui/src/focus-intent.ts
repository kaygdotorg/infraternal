/** Cancels deferred automatic focus when newer focus or input activity supersedes it. */
/** The activity that means "the person has moved on" and cancels a deferred focus. */
const events = ["focusin", "pointerdown", "keydown", "input"] as const;
/** One shared tracker per target: `version` counts activity, `waits` counts open captures. */
const trackers = new WeakMap<EventTarget, { version: number; waits: number; changed(): void }>();

/** One set of passive listeners serves every pending surface; none remain once all waits finish. */
export function captureFocusIntent(target: EventTarget): { isCurrent(): boolean; dispose(): void } {
  let tracker = trackers.get(target);
  if (!tracker) {
    tracker = { version: 0, waits: 0, changed() { this.version++; } };
    tracker.changed = tracker.changed.bind(tracker);
    trackers.set(target, tracker);
    for (const type of events) target.addEventListener(type, tracker.changed, { capture: true, passive: true });
  }
  tracker.waits++;
  const shared = tracker, version = shared.version;
  let disposed = false;
  return {
    isCurrent: () => !disposed && shared.version === version,
    dispose() {
      if (disposed) return;
      disposed = true;
      if (--shared.waits !== 0) return;
      for (const type of events) target.removeEventListener(type, shared.changed, { capture: true });
      trackers.delete(target);
    },
  };
}
