/**
 * Marks code that loads only when the person takes an action (the add-host wizard, the share studio, a Settings
 * window). The transfer gate (chunk-classes.ts) gives such code its own budget, apart from the first screen and
 * from the lazily loaded canvas.
 *
 * How the gate knows: it reads the build graph, not a list. Any module whose file name ends in `.on-demand.ts`
 * is an on-demand root, and everything only it reaches is on-demand. Load such a module through this helper so the
 * call site says so too:
 *
 *   const { mountWizard } = await onDemand(() => import("./wizard.on-demand"));
 *
 * A failed load (the network dropped, a new build replaced the chunk) rejects like any import; callers show a
 * retry rather than a blank window.
 */
export function onDemand<T>(load: () => Promise<T>): Promise<T> {
  return load();
}

/** Runs `run` when the page is idle (a timer where idle callbacks do not exist), so warming never competes with input. */
export function whenIdle(run: () => void, timeout = 3000): void {
  const w = window as unknown as { requestIdleCallback?: (cb: () => void, options?: { timeout: number }) => number };
  if (w.requestIdleCallback) w.requestIdleCallback(run, { timeout }); else window.setTimeout(run, 400);
}
