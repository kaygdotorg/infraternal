import type { TouchSelectHooks } from "./terminal-touch-select.on-demand";

/** How long a finger must rest on the terminal before it starts a selection (the system's long press is about the same). */
const HOLD_MS = 450;
/** Two taps within this time and distance are a double tap, which selects the word under them. */
const DOUBLE_TAP_MS = 350;
const DOUBLE_TAP_PX = 30;
/** A touch that ends sooner than this without moving is a tap. */
const TAP_MS = 300;

/**
 * Routes touch gestures to Ghostty scrollback/font size while the PWA viewport stays fixed [37,84].
 *
 * One finger that moves scrolls, as before (D159). One finger that rests for {@link HOLD_MS} instead selects the word under
 * it, and moving on then extends the selection; a double tap selects a word too (#426). The selection itself is built by
 * `loadSelect` the first time a finger touches the terminal, so a desktop session never loads it. Any later touch of the
 * terminal clears the selection first.
 */
export function terminalTouch(host: HTMLElement, terminal: {
  options: { fontSize: number };
  scrollLines(lines: number): void;
  viewportY: number;
}, metrics: () => { height: number }, fit: () => void, wake: () => void, loadSelect?: () => Promise<TouchSelectHooks>): () => void {
  const events = new AbortController();
  let x = 0, y = 0, startX = 0, startY = 0, carry = 0, velocity = 0, lastTime = 0;
  let axis: "x" | "y" | undefined;
  let dragging = false, pinching = false, distance = 0, baseFont = terminal.options.fontSize;
  let momentum = 0, pinchFrame = 0, suppressClick = false;
  let holdTimer = 0, press = 0, selecting = false, pressTime = 0, lastTap = 0, tapX = 0, tapY = 0, lastTouchAt = 0;
  let loading: Promise<TouchSelectHooks> | undefined;
  /** Runs `use` with the selection hooks, loading them on first use; calls made in order stay in order. */
  const withSelect = (use: (hooks: TouchSelectHooks) => void): void => {
    if (!loadSelect) return;
    if (!loading) {
      loading = loadSelect();
      // A failed load (the network dropped) is tried again by the next touch.
      loading.catch(() => { loading = undefined; });
    }
    loading.then(use).catch((error: unknown) => { console.error("touch selection failed", error); });
  };
  const stop = (): void => { cancelAnimationFrame(momentum); momentum = 0; velocity = 0; };
  const scroll = (pixels: number): boolean => {
    carry += pixels;
    const height = metrics().height;
    const lines = Math.trunc(carry / height);
    if (!lines) return true;
    const before = terminal.viewportY;
    wake();
    terminal.scrollLines(-lines);
    carry -= lines * height;
    return before !== terminal.viewportY;
  };
  const pinch = (scale: number): void => {
    if (!Number.isFinite(scale) || scale <= 0) return;
    cancelAnimationFrame(pinchFrame);
    pinchFrame = requestAnimationFrame(() => {
      pinchFrame = 0;
      const size = Math.round(Math.min(24, Math.max(9, baseFont * scale)) * 2) / 2;
      if (terminal.options.fontSize === size) return;
      wake();
      terminal.options.fontSize = size;
      fit();
    });
  };
  const separation = (touches: TouchList): number => Math.hypot(
    touches[0]!.clientX - touches[1]!.clientX, touches[0]!.clientY - touches[1]!.clientY,
  );
  host.addEventListener("touchstart", (event) => {
    stop();
    clearTimeout(holdTimer);
    selecting = false;
    press++;
    lastTouchAt = event.timeStamp;
    // Loaded now, so the code is there by the time the finger has rested long enough; any new touch ends a selection.
    if (event.touches.length === 1) withSelect((hooks) => { if (hooks.active()) hooks.clear(); });
    dragging = event.touches.length === 1;
    axis = undefined;
    carry = 0;
    if (event.touches.length === 2) {
      pinching = true;
      suppressClick = true;
      distance = separation(event.touches);
      baseFont = terminal.options.fontSize;
    } else if (dragging && !pinching) {
      suppressClick = false;
      x = startX = event.touches[0]!.clientX;
      y = startY = event.touches[0]!.clientY;
      lastTime = pressTime = event.timeStamp;
      holdTimer = window.setTimeout(() => {
        if (axis || pinching || !dragging) return;
        selecting = true;
        suppressClick = true;
        // The hooks may still be loading when the finger lifts, so the check is "still the same touch", not "still selecting".
        const [mine, at, to] = [press, startX, startY];
        withSelect((hooks) => { if (press === mine) hooks.start(at, to); });
      }, HOLD_MS);
    }
  }, { passive: true, signal: events.signal });
  host.addEventListener("touchmove", (event) => {
    event.preventDefault();
    if (selecting) {
      const finger = event.touches[0];
      if (finger && event.touches.length === 1) { const [x, y] = [finger.clientX, finger.clientY]; withSelect((hooks) => hooks.extend(x, y)); }
      return;
    }
    if (event.touches.length === 2 && distance > 0) {
      pinch(separation(event.touches) / distance);
      return;
    }
    if (!dragging || pinching || event.touches.length !== 1) return;
    const next = event.touches[0]!;
    if (!axis && Math.hypot(next.clientX - startX, next.clientY - startY) < 6) return;
    axis ??= Math.abs(next.clientX - startX) > Math.abs(next.clientY - startY) ? "x" : "y";
    clearTimeout(holdTimer);
    suppressClick = true;
    if (axis === "x") host.scrollLeft -= next.clientX - x;
    else {
      const dy = next.clientY - y;
      velocity = Math.max(-3, Math.min(3, dy / Math.max(1, event.timeStamp - lastTime)));
      scroll(dy);
    }
    x = next.clientX;
    y = next.clientY;
    lastTime = event.timeStamp;
  }, { passive: false, signal: events.signal });
  host.addEventListener("touchend", (event) => {
    // A remaining finger after a pinch never becomes a fling or a focus tap.
    if (pinching) { if (!event.touches.length) pinching = false; dragging = false; distance = 0; return; }
    lastTouchAt = event.timeStamp;
    clearTimeout(holdTimer);
    if (selecting) {
      // The finger lifts: show Copy. No click or mouse events follow, or the renderer's own mouse handling would clear it.
      selecting = false; dragging = false; event.preventDefault();
      withSelect((hooks) => hooks.end());
      return;
    }
    if (!dragging || event.touches.length) return;
    dragging = false;
    const lifted = event.changedTouches[0];
    if (!axis && lifted && event.timeStamp - pressTime < TAP_MS) {
      if (event.timeStamp - lastTap < DOUBLE_TAP_MS && Math.hypot(lifted.clientX - tapX, lifted.clientY - tapY) < DOUBLE_TAP_PX) {
        lastTap = 0; suppressClick = true; event.preventDefault();
        const [x, y] = [lifted.clientX, lifted.clientY];
        withSelect((hooks) => { hooks.start(x, y); hooks.end(); });
        return;
      }
      lastTap = event.timeStamp; tapX = lifted.clientX; tapY = lifted.clientY;
    }
    if (axis !== "y" || event.timeStamp - lastTime > 80 || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let previous = performance.now();
    const step = (now: number): void => {
      momentum = 0;
      const dt = Math.min(32, now - previous);
      previous = now;
      if (Math.abs(velocity) < 0.02 || !scroll(velocity * dt)) { stop(); return; }
      // Time-based decay keeps the mockup's 0.95/frame feel at both 60 and 120 Hz.
      velocity *= Math.pow(0.95, dt / 16);
      momentum = requestAnimationFrame(step);
    };
    momentum = requestAnimationFrame(step);
  }, { signal: events.signal });
  host.addEventListener("touchcancel", () => {
    clearTimeout(holdTimer);
    if (selecting) { selecting = false; withSelect((hooks) => hooks.end()); }
    stop(); dragging = pinching = false; distance = carry = 0;
    cancelAnimationFrame(pinchFrame);
  }, { signal: events.signal });
  host.addEventListener("click", (event) => {
    if (!suppressClick) return;
    event.preventDefault(); event.stopImmediatePropagation(); suppressClick = false;
  }, { capture: true, signal: events.signal });
  // A long press can make the browser send a context-menu event; the renderer would answer it by focusing a hidden field.
  host.addEventListener("contextmenu", (event) => {
    if (!dragging && !selecting && event.timeStamp - lastTouchAt > 800) return;
    event.preventDefault(); event.stopImmediatePropagation();
  }, { capture: true, signal: events.signal });
  // Safari's native gestures and touch-distance events coalesce into the same frame.
  host.addEventListener("gesturestart", (event) => {
    event.preventDefault(); stop(); pinching = true; baseFont = terminal.options.fontSize;
  }, { signal: events.signal });
  host.addEventListener("gesturechange", (event) => {
    event.preventDefault();
    const scale = (event as Event & { scale?: number }).scale;
    if (scale !== undefined) pinch(scale);
  }, { signal: events.signal });
  host.addEventListener("gestureend", (event) => { event.preventDefault(); pinching = false; }, { signal: events.signal });
  const hidden = (): void => { if (document.hidden) stop(); };
  document.addEventListener("visibilitychange", hidden, { signal: events.signal });
  return () => { events.abort(); clearTimeout(holdTimer); stop(); cancelAnimationFrame(pinchFrame); void loading?.then((hooks) => hooks.clear()); };
}
