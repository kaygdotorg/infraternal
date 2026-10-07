/** Routes touch gestures to Ghostty scrollback/font size while the PWA viewport stays fixed [37,84]. */
export function terminalTouch(host: HTMLElement, terminal: {
  options: { fontSize: number };
  scrollLines(lines: number): void;
  viewportY: number;
}, metrics: () => { height: number }, fit: () => void, wake: () => void): () => void {
  const events = new AbortController();
  let x = 0, y = 0, startX = 0, startY = 0, carry = 0, velocity = 0, lastTime = 0;
  let axis: "x" | "y" | undefined;
  let dragging = false, pinching = false, distance = 0, baseFont = terminal.options.fontSize;
  let momentum = 0, pinchFrame = 0, suppressClick = false;
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
      lastTime = event.timeStamp;
    }
  }, { passive: true, signal: events.signal });
  host.addEventListener("touchmove", (event) => {
    event.preventDefault();
    if (event.touches.length === 2 && distance > 0) {
      pinch(separation(event.touches) / distance);
      return;
    }
    if (!dragging || pinching || event.touches.length !== 1) return;
    const next = event.touches[0]!;
    if (!axis && Math.hypot(next.clientX - startX, next.clientY - startY) < 6) return;
    axis ??= Math.abs(next.clientX - startX) > Math.abs(next.clientY - startY) ? "x" : "y";
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
    if (!dragging || event.touches.length) return;
    dragging = false;
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
    stop(); dragging = pinching = false; distance = carry = 0;
    cancelAnimationFrame(pinchFrame);
  }, { signal: events.signal });
  host.addEventListener("click", (event) => {
    if (!suppressClick) return;
    event.preventDefault(); event.stopImmediatePropagation(); suppressClick = false;
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
  return () => { events.abort(); stop(); cancelAnimationFrame(pinchFrame); };
}
