/** Runs the auth shader off the UI thread, continuously while visible, at no more than 30 fps. */
import { createFaultyTerminalRenderer, type FaultyTerminalRenderer } from "./faulty-terminal";

/** First message: hands over the offscreen canvas and the initial size, scheme and visibility. */
interface StartMessage {
  type: "start";
  canvas: OffscreenCanvas;
  font: string;
  width: number;
  height: number;
  dpr: number;
  reduced: boolean;
  light: boolean;
  visible: boolean;
}
/** Switches between the dark and the light field. */
interface SchemeMessage { type: "scheme"; light: boolean }
/** The canvas CSS size and device pixel ratio changed. */
interface ResizeMessage { type: "resize"; width: number; height: number; dpr: number }
/** Pointer position as canvas fractions (x from the left, y from the bottom); -1 when it left. */
interface PointerMessage { type: "pointer"; x: number; y: number }
/** Whether the canvas is on screen and the page is visible; drawing pauses when it is not. */
interface VisibilityMessage { type: "visibility"; visible: boolean }
/** Every message the page can send. `wake` redraws after input; `destroy` stops the worker's drawing. */
type WorkerMessage = StartMessage | ResizeMessage | SchemeMessage | PointerMessage | VisibilityMessage | { type: "wake" | "destroy" };

/** The small part of the worker scope used here; it replies `ready` once with `ok` telling whether WebGL started. */
interface WorkerScope {
  addEventListener(type: "message", listener: (event: MessageEvent<WorkerMessage>) => void): void;
  postMessage(response: { type: "ready"; ok: boolean }): void;
}

/** The worker's own global scope. */
const scope = globalThis as unknown as WorkerScope;
/** Latest pointer position, and the glow position the renderer eases toward it. */
const mouse = { x: -1, y: -1 }, glow = { x: -1, y: -1 };
const FRAME_INTERVAL_MS = 1000 / 30;
/** The renderer, set when the `start` message has been handled. */
let renderer: FaultyTerminalRenderer | undefined;
/** `reduced`: motion is reduced, so one still frame is drawn. `visible`: drawing may run. `alive`: false after `destroy`. */
let reduced = false, visible = false, alive = true;
/** The pending frame timer. */
let frameTimer: ReturnType<typeof setTimeout> | undefined;
/** The last size seen; `stillDirty` says the still frame must be redrawn. */
let width = -1, height = -1, dpr = -1, stillDirty = true;

/** Cancels the pending frame. */
function pause(): void {
  if (frameTimer !== undefined) clearTimeout(frameTimer);
  frameTimer = undefined;
}

/** Draws one frame without scheduling another (reduced motion, or after a resize while paused). */
function drawStill(): void {
  if (!alive || !renderer || !visible || !reduced || !stillDirty) return;
  renderer.draw(performance.now(), true, mouse, glow);
  stillDirty = false;
}

/** Draws a frame, then schedules the next one; scheduling after drawing means a slow frame can only lower the 30 fps cap. */
function drawFrame(): void {
  frameTimer = undefined;
  if (!alive || !renderer || !visible || reduced) return;
  renderer.draw(performance.now(), false, mouse, glow);
  // Schedule after drawing so slow frames can only lower, never exceed, the 30 fps cap.
  frameTimer = setTimeout(drawFrame, FRAME_INTERVAL_MS);
}

/** Resumes drawing after input, when allowed. */
function wake(): void {
  if (!alive || !renderer || !visible) return;
  if (reduced) drawStill();
  else if (frameTimer === undefined) drawFrame();
}

/** Applies a new size and marks the still frame dirty. */
function resize(nextWidth: number, nextHeight: number, nextDpr: number): void {
  if (!renderer || (width === nextWidth && height === nextHeight && dpr === nextDpr)) return;
  width = nextWidth; height = nextHeight; dpr = nextDpr;
  renderer.resize(width, height, dpr);
  stillDirty = true;
  drawStill();
}

/** Creates the renderer on the transferred canvas and tells the page whether it worked. */
function start(message: StartMessage): void {
  renderer = createFaultyTerminalRenderer(message.canvas, message.font, message.light);
  if (!renderer) { scope.postMessage({ type: "ready", ok: false }); return; }
  reduced = message.reduced;
  visible = message.visible;
  resize(message.width, message.height, message.dpr);
  scope.postMessage({ type: "ready", ok: true });
  wake();
}

scope.addEventListener("message", (event) => {
  const message = event.data;
  if (message.type === "start") { start(message); return; }
  if (!renderer || !alive) return;
  if (message.type === "resize") {
    resize(message.width, message.height, message.dpr);
    wake();
  } else if (message.type === "scheme") {
    renderer.setLight(message.light);
    stillDirty = true;
    wake();
  } else if (message.type === "pointer") {
    mouse.x = message.x; mouse.y = message.y;
    wake();
  } else if (message.type === "visibility") {
    visible = message.visible;
    if (visible) wake(); else pause();
  } else if (message.type === "wake") {
    wake();
  } else {
    alive = false;
    pause();
    renderer.destroy();
    renderer = undefined;
  }
});
