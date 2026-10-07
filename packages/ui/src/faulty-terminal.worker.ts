/** Runs the auth shader off the UI thread, continuously while visible, at no more than 30 fps. */
import { createFaultyTerminalRenderer, type FaultyTerminalRenderer } from "./faulty-terminal";

interface StartMessage {
  type: "start";
  canvas: OffscreenCanvas;
  font: string;
  width: number;
  height: number;
  dpr: number;
  reduced: boolean;
  visible: boolean;
}
interface ResizeMessage { type: "resize"; width: number; height: number; dpr: number }
interface PointerMessage { type: "pointer"; x: number; y: number }
interface VisibilityMessage { type: "visibility"; visible: boolean }
type WorkerMessage = StartMessage | ResizeMessage | PointerMessage | VisibilityMessage | { type: "wake" | "destroy" };

interface WorkerScope {
  addEventListener(type: "message", listener: (event: MessageEvent<WorkerMessage>) => void): void;
  postMessage(response: { type: "ready"; ok: boolean }): void;
}

const scope = globalThis as unknown as WorkerScope;
const mouse = { x: -1, y: -1 }, glow = { x: -1, y: -1 };
const FRAME_INTERVAL_MS = 1000 / 30;
let renderer: FaultyTerminalRenderer | undefined;
let reduced = false, visible = false, alive = true;
let frameTimer: ReturnType<typeof setTimeout> | undefined;
let width = -1, height = -1, dpr = -1, stillDirty = true;

function pause(): void {
  if (frameTimer !== undefined) clearTimeout(frameTimer);
  frameTimer = undefined;
}

function drawStill(): void {
  if (!alive || !renderer || !visible || !reduced || !stillDirty) return;
  renderer.draw(performance.now(), true, mouse, glow);
  stillDirty = false;
}

function drawFrame(): void {
  frameTimer = undefined;
  if (!alive || !renderer || !visible || reduced) return;
  renderer.draw(performance.now(), false, mouse, glow);
  // Schedule after drawing so slow frames can only lower, never exceed, the 30 fps cap.
  frameTimer = setTimeout(drawFrame, FRAME_INTERVAL_MS);
}

function wake(): void {
  if (!alive || !renderer || !visible) return;
  if (reduced) drawStill();
  else if (frameTimer === undefined) drawFrame();
}

function resize(nextWidth: number, nextHeight: number, nextDpr: number): void {
  if (!renderer || (width === nextWidth && height === nextHeight && dpr === nextDpr)) return;
  width = nextWidth; height = nextHeight; dpr = nextDpr;
  renderer.resize(width, height, dpr);
  stillDirty = true;
  drawStill();
}

function start(message: StartMessage): void {
  renderer = createFaultyTerminalRenderer(message.canvas, message.font);
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
